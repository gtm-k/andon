//! # andon-mcp
//!
//! The MCP stdio server — the surface an agent actually calls (PLAN P6).
//!
//! # A thin adapter, and why thinness is the design
//!
//! Every tool here is a wrapper over a function `andon-cli` already exposes:
//! [`measure_change`](AndonMcp::measure_change) runs `measure::measure` and
//! saves through `store::write_last` exactly as `andon measure` does;
//! [`get_results`](AndonMcp::get_results) reads the same saved record through
//! `store::read_record`; the profile an agent receives comes from
//! `render::profile`, the function behind `--profile agent-mode`. The MCP
//! server computes no number of its own. This project's dominant defect class
//! is two surfaces answering one question differently, and the only structural
//! defence is for there to be one answer both surfaces read.
//!
//! # What an agent receives, and how much of it
//!
//! Measurement tools return the **agent-mode profile** (PREMORTEM A2): a
//! bounded projection whose canonical encoding stays inside
//! `[agent] profile_token_budget` from the repository's own `.andon.toml`, by
//! construction in `build_agent_profile` and asserted here by the conformance
//! test over the actual serialized tool output. A payload that floods an
//! agent's context is one way a tool earns being uninstalled.
//!
//! # Refusals read the repository and say what to do next
//!
//! A tool-level failure (not a repository, nothing measured yet, an unknown
//! metric id) is returned as an MCP *tool error* whose text is the same prose
//! the CLI prints — never a struct dump, and never a protocol error, which
//! most clients render opaquely. The distinction matters: a protocol error is
//! for a request the server cannot route at all.
//!
//! # MCP compatibility policy
//!
//! See [`COMPATIBILITY_POLICY`], which is the statement required by PLAN P6
//! ("MCP spec pinned + compatibility policy stated").

#![deny(missing_docs)]
#![warn(clippy::all)]

use std::path::{Path, PathBuf};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo,
};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use serde::Deserialize;

use andon_cli::{explain, ledger, measure, render, store};
use andon_core::git::Git;
use andon_core::schema::enums::InvocationSource;
use andon_core::schema::payload::MeasurementRecord;

/// The version-compatibility statement for this server, verbatim in the crate
/// so the policy ships beside the code it governs.
///
/// **The MCP protocol versions this server speaks are a property of the pinned
/// `rmcp` release** (`=`-pinned in this crate's manifest, like the grammars):
/// rmcp negotiates per the MCP specification — a client-requested version the
/// server supports is echoed back; an unsupported request is answered with the
/// server's own current version, and a client that cannot proceed with that
/// answer disconnects. This server does not override rmcp's supported set, so
/// there is no hand-maintained version list here to drift from the
/// implementation. The conformance test pins the negotiated version on both
/// branches; bumping the rmcp pin that changes either is therefore a loud,
/// reviewable event, not a silent capability shift.
pub const COMPATIBILITY_POLICY: &str = "\
The MCP protocol versions this server negotiates are exactly those of the rmcp \
release pinned in Cargo.toml. Requested-and-supported versions are echoed; an \
unsupported request is answered with the server's current version per the MCP \
specification's version-negotiation rule. Bumping the pin is a reviewable \
manifest edit, asserted by the conformance test.";

/// Instructions handed to the client at `initialize` — the first thing an
/// agent reads about this server, so it says when to call what.
const INSTRUCTIONS: &str = "\
Andon measures a code change and reaches a verdict that carries its evidence. \
Call `measure_change` after completing a change (and before committing): it \
measures the repository's current change and returns a bounded JSON profile — \
verdict, trust, and findings worst-first, each with a location (path:span:symbol) \
and a `diff_actionable` flag. Act on findings where `diff_actionable` is true; \
a false there is the signal not to grind. `verdict` is one of pass | advise | \
block | escalate_to_human — on `block`, fix what the findings name and measure \
again; on `escalate_to_human`, stop and hand the change to a person. Call \
`explain_finding` with a `metric_id` or `claim_id` to see the evidence behind \
a number and what it does NOT predict. `get_results` re-reads the last \
measurement without measuring; `await_results` also reports what the async \
lane still owes it. `get_ledger` lists measurements recorded in the commits.";

/// Parameters accepted by every tool: where the repository is.
#[derive(Deserialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct RepoParams {
    /// Any path inside the repository. Defaults to the server's working
    /// directory.
    repo: Option<String>,
}

/// Parameters for `measure_change`.
#[derive(Deserialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct MeasureParams {
    /// Any path inside the repository. Defaults to the server's working
    /// directory.
    repo: Option<String>,
    /// Base revision, or `merge-base:<ref>`. Omit for the default ladder:
    /// the fork point against this repository's own upstream.
    base: Option<String>,
    /// Head revision. Omit to measure the working tree as it stands —
    /// passing `HEAD` instead asks about the last commit, which is a
    /// different measurement.
    head: Option<String>,
    /// Harness name for the ledger, when the caller knows it.
    harness: Option<String>,
    /// Model identifier for the ledger, when the harness discloses one.
    model: Option<String>,
}

/// Parameters for `explain_finding`.
#[derive(Deserialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct ExplainParams {
    /// A `metric_id` or `claim_id` from a finding, e.g.
    /// `static.cognitive-complexity-ts`.
    id: String,
    /// Any path inside the repository. Defaults to the server's working
    /// directory.
    repo: Option<String>,
}

/// The Andon MCP server.
pub struct AndonMcp {
    tool_router: ToolRouter<Self>,
}

impl Default for AndonMcp {
    fn default() -> Self {
        Self::new()
    }
}

fn repo_path(repo: &Option<String>) -> PathBuf {
    match repo {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from("."),
    }
}

/// One text block, the shape every tool here answers with.
fn text(content: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(content)])
}

/// A tool-level refusal: the prose reaches the agent as content, `isError`
/// set, so the same words the CLI would print land where the caller can read
/// them.
fn refusal(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

/// The last saved record, or a refusal that names this server's own verb.
///
/// `store::read_last`'s instruction says `andon measure`, which is the right
/// sentence for the actor holding a shell. This actor holds a tool list, so
/// the absence case is re-worded to the tool's name — detected from the same
/// `store::last_record_path` the reader uses, not from a second rule.
fn last_record(git: &Git) -> Result<MeasurementRecord, String> {
    if !store::last_record_path(git).exists() {
        return Err(
            "no measurement has been taken in this checkout yet. Call `measure_change` first; \
             it measures the current change and stores the record this tool reads."
                .to_string(),
        );
    }
    store::read_last(git)
}

#[tool_router(router = tool_router)]
impl AndonMcp {
    /// A server with the five tools routed.
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Measure the repository's current change and return the agent profile.
    ///
    /// Sync on purpose, like every tool here: the measurement pipeline is
    /// synchronous and the store's iteration counter assumes one writer per
    /// process, so tools executing one at a time on the single-threaded
    /// runtime is the concurrency design, not an accident of it.
    #[tool(
        description = "Measure the current change in a git repository and return Andon's verdict as a bounded JSON profile: verdict (pass|advise|block|escalate_to_human), trust, iteration count against the loop cap, and findings worst-first — each with metric_id, location (path:span:symbol), measured value, evidence tier, and whether it is fixable inside the change (diff_actionable). Call it after completing a change, before committing. On `block`, fix what the findings name and call it again."
    )]
    fn measure_change(&self, Parameters(p): Parameters<MeasureParams>) -> CallToolResult {
        let repo = repo_path(&p.repo);
        let request = measure::Request {
            repo: repo.clone(),
            base: p.base,
            head: p.head,
            source: InvocationSource::AgentInitiated,
            harness: p.harness,
            model: p.model,
            ..measure::Request::default()
        };

        let measurement = match measure::measure(&request) {
            Ok(measurement) => measurement,
            Err(e) => return refusal(e.to_string()),
        };

        // Saved for `get_results`/`await_results` and for the CLI's `report`,
        // best-effort for the CLI's reason: a transient filesystem failure must
        // not throw away a computed measurement. The failure is appended to the
        // payload text rather than logged, because stderr is not a surface this
        // caller reads.
        let save_failure = match Git::open(&repo) {
            Ok(git) => store::write_last(&git, &measurement.record).err(),
            Err(e) => Some(e.to_string()),
        };

        let profile =
            match render::profile(&measurement.record, andon_core::schema::agent_profile::PROFILE_NAME, &repo) {
                Ok(profile) => profile,
                Err(e) => return refusal(e),
            };
        match save_failure {
            None => text(profile),
            Some(e) => CallToolResult::success(vec![
                ContentBlock::text(profile),
                ContentBlock::text(format!(
                    "note: this measurement was not saved for `get_results`: {e}. The profile \
                     above is unaffected; call `measure_change` again to store it."
                )),
            ]),
        }
    }

    /// Re-serve the last measurement as the agent profile, without measuring.
    #[tool(
        description = "Return the agent profile of the last measurement taken in this checkout, without re-measuring. Use it to re-read a verdict; use `measure_change` to take a new one."
    )]
    fn get_results(&self, Parameters(p): Parameters<RepoParams>) -> CallToolResult {
        let repo = repo_path(&p.repo);
        let git = match Git::open(&repo) {
            Ok(git) => git,
            Err(e) => return refusal(e.to_string()),
        };
        let record = match last_record(&git) {
            Ok(record) => record,
            Err(e) => return refusal(e),
        };
        match render::profile(&record, andon_core::schema::agent_profile::PROFILE_NAME, &repo) {
            Ok(profile) => text(profile),
            Err(e) => refusal(e),
        }
    }

    /// The last measurement, plus what the async lane still owes it.
    #[tool(
        description = "Return the agent profile of the last measurement plus what the async lane still owes it. Until the async lane ships (PLAN P7), every shipped engine answers in the fast lane, so the owed list is empty and this differs from `get_results` only by the lane report."
    )]
    fn await_results(&self, Parameters(p): Parameters<RepoParams>) -> CallToolResult {
        let repo = repo_path(&p.repo);
        let git = match Git::open(&repo) {
            Ok(git) => git,
            Err(e) => return refusal(e.to_string()),
        };
        let record = match last_record(&git) {
            Ok(record) => record,
            Err(e) => return refusal(e),
        };
        let profile = match render::profile(&record, andon_core::schema::agent_profile::PROFILE_NAME, &repo) {
            Ok(profile) => profile,
            Err(e) => return refusal(e),
        };
        // Two blocks: the machine-readable profile stays one parseable JSON
        // document, and the lane report — prose about what is still owed —
        // rides beside it rather than corrupting it.
        CallToolResult::success(vec![
            ContentBlock::text(profile),
            ContentBlock::text(andon_cli::lanes::wait(&record)),
        ])
    }

    /// The claim behind a number, and what it does not predict.
    #[tool(
        description = "Explain the evidence behind a finding: pass a metric_id or claim_id from a measurement (e.g. `static.cognitive-complexity-ts`) and get the claim it stands on — tier, citation, population, effect, re-review date, and what the number does NOT predict."
    )]
    fn explain_finding(&self, Parameters(p): Parameters<ExplainParams>) -> CallToolResult {
        match explain::run(&repo_path(&p.repo), None, &p.id) {
            Ok(answer) => text(answer),
            Err(e) => refusal(e),
        }
    }

    /// Measurements recorded in the commits — the ledger-min view.
    #[tool(
        description = "List the measurements recorded against commits in this repository (the git-notes ledger): commit, record count, verdict, and who invoked the measurement. A stub of the full ledger surface — stats and dimension queries ship with PLAN P8; `andon ledger` on the CLI reads the same notes."
    )]
    fn get_ledger(&self, Parameters(p): Parameters<RepoParams>) -> CallToolResult {
        let repo = repo_path(&p.repo);
        let git = match Git::open(&repo) {
            Ok(git) => git,
            Err(e) => return refusal(e.to_string()),
        };
        match ledger::list(&git) {
            Ok(listing) => text(bounded_listing(listing, &repo)),
            Err(e) => refusal(e),
        }
    }
}

/// Cut a ledger listing to the agent-profile byte budget, announced.
///
/// The listing grows one line per annotated commit without bound, and the
/// budget this surface promises is the same one the profile keeps. Truncation
/// drops whole lines from the end and says how many, because a silent cut
/// would make "the ledger holds N commits" and "the ledger listing showed N
/// commits" the same observation — the shape of defect the profile's
/// `truncated` flag exists to prevent.
fn bounded_listing(listing: String, repo: &Path) -> String {
    let budget = agent_budget_bytes(repo);
    if listing.len() <= budget {
        return listing;
    }
    let mut kept = String::new();
    let mut dropped: usize = 0;
    for line in listing.lines() {
        // The strict bound covers the newline; the announcement line needs
        // room too, hence /10.
        if kept.len() + line.len() < budget.saturating_sub(budget / 10) {
            kept.push_str(line);
            kept.push('\n');
        } else {
            dropped += 1;
        }
    }
    kept.push_str(&format!(
        "  …{dropped} more line(s) were cut to stay inside the agent payload budget. \
         Run `andon ledger list` for the full listing.\n"
    ));
    kept
}

/// The byte budget the repository's own policy declares for agent payloads —
/// read through the same loader the profile render uses, defaults outside a
/// repository or without a policy file.
fn agent_budget_bytes(repo: &Path) -> usize {
    let policy = match Git::open(repo) {
        Ok(git) => measure::load_policy(&git, &measure::PolicySource::Worktree)
            .unwrap_or_default(),
        Err(_) => andon_core::policy::Policy::default(),
    };
    (policy.agent.profile_token_budget as usize) * (policy.agent.bytes_per_token as usize)
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AndonMcp {
    fn get_info(&self) -> ServerInfo {
        // The default protocol version is the pinned rmcp release's current
        // one — see COMPATIBILITY_POLICY for why no version is named here.
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("andon", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}
