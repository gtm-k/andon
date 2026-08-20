//! `andon hook <kind>` — what an installed hook actually runs.
//!
//! # One measurement, two gate contracts
//!
//! Both kinds take the same measurement the CLI takes — `measure::measure`
//! over the working change, `--no-fallback` semantics, recorded to the ledger
//! with `invocation_source: hook` (the P6 dogfood dimension). What differs is
//! the contract with the caller:
//!
//! - **`claude-stop`** speaks Claude Code's Stop-hook protocol: exit 2 blocks
//!   the stop and stderr reaches the *agent*, so a `block` puts the agent
//!   profile there — a headline it can read and JSON it can parse. Exit 3 on
//!   an escalation is a non-blocking error: the stop proceeds, stderr reaches
//!   the *user*, which is who an escalation is for.
//! - **`pre-commit`** speaks git's: any non-zero exit refuses the commit, and
//!   both streams land in front of whoever ran `git commit`.
//!
//! # Silence when nothing is in flight
//!
//! A Stop hook fires at the end of *every* response, including a session that
//! never touched code. Measuring the last merged change there would gate the
//! present on the past (the A2 uninstall loop); erroring would be noise at
//! every stop. So "there is no working change" is, for a hook alone, a clean
//! quiet exit — detected by matching the resolver's own refusal, not by a
//! second copy of its rules.
//!
//! # A change nobody read does not pass a gate
//!
//! Unreadable changed paths exit 1 whatever the verdict says, the binary's
//! own rule (`main.rs`), because the honest shape of an unmeasured thing is
//! not the shape of a clean measurement.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use andon_core::git::Git;
use andon_core::schema::enums::{InvocationSource, Verdict};

use crate::args::Flags;
use crate::measure::{self, MeasureError};
use crate::resolve::ResolveFailure;
use crate::{ledger, render, store};

/// Which gate contract the caller speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    /// Claude Code's Stop hook: exit 2 blocks the stop, stderr feeds the agent.
    ClaudeStop,
    /// git's pre-commit hook: any non-zero exit refuses the commit.
    PreCommit,
}

impl HookKind {
    fn parse(name: &str) -> Result<Self, String> {
        match name {
            "claude-stop" => Ok(HookKind::ClaudeStop),
            "pre-commit" => Ok(HookKind::PreCommit),
            other => Err(format!(
                "unknown hook kind '{other}'; one of claude-stop, pre-commit"
            )),
        }
    }

    /// The harness dimension, where the kind itself proves it. A pre-commit
    /// hook can be fired by any harness or by a person, so it claims none.
    fn harness(self) -> Option<String> {
        match self {
            HookKind::ClaudeStop => Some("claude-code".to_string()),
            HookKind::PreCommit => None,
        }
    }
}

/// `andon hook <kind> [--self-measure] [--repo <PATH>]`: measure, record,
/// exit per the kind's gate contract. Returns the exit code.
pub fn cmd_hook(flags: &Flags) -> Result<u8, String> {
    if flags.on("help") {
        println!(
            "andon hook <claude-stop|pre-commit> [--self-measure] [--repo <PATH>]\n\n  \
             What an installed hook runs: measure the working change, record it in the \
             ledger,\n  and exit per the harness's gate contract (0 keep going, 2 stop the \
             line, 3 a human\n  decides, 1 the tool or the read failed). Installed by `andon \
             init`; not intended\n  to be run by hand, but harmless if you do."
        );
        return Ok(0);
    }
    flags.reject_unknown(&["repo"])?;
    let kind = match flags.first() {
        Some(name) => HookKind::parse(name)?,
        None => return Err("which hook? one of: claude-stop, pre-commit".to_string()),
    };
    drain_stdin();
    Ok(run(kind, flags.path("repo", "."), flags.on("self-measure")))
}

/// Claude Code hands the hook a JSON payload on stdin. Reading it to EOF —
/// only when stdin is actually a pipe — keeps the writer from an EPIPE and
/// this process from blocking on a terminal.
fn drain_stdin() {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        let mut sink = Vec::new();
        let _ = stdin.lock().read_to_end(&mut sink);
    }
}

fn run(kind: HookKind, repo: PathBuf, self_measure: bool) -> u8 {
    let request = measure::Request {
        repo: repo.clone(),
        no_fallback: true,
        self_measure,
        source: InvocationSource::Hook,
        harness: kind.harness(),
        ..measure::Request::default()
    };

    let measurement = match measure::measure(&request) {
        Ok(measurement) => measurement,
        // Nothing in flight is, for a hook, nothing to gate. The resolver's
        // own refusals are the detector — no second copy of its ladder here.
        // Two refusals mean it: `NoWorkingChange` (a clean tree whose HEAD
        // matches every base on offer), and `NoParent` (a clean tree on a
        // root commit, where even the last merged change does not exist —
        // a dirty tree never reaches it here, because a worktree head
        // measures against the root commit fine).
        Err(MeasureError::Resolve(
            ResolveFailure::NoWorkingChange { .. } | ResolveFailure::NoParent { .. },
        )) => return 0,
        Err(e) => {
            eprintln!("andon: {e}");
            return 1;
        }
    };
    let record = &measurement.record;

    // The same two best-effort writes as `andon measure`, so a hook run and a
    // CLI run leave the same trail: the saved copy for `report`/`get_results`,
    // the ledger note for the dogfood ledger (invocation_source: hook).
    match Git::open(&repo) {
        Ok(git) => {
            if let Err(e) = store::write_last(&git, record) {
                eprintln!("andon: the measurement was not saved for `andon report`: {e}");
            }
            match ledger::record(&git, record, &measurement.ledger_anchor) {
                Ok(note) => {
                    if kind == HookKind::ClaudeStop {
                        // Transcript-visible on exit 0, agent-visible on exit 2;
                        // either way the write is observable.
                        eprintln!("andon: {note}");
                    }
                }
                Err(e) => eprintln!("andon: the measurement was not recorded in the ledger: {e}"),
            }
        }
        Err(e) => eprintln!("andon: the measurement was neither saved nor recorded: {e}"),
    }

    // The binary's coverage rule, before any verdict: a change nobody could
    // fully read does not pass a gate, and the paths are named where the
    // caller looks.
    if !record.unreadable_paths.is_empty() {
        eprintln!(
            "andon: {} changed path(s) could not be read, so nothing measured describes \
             them: {}. This gate does not pass a change it could not read.",
            record.unreadable_paths.len(),
            record.unreadable_paths.join(", ")
        );
        return 1;
    }

    let verdict = record.verdict.verdict;
    match verdict {
        Verdict::Pass | Verdict::Advise => {
            // One transcript line, derived from the record it describes.
            println!(
                "andon: {} — {} finding(s) over {}",
                render::verdict_word(verdict),
                render::findings(record).len(),
                crate::resolve::change_line(&record.compare_context)
            );
            0
        }
        Verdict::Block => {
            // The agent's copy: a headline it can read, then the same bounded
            // profile the MCP surface serves, then the way forward. All three
            // derived — verdict words from the render table, the profile from
            // render::profile, the id in the hint from the profile's own
            // leading finding.
            eprintln!(
                "andon: {} — {}",
                render::verdict_word(verdict),
                render::verdict_meaning(verdict)
            );
            match render::profile(
                record,
                andon_core::schema::agent_profile::PROFILE_NAME,
                &repo,
            ) {
                Ok(profile) => eprintln!("{profile}"),
                Err(e) => eprintln!("andon: the agent profile could not be rendered: {e}"),
            }
            eprintln!(
                "Fix what the findings name (scope is path:span:symbol), then finish your \
                 turn again — the gate re-measures. `andon explain <metric-id>` shows the \
                 evidence behind any number."
            );
            2
        }
        Verdict::EscalateToHuman => {
            eprintln!(
                "andon: {} — {}",
                render::verdict_word(verdict),
                render::verdict_meaning(verdict)
            );
            eprintln!(
                "Pass {} of a cap of {} on this branch. `andon ledger ack` records that a \
                 human looked, and clears the counter.",
                record.verdict.iteration.count, record.verdict.iteration.cap
            );
            3
        }
    }
}
