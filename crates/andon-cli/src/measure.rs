//! One measurement, end to end: five engines over one change, assembled into one
//! record.
//!
//! # Where the evidence registry comes from, and why it is not the checkout
//!
//! `payload::prepare` needs a merged registry, and there are two ways to get
//! one: read the `registry/` directory beside the code, or merge the copies the
//! engine crates compile into themselves with `include_str!`.
//!
//! This binary uses the compiled-in copies, and the reason is the one that
//! decides whether the tool works at all outside its own repository. A stranger
//! measuring their own project has no `registry/` directory, and a binary that
//! insisted on one would fail on every repository except Andon's — which is
//! PREMORTEM A1's failure reached by a different road. The compiled-in registry
//! travels with the binary, so `expected_engines` is exactly the set of engines
//! this build ships, by construction rather than by a list somebody maintains.
//!
//! `--registry <dir>` overrides it, for the case where the operator wants to
//! measure under a registry they can see and edit. Taking that option means the
//! binary and the directory can disagree about a claim's tier, which is not
//! hidden: `payload::prepare` collects the disagreement and the verdict carries
//! `evidence-registry-skew`.
//!
//! # An engine that fails is named, never dropped
//!
//! Every engine either contributes results or contributes an
//! [`EngineFailure`], and `payload::prepare` refuses a payload where one does
//! neither. A dropped engine would make "this detector found nothing" and "this
//! detector never ran" the same observation, and the wrong one of those passes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use andon_core::date::Date;
use andon_core::engine::{run_engine, MeasureContext, MeasureEngine};
use andon_core::git::{BlobBatch, ChangedEntry, ChangedSet, Git};
use andon_core::payload::registry_load::{self, LoadedRegistry};
use andon_core::payload::{AssembleRequest, EngineOutput};
use andon_core::policy::Policy;
use andon_core::registry::EngineRegistryFile;
use andon_core::schema::enums::{InvocationSource, MetricClass, RecordKind};
use andon_core::schema::payload::{
    Invocation, MeasurementRecord, MeasurementResult, MetricValue, Reserved, ScopeKind,
    ToolIdentity,
};
use andon_core::verdict::iteration::IterationStore;
use andon_core::verdict::policy_change::{self, PolicyChange};
use andon_core::verdict::EngineFailure;

use crate::resolve::{self, Resolution, Substitution};
use crate::store;

/// Tool name on every record this binary writes.
pub const TOOL_NAME: &str = "andon";

/// What to measure, and under what.
#[derive(Debug, Clone)]
pub struct Request {
    /// Any path inside the repository.
    pub repo: PathBuf,
    /// `--base`, or `None` for the ladder in [`crate::resolve`].
    pub base: Option<String>,
    /// `--head`, defaulting to `HEAD`.
    pub head: Option<String>,
    /// Refuse rather than fall back to the last merged change.
    pub no_fallback: bool,
    /// `--registry <dir>`, or `None` for the compiled-in registry.
    pub registry_dir: Option<PathBuf>,
    /// Apply `policy.self_measure.excluded_paths` — Andon measuring Andon.
    pub self_measure: bool,
    /// Who asked.
    pub source: InvocationSource,
    /// Harness name, when one is calling.
    pub harness: Option<String>,
    /// Model identifier, when the harness discloses one.
    pub model: Option<String>,
    /// Self-report or verifier attestation.
    pub record_kind: RecordKind,
    /// Which copy of `.andon.toml` is in force.
    pub policy_source: PolicySource,
}

/// Where the policy in force is read from.
///
/// The verifier reads it from the **base** commit, so that editing a threshold
/// inside the pull request being measured gains nothing (PLAN B6). The agent
/// side reads the working tree, which is the file the operator can see and edit.
/// Two answers to one question, and which one applies is a property of who is
/// asking — so it is a parameter rather than a rule buried in one caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// `.andon.toml` as it sits in the checkout.
    Worktree,
    /// `.andon.toml` as of a commit, for the verifier.
    Commit(String),
}

impl Default for Request {
    fn default() -> Self {
        Request {
            repo: PathBuf::from("."),
            base: None,
            head: None,
            no_fallback: false,
            registry_dir: None,
            self_measure: false,
            source: InvocationSource::HumanCli,
            harness: None,
            model: None,
            record_kind: RecordKind::SelfReport,
            policy_source: PolicySource::Worktree,
        }
    }
}

/// A finished measurement and everything a surface needs to render it honestly.
#[derive(Debug)]
pub struct Measurement {
    /// The record.
    pub record: MeasurementRecord,
    /// Present when the no-diff fallback fired. Every renderer shows it.
    pub substitution: Option<Substitution>,
    /// One line naming the range measured.
    pub how: String,
    /// Paths withheld by `policy.self_measure.excluded_paths`, when
    /// `--self-measure` was given.
    pub excluded: Vec<String>,
    /// Registry loader notices: stale claims, uncited claims, schedule hygiene.
    pub registry_notices: Vec<String>,
    /// The branch the iteration counter was keyed on.
    pub branch: String,
    /// How many files the measured change touched, after any exclusions.
    ///
    /// Reported because zero is a real and confusing answer — an empty commit,
    /// or a change consisting only of paths the self-measure policy withholds —
    /// and a reader seeing change-scope zeros deserves to know which it was.
    pub changed_files: usize,
}

/// Anything that stopped a measurement before it produced a record.
#[derive(Debug, thiserror::Error)]
pub enum MeasureError {
    /// The range could not be resolved.
    #[error(transparent)]
    Resolve(#[from] resolve::ResolveFailure),
    /// Git refused.
    #[error(transparent)]
    Git(#[from] andon_core::git::GitError),
    /// The registry could not be loaded, so no number may be reported.
    #[error("the evidence registry could not be loaded: {0}")]
    Registry(String),
    /// `.andon.toml` could not be read.
    #[error("policy: {0}")]
    Policy(String),
    /// The payload could not be assembled.
    #[error("assembly: {0}")]
    Assembly(#[from] andon_core::payload::AssemblyError),
    /// The iteration counter could not be read or written.
    #[error("iteration state: {0}")]
    Iteration(String),
}

/// The shipped engine registry files, as this binary compiles them in.
///
/// The roster of a *deployment* rather than a constant list of five: every entry
/// comes from [`crate::shipped::SHIPPED`], whose ids are asserted equal to the
/// `engine =` headers of these same files, so an engine cannot join the binary
/// and leave a gap in `expected_engines`.
fn compiled_registry_files() -> Result<Vec<(String, EngineRegistryFile)>, MeasureError> {
    crate::shipped::SHIPPED
        .iter()
        .map(|engine| {
            (engine.registry_file)()
                .map(|file| {
                    (
                        format!("<compiled-in>/{}.toml", engine.engine_id),
                        file.clone(),
                    )
                })
                .map_err(MeasureError::Registry)
        })
        .collect()
}

/// Load the evidence registry: compiled-in by default, from `dir` on request.
pub fn load_registry(
    dir: Option<&Path>,
    policy: &Policy,
    as_of: Date,
) -> Result<LoadedRegistry, MeasureError> {
    match dir {
        Some(dir) => registry_load::load(dir, &policy.registry, as_of)
            .map_err(|e| MeasureError::Registry(e.to_string())),
        None => {
            let files = compiled_registry_files()?;
            registry_load::load_files(&files, &policy.registry, as_of, "<compiled-in>")
                .map_err(|e| MeasureError::Registry(e.to_string()))
        }
    }
}

/// Measure a change.
pub fn measure(request: &Request) -> Result<Measurement, MeasureError> {
    let git = Git::open(&request.repo)?;
    let resolution = resolve::resolve(
        &git,
        &resolve::Request {
            base: request.base.clone(),
            head: request.head.clone(),
            no_fallback: request.no_fallback,
        },
    )?;

    let policy = load_policy(&git, &request.policy_source)?;
    let as_of = Date::today_utc().map_err(|_| {
        MeasureError::Registry(
            "the system clock could not be read, so claim expiry cannot be \
                                evaluated"
                .to_string(),
        )
    })?;
    let registry = load_registry(request.registry_dir.as_deref(), &policy, as_of)?;

    // Self-measurement withholds the fixtures that exist to fire the tamper
    // suite. Declared policy, applied here, and the withheld paths are reported
    // — an exclusion nobody can see is how a dogfood gate stops meaning
    // anything (PREMORTEM S3, docs/self-measure.md).
    let (changed, excluded) = if request.self_measure {
        apply_exclusions(&resolution.changed, &policy.self_measure.excluded_paths)
    } else {
        (resolution.changed.clone(), Vec::new())
    };

    let ctx = MeasureContext {
        compare_context: resolution.compare_context.clone(),
        policy: policy.clone(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox_available: false,
    };

    let (engines, engine_failures) = run_all_engines(&git, &resolution, &changed, &policy, &ctx);

    let policy_change = detect_policy_change(&git, &changed).map_err(MeasureError::Policy)?;

    let prepared = andon_core::payload::prepare(AssembleRequest {
        tool: tool_identity(),
        record_kind: request.record_kind,
        compare_context: resolution.compare_context.clone(),
        invocation: Invocation {
            source: request.source,
            harness: request.harness.clone(),
            model: request.model.clone(),
            author: None,
            // Overwritten by the counter in `finish` — the on-disk state is the
            // party that knows which pass this is.
            iteration: 0,
        },
        reserved: Reserved::default(),
        policy: &policy,
        registry: &registry,
        engines,
        engine_failures,
        policy_change,
    })?;

    let branch = current_branch(&git, &resolution);
    let store = IterationStore::open(store::state_dir(&git))
        .map_err(|e| MeasureError::Iteration(e.to_string()))?;
    let advance = store
        .advance(
            &branch,
            policy.loop_policy.iteration_cap,
            prepared.loop_outcome(),
        )
        .map_err(|e| MeasureError::Iteration(e.to_string()))?;

    let record = prepared.finish(advance);

    Ok(Measurement {
        record,
        substitution: resolution.substitution,
        how: resolution.how,
        excluded,
        changed_files: changed.len(),
        registry_notices: registry
            .notices
            .iter()
            .map(|d| format!("{}: {}", d.code, d.message))
            .collect(),
        branch,
    })
}

/// Run every shipped engine, turning each failure into a named absence.
fn run_all_engines(
    git: &Git,
    resolution: &Resolution,
    changed: &ChangedSet,
    policy: &Policy,
    ctx: &MeasureContext,
) -> (Vec<EngineOutput>, Vec<EngineFailure>) {
    let mut outputs: Vec<EngineOutput> = Vec::new();
    let mut failures: Vec<EngineFailure> = Vec::new();

    // A closure rather than five copies: an engine whose failure path differed
    // from the others' would be an engine whose absence reads differently, and
    // the reader cannot tell a bespoke message from a bespoke rule.
    let record = |engine_id: &str,
                  built: Result<Box<dyn MeasureEngine>, String>,
                  out: &mut Vec<EngineOutput>,
                  failed: &mut Vec<EngineFailure>| {
        match built {
            Ok(engine) => {
                let descriptor = engine.descriptor();
                match run_engine(engine.as_ref(), ctx) {
                    Ok(results) => out.push(EngineOutput {
                        descriptor,
                        results,
                    }),
                    Err(e) => failed.push(EngineFailure {
                        engine_id: engine_id.to_string(),
                        reason: e.to_string(),
                    }),
                }
            }
            Err(reason) => failed.push(EngineFailure {
                engine_id: engine_id.to_string(),
                reason,
            }),
        }
    };

    record(
        "static-metrics",
        andon_static_metrics::StaticMetricsEngine::for_change(
            git,
            changed,
            andon_static_metrics::engine_version(),
        )
        .map(|e| Box::new(e) as Box<dyn MeasureEngine>)
        .map_err(|e| e.to_string()),
        &mut outputs,
        &mut failures,
    );

    record(
        "clones",
        andon_engine_clones::ClonesEngine::for_change(
            git,
            changed,
            Some(&store::clones_index(git)),
        )
        .map(|e| Box::new(e) as Box<dyn MeasureEngine>)
        .map_err(|e| e.to_string()),
        &mut outputs,
        &mut failures,
    );

    record(
        "tamper",
        andon_engine_tamper::TamperEngine::for_change(git, changed)
            .map(|e| Box::new(e) as Box<dyn MeasureEngine>)
            .map_err(|e| e.to_string()),
        &mut outputs,
        &mut failures,
    );

    // The process engine's hotspot metric needs a complexity number per path,
    // and the static engine is the only thing in the workspace that has one.
    // Wiring it here is what `process/src/complexity.rs` says the assembly phase
    // owes it; the alternative is every hotspot reporting
    // `unwitnessed: no complexity input for this path`, which is honest and
    // useless.
    let complexity = complexity_from(&outputs);
    let cache = andon_engine_process::cache::HistoryCache::for_repo(git).ok();
    record(
        "process",
        andon_engine_process::ProcessEngine::for_change(
            git,
            &resolution.range,
            changed,
            policy,
            &complexity,
            cache.as_ref(),
        )
        .map(|e| Box::new(e) as Box<dyn MeasureEngine>)
        .map_err(|e| e.to_string()),
        &mut outputs,
        &mut failures,
    );

    // `for_discovery` rather than `for_change`: discovery carries the reports it
    // could not read, and a report that failed to parse becomes a named
    // `unwitnessed` result rather than a silence.
    let discovery = andon_engine_artifacts::engine::discover(git.workdir());
    record(
        "artifacts",
        andon_engine_artifacts::ArtifactsEngine::for_discovery(
            git,
            &resolution.range,
            changed,
            &discovery,
        )
        .map(|e| Box::new(e) as Box<dyn MeasureEngine>)
        .map_err(|e| e.to_string()),
        &mut outputs,
        &mut failures,
    );

    (outputs, failures)
}

/// Per-path complexity for the hotspot metric, from the static engine's results.
///
/// # Why the maximum and not the sum
///
/// A hotspot ranks *where a change is risky*, and the trait it feeds asks only
/// that the number be monotonic in difficulty. Summing a file's functions makes
/// a long file of trivial helpers outrank a short file holding one function
/// nobody can follow — which inverts the signal, because the second file is the
/// dangerous one to edit. The maximum answers "how bad is the worst thing in
/// here", which is the question a reader opening the file is actually asking.
///
/// Cognitive rather than cyclomatic, for the reason the metric exists: cyclomatic
/// counts branches, cognitive counts the nesting that makes them hard to hold in
/// mind, and comprehension is what the ranking is about.
fn complexity_from(outputs: &[EngineOutput]) -> BTreeMap<String, u64> {
    let mut by_path: BTreeMap<String, u64> = BTreeMap::new();
    for output in outputs {
        if output.descriptor.engine_id != "static-metrics" {
            continue;
        }
        for result in &output.results {
            if !result.metric_id.starts_with("static.cognitive-complexity") {
                continue;
            }
            let (Some(path), MetricValue::Count(value)) = (&result.scope.path, &result.value)
            else {
                continue;
            };
            let entry = by_path.entry(path.clone()).or_insert(0);
            *entry = (*entry).max(*value);
        }
    }
    by_path
}

/// The `.andon.toml` edit inside this change, if there is one.
///
/// Read from the two sides' blobs rather than from the working tree: the
/// question is what the change did to policy, and the working tree is neither
/// side of it. A missing base copy means the change *added* the file, which
/// `policy_change::resolve` compares against the conservative defaults — adding
/// a file that turns tamper blocking off is a loosening, and comparing it
/// against nothing would have made it invisible.
fn detect_policy_change(git: &Git, changed: &ChangedSet) -> Result<Option<PolicyChange>, String> {
    let Some(entry) = changed
        .entries
        .iter()
        .find(|e| e.path == ".andon.toml" || e.old_path.as_deref() == Some(".andon.toml"))
    else {
        return Ok(None);
    };

    let mut batch = BlobBatch::open(git).map_err(|e| e.to_string())?;
    let mut read = |oid: Option<&str>| -> Result<Option<String>, String> {
        let Some(oid) = oid.filter(|o| !o.chars().all(|c| c == '0')) else {
            return Ok(None);
        };
        let content = batch.read(oid).map_err(|e| e.to_string())?;
        String::from_utf8(content.into_bytes())
            .map(Some)
            .map_err(|_| ".andon.toml is not UTF-8".to_string())
    };
    let before = read(entry.src_oid.as_deref())?;
    let after = read(entry.dst_oid.as_deref())?;

    let base = policy_change::resolve(before.as_deref()).map_err(|e| e.to_string())?;
    let head = policy_change::resolve(after.as_deref()).map_err(|e| e.to_string())?;
    // No justification: minting a verified one is the verifier's alone, and a
    // self-report carrying one is refused by assembly. P8's ledger is where an
    // unverified justification will come from.
    let change = policy_change::evaluate(&base, &head, None);
    Ok((!change.is_empty()).then_some(change))
}

/// Withhold paths the self-measure policy excludes, and say which.
fn apply_exclusions(changed: &ChangedSet, patterns: &[String]) -> (ChangedSet, Vec<String>) {
    let mut kept: Vec<ChangedEntry> = Vec::new();
    let mut withheld: Vec<String> = Vec::new();
    for entry in &changed.entries {
        if patterns.iter().any(|p| matches_prefix(p, &entry.path)) {
            withheld.push(entry.path.clone());
        } else {
            kept.push(entry.clone());
        }
    }
    (ChangedSet { entries: kept }, withheld)
}

/// Match the `dir/**` shape every shipped exclusion uses.
///
/// Not a glob engine. All five shipped patterns are a literal prefix followed by
/// `/**`, and a pattern this cannot express is refused rather than
/// approximated — an exclusion list whose entries silently match nothing is
/// worse than one that does not parse, because the operator believes the paths
/// are excluded and they are not.
fn matches_prefix(pattern: &str, path: &str) -> bool {
    match pattern.strip_suffix("/**") {
        Some(prefix) => path == prefix || path.starts_with(&format!("{prefix}/")),
        None => path == pattern,
    }
}

/// Read `.andon.toml` from wherever this caller's policy lives.
///
/// Absent means the conservative defaults were in force, which is what the
/// binary would have used and what every repository but this one will hit.
/// A file that exists and cannot be read is surfaced rather than defaulted: a
/// policy the operator believes is in force and is not is the whole reason
/// `Policy` refuses unknown keys.
fn load_policy(git: &Git, source: &PolicySource) -> Result<Policy, MeasureError> {
    let text = match source {
        PolicySource::Worktree => {
            let path = git.workdir().join(".andon.toml");
            match std::fs::read_to_string(&path) {
                Ok(text) => Some(text),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(MeasureError::Policy(format!("{}: {e}", path.display()))),
            }
        }
        PolicySource::Commit(oid) => git
            .cmd(["show", "--no-textconv", &format!("{oid}:.andon.toml")])
            .succeeds_with_output()
            .map_err(|e| MeasureError::Policy(e.to_string()))?,
    };
    match text {
        Some(text) => {
            Policy::from_toml(&text).map_err(|e| MeasureError::Policy(format!("{source:?}: {e}")))
        }
        None => Ok(Policy::default()),
    }
}

/// The branch the iteration counter is keyed on.
///
/// A detached HEAD has no branch name, and keying every detached measurement
/// under one shared name would make an agent's third pass on one commit escalate
/// an unrelated first pass on another. The head OID is the honest key there: it
/// is per-change, which is what the counter is counting.
fn current_branch(git: &Git, resolution: &Resolution) -> String {
    match git
        .cmd(["symbolic-ref", "--quiet", "--short", "HEAD"])
        .succeeds_with_output()
    {
        Ok(Some(name)) if !name.trim().is_empty() => name.trim().to_string(),
        _ => format!("detached:{}", resolution.compare_context.head_oid),
    }
}

/// Who measured.
///
/// `attested_release` is false and will stay false until a release exists whose
/// own measurement CI attested. Saying `true` here would be the self-measure
/// rule asserting itself (`docs/self-measure.md`), which is the one thing a
/// self-report may not do.
fn tool_identity() -> ToolIdentity {
    ToolIdentity {
        name: TOOL_NAME.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_oid: option_env!("ANDON_BUILD_OID")
            .unwrap_or("unknown")
            .to_string(),
        attested_release: false,
    }
}

/// Results an agent could act on inside this change, worst first.
///
/// The report's ordering, and it is a sort rather than a score: nothing here
/// combines two metrics into one number. Severity, then metric id, so two runs
/// over one change order identically.
pub fn actionable_first(results: &[MeasurementResult]) -> Vec<&MeasurementResult> {
    let mut ordered: Vec<&MeasurementResult> = results.iter().collect();
    ordered.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| {
                actionability_rank(a.metric_class).cmp(&actionability_rank(b.metric_class))
            })
            .then_with(|| a.metric_id.cmp(&b.metric_id))
            .then_with(|| scope_label(a).cmp(&scope_label(b)))
    });
    ordered
}

fn actionability_rank(class: MetricClass) -> u8 {
    match class {
        MetricClass::DiffActionable => 0,
        MetricClass::ContextInformational => 1,
    }
}

/// What a result is about, in one string.
pub fn scope_label(result: &MeasurementResult) -> String {
    let scope = &result.scope;
    match (scope.kind, &scope.path, &scope.symbol) {
        (ScopeKind::Repository, _, _) => "the repository".to_string(),
        (ScopeKind::Change, _, _) => "this change".to_string(),
        (ScopeKind::File, Some(path), _) => path.clone(),
        (ScopeKind::Function, Some(path), Some(symbol)) => match scope.line_span {
            Some(span) => format!("{path}:{} {symbol}", span.start),
            None => format!("{path} {symbol}"),
        },
        (_, Some(path), _) => path.clone(),
        (_, None, _) => "this change".to_string(),
    }
}

/// A metric value as a human reads it.
pub fn value_label(value: &MetricValue) -> String {
    match value {
        MetricValue::Count(n) => n.to_string(),
        MetricValue::Integer(n) => {
            if *n > 0 {
                format!("+{n}")
            } else {
                n.to_string()
            }
        }
        MetricValue::Ratio(r) => format!("{:.4}", r),
        MetricValue::Duration { millis } => format!("{millis} ms"),
        MetricValue::Flag(true) => "fired".to_string(),
        MetricValue::Flag(false) => "did not fire".to_string(),
        MetricValue::Text(text) => text.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_double_star_pattern_matches_the_directory_and_its_contents() {
        assert!(matches_prefix("fixtures/gamed/**", "fixtures/gamed/a.ts"));
        assert!(matches_prefix("fixtures/gamed/**", "fixtures/gamed/x/y.ts"));
        assert!(matches_prefix("fixtures/gamed/**", "fixtures/gamed"));
    }

    #[test]
    fn a_prefix_that_is_not_a_path_boundary_does_not_match() {
        // The bug this pins: `starts_with("fixtures/gamed")` also excludes
        // `fixtures/gamed-honest/`, which is a different directory and one
        // nobody declared.
        assert!(!matches_prefix(
            "fixtures/gamed/**",
            "fixtures/gamed-honest/a.ts"
        ));
    }

    #[test]
    fn a_literal_pattern_matches_only_itself() {
        assert!(matches_prefix(".andon.toml", ".andon.toml"));
        assert!(!matches_prefix(".andon.toml", "docs/.andon.toml"));
    }

    #[test]
    fn the_shipped_exclusions_are_all_expressible() {
        // The refusal-rather-than-approximate claim, checked against the shipped
        // list rather than against an example: a pattern this matcher cannot
        // express would silently exclude nothing.
        for pattern in Policy::default().self_measure.excluded_paths {
            assert!(
                pattern.ends_with("/**"),
                "{pattern} is not the `dir/**` shape this matcher implements"
            );
        }
    }
}
