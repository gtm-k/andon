//! The process engine: six metrics over one windowed history.
//!
//! # The emission rule that keeps honest changes out of the tamper bucket
//!
//! This is the phase's most consequential decision, so it is stated before the
//! code rather than after it.
//!
//! `ResultDigestInput` covers both `value` and `completeness`. A result the
//! agent measured as `Count(7) / complete` and the verifier produced as
//! `Text(unwitnessed) / unwitnessed` is therefore a **digest mismatch on the
//! same `(metric_id, scope)`**, and `andon_core::compare` maps a mismatch to
//! `divergent` — the first-class tamper outcome. That asymmetry is not exotic:
//! `actions/checkout` clones at depth 1 by default, so a CI verifier with a
//! shallow history meeting an agent with a full one is the *ordinary* case, and
//! the process family would accuse every honest PR of gaming.
//!
//! The rule that closes it:
//!
//! > **When the window is truncated, no per-file result is emitted at all.**
//! > The engine emits one change-scoped `unwitnessed` result per metric instead.
//!
//! A truncated side and a complete side then have *nothing paired*: their
//! results sit at different scopes. `compare` reaches step 4, finds deterministic
//! results the other side never witnessed, and returns `unwitnessed` — the
//! pass is withheld and nobody is accused, which is precisely what R2-4
//! established for the tuple axis and what PREMORTEM T1 demands here.
//! `tests/compare_asymmetry.rs` proves both directions against the real
//! `classify`, so this paragraph cannot quietly stop being true.
//!
//! The consequence for P9 is a hard requirement rather than a preference: **the
//! verifier must unshallow before recomputing**, or every process metric it
//! produces is an unwitnessed marker and no self-report can ever be confirmed on
//! them. It is recorded in `docs/patches/p4-spike-matrix-join.md` and in the
//! phase's return packet.
//!
//! Per-file `unwitnessed` results are still emitted for causes that are
//! **properties of the history rather than of the checkout** — a path with no
//! commit inside the window, a file only ever touched as binary, a hotspot with
//! no complexity input. Both sides see the same history and the same absence, so
//! both produce the same result and the digests agree. The distinction is the
//! whole of the rule: what the checkout can change must not be allowed to pair.
//!
//! # Why every metric here is context-informational
//!
//! Policy may only escalate a `diff-actionable` metric to MED+ (PREMORTEM A4),
//! and not one of these numbers is fixable inside the change being measured. A
//! file's churn, its age, and who has owned it are facts about the past; no edit
//! in this diff moves them. They answer "is this a risky place to be working",
//! which is context an agent should have and never a bar it should be made to
//! clear.
//!
//! # Why there are no deltas
//!
//! `delta` is `None` on every result. A delta would mean reading a second window
//! anchored at the base commit — double the cold cost — to answer a question
//! nobody asked: the history of a file is not something the change under
//! measurement moved.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use andon_core::date::Date;
use andon_core::engine::{
    EngineDescriptor, EngineError, MeasureContext, MeasureEngine, MetricDescriptor,
};
use andon_core::git::{ChangedSet, Git, ResolvedRange};
use andon_core::policy::Policy;
use andon_core::registry::{lint, parse_file, EngineRegistryFile, Registry};
use andon_core::schema::enums::{
    Completeness, EngineClass, EngineFamily, Lane, MetricClass, Severity,
};
use andon_core::schema::payload::{
    CacheState, EvidenceRef, Freshness, MeasurementResult, MetricValue, ResultScope, ScopeKind,
};
use andon_core::schema::regime::MeasurementRegime;

use crate::cache::{HistoryCache, HistoryCacheError};
use crate::complexity::ComplexitySource;
use crate::entropy::{entropy_microbits, MICROBITS_PER_BIT};
use crate::history::{HistoryError, HistoryWindow};
use crate::metrics::{aggregate, coupled_absent_partners, PathHistory};

/// Engine id. Matches the `engine` field of `registry/process.toml`.
pub const ENGINE_ID: &str = "process";

/// Revision of the counting spec: the traversal flags, the coupling constants,
/// and the definitions in this file.
///
/// `MeasurementRegime::Process` has no `spec_revision` field — it carries the
/// engine version, the git version, and the window — so the spec revision is
/// folded into the version this engine *reports* (see [`engine_version`]).
/// Changing how a number is counted therefore moves the regime whether or not
/// anyone remembers to bump `Cargo.toml`, and old and new numbers become
/// incomparable rather than silently different.
pub const SPEC_REVISION: &str = "p4-process-1";

/// Commits touching this path inside the window.
pub const METRIC_CHURN_COMMITS: &str = "process.churn-commits";
/// Lines added plus deleted inside the window.
pub const METRIC_CHURN_LINES: &str = "process.churn-lines";
/// Days since this path last changed, measured from the anchor commit.
pub const METRIC_CODE_AGE: &str = "process.code-age-days";
/// Shannon entropy of the author distribution, in bits.
pub const METRIC_OWNERSHIP_ENTROPY: &str = "process.ownership-entropy";
/// Churn × complexity.
pub const METRIC_HOTSPOT: &str = "process.hotspot";
/// Habitual co-change partners absent from this change.
pub const METRIC_CHANGE_COUPLING: &str = "process.change-coupling";

/// Claim behind both churn metrics.
pub const CLAIM_CHURN: &str = "andon.process.churn@1|any|defect-proneness";
/// Claim behind code age.
pub const CLAIM_CODE_AGE: &str = "andon.process.code-age@1|any|defect-proneness";
/// Claim behind ownership entropy.
pub const CLAIM_OWNERSHIP: &str = "andon.process.ownership@1|any|defect-proneness";
/// Claim behind hotspots.
pub const CLAIM_HOTSPOT: &str = "andon.process.hotspot@1|any|risk-prioritisation";
/// Claim behind change coupling.
pub const CLAIM_COUPLING: &str = "andon.process.change-coupling@1|any|co-change-risk";

/// The window could not be walked because the clone is truncated.
pub const REASON_SHALLOW: &str = "unwitnessed: shallow clone, history window truncated";
/// No commit inside the window touched this path.
pub const REASON_NO_COMMITS: &str = "unwitnessed: no commit in the window touched this path";
/// Every touch in the window was binary, so there are no line counts.
pub const REASON_BINARY_ONLY: &str = "unwitnessed: every touch in the window was binary";
/// No complexity input was supplied for this path.
pub const REASON_NO_COMPLEXITY: &str = "unwitnessed: no complexity input for this path";

/// Every reason string this engine can emit.
///
/// Closed, and constant. Reason strings travel inside `MetricValue::Text` and
/// therefore inside `ResultDigestInput`: a reason built by interpolating a path,
/// a count, or a machine name would make two honestly-unwitnessed sides disagree
/// on the *explanation* and produce a digest mismatch — the same false
/// divergence the emission rule above exists to prevent, arriving through the
/// prose. `tests` asserts every emitted unwitnessed value is one of these.
pub const UNWITNESSED_REASONS: &[&str] = &[
    REASON_SHALLOW,
    REASON_NO_COMMITS,
    REASON_BINARY_ONLY,
    REASON_NO_COMPLEXITY,
];

/// The shipped evidence registry, compiled in.
///
/// Embedded rather than read from disk for the reason P1.5 established: the
/// verifier resolves `deterministic` from its own registry load and never from
/// the record under examination (PLAN P9 / DEFERRED-APPROVALS E4), so the
/// registry has to be part of the binary rather than a file a hostile checkout
/// could move.
const REGISTRY_TOML: &str = include_str!("../../../../registry/process.toml");

/// The engine version this build reports, spec revision included.
pub fn engine_version() -> String {
    format!("{}+{}", env!("CARGO_PKG_VERSION"), SPEC_REVISION)
}

/// Something the process engine could not do.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// The history could not be read.
    #[error(transparent)]
    History(#[from] HistoryError),
    /// The history cache failed.
    #[error(transparent)]
    Cache(#[from] HistoryCacheError),
    /// The compiled-in registry does not parse or does not lint. A build-time
    /// bug, surfaced at runtime because `include_str!` cannot be checked earlier.
    #[error("the compiled-in process registry is invalid: {0}")]
    Registry(String),
    /// The system clock could not be read, so claim expiry cannot be evaluated.
    #[error(transparent)]
    Clock(#[from] andon_core::date::ClockError),
}

/// The compiled-in registry file, parsed once.
pub fn registry_file() -> Result<&'static EngineRegistryFile, ProcessError> {
    static PARSED: OnceLock<Result<EngineRegistryFile, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            parse_file("registry/process.toml", REGISTRY_TOML).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| ProcessError::Registry(e.clone()))
}

/// The merged registry for this engine's claims, resolved against `as_of`.
pub fn registry(as_of: Date) -> Result<Registry, ProcessError> {
    let file = registry_file()?;
    let files = vec![("registry/process.toml".to_string(), file.clone())];
    let (registry, report) = lint(&files, &Policy::default().registry, as_of);
    if report.failed() {
        let messages: Vec<String> = report
            .errors()
            .map(|d| format!("{}: {}", d.code, d.message))
            .collect();
        return Err(ProcessError::Registry(messages.join("; ")));
    }
    Ok(registry)
}

/// Everything the six metrics need about one changed path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFacts {
    path: String,
    churn_commits: u64,
    /// `None` when every touch was binary — a real absence, not a zero.
    churn_lines: Option<u64>,
    /// True when some touches were binary and some were not.
    churn_lines_partial: bool,
    age_days: Option<u64>,
    entropy_microbits: Option<u64>,
    hotspot: Option<u64>,
    coupled_absent: Option<u64>,
}

/// The process engine, holding what it read.
///
/// Reading happens in [`ProcessEngine::for_change`] and formatting in `measure`,
/// following P1.5's spike: P0's [`MeasureContext`] carries no git handle, and
/// widening it belongs to a phase that owns `crates/andon-core`.
#[derive(Debug, Clone)]
pub struct ProcessEngine {
    version: String,
    window_days: u32,
    git_version: String,
    /// Empty exactly when the window was truncated — see the module docs.
    files: Vec<FileFacts>,
    truncated: bool,
}

impl ProcessEngine {
    /// Read the window and derive every per-file number.
    ///
    /// Two git spawns cold — one for the anchor's timestamp, one for the walk —
    /// and **none** on a cache hit. `tests/spawn_budget.rs` asserts both, because
    /// the count is the early warning that the cost model has changed and the
    /// clock is the late one (PREMORTEM T6).
    pub fn for_change(
        git: &Git,
        range: &ResolvedRange,
        changed: &ChangedSet,
        policy: &Policy,
        complexity: &dyn ComplexitySource,
        cache: Option<&HistoryCache>,
    ) -> Result<Self, ProcessError> {
        let version = engine_version();
        let anchor = range.head.anchor_oid().to_string();
        let window = match cache {
            Some(cache) => cache.load_or_read(git, &anchor, policy, &version)?,
            None => HistoryWindow::read(git, &anchor, policy.history.window_days)?,
        };
        Ok(Self::from_window(&window, changed, complexity))
    }

    /// Derive the per-file numbers from an already-read window.
    ///
    /// Separate from [`ProcessEngine::for_change`] so the derivation can be
    /// tested against a constructed window without a repository, and so the
    /// matrix probe can read once and format twice.
    pub fn from_window(
        window: &HistoryWindow,
        changed: &ChangedSet,
        complexity: &dyn ComplexitySource,
    ) -> Self {
        let base = ProcessEngine {
            version: engine_version(),
            window_days: window.window_days,
            git_version: window.git_version.clone(),
            files: Vec::new(),
            truncated: window.truncated,
        };
        if window.truncated {
            // The emission rule. Nothing per-file is derived, because nothing
            // per-file can be honestly compared against a side that saw the
            // whole history.
            return base;
        }

        let paths: Vec<String> = changed.entries.iter().map(|e| e.path.clone()).collect();
        let histories = aggregate(window, &paths);
        let files = paths
            .iter()
            .map(|path| {
                let history = histories.get(path).cloned().unwrap_or_default();
                file_facts(window, path, &paths, &history, complexity)
            })
            .collect();
        ProcessEngine { files, ..base }
    }

    /// How many changed paths this engine derived numbers for.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Whether the window was truncated, so only change-scoped markers are
    /// emitted.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// Derive one path's six numbers.
///
/// A path with no commits in the window gets `None` for everything except the
/// churn counts. Zero commits and zero lines are measurements — the window was
/// walked and it held no change to this file — while an age, an ownership
/// distribution, and a coupling ratio computed from nothing would be
/// fabrications wearing a number.
fn file_facts(
    window: &HistoryWindow,
    path: &str,
    changed: &[String],
    history: &PathHistory,
    complexity: &dyn ComplexitySource,
) -> FileFacts {
    let seen = history.commits > 0;
    let all_binary = history.text_touches == 0 && history.binary_touches > 0;
    FileFacts {
        path: path.to_string(),
        churn_commits: history.commits,
        churn_lines: (!all_binary).then_some(history.text_lines),
        churn_lines_partial: history.binary_touches > 0 && history.text_touches > 0,
        age_days: history.age_days(window.anchor_committed_at),
        entropy_microbits: seen.then(|| entropy_microbits(&history.author_counts())),
        hotspot: complexity
            .complexity(path)
            .filter(|_| seen)
            .map(|c| history.commits.saturating_mul(c)),
        coupled_absent: seen.then(|| coupled_absent_partners(window, path, changed)),
    }
}

/// Descriptors for the six metrics, in registry order.
pub fn metric_descriptors() -> Vec<MetricDescriptor> {
    [
        (METRIC_CHURN_COMMITS, CLAIM_CHURN),
        (METRIC_CHURN_LINES, CLAIM_CHURN),
        (METRIC_CODE_AGE, CLAIM_CODE_AGE),
        (METRIC_OWNERSHIP_ENTROPY, CLAIM_OWNERSHIP),
        (METRIC_HOTSPOT, CLAIM_HOTSPOT),
        (METRIC_CHANGE_COUPLING, CLAIM_COUPLING),
    ]
    .into_iter()
    .map(|(metric_id, claim_id)| MetricDescriptor {
        metric_id: metric_id.to_string(),
        claim_id: claim_id.to_string(),
        // See the module docs: no edit in a diff changes a file's history.
        class: MetricClass::ContextInformational,
        // Every number here is derived from committed objects by integer
        // arithmetic, with the window anchored to a commit rather than a clock.
        // Nothing is seeded and nothing is timed, so all six belong in the
        // digest compare set.
        deterministic: true,
    })
    .collect()
}

impl MeasureEngine for ProcessEngine {
    fn descriptor(&self) -> EngineDescriptor {
        EngineDescriptor {
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Process,
            // Reads git objects and counts. Nothing from the repository is
            // executed (Codex #19), and PLAN P4 says plain git subprocess only.
            class: EngineClass::StaticSafe,
            version: self.version.clone(),
        }
    }

    fn metrics(&self) -> Vec<MetricDescriptor> {
        metric_descriptors()
    }

    fn regime(&self) -> MeasurementRegime {
        MeasurementRegime::Process {
            engine_version: self.version.clone(),
            // Bound deliberately, and with a known cost: three matrix runners
            // ship three gits, so process results from different operating
            // systems classify as `unwitnessed-version-skew` rather than being
            // compared. That is the honest answer — git's date-limited traversal
            // and its diff machinery are part of how these numbers were produced
            // — and PREMORTEM S4's prevention line demonstrated rather than
            // assumed. See docs/patches/p4-spike-matrix-join.md for what the
            // matrix asserts instead.
            git_version: self.git_version.clone(),
            history_window_days: self.window_days,
        }
    }

    fn measure(&self, ctx: &MeasureContext) -> Result<Vec<MeasurementResult>, EngineError> {
        let as_of = Date::today_utc().map_err(|e| failed(e.to_string()))?;
        let registry = registry(as_of).map_err(|e| failed(e.to_string()))?;
        let descriptors = metric_descriptors();
        let evidence = |metric_id: &str| -> EvidenceRef {
            let descriptor = descriptors
                .iter()
                .find(|d| d.metric_id == metric_id)
                .expect("every emitted metric has a descriptor");
            registry
                .claims
                .get(&descriptor.claim_id)
                .expect("the registry lint proved every claim resolves")
                .to_evidence_ref()
        };
        let _ = ctx;

        if self.truncated {
            return Ok(descriptors
                .iter()
                .map(|d| {
                    self.result(
                        &d.metric_id,
                        change_scope(),
                        MetricValue::Text(REASON_SHALLOW.to_string()),
                        Completeness::Unwitnessed,
                        evidence(&d.metric_id),
                    )
                })
                .collect());
        }

        let mut results = Vec::with_capacity(self.files.len() * descriptors.len());
        for file in &self.files {
            let scope = || ResultScope {
                kind: ScopeKind::File,
                path: Some(file.path.clone()),
                // No blob OID: these numbers are about a path's history, not
                // about the bytes at its head. Naming a blob would suggest the
                // reader could re-derive the number from it, and they could not.
                blob_oid: None,
                symbol: None,
                line_span: None,
            };

            results.push(self.result(
                METRIC_CHURN_COMMITS,
                scope(),
                MetricValue::Count(file.churn_commits),
                Completeness::Complete,
                evidence(METRIC_CHURN_COMMITS),
            ));

            results.push(match file.churn_lines {
                Some(lines) => self.result(
                    METRIC_CHURN_LINES,
                    scope(),
                    MetricValue::Count(lines),
                    // Some touches had line counts and some did not: the number
                    // is real and it is not the whole story.
                    if file.churn_lines_partial {
                        Completeness::Partial
                    } else {
                        Completeness::Complete
                    },
                    evidence(METRIC_CHURN_LINES),
                ),
                None => self.unwitnessed(
                    METRIC_CHURN_LINES,
                    scope(),
                    REASON_BINARY_ONLY,
                    evidence(METRIC_CHURN_LINES),
                ),
            });

            results.push(match file.age_days {
                Some(days) => self.result(
                    METRIC_CODE_AGE,
                    scope(),
                    MetricValue::Count(days),
                    Completeness::Complete,
                    evidence(METRIC_CODE_AGE),
                ),
                None => self.unwitnessed(
                    METRIC_CODE_AGE,
                    scope(),
                    REASON_NO_COMMITS,
                    evidence(METRIC_CODE_AGE),
                ),
            });

            results.push(match file.entropy_microbits {
                Some(micro) => self.result(
                    METRIC_OWNERSHIP_ENTROPY,
                    scope(),
                    // Integer micro-bits divided by an exact power-of-ten
                    // constant: IEEE 754 requires division to be correctly
                    // rounded, so this is the same f64 on every platform, and
                    // the payload's six-decimal quantization recovers the
                    // integer exactly. See `crate::entropy`.
                    MetricValue::Ratio(micro as f64 / MICROBITS_PER_BIT as f64),
                    Completeness::Complete,
                    evidence(METRIC_OWNERSHIP_ENTROPY),
                ),
                None => self.unwitnessed(
                    METRIC_OWNERSHIP_ENTROPY,
                    scope(),
                    REASON_NO_COMMITS,
                    evidence(METRIC_OWNERSHIP_ENTROPY),
                ),
            });

            results.push(match file.hotspot {
                Some(product) => self.result(
                    METRIC_HOTSPOT,
                    scope(),
                    MetricValue::Count(product),
                    Completeness::Complete,
                    evidence(METRIC_HOTSPOT),
                ),
                None => self.unwitnessed(
                    METRIC_HOTSPOT,
                    scope(),
                    if file.churn_commits == 0 {
                        REASON_NO_COMMITS
                    } else {
                        REASON_NO_COMPLEXITY
                    },
                    evidence(METRIC_HOTSPOT),
                ),
            });

            results.push(match file.coupled_absent {
                Some(partners) => self.result(
                    METRIC_CHANGE_COUPLING,
                    scope(),
                    MetricValue::Count(partners),
                    Completeness::Complete,
                    evidence(METRIC_CHANGE_COUPLING),
                ),
                None => self.unwitnessed(
                    METRIC_CHANGE_COUPLING,
                    scope(),
                    REASON_NO_COMMITS,
                    evidence(METRIC_CHANGE_COUPLING),
                ),
            });
        }
        Ok(results)
    }
}

fn failed(reason: String) -> EngineError {
    EngineError::Failed {
        engine_id: ENGINE_ID.to_string(),
        reason,
    }
}

/// The scope every truncation marker is emitted at.
fn change_scope() -> ResultScope {
    ResultScope {
        kind: ScopeKind::Change,
        path: None,
        blob_oid: None,
        symbol: None,
        line_span: None,
    }
}

impl ProcessEngine {
    /// An unwitnessed result: a constant reason and no number, ever.
    fn unwitnessed(
        &self,
        metric_id: &str,
        scope: ResultScope,
        reason: &'static str,
        evidence: EvidenceRef,
    ) -> MeasurementResult {
        debug_assert!(
            UNWITNESSED_REASONS.contains(&reason),
            "unwitnessed reasons must come from the closed set: {reason}"
        );
        self.result(
            metric_id,
            scope,
            MetricValue::Text(reason.to_string()),
            Completeness::Unwitnessed,
            evidence,
        )
    }

    fn result(
        &self,
        metric_id: &str,
        scope: ResultScope,
        value: MetricValue,
        completeness: Completeness,
        evidence: EvidenceRef,
    ) -> MeasurementResult {
        let descriptor = metric_descriptors()
            .into_iter()
            .find(|d| d.metric_id == metric_id)
            .expect("every emitted metric has a descriptor");
        MeasurementResult {
            metric_id: metric_id.to_string(),
            claim_id: descriptor.claim_id.clone(),
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Process,
            engine_class: EngineClass::StaticSafe,
            metric_class: descriptor.class,
            scope,
            value,
            // See the module docs: a delta would need a second window and
            // answers a question the change did not raise.
            delta: None,
            // Never above `Info` from the engine. Severity is policy's to decide
            // and the verifier computes its own — which is why `severity` sits
            // outside `ResultDigestInput`.
            severity: Severity::Info,
            completeness,
            measurement_regime: self.regime(),
            evidence,
            deterministic: descriptor.deterministic,
            // Filled by `MeasurementResult::seal`, which `run_engine` calls.
            digest: String::new(),
            freshness: Freshness {
                measured_at: String::new(),
                duration_ms: 0,
                lane: Lane::Fast,
                cache: CacheState::Cold,
            },
        }
    }
}

/// Metric ids this engine emits, for callers that need the set without an
/// instance.
pub fn metric_ids() -> Vec<String> {
    metric_descriptors()
        .into_iter()
        .map(|d| d.metric_id)
        .collect()
}

/// Claim ids this engine's metrics cite, deduplicated.
pub fn claim_ids() -> Vec<String> {
    let mut ids: Vec<String> = metric_descriptors()
        .into_iter()
        .map(|d| d.claim_id)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// The registry file's declared metrics, for the drift check.
pub fn declared_metrics() -> Result<BTreeMap<String, String>, ProcessError> {
    Ok(registry_file()?
        .metrics
        .iter()
        .map(|m| (m.metric_id.clone(), m.claim_id.clone()))
        .collect())
}
