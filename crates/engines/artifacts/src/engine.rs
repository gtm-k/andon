//! The artifacts engine: diff-coverage gaps, and nothing else.
//!
//! # One metric, and the three numbers it refuses to be
//!
//! `artifacts.uncovered-changed-lines` counts lines this change added or
//! modified that the coverage report says were never executed. It is **not** a
//! coverage percentage, not a coverage delta, and not a covered-line count.
//!
//! That is PLAN P4's "negative signal only", and the reason is in
//! `docs/metric-families.csv`: coverage is tier C, weak as a target and useful
//! as a gap-finder, because Inozemtseva & Holmes showed suite effectiveness is
//! only weakly correlated with coverage once suite size is controlled — and
//! because the classic assertion-free test scores 100%. A percentage in an
//! agent's loop is a number to be raised. A list of changed lines no test
//! touched is a question to be answered.
//!
//! # Why every result here is `deterministic: false`
//!
//! A coverage report is an untracked build output. It is not in any commit, no
//! blob OID names it, and the verifier recomputing from a clean checkout has no
//! way to produce one without executing the repository's test suite — which this
//! engine may not do and the fast lane could not afford. So these results are
//! **CI-authoritative-only** in the sense `docs/trust-boundary.md` defines: they
//! are excluded from the digest compare set by the registry's `deterministic`
//! flag, which the verifier reads from its own registry load and never from the
//! record (PLAN P9 / DEFERRED-APPROVALS E4).
//!
//! The flag is per-metric and static, which is what makes this safe. A result
//! that was sometimes deterministic — when the report happened to be committed,
//! say — would be a compare-set membership that varies with the input, and
//! membership is exactly the thing a self-report may not decide.
//!
//! # Parse only
//!
//! `EngineClass::StaticSafe`, and it means what it says: this engine reads files
//! and parses them. It never invokes a test runner, a coverage tool, or a build.
//! Running the suite is `code-exec` work and belongs to P7's sandbox behind the
//! trait boundary that keeps the two apart (Codex #19).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use andon_core::date::Date;
use andon_core::engine::{
    EngineDescriptor, EngineError, MeasureContext, MeasureEngine, MetricDescriptor,
};
use andon_core::git::{ChangeStatus, ChangedSet, Git, ResolvedRange};
use andon_core::policy::Policy;
use andon_core::registry::{lint, parse_file, EngineRegistryFile, Registry};
use andon_core::schema::enums::{
    Completeness, EngineClass, EngineFamily, Lane, MetricClass, Severity,
};
use andon_core::schema::payload::{
    CacheState, EvidenceRef, Freshness, MeasurementResult, MetricValue, ResultScope, ScopeKind,
};
use andon_core::schema::regime::MeasurementRegime;

use crate::hunks::{ChangedLines, HunkError};
use crate::report::{CoverageReport, ReportError, ReportFormat};

/// Engine id. Matches the `engine` field of `registry/artifacts.toml`.
pub const ENGINE_ID: &str = "artifacts";

/// Revision of the counting spec: the candidate report paths, the path-matching
/// rule, and the definition of an uncovered changed line.
///
/// Folded into the reported engine version for the same reason the process
/// engine does it — `MeasurementRegime::Artifacts` carries parser versions and
/// an engine version, and a change to *how* a gap is counted has to move
/// something.
pub const SPEC_REVISION: &str = "p4-artifacts-1";

/// Changed lines in this file that the coverage report shows as never executed.
pub const METRIC_UNCOVERED_CHANGED_LINES: &str = "artifacts.uncovered-changed-lines";

/// The claim behind it.
pub const CLAIM_DIFF_COVERAGE: &str = "andon.artifacts.diff-coverage@1|any|test-gap";

/// No coverage report was found or supplied.
pub const REASON_NO_REPORT: &str = "unwitnessed: no coverage report found";
/// A report file was found and could not be read.
///
/// Distinct from [`REASON_NO_REPORT`] on the actor-observability principle: "you
/// have no coverage report" and "your `coverage.xml` is malformed" call for
/// different actions from whoever reads the payload, and only one of them is
/// something they can fix. Collapsing the second into the first would leave a
/// broken report invisible — the reader would go looking for a coverage step
/// they already have.
pub const REASON_REPORT_UNREADABLE: &str =
    "unwitnessed: a coverage report was found but could not be read";
/// A report was read, but it does not cover this file.
pub const REASON_NOT_IN_REPORT: &str = "unwitnessed: this file is not in the coverage report";

/// Every reason string this engine can emit. Constant, for the reason the
/// process engine's equivalent set is constant: reason strings are values, and a
/// value built by interpolation is a value two honest sides can disagree on.
pub const UNWITNESSED_REASONS: &[&str] = &[
    REASON_NO_REPORT,
    REASON_REPORT_UNREADABLE,
    REASON_NOT_IN_REPORT,
];

/// Where a coverage report is looked for, relative to the repository root.
///
/// A fixed list rather than a walk. Walking a repository for anything named
/// `coverage.xml` is a full-tree traversal on the fast lane (PREMORTEM T6) and
/// it finds fixtures, vendored directories, and other projects' reports — the
/// last of which would attach a stranger's coverage numbers to this change.
/// Extending the list is a spec revision; supplying a report explicitly through
/// [`ArtifactsEngine::for_change`] needs no list at all.
pub const CANDIDATE_REPORTS: &[&str] = &[
    "lcov.info",
    "coverage/lcov.info",
    "coverage/lcov.dat",
    "target/coverage/lcov.info",
    "coverage.xml",
    "coverage/coverage.xml",
    "cobertura.xml",
    "coverage/cobertura-coverage.xml",
    "target/coverage/cobertura.xml",
];

/// The shipped evidence registry, compiled in. See the process engine's note on
/// why this is `include_str!` and not a file read.
const REGISTRY_TOML: &str = include_str!("../../../../registry/artifacts.toml");

/// The engine version this build reports, spec revision included.
pub fn engine_version() -> String {
    format!("{}+{}", env!("CARGO_PKG_VERSION"), SPEC_REVISION)
}

/// Something the artifacts engine could not do.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactsError {
    /// The hunk diff failed.
    #[error(transparent)]
    Hunks(#[from] HunkError),
    /// The compiled-in registry does not parse or does not lint.
    #[error("the compiled-in artifacts registry is invalid: {0}")]
    Registry(String),
}

/// The compiled-in registry file, parsed once.
pub fn registry_file() -> Result<&'static EngineRegistryFile, ArtifactsError> {
    static PARSED: OnceLock<Result<EngineRegistryFile, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            parse_file("registry/artifacts.toml", REGISTRY_TOML).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| ArtifactsError::Registry(e.clone()))
}

/// The merged registry for this engine's claim, resolved against `as_of`.
pub fn registry(as_of: Date) -> Result<Registry, ArtifactsError> {
    let file = registry_file()?;
    let files = vec![("registry/artifacts.toml".to_string(), file.clone())];
    let (registry, report) = lint(&files, &Policy::default().registry, as_of);
    if report.failed() {
        let messages: Vec<String> = report
            .errors()
            .map(|d| format!("{}: {}", d.code, d.message))
            .collect();
        return Err(ArtifactsError::Registry(messages.join("; ")));
    }
    Ok(registry)
}

/// What discovery found, including what it could not read.
///
/// Failures are carried rather than dropped. A `coverage.xml` that is present
/// and malformed is a different situation from no report at all, and a caller
/// that cannot tell them apart cannot tell the user which one they are in.
#[derive(Debug, Default)]
pub struct Discovery {
    /// Reports that parsed, in candidate-list order.
    pub reports: Vec<CoverageReport>,
    /// Files that were present but could not be read.
    pub problems: Vec<ReportError>,
}

/// Look for coverage reports at the known paths under `root`.
pub fn discover(root: &Path) -> Discovery {
    let mut discovery = Discovery::default();
    for candidate in CANDIDATE_REPORTS {
        let path = root.join(candidate);
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        match CoverageReport::parse(candidate, &bytes) {
            Ok(report) => discovery.reports.push(report),
            Err(problem) => discovery.problems.push(problem),
        }
    }
    discovery
}

/// One changed file's coverage gap.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFinding {
    path: String,
    /// `None` when no report covers this file.
    uncovered: Option<u64>,
    /// True when the report that covered it did not fully parse.
    degraded: bool,
}

/// The artifacts engine, holding what it read.
#[derive(Debug, Clone)]
pub struct ArtifactsEngine {
    version: String,
    findings: Vec<FileFinding>,
    /// True when no report was available at all.
    no_report: bool,
    /// True when a report file existed and could not be read. Only meaningful
    /// alongside `no_report`: a readable report elsewhere answers the question,
    /// and one unreadable file beside it is not the headline.
    unreadable: bool,
}

impl ArtifactsEngine {
    /// Read the hunks and attribute coverage to them. One git spawn.
    ///
    /// `reports` is usually [`discover`]'s output; a caller with an explicit
    /// report path — a CI job that knows where its coverage lands — passes it
    /// directly and the candidate list is never consulted.
    pub fn for_change(
        git: &Git,
        range: &ResolvedRange,
        changed: &ChangedSet,
        reports: &[CoverageReport],
    ) -> Result<Self, ArtifactsError> {
        let lines = ChangedLines::for_range(git, range)?;
        Ok(Self::from_lines(&lines, changed, reports))
    }

    /// Measure from a [`Discovery`], so that a report which was *found and
    /// unreadable* reaches the payload as itself.
    ///
    /// The reason this exists rather than being left to the caller: `discover`
    /// carries its failures, and a failure nobody consumes is a failure that
    /// does not exist for the person who has to act on it. Every caller that
    /// discovers rather than being handed a report should use this.
    pub fn for_discovery(
        git: &Git,
        range: &ResolvedRange,
        changed: &ChangedSet,
        discovery: &Discovery,
    ) -> Result<Self, ArtifactsError> {
        let lines = ChangedLines::for_range(git, range)?;
        let mut engine = Self::from_lines(&lines, changed, &discovery.reports);
        engine.unreadable = !discovery.problems.is_empty();
        Ok(engine)
    }

    /// Attribute coverage to an already-computed set of changed lines.
    ///
    /// Split out so the attribution rules can be tested without a repository.
    pub fn from_lines(
        lines: &ChangedLines,
        changed: &ChangedSet,
        reports: &[CoverageReport],
    ) -> Self {
        let findings = changed
            .entries
            .iter()
            // A deleted file has no head-side lines and no coverage to have.
            // Reporting zero uncovered lines for it would be true and useless;
            // reporting it at all would put a coverage result on a file that is
            // gone.
            //
            // This is the one place in P4 that reads `ChangeStatus`, and it is
            // worth naming because of P1's P2-entry note: for the `INDEX`
            // sentinel, a path staged and then deleted from disk derives its
            // status from the worktree side rather than the index side, so it
            // arrives here as `Deleted` when the measured state — the index —
            // still holds it. The consequence is bounded to this filter: one
            // staged-then-deleted file goes unreported in an index-scoped
            // coverage run. It is advisory-lane, it produces no wrong number and
            // no accusation, and the fix belongs to whoever owns
            // `ChangedSet`. The process engine reads `entry.path` and nothing
            // else, so the compared lane is untouched by the note entirely.
            .filter(|entry| entry.status != ChangeStatus::Deleted)
            .map(|entry| {
                let touched = lines.for_path(&entry.path);
                // First report that covers the path wins. Reports arrive in the
                // fixed candidate-list order, so "first" is a property of the
                // list and not of a directory read.
                let covering = reports
                    .iter()
                    .find_map(|r| r.lines_for(&entry.path).map(|l| (r, l)));
                match covering {
                    Some((report, coverage)) => FileFinding {
                        path: entry.path.clone(),
                        // A changed line the report does not mention is not an
                        // uncovered line: coverage tools omit blank lines,
                        // comments, and declarations, and counting those as gaps
                        // would make every reformat look like a testing failure.
                        uncovered: Some(
                            touched
                                .iter()
                                .filter(|line| coverage.get(line) == Some(&0))
                                .count() as u64,
                        ),
                        degraded: report.degraded,
                    },
                    None => FileFinding {
                        path: entry.path.clone(),
                        uncovered: None,
                        degraded: false,
                    },
                }
            })
            .collect();

        ArtifactsEngine {
            version: engine_version(),
            findings,
            no_report: reports.is_empty(),
            unreadable: false,
        }
    }

    /// How many changed files this engine has a finding for.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}

/// Descriptor for the single metric.
pub fn metric_descriptors() -> Vec<MetricDescriptor> {
    vec![MetricDescriptor {
        metric_id: METRIC_UNCOVERED_CHANGED_LINES.to_string(),
        claim_id: CLAIM_DIFF_COVERAGE.to_string(),
        // The one metric in this phase an agent can act on inside its own
        // change: the lines are in the diff and a test can cover them. Tier C
        // keeps it advisory under the default policy's `max_severity_for_c_tier`,
        // which is the right pairing — actionable, and never a blocker.
        class: MetricClass::DiffActionable,
        // See the module docs. A coverage report is an untracked build output;
        // no verifier can reproduce it without running the suite.
        deterministic: false,
    }]
}

impl MeasureEngine for ArtifactsEngine {
    fn descriptor(&self) -> EngineDescriptor {
        EngineDescriptor {
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Artifacts,
            class: EngineClass::StaticSafe,
            version: self.version.clone(),
        }
    }

    fn metrics(&self) -> Vec<MetricDescriptor> {
        metric_descriptors()
    }

    fn regime(&self) -> MeasurementRegime {
        MeasurementRegime::Artifacts {
            engine_version: self.version.clone(),
            // Every parser this build carries, not only the ones this run used.
            // A regime that varied with the input would make two runs of the
            // same binary look like two binaries.
            parser_versions: BTreeMap::from([
                (
                    ReportFormat::Lcov.name().to_string(),
                    crate::lcov::PARSER_VERSION.to_string(),
                ),
                (
                    ReportFormat::Cobertura.name().to_string(),
                    crate::cobertura::PARSER_VERSION.to_string(),
                ),
                (
                    ReportFormat::CoveragePy.name().to_string(),
                    crate::cobertura::PARSER_VERSION.to_string(),
                ),
            ]),
        }
    }

    fn measure(&self, ctx: &MeasureContext) -> Result<Vec<MeasurementResult>, EngineError> {
        let as_of = Date::today_utc().map_err(|e| EngineError::Failed {
            engine_id: ENGINE_ID.to_string(),
            reason: e.to_string(),
        })?;
        let registry = registry(as_of).map_err(|e| EngineError::Failed {
            engine_id: ENGINE_ID.to_string(),
            reason: e.to_string(),
        })?;
        let evidence = registry
            .claims
            .get(CLAIM_DIFF_COVERAGE)
            .expect("the registry lint proved the claim resolves")
            .to_evidence_ref();
        let _ = ctx;

        if self.no_report {
            // One change-scoped marker rather than a per-file one. "There is no
            // coverage report" is a fact about the run, not about each file, and
            // repeating it once per changed file would bury the finding that
            // matters under noise the reader cannot act on.
            let reason = if self.unreadable {
                REASON_REPORT_UNREADABLE
            } else {
                REASON_NO_REPORT
            };
            return Ok(vec![self.result(
                change_scope(),
                MetricValue::Text(reason.to_string()),
                Completeness::Unwitnessed,
                evidence,
            )]);
        }

        Ok(self
            .findings
            .iter()
            .map(|finding| {
                let scope = ResultScope {
                    kind: ScopeKind::File,
                    path: Some(finding.path.clone()),
                    blob_oid: None,
                    symbol: None,
                    line_span: None,
                };
                match finding.uncovered {
                    Some(count) => self.result(
                        scope,
                        MetricValue::Count(count),
                        if finding.degraded {
                            Completeness::ParseDegraded
                        } else {
                            Completeness::Complete
                        },
                        evidence.clone(),
                    ),
                    None => self.result(
                        scope,
                        MetricValue::Text(REASON_NOT_IN_REPORT.to_string()),
                        Completeness::Unwitnessed,
                        evidence.clone(),
                    ),
                }
            })
            .collect())
    }
}

fn change_scope() -> ResultScope {
    ResultScope {
        kind: ScopeKind::Change,
        path: None,
        blob_oid: None,
        symbol: None,
        line_span: None,
    }
}

impl ArtifactsEngine {
    fn result(
        &self,
        scope: ResultScope,
        value: MetricValue,
        completeness: Completeness,
        evidence: EvidenceRef,
    ) -> MeasurementResult {
        let descriptor = metric_descriptors()
            .into_iter()
            .next()
            .expect("the engine declares one metric");
        MeasurementResult {
            metric_id: descriptor.metric_id.clone(),
            claim_id: descriptor.claim_id.clone(),
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Artifacts,
            engine_class: EngineClass::StaticSafe,
            metric_class: descriptor.class,
            scope,
            // No delta. A coverage delta needs the base's report, which nobody
            // has: the report describes the tree the suite ran against, and that
            // is the head.
            delta: None,
            value,
            severity: Severity::Info,
            completeness,
            measurement_regime: self.regime(),
            evidence,
            deterministic: descriptor.deterministic,
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
