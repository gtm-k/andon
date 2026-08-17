//! The closed vocabularies of payload schema v1.
//!
//! Every string an agent or a verifier branches on lives here as an enum. The
//! wire spellings are copied verbatim from PLAN.md's acceptance criteria — which
//! is why they are not internally consistent: `escalate_to_human` is snake_case
//! while `confirmed-static` and `parse-degraded` are kebab-case. PLAN.md is the
//! contract, so the inconsistency is reproduced rather than tidied. See
//! `schemas/README.md`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What an actor is told to do about a change.
///
/// Deliberately categorical: PRE-DECISIONS non-goal 1 bars a composite score,
/// forever. There is no numeric quality value anywhere in this schema for an
/// agent to optimize against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Nothing above the policy's advisory floor.
    Pass,
    /// Findings worth reporting that must not stop the line.
    Advise,
    /// The line stops. Reserved for tamper signals, test failures, and MED+
    /// findings on diff-actionable metrics.
    Block,
    /// The iteration cap fired, or a finding is real but not agent-fixable.
    /// A human decides; the agent must not keep grinding (PREMORTEM A4/S6).
    #[serde(rename = "escalate_to_human")]
    EscalateToHuman,
}

/// How much trust a measurement record has earned.
///
/// A self-reported record starts life unattested; CI moves it. Only `confirmed`
/// and `confirmed-static` are passes. The `unwitnessed-*` values are explicitly
/// **not** tamper accusations — conflating them with `divergent` is the
/// false-divergence epidemic of PREMORTEM T1/Story 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Attestation {
    /// CI recomputed the deterministic compare set and every per-result digest
    /// matched.
    Confirmed,
    /// Fork tier (PREMORTEM T5): CI recomputed from an unprivileged job with no
    /// self-report available to compare against. A pass, labelled as the weaker
    /// one it is.
    ConfirmedStatic,
    /// Digests disagree on an equal `(base_oid, head_oid)` tuple at an equal
    /// measurement regime — or a tamper signal fired. The first-class tamper
    /// outcome.
    Divergent,
    /// No CI recompute happened. Neutral, not negative.
    Unwitnessed,
    /// The regimes differ (engine, grammar, or git version skew), so the digests
    /// were never comparable. Never `divergent` — PREMORTEM S4.
    UnwitnessedVersionSkew,
    /// The claimed base is an ancestor of the trusted branch — a stale base or a
    /// rebase, not an attack. A non-tamper outcome that is still **not a pass**:
    /// the record stays self-reported and never counts downstream (PLAN R2-4).
    UnwitnessedBaseMismatch,
}

impl Attestation {
    /// Whether a record with this value may count as evidence downstream.
    ///
    /// The `unwitnessed-*` family answers `false` — the point of R2-4 is that a
    /// non-tamper explanation is still not a confirmation.
    pub fn counts_downstream(self) -> bool {
        matches!(self, Attestation::Confirmed | Attestation::ConfirmedStatic)
    }
}

/// Deterministic signals that a number moved for a reason other than the code
/// getting better.
///
/// Seven of these are the P3 detector suite (six from the metric catalogue plus
/// the parse-error delta of PREMORTEM T3). `base-fabrication` is different in
/// kind: it is raised by the git/attest lane, not by a content detector, when a
/// record claims a base that is not an ancestor of the trusted branch (R2-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum TamperSignal {
    /// `noqa` / `eslint-disable` / equivalent density rising in the diff.
    SuppressionDensity,
    /// Tests deleted or marked skipped.
    TestRemoval,
    /// Coverage-exclusion configuration widened.
    CoverageExclusionDrift,
    /// New tests that execute code without asserting on it.
    AssertionFreeTest,
    /// Thresholds edited in tool configuration inside the measured change.
    ThresholdConfigEdit,
    /// A hard-coded lookup table standing in for an implementation.
    LookupTableBlowup,
    /// Parse errors rose, hiding code from the static engines (PREMORTEM T3).
    ParseErrorDelta,
    /// The claimed base is not an ancestor of the trusted branch, or is an
    /// unknown OID. Raised by the verifier; forces `divergent` (PLAN R2-4).
    BaseFabrication,
}

/// How complete a measurement is. Absence of data is always said out loud rather
/// than reported as a zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Completeness {
    /// Everything the engine set out to measure was measured.
    Complete,
    /// The fast lane hit its cold cap and spilled to async, or an engine was
    /// skipped. Some results are missing and named as missing.
    Partial,
    /// The parser produced ERROR/MISSING nodes over part of the input. Results
    /// so marked never drive MED+ and never carry full-confidence claims
    /// (PREMORTEM T3).
    ParseDegraded,
    /// The inputs needed did not exist — a shallow clone with no history for a
    /// process metric, for instance. Never a fabricated zero (PLAN P4).
    Unwitnessed,
}

/// Finding severity. "MED+" throughout the plan means `Medium` or above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Reported for context; never acted on.
    Info,
    /// Worth mentioning. Advises, never blocks.
    Low,
    /// The bottom of the MED+ band.
    Medium,
    /// A strong finding on a diff-actionable metric.
    High,
    /// Tamper signals and test failures under conservative defaults.
    Critical,
}

impl Severity {
    /// The MED+ band that policy may allow to block.
    pub fn is_med_plus(self) -> bool {
        self >= Severity::Medium
    }
}

/// The five engine families. Fixed in v1: every `MeasurementRegime` variant and
/// every registry file maps onto exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EngineFamily {
    /// tree-sitter size and complexity metrics (P2).
    Static,
    /// Token-level duplication detection (P3).
    Clones,
    /// Static gaming detectors (P3).
    Tamper,
    /// git-history signals: churn, age, ownership, coupling (P4).
    Process,
    /// Coverage-report parsing, negative signal only (P4).
    Artifacts,
}

/// Whether running an engine executes repository code.
///
/// Enforced at the trait boundary, not by convention: the sandbox of P7 keys off
/// this, and a `code-exec` engine may never run in a context that promised only
/// static analysis (Codex #19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EngineClass {
    /// Reads bytes and parses. Never spawns repository code.
    StaticSafe,
    /// Runs code from the repository under test. Requires the sandbox.
    CodeExec,
}

/// Whether a finding is something the agent that made the change can act on.
///
/// The uninstall loop of PREMORTEM A4 comes from blocking on metrics nobody can
/// fix in the diff. Policy may only escalate to MED+ on `diff-actionable`
/// metrics, and `context-informational` findings are exempt from the iteration
/// counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MetricClass {
    /// Fixable inside the change being measured.
    DiffActionable,
    /// True and worth knowing, but about the surrounding code. Never blocks.
    ContextInformational,
}

/// Evidence strength for a claim, as graded in `docs/metric-families.csv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EvidenceTier {
    /// Validated against outcomes at scale.
    A,
    /// Published validation, narrower population or weaker linkage.
    B,
    /// Weak or contested on its own.
    C,
    /// Critiqued; not to be used as a headline.
    D,
    /// Novel and unvalidated. Motivated by evidence, not yet supported by it.
    N,
}

/// Who or what asked for this measurement.
///
/// A ledger dimension, and the evidence for PREMORTEM A2: a tool that is
/// installed but never invoked shows up here as an empty `agent-initiated`
/// column. P6's acceptance criterion counts these directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum InvocationSource {
    /// A harness hook fired — the gate-shaped path.
    Hook,
    /// An agent chose to call the MCP tool without a hook forcing it.
    AgentInitiated,
    /// A human ran the CLI.
    HumanCli,
    /// The CI verifier recomputing.
    CiVerifier,
}

/// Which lane produced a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Lane {
    /// Sub-second static diff measurement.
    Fast,
    /// Long-running work returning a job handle.
    Async,
}

/// Whether a record is a self-report or a verifier's attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RecordKind {
    /// Written by the agent-side binary to `refs/notes/andon-measure`.
    SelfReport,
    /// Written by the CI verifier to `refs/notes/andon-attest`.
    Attestation,
}
