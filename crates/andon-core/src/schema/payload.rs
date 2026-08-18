//! Payload schema v1 — the stability contract for all four surfaces (CLI, MCP,
//! JSON, report) and for the CI verifier.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::enums::{
    Attestation, Completeness, EngineClass, EngineFamily, EvidenceTier, InvocationSource, Lane,
    MetricClass, RecordKind, Severity, TamperSignal, Verdict,
};
use super::regime::MeasurementRegime;
use crate::canonical::{self, CanonicalError};

/// The version of this schema. Bumped by a plan change, never by a phase.
///
/// **2 since the uncommitted-tree representation (P5b, mini-G2 ruling).** This
/// is a real migration rather than a v1 definition change, and the distinction
/// is the one `schemas/README.md` draws: the pre-release carve-out covers *an
/// additive field with a default*, and this is not that. [`CompareContext`]'s
/// `head_oid` used to mean "a commit OID" unconditionally, and now means "the
/// head's identity, of the kind [`CompareContext::head_kind`] names". A v1
/// consumer that read `head_oid` and handed it to `git cat-file` was correct
/// then and is wrong now, which is what a version number exists to tell it.
pub const SCHEMA_VERSION: u32 = 2;

/// One `andon measure` run, or one verifier recompute of the same change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MeasurementRecord {
    /// Payload schema version. See [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Self-report or verifier attestation.
    pub record_kind: RecordKind,
    /// Which binary produced it.
    pub tool: ToolIdentity,
    /// The `(base_oid, head_oid)` tuple, required on every record (PLAN B3).
    pub compare_context: CompareContext,
    /// Ledger dimensions: who asked, through what, on which pass.
    pub invocation: Invocation,
    /// Fields reserved for monorepo and orchestrator support.
    pub reserved: Reserved,
    /// Digest of the policy in force. A record-level field and deliberately
    /// **not** part of any per-result digest — see [`ResultDigestInput`].
    pub policy_hash: String,
    /// Every measured number.
    pub results: Vec<MeasurementResult>,
    /// Record-level completeness, the weakest of the results'.
    pub completeness: Completeness,
    /// The categorical outcome and why.
    pub verdict: VerdictSummary,
    /// The trust half: attestation value, tamper signals, compare detail.
    pub attestation: AttestationBlock,
}

/// Which binary produced the record, and whether it was one we trust to measure
/// itself (PREMORTEM S3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolIdentity {
    /// Tool name, `andon`.
    pub name: String,
    /// Release version.
    pub version: String,
    /// Commit the binary was built from.
    pub build_oid: String,
    /// True when this binary is an attested release. False means the bootstrap
    /// exception is in force and the self-measurement is provisional.
    pub attested_release: bool,
}

/// What kind of thing the head of a measured range is.
///
/// # Why this exists rather than a commit OID standing in for a working tree
///
/// The state the product exists for is an agent that has just written a change
/// and not committed it. Measuring it needs a head, and the working tree has no
/// commit OID — so there were only ever two honest options, and the tempting
/// third one is a vulnerability.
///
/// The tempting one: write `HEAD`'s OID into `head_oid` and carry on. That
/// produces a record which passes the verifier's tuple-equality check while
/// describing bytes that were never committed, so the verifier recomputes the
/// *commit*, gets different numbers, and reports `divergent` on honest work.
/// That is the R2-4 laundering path from one side and PREMORTEM Story 1's false
/// accusation from the other, and P1's `git::resolve` refused to build a
/// `CompareContext` from a dirty endpoint precisely to keep it shut.
///
/// So the head says what it **is**. An uncommitted head carries the content
/// hash of its own snapshot, which no commit OID can collide with in practice
/// and which nothing downstream will mistake for one, because this field says
/// not to. [`crate::compare::classify`] reads it before it reads anything else
/// and refuses to compare, so a dirty record can never be accused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HeadKind {
    /// A commit. The only kind a verifier can check out and recompute.
    Commit,
    /// An uncommitted working tree, including anything staged. `head_oid` is the
    /// content hash of the dirty snapshot, never a commit OID.
    UncommittedWorktree,
    /// The index alone — staged content, with unstaged edits excluded.
    /// `head_oid` is the content hash of that snapshot.
    UncommittedIndex,
}

impl HeadKind {
    /// Whether a verifier could ever recompute this head.
    ///
    /// False for both uncommitted kinds, permanently and for a reason no future
    /// verifier removes: CI cannot check out somebody's working tree. It is not
    /// "no recompute happened yet"; it is "no recompute is possible", and
    /// [`Attestation::UnwitnessedUncommitted`] is how a record says so.
    pub fn is_witnessable(self) -> bool {
        matches!(self, HeadKind::Commit)
    }
}

/// The git tuple every measurement is pinned to.
///
/// `base_oid` and `head_oid` are required, never optional: a record that cannot
/// say what it measured cannot be compared, and an uncomparable record that
/// looks comparable is how a fabricated base gets laundered (PLAN B3, R2-4).
///
/// The **base is always a commit**. A dirty base is refused everywhere — by
/// `git::resolve`, by `ChangedSet::enumerate`, and here by contract — because
/// "compared against uncommitted content" is a comparison nothing can stand in
/// for. Only the head has a kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CompareContext {
    /// Full 40-character base commit OID. Always a commit.
    pub base_oid: String,
    /// The head's identity, of the kind [`Self::head_kind`] names: a full
    /// 40-character commit OID for `commit` — the PR head SHA, never the
    /// synthetic merge ref (PLAN B3) — or the content hash of an uncommitted
    /// snapshot otherwise.
    ///
    /// **Read `head_kind` before interpreting this.** It was unconditionally a
    /// commit OID at `schema_version` 1, which is why 2 exists.
    pub head_oid: String,
    /// What `head_oid` identifies.
    pub head_kind: HeadKind,
    /// `git --version` output of the git that resolved this tuple.
    pub git_version: String,
    /// How the base was arrived at, e.g. `merge-base`, `explicit`, `worktree`.
    pub base_resolution: String,
}

/// Ledger dimensions. Queryable by `andon ledger stats` (P8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Invocation {
    /// Hook, agent, human, or verifier.
    pub source: InvocationSource,
    /// Harness name, e.g. `claude-code`, `cursor`.
    pub harness: Option<String>,
    /// Model identifier, when the harness discloses one.
    pub model: Option<String>,
    /// Change author, when known.
    pub author: Option<String>,
    /// Which pass around the agent loop this is, for the iteration cap.
    pub iteration: u32,
}

/// Fields reserved so that monorepo and orchestrator support (VISION §3.3) land
/// without a breaking schema change.
///
/// Always serialized, `null` when unset, so the shape of a record never varies
/// with content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Reserved {
    /// Reserved: orchestrator run correlation.
    pub run_id: Option<String>,
    /// Reserved: multi-workspace identity.
    pub workspace_id: Option<String>,
    /// Reserved: monorepo package boundary.
    pub package_scope: Option<String>,
}

/// One measured number, with everything needed to trust it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MeasurementResult {
    /// Stable metric id, e.g. `static.cognitive-complexity`.
    pub metric_id: String,
    /// The evidence claim this number stands on. The registry lint fails the
    /// build if it does not resolve (PLAN P0/graft 3).
    pub claim_id: String,
    /// Engine that produced it.
    pub engine_id: String,
    /// Engine family.
    pub family: EngineFamily,
    /// Whether producing it executed repository code.
    pub engine_class: EngineClass,
    /// Whether the agent can act on it inside its own change.
    pub metric_class: MetricClass,
    /// What the number is about.
    pub scope: ResultScope,
    /// The number.
    pub value: MetricValue,
    /// Change against the base. `None` where a delta is meaningless.
    pub delta: Option<MetricValue>,
    /// How serious, after policy. Excluded from the digest — the verifier
    /// computes its own from base-commit policy.
    pub severity: Severity,
    /// How complete this particular result is.
    pub completeness: Completeness,
    /// The engine-and-configuration tuple it was produced under.
    pub measurement_regime: MeasurementRegime,
    /// What this number does and does not support, resolved from the registry.
    pub evidence: EvidenceRef,
    /// Whether this result is seed-free and reproducible. Seeded or
    /// timing-dependent results are CI-authoritative only (APPROACH graft 2).
    ///
    /// On a **self-report this is a claim, not a grant of exemption**. Compare-set
    /// membership is decided by the verifier's own copy of this flag: the field
    /// is outside [`ResultDigestInput`] and therefore unsigned, so honouring a
    /// self-report's `false` would let any result be excused from the compare by
    /// setting one boolean. A disagreement between the two sides is recorded in
    /// [`CompareOutcome::flag_disagreements`].
    pub deterministic: bool,
    /// SHA-256 over [`ResultDigestInput`]. Empty until [`MeasurementResult::seal`].
    pub digest: String,
    /// Timing and cache metadata. Never enters a digest.
    pub freshness: Freshness,
}

impl MeasurementResult {
    /// Compute and store this result's digest.
    ///
    /// Takes the compare context by argument rather than reading it off the
    /// result, because the tuple lives once on the record: binding it here means
    /// a digest is only ever meaningful for the base/head it was sealed against.
    pub fn seal(&mut self, ctx: &CompareContext) -> Result<(), CanonicalError> {
        // Cleared first, so a failed seal leaves no digest rather than the
        // previous one. Re-sealing a result whose contents have since become
        // unserializable is exactly when this matters: the error is returned
        // either way, but a caller that logs and carries on would otherwise be
        // holding a record that still looks sealed and whose digest now
        // describes a value it no longer holds. An absent digest is a visible
        // problem; a stale one is indistinguishable from a valid seal.
        //
        // Safe by construction: `digest` is not part of `ResultDigestInput`, so
        // clearing it cannot change the digest being computed.
        self.digest = String::new();
        self.digest = canonical::digest(&self.digest_input(ctx))?;
        Ok(())
    }

    /// The exact bytes this result's digest covers.
    pub fn digest_input<'a>(&'a self, ctx: &'a CompareContext) -> ResultDigestInput<'a> {
        ResultDigestInput {
            schema_version: SCHEMA_VERSION,
            base_oid: &ctx.base_oid,
            head_oid: &ctx.head_oid,
            head_kind: ctx.head_kind,
            engine_id: &self.engine_id,
            metric_id: &self.metric_id,
            claim_id: &self.claim_id,
            family: self.family,
            scope: &self.scope,
            value: &self.value,
            delta: self.delta.as_ref(),
            completeness: self.completeness,
            measurement_regime: &self.measurement_regime,
        }
    }
}

/// The compare set: the measurement facts a per-result digest covers.
///
/// # What is deliberately absent, and why
///
/// The digest answers one question — *did both sides measure the same thing and
/// get the same number?* Anything that can legitimately differ between the agent
/// and the verifier while the measurement is identical must stay out, or an
/// honest change is reported as tampering (PREMORTEM T1).
///
/// - **`policy_hash` and `severity`.** The verifier loads policy from the BASE
///   commit while the agent measured under the head's policy, so any PR that
///   edits `.andon.toml` would flip every digest and read as `divergent` — a
///   designed-in false tamper on precisely the case PLAN B6 ruled *advisory*.
///   Nothing is laundered by leaving them out: P9's two-axis rule has the
///   verifier compute its own verdict from its own recompute, so a lied-about
///   severity cannot turn a CI-computed `block` into a pass.
/// - **`freshness`.** Wall-clock timings and cache state differ by construction.
/// - **`invocation`.** Harness, model, and author differ between the agent and
///   the verifier by construction.
/// - **`evidence`.** Carries a staleness flag derived from the current date, so
///   including it would make yesterday's digest fail to reproduce today.
/// - **`deterministic` and `digest`.** Metadata about the compare, not facts
///   about the measurement.
///
/// The `(base_oid, head_oid)` tuple *is* included, so a tuple difference changes
/// every digest. That is defence in depth, not the primary mechanism: the
/// verifier compares the tuple explicitly first, because R2-4 needs a mismatch
/// to be classified rather than merely detected.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct ResultDigestInput<'a> {
    /// Bound so a schema change cannot silently preserve a digest.
    pub schema_version: u32,
    /// Base of the measured change.
    pub base_oid: &'a str,
    /// Head of the measured change.
    pub head_oid: &'a str,
    /// What `head_oid` identifies.
    ///
    /// Bound because it is a fact about the measurement rather than about the
    /// compare: "these numbers came off an uncommitted tree" is part of what was
    /// measured, and a digest that omitted it would let a commit measurement and
    /// a working-tree measurement of the same bytes seal identically.
    pub head_kind: HeadKind,
    /// Engine that produced the number.
    pub engine_id: &'a str,
    /// Which metric.
    pub metric_id: &'a str,
    /// Which claim it cites.
    pub claim_id: &'a str,
    /// Engine family.
    pub family: EngineFamily,
    /// What the number is about.
    pub scope: &'a ResultScope,
    /// The number itself.
    pub value: &'a MetricValue,
    /// The delta, where one exists.
    pub delta: Option<&'a MetricValue>,
    /// Completeness, which is a measurement fact rather than a policy one.
    pub completeness: Completeness,
    /// The regime, so a version change cannot pass as an equal measurement.
    pub measurement_regime: &'a MeasurementRegime,
}

/// What a result is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResultScope {
    /// Granularity: repository, change, file, or function.
    pub kind: ScopeKind,
    /// Repository-relative path with forward slashes, as git spells it. Never a
    /// filesystem path: worktree separators and case-folding differ per OS.
    pub path: Option<String>,
    /// The git blob OID the bytes came from. Present for every result in the
    /// compare set — the compared lane reads blobs, never the worktree, which is
    /// what makes a digest checkout-independent (PREMORTEM T1).
    pub blob_oid: Option<String>,
    /// Function or class name, where the metric is scoped below file level.
    pub symbol: Option<String>,
    /// Line range within the file, where the metric is line-scoped.
    pub line_span: Option<LineSpan>,
}

/// What granularity a result was measured at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeKind {
    /// The repository as a whole.
    Repository,
    /// The change as a whole — the delta-first default.
    Change,
    /// One file.
    File,
    /// One function or method.
    Function,
}

/// A 1-based inclusive line range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LineSpan {
    /// First line, 1-based and inclusive.
    pub start: u32,
    /// Last line, 1-based and inclusive.
    pub end: u32,
}

/// Number of decimal places a [`MetricValue::Ratio`] is quantized to.
///
/// Six places is far more resolution than any code metric carries, and the
/// rounding buys a property that matters more than the lost digits: the value
/// survives a JSON round trip through any conforming parser.
///
/// The hazard is concrete, not theoretical. `serde_json`'s float parser is not
/// correctly rounded for every input — it reads the seventeen-digit
/// `1.2689392828653361e-47` back one ULP low. A raw `f64` in the compare set
/// could therefore be written by the agent, re-read by a consumer, and re-hash
/// to a different digest: a `divergent` verdict on an honest change, which is
/// PREMORTEM T1 arriving through the back door. Quantized values are short
/// enough to land on every parser's exact path.
pub const RATIO_DECIMAL_PLACES: i32 = 6;

/// A ratio that cannot be carried on the wire.
///
/// Rejecting here is what makes [`crate::canonical`]'s "non-finite floats are
/// rejected" rule true in practice. `serde_json::to_value` — which the
/// canonicalizer runs first — maps a non-finite `f64` to `null` rather than
/// failing, so by the time bytes reach the canonicalizer the value is already
/// gone and a perfectly valid digest would be taken over a hole where a
/// measurement should be. [`MetricValue::Ratio`] is the only float the schema
/// declares, which makes this the one boundary that has to hold.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum RatioError {
    /// NaN or an infinity. JSON cannot represent either, and an engine that
    /// produced one has a bug worth surfacing rather than a number worth
    /// rounding.
    #[error("ratio {0} is not finite and has no JSON representation")]
    NonFinite(f64),
    /// Finite, but so large that scaling it for rounding overflows to infinity.
    /// A proportion or rate at this magnitude is not a measurement either.
    #[error("ratio {0} is too large to quantize without overflowing to infinity")]
    NotQuantizable(f64),
}

/// Round to [`RATIO_DECIMAL_PLACES`], rejecting anything that cannot survive it.
///
/// Idempotent: quantizing a quantized value returns it unchanged, so repeated
/// serialization is stable.
pub fn quantize_ratio(value: f64) -> Result<f64, RatioError> {
    if !value.is_finite() {
        return Err(RatioError::NonFinite(value));
    }
    let scale = 10f64.powi(RATIO_DECIMAL_PLACES);
    let quantized = (value * scale).round() / scale;
    // `value * scale` overflows for anything above roughly 1.8e302, which turns
    // a finite input into an infinity — and then into a `null` in the digest.
    if !quantized.is_finite() {
        return Err(RatioError::NotQuantizable(value));
    }
    Ok(quantized)
}

fn serialize_ratio<S: serde::Serializer>(value: &f64, serializer: S) -> Result<S::Ok, S::Error> {
    let quantized = quantize_ratio(*value).map_err(serde::ser::Error::custom)?;
    serializer.serialize_f64(quantized)
}

fn deserialize_ratio<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<f64, D::Error> {
    let raw = f64::deserialize(deserializer)?;
    quantize_ratio(raw).map_err(serde::de::Error::custom)
}

/// A measured value.
///
/// Adjacently tagged so the type is explicit on the wire and a consumer never
/// has to guess whether `3` was a count or a rounded ratio. Counts are integers
/// and stay exact through canonical serialization (PLAN P5b: "counts always
/// exact"); `Ratio` is the only float, and it is quantized on the way out and
/// on the way back in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum MetricValue {
    /// An exact non-negative count.
    Count(u64),
    /// An exact signed quantity, e.g. a delta.
    Integer(i64),
    /// A proportion or rate, finite and quantized to
    /// [`RATIO_DECIMAL_PLACES`].
    Ratio(
        #[serde(
            serialize_with = "serialize_ratio",
            deserialize_with = "deserialize_ratio"
        )]
        f64,
    ),
    /// An elapsed time.
    Duration {
        /// Elapsed milliseconds.
        millis: u64,
    },
    /// A boolean outcome, e.g. whether a detector fired.
    Flag(bool),
    /// A categorical or free-text value.
    Text(String),
}

/// The evidence a number stands on, resolved from the registry at report time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceRef {
    /// The claim resolved.
    pub claim_id: String,
    /// Evidence strength behind it.
    pub tier: EvidenceTier,
    /// Short citation key; the registry holds the full citation.
    pub citation: String,
    /// The honesty field. What this number is *not* evidence for.
    pub does_not_predict: Vec<String>,
    /// True once the claim is past its expiry. Set by the registry loader
    /// against the run date, surfaced in every rendering, and never silent
    /// (PREMORTEM S2). Excluded from digests precisely because it is
    /// time-dependent.
    pub stale: bool,
}

/// Timing and cache metadata. Excluded from every digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Freshness {
    /// RFC 3339 timestamp.
    pub measured_at: String,
    /// How long the measurement took.
    pub duration_ms: u64,
    /// Fast or async lane.
    pub lane: Lane,
    /// Whether the cache served it.
    pub cache: CacheState,
}

/// Whether the cache served this result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CacheState {
    /// Served from a populated cache.
    Warm,
    /// Computed with an empty cache.
    Cold,
    /// The cache was populated but this key was absent.
    Miss,
}

/// The categorical outcome and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VerdictSummary {
    /// The categorical outcome.
    pub verdict: Verdict,
    /// Why, one entry per contributing cause.
    pub reasons: Vec<VerdictReason>,
    /// Where this run sits against the iteration cap.
    pub iteration: IterationState,
}

/// One reason a verdict is what it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VerdictReason {
    /// Stable machine code, e.g. `tamper-signal`, `iteration-cap`.
    pub code: String,
    /// How serious this reason is.
    pub severity: Severity,
    /// Human-readable explanation.
    pub message: String,
    /// Which results drove it.
    pub metric_ids: Vec<String>,
}

/// Loop-iteration accounting, per branch, held in tool state so it survives
/// session restarts (APPROACH graft 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IterationState {
    /// Passes taken on this branch so far.
    pub count: u32,
    /// From the policy field, never a hardcode.
    pub cap: u32,
    /// True once the cap fired and the verdict became `escalate_to_human`.
    pub escalated: bool,
}

/// The trust half of a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttestationBlock {
    /// How much trust this record has earned.
    pub value: Attestation,
    /// Every tamper signal that fired.
    pub tamper_signals: Vec<TamperSignal>,
    /// Present on verifier records only.
    pub verifier: Option<VerifierIdentity>,
    /// Present once a compare has been attempted.
    pub compare: Option<CompareOutcome>,
}

impl Default for AttestationBlock {
    /// A record starts self-reported and unwitnessed. Trust is earned by CI, so
    /// the default cannot be a pass.
    fn default() -> Self {
        Self {
            value: Attestation::Unwitnessed,
            tamper_signals: Vec::new(),
            verifier: None,
            compare: None,
        }
    }
}

/// Who attested. v1 trust is GitHub Actions provenance, not a signature —
/// anyone with push access can write the attest ref (VISION §5, advisor F4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VerifierIdentity {
    /// Provenance source, e.g. `github-actions`.
    pub provider: String,
    /// Workflow run URL or equivalent provenance pointer.
    pub run_ref: Option<String>,
    /// The base the verifier resolved for itself, never the agent-claimed one.
    pub trusted_base_oid: String,
}

/// The result of comparing a self-report against a recompute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CompareOutcome {
    /// Did the `(base_oid, head_oid)` tuples match? Checked first, so that a
    /// mismatch is classified rather than reported as divergence (PLAN R2-4).
    pub tuple_equal: bool,
    /// Did the measurement regimes match? Checked second; unequal means
    /// `unwitnessed-version-skew`, never `divergent` (PREMORTEM S4).
    pub regime_equal: bool,
    /// Metric ids whose digests were compared and agreed.
    pub matched: Vec<String>,
    /// Metric ids whose digests were compared and disagreed.
    pub mismatched: Vec<String>,
    /// Metric ids present on one side only.
    pub unpaired: Vec<String>,
    /// Metric ids the two sides paired but disagreed about the `deterministic`
    /// flag on.
    ///
    /// The verifier's flag decides compare-set membership, so a disagreement
    /// changes nothing about the outcome — but it is exactly the shape an
    /// attempt to duck the compare would leave, and a signal nobody can see is
    /// a signal that does not exist. Entries here are worth a look; they are
    /// not an accusation, since an engine version can legitimately change
    /// whether a metric is seed-free.
    pub flag_disagreements: Vec<String>,
}
