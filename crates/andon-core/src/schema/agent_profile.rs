//! The agent-mode profile: a named view over [`MeasurementRecord`] with a token
//! budget that holds by construction.
//!
//! PREMORTEM A2 is about a tool that is installed and ignored. A payload that
//! blows an agent's context is one way to earn that. So the agent-facing view is
//! not "the full record, hopefully small" — it is a separate, bounded projection
//! whose size cannot exceed the budget regardless of what the record contains.
//!
//! The bound is enforced by adding findings one at a time and stopping before
//! the canonical encoding would cross the budget, with `truncated` telling the
//! agent that it happened. Caps on count and string length keep the common case
//! readable; the encode-and-check loop is what makes the guarantee total, even
//! for a record carrying pathological identifiers.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::enums::{Attestation, Completeness, EvidenceTier, Severity, Verdict};
use super::payload::{HeadKind, IterationState, MeasurementRecord, MetricValue, SCHEMA_VERSION};
use crate::canonical;

/// The name of this schema view, emitted in the payload so a consumer can tell
/// a profile from a full record at a glance.
pub const PROFILE_NAME: &str = "agent-mode";

/// Size limits for [`build_agent_profile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentProfileBounds {
    /// Hard cap on findings, before the byte budget is even consulted.
    pub max_findings: usize,
    /// Hard cap on verdict reasons, before the byte budget is consulted.
    ///
    /// **Sized against the adversarial case, not the common one, because the
    /// adversarial case is the one this projection exists for.** An earlier
    /// version of this comment reasoned "the vocabulary is 16 codes and a single
    /// verdict draws on a handful" and set the cap at 8. That was wrong, and a
    /// review disproved it by building one realistic commit: the vocabulary is
    /// not the constraint, because `tamper-signal` is pushed **once per firing
    /// detector** (`verdict::compute`'s per-result loop) rather than aggregated
    /// the way `severity-med-plus` and `finding-advisory` are. Seven detectors
    /// exist, a multi-vector gaming attempt fires several at once, and that
    /// probe produced ten reasons — silently dropping `policy-change`, one of
    /// the four codes this whole field was added to make visible.
    ///
    /// So the bound is derived, and it is exact rather than padded. Exactly two
    /// constructions in `verdict::compute` multiply — `for result in fired`
    /// (tamper) and the `fired_suite_failure` filter (test-failure); the other
    /// twelve codes are each a single condition and a single push. The tamper
    /// ceiling is 7 rather than 8 because `TamperSignal::BaseFabrication` is
    /// raised by the attest lane, never by anything that reads content — and
    /// that is test-pinned, not merely documented, by
    /// `detectors::tests::base_fabrication_is_not_one_of_ours`. 7 + 1 + 12 =
    /// **20**, with no slack beyond it: nothing in the current vocabulary can
    /// produce a 21st.
    ///
    /// That exactness carries an obligation, and it is partly defended already.
    /// An eighth tamper detector would trip `assert_eq!(signals.len(), 7)` and
    /// `assert_eq!(metrics.len(), 14)` in the same test module before it could
    /// raise this ceiling quietly — so whoever fixes those is the person who
    /// must re-derive this number. What is NOT defended is a third multiplying
    /// construction in `verdict::compute`: nothing counts those loops, and
    /// adding one would raise the true ceiling with no test objecting. That is
    /// the silent path, and it is the narrow one.
    pub max_reasons: usize,
    /// Byte cap on identifier-like strings.
    pub max_string_bytes: usize,
    /// Byte cap on the free-text hint.
    pub max_hint_bytes: usize,
    /// The budget the canonical encoding must not exceed.
    pub budget_bytes: usize,
}

impl AgentProfileBounds {
    /// Derive bounds from the policy's token budget.
    ///
    /// Tokens are converted with a fixed bytes-per-token divisor rather than a
    /// real tokenizer: the budget is a guardrail, and a deterministic estimator
    /// that never under-counts is worth more here than an accurate one that
    /// varies by model.
    pub fn from_token_budget(tokens: u32, bytes_per_token: u32) -> Self {
        Self {
            max_findings: 12,
            max_reasons: 20,
            max_string_bytes: 64,
            max_hint_bytes: 128,
            budget_bytes: (tokens as usize) * (bytes_per_token as usize),
        }
    }
}

impl Default for AgentProfileBounds {
    fn default() -> Self {
        Self::from_token_budget(
            crate::policy::DEFAULT_AGENT_PROFILE_TOKEN_BUDGET,
            crate::policy::DEFAULT_BYTES_PER_TOKEN,
        )
    }
}

/// The bounded, agent-facing view of a measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AgentProfile {
    /// Payload schema version this view belongs to.
    pub schema_version: u32,
    /// Always [`PROFILE_NAME`].
    pub profile: String,
    /// What to do about the change.
    ///
    /// Read [`Self::verdict_invalid`] first. When that is `true` this is the
    /// word the record stores and not a verdict about the change.
    pub verdict: Verdict,
    /// True when the stored verdict contradicts the record it came from.
    ///
    /// A structural field rather than prose, because this is the surface built
    /// for a reader that does not read prose. Records sealed before a change
    /// nobody read was a reason not to pass carry `verdict: pass` beside a
    /// non-zero [`Self::unread_paths`], and an agent branching on `verdict`
    /// alone would act on the older of two contradicting halves of one record.
    ///
    /// Additive with a default, so a consumer built against a profile without
    /// it reads `false` and is right about every record that predates the
    /// contradiction being detectable.
    #[serde(default)]
    pub verdict_invalid: bool,
    /// How much trust the measurement has earned.
    pub attestation: Attestation,
    /// Whether this measurement may count downstream. Stated outright so an
    /// agent does not have to know which attestation values are passes.
    pub counts_downstream: bool,
    /// How complete the measurement behind it was.
    pub completeness: Completeness,
    /// Base commit measured against. Always a commit.
    pub base_oid: String,
    /// The head's identity, of the kind [`Self::head_kind`] names: a commit OID
    /// for `commit`, and otherwise the content hash of an uncommitted snapshot.
    ///
    /// **Read `head_kind` before interpreting this.** Its description here used
    /// to say "head commit measured", which is false for two of the three kinds
    /// this profile can carry — on the one surface written for a reader that
    /// does not read prose.
    pub head_oid: String,
    /// What `head_oid` identifies.
    ///
    /// Present for the same reason it is present on the record: an uncommitted
    /// head cannot be recomputed by anything, and a consumer that took
    /// `head_oid` for a commit would ask CI to check out a working tree.
    pub head_kind: HeadKind,
    /// Present when something other than what was asked for was measured.
    ///
    /// Bounded like everything else here, and included because an agent acting
    /// on a fallback verdict without knowing it is a fallback is PREMORTEM A1
    /// reached through the one surface built for agents.
    pub measured_instead: Option<String>,
    /// How many changed paths the policy withheld from this measurement, so no
    /// finding describes them either.
    ///
    /// Non-zero only under `--self-measure`, which is Andon measuring Andon. A
    /// count rather than the paths, for the reason [`Self::unread_paths`] is one:
    /// this view has a byte budget, and what an agent needs is that the verdict
    /// covers less than the change.
    ///
    /// Additive with a default. A consumer built against a profile without it
    /// reads zero, which is right for every measurement of a repository that is
    /// not this one.
    #[serde(default)]
    pub withheld_paths: u32,
    /// How many changed paths nothing could read, so no finding describes them.
    ///
    /// A count rather than the paths: this view has a byte budget, and what an
    /// agent needs from it is "this verdict covers less than you asked about",
    /// which a number carries. `andon report` names them.
    pub unread_paths: u32,
    /// Where the agent is against its iteration cap.
    pub iteration: IterationState,
    /// Findings, worst first, cut to fit the budget.
    pub findings: Vec<AgentFinding>,
    /// True when anything — findings or reasons — was dropped to stay inside
    /// the budget.
    ///
    /// One flag covers both, so it does not say WHICH was cut. To check reasons
    /// specifically, compare `reasons.len()` against [`Self::total_reasons`];
    /// for findings, `findings.len()` against [`Self::total_findings`]. Named
    /// here because a consumer that trusts the flag alone learns that something
    /// was lost and not that the explanation was.
    pub truncated: bool,
    /// How many findings the full record held.
    pub total_findings: u32,
    /// Why the verdict came out the way it did, worst first.
    ///
    /// # The gap this closes
    ///
    /// An agent could be told `block` with nothing in this payload explaining
    /// it. Of the 16 `VerdictReason` codes, four — `policy-change`,
    /// `policy-change-loosening`, `evidence-registry-skew`,
    /// `iteration-state-reset` — have no backing `MeasurementResult` and no
    /// field of their own, so they reached the agent through nothing at all;
    /// four more moved a field that never said which cause moved it. Only six
    /// are backed by a real result and arrive via `findings`.
    ///
    /// The worst of them was `policy-change-loosening`, which fires exactly when
    /// an agent edits `.andon.toml` mid-change — the scenario the rule exists to
    /// police — and produced a silent `block` an agent could not act on. The
    /// server's own instructions say "on `block`, fix what the findings name",
    /// and the findings named nothing.
    ///
    /// Additive with `#[serde(default)]`, the same shape `verdict_invalid` used,
    /// so a v1 consumer that predates this field still parses.
    #[serde(default)]
    pub reasons: Vec<AgentReason>,
    /// How many reasons the full record held.
    #[serde(default)]
    pub total_reasons: u32,
}

/// One verdict reason, trimmed for an agent's context.
///
/// The `metric_ids` a `VerdictReason` carries are deliberately not projected:
/// where they exist the metrics are already in `findings`, and where the reason
/// class has no backing result the list is empty. Repeating it would spend
/// budget to say what the payload says elsewhere or nothing at all.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AgentReason {
    /// Stable machine code, e.g. `policy-change-loosening`, `tamper-signal`.
    pub code: String,
    /// How serious this reason is.
    pub severity: Severity,
    /// The reason's own explanation, in its own words.
    pub message: String,
}

/// One finding, trimmed for an agent's context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AgentFinding {
    /// Which metric fired.
    pub metric_id: String,
    /// The claim its number stands on.
    pub claim_id: String,
    /// Rendered location, e.g. `src/index.ts:handleRequest`.
    pub scope: String,
    /// How serious.
    pub severity: Severity,
    /// The measured value.
    pub value: MetricValue,
    /// Change against the base, where one is meaningful.
    pub delta: Option<MetricValue>,
    /// Evidence strength behind the claim.
    pub evidence_tier: EvidenceTier,
    /// True when the claim behind this number is past its expiry (PREMORTEM S2).
    pub evidence_stale: bool,
    /// True when the agent can fix this inside the change it just made. A
    /// `false` here is the agent's signal not to grind (PREMORTEM A4).
    pub diff_actionable: bool,
}

/// Project a record into the agent view, never exceeding `bounds.budget_bytes`.
pub fn build_agent_profile(
    record: &MeasurementRecord,
    bounds: &AgentProfileBounds,
) -> AgentProfile {
    let mut profile = AgentProfile {
        schema_version: SCHEMA_VERSION,
        profile: PROFILE_NAME.to_string(),
        verdict: record.verdict.verdict,
        verdict_invalid: crate::verdict::stored_verdict_is_contradicted(record),
        attestation: record.attestation.value,
        counts_downstream: record.attestation.value.counts_downstream(),
        completeness: record.completeness,
        base_oid: truncate_bytes(&record.compare_context.base_oid, bounds.max_string_bytes),
        head_oid: truncate_bytes(&record.compare_context.head_oid, bounds.max_string_bytes),
        head_kind: record.compare_context.head_kind,
        measured_instead: record
            .substitution
            .as_ref()
            .map(|s| truncate_bytes(&s.measured, bounds.max_hint_bytes)),
        withheld_paths: record
            .self_measure
            .as_ref()
            .map_or(0, |p| p.excluded_paths.len() as u32),
        unread_paths: record.unreadable_paths.len() as u32,
        iteration: record.verdict.iteration,
        findings: Vec::new(),
        truncated: false,
        total_findings: record.results.len() as u32,
        reasons: Vec::new(),
        total_reasons: record.verdict.reasons.len() as u32,
    };

    // REASONS BEFORE FINDINGS, and the order is the point rather than an
    // accident of where the code was added.
    //
    // A verdict an agent cannot explain is the defect this field closes, so a
    // budget squeeze spends findings before it spends reasons. That is a
    // RELATIVE priority, not a guarantee that every reason survives: reasons can
    // still be cut, by `max_reasons` or by the byte budget, and `truncated` says
    // so. Findings are elaboration; a `block` with no reason is a locked door
    // with no sign on it.
    //
    // Sorted worst-first with `code` breaking ties, so the projection is
    // deterministic and two runs over one record cannot disagree about what was
    // dropped — the same rule the findings sort follows below.
    //
    // `metric_ids` is deliberately not carried: where a reason has them the
    // metrics are already in `findings`, and where it does not the list is
    // empty. The message takes the hint cap rather than the identifier cap
    // because it is prose written for a reader, and its first clause is the part
    // that names what to do.
    let mut reason_candidates: Vec<&crate::schema::payload::VerdictReason> =
        record.verdict.reasons.iter().collect();
    reason_candidates.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.code.cmp(&b.code))
    });

    let reasons_dropped_by_count = reason_candidates.len() > bounds.max_reasons;
    for reason in reason_candidates.iter().take(bounds.max_reasons) {
        profile.reasons.push(AgentReason {
            code: truncate_bytes(&reason.code, bounds.max_string_bytes),
            severity: reason.severity,
            message: truncate_bytes(&reason.message, bounds.max_hint_bytes),
        });
        if encoded_len(&profile) > bounds.budget_bytes {
            // This reason pushed us over; drop it and stop.
            profile.reasons.pop();
            profile.truncated = true;
            break;
        }
    }
    profile.truncated = profile.truncated || reasons_dropped_by_count;

    // Worst first: if the budget forces a cut, the agent keeps what matters.
    // `metric_id` breaks severity ties so the projection is deterministic and
    // two runs over the same record cannot disagree about what was dropped.
    let mut candidates: Vec<&crate::schema::payload::MeasurementResult> =
        record.results.iter().collect();
    candidates.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.metric_id.cmp(&b.metric_id))
    });

    let dropped_by_count = candidates.len() > bounds.max_findings;
    for result in candidates.iter().take(bounds.max_findings) {
        let finding = AgentFinding {
            metric_id: truncate_bytes(&result.metric_id, bounds.max_string_bytes),
            claim_id: truncate_bytes(&result.claim_id, bounds.max_string_bytes),
            scope: truncate_bytes(&render_scope(&result.scope), bounds.max_hint_bytes),
            severity: result.severity,
            value: result.value.clone(),
            delta: result.delta.clone(),
            evidence_tier: result.evidence.tier,
            evidence_stale: result.evidence.stale,
            diff_actionable: matches!(
                result.metric_class,
                super::enums::MetricClass::DiffActionable
            ),
        };
        profile.findings.push(finding);
        if encoded_len(&profile) > bounds.budget_bytes {
            // This finding pushed us over; drop it and stop.
            profile.findings.pop();
            profile.truncated = true;
            break;
        }
    }
    profile.truncated = profile.truncated || dropped_by_count;

    // The header alone can only exceed the budget under absurdly small bounds.
    // Say so rather than silently shipping an over-budget payload.
    debug_assert!(
        encoded_len(&profile) <= bounds.budget_bytes
            || (profile.findings.is_empty() && profile.reasons.is_empty()),
        "agent profile exceeded its budget with findings or reasons still attached"
    );
    profile
}

/// Canonical encoded size in bytes — the quantity the budget is expressed in.
pub fn encoded_len(profile: &AgentProfile) -> usize {
    canonical::to_canonical_string(profile)
        .map(|s| s.len())
        // A profile that cannot be canonically encoded has no finite size; treat
        // it as over budget so the caller stops adding to it.
        .unwrap_or(usize::MAX)
}

// The span sits between path and symbol so the prefix stays an editor-clickable
// `path:line` reference, and so byte-cap truncation (which cuts from the end)
// costs the symbol before it costs the location. The CLI's human render shows
// only the start line; this view carries the whole span because its reader has
// to know where the region ends without opening the file to look.
fn render_scope(scope: &super::payload::ResultScope) -> String {
    let span = scope
        .line_span
        .map(|span| format!("{}-{}", span.start, span.end));
    match (&scope.path, &scope.symbol, span) {
        (Some(path), Some(symbol), Some(span)) => format!("{path}:{span}:{symbol}"),
        (Some(path), Some(symbol), None) => format!("{path}:{symbol}"),
        (Some(path), None, Some(span)) => format!("{path}:{span}"),
        (Some(path), None, None) => path.clone(),
        (None, Some(symbol), _) => symbol.clone(),
        (None, None, _) => format!("{:?}", scope.kind).to_lowercase(),
    }
}

/// Truncate to at most `max` bytes without splitting a UTF-8 character.
fn truncate_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_respects_char_boundaries() {
        // "é" is two bytes; cutting at 3 must fall back to 2.
        assert_eq!(truncate_bytes("aé", 3), "aé");
        assert_eq!(truncate_bytes("aéb", 3), "aé");
        assert_eq!(truncate_bytes("aéb", 2), "a");
    }

    #[test]
    fn a_med_plus_finding_carries_path_span_and_symbol() {
        // PLAN P6's agent-consumer bar: a MED+ finding must carry a location an
        // agent can act on — path, span, and symbol — through the one surface
        // built for agents. The engines put all three on the result; this pins
        // that the projection does not drop the span on the way through.
        let mut record = crate::testing::sample_record();
        let mut result = crate::testing::sample_result();
        result.severity = Severity::Medium;
        result.scope.kind = crate::schema::payload::ScopeKind::Function;
        result.scope.path = Some("src/index.ts".to_string());
        result.scope.symbol = Some("classify".to_string());
        result.scope.line_span = Some(crate::schema::payload::LineSpan { start: 12, end: 84 });
        record.results = vec![result];

        let profile = build_agent_profile(&record, &AgentProfileBounds::default());
        assert_eq!(profile.findings.len(), 1);
        assert_eq!(profile.findings[0].scope, "src/index.ts:12-84:classify");
    }

    #[test]
    fn a_finding_without_a_span_renders_path_and_symbol() {
        // The doc example on `AgentFinding::scope` — this shape still exists.
        let mut record = crate::testing::sample_record();
        let mut result = crate::testing::sample_result();
        result.scope.kind = crate::schema::payload::ScopeKind::Function;
        result.scope.path = Some("src/index.ts".to_string());
        result.scope.symbol = Some("handleRequest".to_string());
        result.scope.line_span = None;
        record.results = vec![result];

        let profile = build_agent_profile(&record, &AgentProfileBounds::default());
        assert_eq!(profile.findings[0].scope, "src/index.ts:handleRequest");
    }

    #[test]
    fn profile_names_itself_and_states_trust_directly() {
        let record = crate::testing::sample_record();
        let profile = build_agent_profile(&record, &AgentProfileBounds::default());
        assert_eq!(profile.profile, PROFILE_NAME);
        // The sample record is unwitnessed, so it must not read as countable.
        assert!(!profile.counts_downstream);
    }

    /// A reason with no backing result — the class that reached an agent
    /// through nothing at all before this field existed.
    fn loosening_reason() -> crate::schema::payload::VerdictReason {
        crate::schema::payload::VerdictReason {
            code: "policy-change-loosening".to_string(),
            severity: Severity::High,
            message: "policy loosened with no ledgered justification:                       sandbox.test_timeout_ms: 600000 -> 30000 (loosens)"
                .to_string(),
            metric_ids: Vec::new(),
        }
    }

    #[test]
    fn a_reason_with_no_backing_result_still_reaches_the_agent() {
        // The defect this field closes. `policy-change-loosening` is computed
        // with no `MeasurementResult` behind it, so before `reasons` existed an
        // agent received a verdict and nothing whatsoever explaining it — and
        // this is the code that fires exactly when an agent edits `.andon.toml`
        // mid-change, the case the rule exists to police.
        let mut record = crate::testing::sample_record();
        record.verdict.reasons = vec![loosening_reason()];

        let profile = build_agent_profile(&record, &AgentProfileBounds::default());

        assert_eq!(profile.total_reasons, 1);
        let reason = profile
            .reasons
            .first()
            .expect("a reason with no result behind it must still be projected");
        assert_eq!(reason.code, "policy-change-loosening");
        assert!(
            reason.message.contains("no ledgered justification"),
            "the reason's own words are the actionable part: {}",
            reason.message
        );
        // And it is genuinely not reachable the other way: nothing in findings
        // describes it, which is why the field was needed.
        assert!(
            !profile
                .findings
                .iter()
                .any(|f| f.metric_id.contains("policy")),
            "no finding backs this reason; that is the whole point"
        );
    }

    #[test]
    fn every_tamper_detector_firing_at_once_still_fits() {
        // The case the first cap got wrong, pinned. `tamper-signal` is pushed
        // once per FIRING DETECTOR rather than aggregated the way
        // `severity-med-plus` is, so a multi-vector gaming attempt — the exact
        // adversary this tool is positioned against — produces one reason per
        // detector plus everything else the change triggers.
        //
        // A review built this shape from a single real commit and got ten
        // reasons against a cap of eight. The two silently dropped were
        // `policy-change` and `measurement-incomplete`, and `policy-change` is
        // one of the four codes the `reasons` field exists to make visible: the
        // feature was hiding its own headline case.
        let mut record = crate::testing::sample_record();
        let detectors = [
            "test-removal",
            "suppression-density",
            "assertion-free-test",
            "coverage-exclusion-drift",
            "threshold-config-edit",
            "lookup-table-blowup",
            "parse-error-delta",
        ];
        record.verdict.reasons = detectors
            .iter()
            .map(|d| crate::schema::payload::VerdictReason {
                code: "tamper-signal".to_string(),
                severity: Severity::Critical,
                message: format!("tamper.{d} fired on this change"),
                metric_ids: vec![format!("tamper.{d}")],
            })
            .chain([
                loosening_reason(),
                crate::schema::payload::VerdictReason {
                    code: "policy-change".to_string(),
                    severity: Severity::Low,
                    message: "policy edited in this change".to_string(),
                    metric_ids: Vec::new(),
                },
                crate::schema::payload::VerdictReason {
                    code: "measurement-incomplete".to_string(),
                    severity: Severity::Info,
                    message: "this measurement is unwitnessed".to_string(),
                    metric_ids: Vec::new(),
                },
            ])
            .collect();

        let profile = build_agent_profile(&record, &AgentProfileBounds::default());

        assert_eq!(profile.total_reasons, 10);
        assert_eq!(
            profile.reasons.len(),
            10,
            "all ten must survive the default bounds; the count cap is a runaway              guard, not a routine cut:
{:?}",
            profile.reasons.iter().map(|r| &r.code).collect::<Vec<_>>()
        );
        // The specific regression: the low-severity policy code sorts last and
        // is what a too-small cap eats first.
        assert!(
            profile.reasons.iter().any(|r| r.code == "policy-change"),
            "the code this field exists for must not be the one dropped"
        );
        // Reasons must not have eaten the whole payload — an agent needs where
        // as well as why.
        assert!(
            !profile.findings.is_empty(),
            "reasons-first must not starve findings entirely"
        );
    }

    #[test]
    fn the_true_ceiling_of_twenty_still_leaves_room_for_findings() {
        // D27. `every_tamper_detector_firing_at_once_still_fits` proves n=10 with
        // short synthetic messages. The derived ceiling is 20, and the messages
        // that reach it are not short: the single-push codes carry prose that
        // hits the 128-byte hint cap in practice, where a tamper message runs
        // about fifty. So the case nobody had measured is the one where the
        // count is highest AND the strings are longest.
        //
        // Reasons fill before findings, so if twenty long reasons can exhaust
        // the budget the agent gets the whole "why" and none of the "where" —
        // which is a defensible trade only if somebody chose it, and nobody had.
        let mut record = crate::testing::sample_record();

        // Seven tamper reasons: one per detector, the multiplying family.
        let mut reasons: Vec<crate::schema::payload::VerdictReason> = (0..7)
            .map(|i| crate::schema::payload::VerdictReason {
                code: "tamper-signal".to_string(),
                severity: Severity::Critical,
                message: format!(
                    "tamper.detector-number-{i} fired on this change; the detector read a                      partial view, so its reported severity is capped and its finding is a                      lower bound — a firing is still a firing"
                ),
                metric_ids: vec![format!("tamper.detector-{i}")],
            })
            .collect();

        // Thirteen single-push codes at realistic length. Every message here is
        // longer than the 128-byte hint cap on purpose: truncation is part of
        // what is being measured, not something to design around.
        let long = "policy loosened with no ledgered justification:                     sandbox.test_timeout_ms: 600000 -> 30000 (loosens), and the justification                     the gate requires was not found in the ledger for this change";
        for code in [
            "test-failure",
            "severity-med-plus",
            "finding-advisory",
            "policy-change",
            "policy-change-loosening",
            "engine-unavailable",
            "engine-spilled-async",
            "change-not-read",
            "evidence-stale",
            "evidence-registry-skew",
            "measurement-incomplete",
            "iteration-state-reset",
            "iteration-cap",
        ] {
            reasons.push(crate::schema::payload::VerdictReason {
                code: code.to_string(),
                severity: Severity::Medium,
                message: long.to_string(),
                metric_ids: Vec::new(),
            });
        }
        assert_eq!(reasons.len(), 20, "the derived ceiling is 20");
        record.verdict.reasons = reasons;

        let bounds = AgentProfileBounds::default();
        let profile = build_agent_profile(&record, &bounds);

        assert_eq!(profile.total_reasons, 20);
        assert_eq!(
            profile.reasons.len(),
            20,
            "the count cap is derived to admit exactly this case; if it drops one              here the derivation is wrong:
{:?}",
            profile.reasons.iter().map(|r| &r.code).collect::<Vec<_>>()
        );
        assert!(
            !profile.findings.is_empty(),
            "twenty long reasons must not starve findings entirely — an agent needs              where as well as why:
{profile:?}"
        );
        assert!(
            encoded_len(&profile) <= bounds.budget_bytes,
            "the budget is a guarantee at the ceiling too, not only in the common case"
        );
    }

    #[test]
    fn a_squeezed_budget_keeps_why_and_drops_detail() {
        // Ordering, asserted rather than assumed. Reasons are filled before
        // findings so a budget cut costs the Nth detail and never the answer to
        // "why am I blocked" — the inverse would reintroduce the defect under
        // exactly the conditions that make it hardest to debug.
        let mut record = crate::testing::sample_record();
        record.verdict.reasons = vec![loosening_reason()];

        // Tight enough that the header plus one reason is about all that fits.
        let bounds = AgentProfileBounds {
            budget_bytes: 900,
            ..AgentProfileBounds::default()
        };
        let profile = build_agent_profile(&record, &bounds);

        assert!(
            !profile.reasons.is_empty(),
            "the reason must survive a squeeze that cuts findings:
{profile:?}"
        );
        assert!(
            profile.truncated,
            "a squeeze that drops anything has to say so"
        );
        assert!(
            encoded_len(&profile) <= bounds.budget_bytes,
            "the budget is a guarantee, not a target"
        );
    }
}
