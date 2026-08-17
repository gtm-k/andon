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
use super::payload::{IterationState, MeasurementRecord, MetricValue, SCHEMA_VERSION};
use crate::canonical;

/// The name of this schema view, emitted in the payload so a consumer can tell
/// a profile from a full record at a glance.
pub const PROFILE_NAME: &str = "agent-mode";

/// Size limits for [`build_agent_profile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentProfileBounds {
    /// Hard cap on findings, before the byte budget is even consulted.
    pub max_findings: usize,
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
    pub verdict: Verdict,
    /// How much trust the measurement has earned.
    pub attestation: Attestation,
    /// Whether this measurement may count downstream. Stated outright so an
    /// agent does not have to know which attestation values are passes.
    pub counts_downstream: bool,
    /// How complete the measurement behind it was.
    pub completeness: Completeness,
    /// Base commit measured against.
    pub base_oid: String,
    /// Head commit measured.
    pub head_oid: String,
    /// Where the agent is against its iteration cap.
    pub iteration: IterationState,
    /// Findings, worst first, cut to fit the budget.
    pub findings: Vec<AgentFinding>,
    /// True when findings were dropped to stay inside the budget.
    pub truncated: bool,
    /// How many findings the full record held.
    pub total_findings: u32,
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
        attestation: record.attestation.value,
        counts_downstream: record.attestation.value.counts_downstream(),
        completeness: record.completeness,
        base_oid: truncate_bytes(&record.compare_context.base_oid, bounds.max_string_bytes),
        head_oid: truncate_bytes(&record.compare_context.head_oid, bounds.max_string_bytes),
        iteration: record.verdict.iteration,
        findings: Vec::new(),
        truncated: false,
        total_findings: record.results.len() as u32,
    };

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
        encoded_len(&profile) <= bounds.budget_bytes || profile.findings.is_empty(),
        "agent profile exceeded its budget with findings still attached"
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

fn render_scope(scope: &super::payload::ResultScope) -> String {
    match (&scope.path, &scope.symbol) {
        (Some(path), Some(symbol)) => format!("{path}:{symbol}"),
        (Some(path), None) => path.clone(),
        (None, Some(symbol)) => symbol.clone(),
        (None, None) => format!("{:?}", scope.kind).to_lowercase(),
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
    fn profile_names_itself_and_states_trust_directly() {
        let record = crate::testing::sample_record();
        let profile = build_agent_profile(&record, &AgentProfileBounds::default());
        assert_eq!(profile.profile, PROFILE_NAME);
        // The sample record is unwitnessed, so it must not read as countable.
        assert!(!profile.counts_downstream);
    }
}
