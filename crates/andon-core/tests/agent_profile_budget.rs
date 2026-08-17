//! The agent-mode profile stays inside its token budget.
//!
//! PREMORTEM A2 is a tool that gets installed and ignored, and a payload that
//! floods an agent's context is one way to earn that. The bound therefore has to
//! hold for *any* record, including one carrying pathological identifiers — so
//! these are properties over generated input rather than a check against one
//! synthetic payload, which would only prove the bound for the payload someone
//! happened to write.

use andon_core::policy::Policy;
use andon_core::schema::agent_profile::{
    build_agent_profile, encoded_len, AgentProfileBounds, PROFILE_NAME,
};
use andon_core::schema::enums::Severity;
use andon_core::schema::payload::{MeasurementRecord, MeasurementResult};
use andon_core::testing::{sample_record, sample_result};
use proptest::prelude::*;

/// Build a record with `count` results whose strings are `width` characters of
/// the given filler — the shape an adversarial or simply verbose repository
/// would produce.
fn record_with(count: usize, width: usize, filler: char) -> MeasurementRecord {
    let mut record = sample_record();
    record.results = (0..count)
        .map(|i| {
            let mut result: MeasurementResult = sample_result();
            let pad: String = std::iter::repeat_n(filler, width).collect();
            result.metric_id = format!("{i}.{pad}");
            result.claim_id = format!("claim.{i}.{pad}");
            result.scope.path = Some(format!("src/{pad}.ts"));
            result.scope.symbol = Some(pad.clone());
            result.severity = match i % 5 {
                0 => Severity::Critical,
                1 => Severity::High,
                2 => Severity::Medium,
                3 => Severity::Low,
                _ => Severity::Info,
            };
            result
        })
        .collect();
    record
}

#[test]
fn the_default_budget_comes_from_policy() {
    let policy = Policy::default();
    let bounds = AgentProfileBounds::from_token_budget(
        policy.agent.profile_token_budget,
        policy.agent.bytes_per_token,
    );
    assert_eq!(bounds, AgentProfileBounds::default());
    assert_eq!(bounds.budget_bytes, 1500 * 4);
}

#[test]
fn a_typical_record_is_not_truncated() {
    // The bound must not be so tight that ordinary use hits it — a profile that
    // is always truncated tells an agent nothing it can rely on.
    let record = record_with(5, 24, 'a');
    let profile = build_agent_profile(&record, &AgentProfileBounds::default());
    assert!(!profile.truncated, "an ordinary record must fit");
    assert_eq!(profile.findings.len(), 5);
    assert_eq!(profile.total_findings, 5);
}

#[test]
fn truncation_is_announced_rather_than_silent() {
    let record = record_with(400, 64, 'x');
    let profile = build_agent_profile(&record, &AgentProfileBounds::default());
    assert!(profile.truncated);
    assert_eq!(
        profile.total_findings, 400,
        "the agent must be able to see how much it is not being shown"
    );
    assert!(profile.findings.len() < 400);
}

#[test]
fn the_worst_findings_survive_truncation() {
    let record = record_with(200, 40, 'y');
    let profile = build_agent_profile(&record, &AgentProfileBounds::default());
    assert!(profile.truncated);
    assert!(
        profile
            .findings
            .iter()
            .all(|f| f.severity == Severity::Critical),
        "truncation must drop the least serious findings, not an arbitrary slice"
    );
}

#[test]
fn the_projection_is_deterministic() {
    // Two runs over one record must agree about what was dropped, or the agent
    // sees the measurement flicker between identical inputs.
    let record = record_with(100, 50, 'z');
    let bounds = AgentProfileBounds::default();
    assert_eq!(
        build_agent_profile(&record, &bounds),
        build_agent_profile(&record, &bounds)
    );
}

#[test]
fn the_profile_names_its_view() {
    let profile = build_agent_profile(&sample_record(), &AgentProfileBounds::default());
    assert_eq!(profile.profile, PROFILE_NAME);
}

proptest! {
    /// The bound, over arbitrary shapes: never over budget, whatever the record.
    #[test]
    fn the_encoded_profile_never_exceeds_the_budget(
        count in 0usize..300,
        width in 0usize..200,
        filler in prop_oneof![Just('a'), Just('\u{1}'), Just('"'), Just('\\'), Just('\u{4e2d}')],
    ) {
        let record = record_with(count, width, filler);
        let bounds = AgentProfileBounds::default();
        let profile = build_agent_profile(&record, &bounds);
        let size = encoded_len(&profile);
        prop_assert!(
            size <= bounds.budget_bytes,
            "profile of {size} bytes exceeds the {} byte budget with {count} findings \
             of width {width} (filler {filler:?})",
            bounds.budget_bytes
        );
    }

    /// Escaping is where a naive byte cap goes wrong: one control character
    /// becomes six bytes of ``, so a limit applied to the input string
    /// says nothing about the size of the output.
    #[test]
    fn escape_heavy_content_still_respects_the_budget(
        count in 0usize..80,
        width in 0usize..120,
    ) {
        let record = record_with(count, width, '\u{7}');
        let bounds = AgentProfileBounds::default();
        let profile = build_agent_profile(&record, &bounds);
        prop_assert!(encoded_len(&profile) <= bounds.budget_bytes);
    }

    /// A tight budget cannot make the profile lie: it drops findings and says so.
    #[test]
    fn a_small_budget_truncates_instead_of_overflowing(
        budget in 600usize..3000,
        count in 1usize..60,
    ) {
        let record = record_with(count, 48, 'q');
        let bounds = AgentProfileBounds { budget_bytes: budget, ..AgentProfileBounds::default() };
        let profile = build_agent_profile(&record, &bounds);
        if !profile.findings.is_empty() {
            prop_assert!(encoded_len(&profile) <= budget);
        }
        if profile.findings.len() < profile.total_findings as usize {
            prop_assert!(profile.truncated, "dropped findings must set the flag");
        }
    }
}
