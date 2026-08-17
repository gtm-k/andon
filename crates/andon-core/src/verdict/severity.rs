//! Severity policy: how serious a finding is allowed to become.
//!
//! Engines set a *pre-policy* severity — the strength of the thing they found,
//! in their own terms. This module applies the ceilings `.andon.toml` declares,
//! and the result is the severity every actor downstream reads.
//!
//! # Every rule here is a ceiling, never a floor
//!
//! Policy can lower a severity and can never raise one. That asymmetry is the
//! whole safety argument: an operator editing `.andon.toml` can make Andon
//! quieter about their repository and cannot make it louder about someone
//! else's, and a bug in this module can only ever under-report. The one thing
//! that stops the line without consulting a severity at all is the tamper flag —
//! see below, and see [`stops_the_line`].
//!
//! # The ceilings, and where each comes from
//!
//! | Ceiling | Source | Why |
//! |---|---|---|
//! | completeness | [`crate::parse_health::severity_ceiling`] | a number computed over data that is partly missing must not stop the line (PREMORTEM T3) |
//! | evidence tier | `severity.med_plus_tiers` | a tier the operator has not admitted to the MED+ band caps at `Low` |
//! | C-tier | `severity.max_severity_for_c_tier` | weak or contested evidence advises; the more specific rule wins where both apply |
//! | actionability | `severity.med_plus_requires_diff_actionable` | blocking on what nobody can fix in the diff is the uninstall loop of PREMORTEM A4 |
//!
//! # The severity-ceiling muzzle
//!
//! This is the sharp one, and it is why [`stops_the_line`] does not read
//! `severity`.
//!
//! A tamper detector that fires over a partly-unreadable file has its result
//! demoted: `completeness` becomes `parse-degraded` and the ceiling caps its
//! severity at `Low` (`andon_core::parse_health`). That demotion is correct and
//! must stay — the number was computed over a partial view and says so. But if
//! *line-stopping* were keyed on the capped severity, a single parked parse
//! error anywhere in the change would silence the entire tamper suite: break one
//! file in an earlier commit nobody examined, and every detector that reads it
//! reports `Low` forever after. The demotion would have become the evasion.
//!
//! So the flag decides. `parse_health`'s own module documentation names this as
//! P5a's call and leaves the information in place for it: "the flag and the
//! magnitude survive demotion untouched and are digest-bound, and only the
//! pre-policy severity is capped". A firing over a degraded view is a *lower
//! bound* — the detector saw real evidence in the part it could read, and the
//! part it could not read can only hide more. A lower bound above zero is still
//! evidence. The reported severity stays capped, honestly; the line still stops.
//!
//! There is a second route to the same cap, and in the shipped configuration it
//! is the *usual* one: every claim in `registry/tamper.toml` is tier N, N is not
//! in the default `med_plus_tiers`, and so the tier ceiling caps **every** tamper
//! firing at `Low` — complete parses included, with no degradation anywhere. A
//! severity-keyed rule would therefore not merely be muzzled by a parked parse
//! error; it would never stop the line for a tamper signal on any change at all.
//! The flag is not a refinement of the severity path. It is the only path.
//!
//! # The one detector that does not stop the line
//!
//! `tamper.threshold-config-edit` fires on a loosened quality threshold, and it
//! is advisory by design — PLAN round-1 B6, and the detector's own module says
//! so: a tool that blocks on policy edits has made legitimate policy evolution
//! impossible, and a project that cannot change its own thresholds changes tools
//! instead. Folding it into the blanket fired-flag rule would recreate exactly
//! the designed-in false positive B6 ruled out. It routes through
//! [`super::policy_change`] instead, which blocks only on loosening that carries
//! no ledgered justification.

use crate::parse_health;
use crate::policy::{Policy, SeverityPolicy};
use crate::schema::enums::{EvidenceTier, MetricClass, Severity, TamperSignal};
use crate::schema::payload::{MeasurementResult, MetricValue};

use crate::payload::tamper_signals;

/// The strongest severity policy allows this result to reach.
///
/// The minimum of every applicable ceiling. Order of evaluation does not matter
/// because they compose by `min`, which is the point of expressing them as
/// ceilings.
pub fn ceiling(result: &MeasurementResult, policy: &SeverityPolicy) -> Severity {
    let mut ceiling = parse_health::severity_ceiling(result.completeness);

    // A tier the operator has not admitted to the MED+ band cannot reach it.
    if !policy.med_plus_tiers.contains(&result.evidence.tier) {
        ceiling = ceiling.min(Severity::Low);
    }
    // The C-tier rule is separate and more specific: it names one tier and a
    // ceiling for it, so it applies even where `med_plus_tiers` would have let
    // that tier through.
    if result.evidence.tier == EvidenceTier::C {
        ceiling = ceiling.min(policy.max_severity_for_c_tier);
    }
    if policy.med_plus_requires_diff_actionable
        && result.metric_class == MetricClass::ContextInformational
    {
        ceiling = ceiling.min(Severity::Low);
    }
    ceiling
}

/// Apply the ceilings to every result, in place.
///
/// Idempotent: a second application changes nothing, because every rule is a
/// `min` against a value the first application already produced.
///
/// Safe to run after sealing. `severity` is deliberately outside
/// [`crate::schema::payload::ResultDigestInput`] — the verifier computes its own
/// from base-commit policy — so lowering one here cannot invalidate a digest.
pub fn apply(results: &mut [MeasurementResult], policy: &Policy) {
    for result in results.iter_mut() {
        result.severity = result.severity.min(ceiling(result, &policy.severity));
    }
}

/// Whether this result, on its own, stops the line.
///
/// Two disjoint routes, and the first does not consult `severity`:
///
/// 1. **A fired tamper flag**, when policy blocks on tamper — except
///    `threshold-config-edit`, which is [`super::policy_change`]'s to rule on.
///    Keyed on the flag so that a completeness demotion cannot muzzle the suite.
/// 2. **A MED+ finding**, after the ceilings above. Under the conservative
///    default that also requires a diff-actionable metric, which
///    [`ceiling`] has already enforced by capping everything else at `Low`.
pub fn stops_the_line(result: &MeasurementResult, policy: &SeverityPolicy) -> bool {
    if let Some(signal) = fired_signal(result) {
        return policy.block_on_tamper && signal_stops_the_line(signal);
    }
    result.severity.is_med_plus()
}

/// The signal this result reports as fired, if it is a fired tamper flag.
pub fn fired_signal(result: &MeasurementResult) -> Option<TamperSignal> {
    if !tamper_signals::is_tamper_flag(result) || result.value != MetricValue::Flag(true) {
        return None;
    }
    tamper_signals::signal_for(&result.metric_id)
}

/// Whether a fired signal is one that stops the line.
///
/// Six of the seven do. `ThresholdConfigEdit` does not, for B6's reason; it
/// becomes a `policy-change` finding, which blocks only on unjustified
/// loosening. `BaseFabrication` is the verifier's, raised by
/// [`crate::compare`] rather than by a detector, and never appears as a result
/// here — it is listed so that adding a variant forces a decision rather than
/// silently taking a default.
pub fn signal_stops_the_line(signal: TamperSignal) -> bool {
    match signal {
        TamperSignal::SuppressionDensity
        | TamperSignal::TestRemoval
        | TamperSignal::CoverageExclusionDrift
        | TamperSignal::AssertionFreeTest
        | TamperSignal::LookupTableBlowup
        | TamperSignal::ParseErrorDelta
        | TamperSignal::BaseFabrication => true,
        // PLAN round-1 B6. Routed to `policy_change`, not ignored.
        TamperSignal::ThresholdConfigEdit => false,
    }
}

/// Whether this result advances the per-branch iteration counter.
///
/// PREMORTEM A4: an agent must not burn its loop budget on findings it cannot
/// act on inside its own change. Context-informational findings are exempt
/// unless the operator opts in with `loop.count_context_informational`.
pub fn counts_toward_iteration(result: &MeasurementResult, policy: &Policy) -> bool {
    if result.severity == Severity::Info && fired_signal(result).is_none() {
        return false;
    }
    match result.metric_class {
        MetricClass::DiffActionable => true,
        MetricClass::ContextInformational => policy.loop_policy.count_context_informational,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::enums::{Completeness, EngineFamily};
    use crate::testing::sample_result;

    fn tamper_flag(metric_id: &str, fired: bool) -> MeasurementResult {
        let mut result = sample_result();
        result.metric_id = metric_id.to_string();
        result.engine_id = "tamper".to_string();
        result.family = EngineFamily::Tamper;
        result.metric_class = MetricClass::DiffActionable;
        result.evidence.tier = EvidenceTier::N;
        result.value = MetricValue::Flag(fired);
        result.delta = None;
        result.severity = Severity::High;
        result
    }

    #[test]
    fn a_degraded_tamper_firing_still_stops_the_line() {
        // THE MUZZLE RULE. A parked parse error demotes the result and caps its
        // severity at Low; if blocking read the severity, that one parse error
        // would silence every detector in the suite.
        let mut result = tamper_flag("tamper.test-removal", true);
        parse_health::demote(
            &mut result,
            parse_health::ParseHealth {
                error_nodes: 1,
                missing_nodes: 0,
                total_nodes: 50,
            },
        );
        assert_eq!(result.completeness, Completeness::ParseDegraded);
        assert!(
            !result.severity.is_med_plus(),
            "the demotion must still cap the reported severity: {:?}",
            result.severity
        );
        assert!(
            stops_the_line(&result, &SeverityPolicy::default()),
            "but the fired flag, not the capped severity, decides the line"
        );
    }

    #[test]
    fn a_complete_tamper_firing_is_capped_by_its_tier_and_still_stops_the_line() {
        // The second route to the same place, and under shipped conditions it is
        // the *common* one. Every claim in `registry/tamper.toml` is tier N, and
        // N is not in the default `med_plus_tiers`, so `apply` caps every tamper
        // firing at `Low` — with no degraded parse anywhere in sight.
        //
        // Which means a severity-keyed rule would not merely be muzzled by a
        // parked parse error: it would never stop the line for a tamper signal
        // at all, on any change, in the shipped configuration. The flag is not a
        // refinement of the severity path; it is the only path.
        let mut result = tamper_flag("tamper.test-removal", true);
        result.completeness = Completeness::Complete;
        assert_eq!(result.evidence.tier, EvidenceTier::N);

        let policy = Policy::default();
        assert!(
            !policy.severity.med_plus_tiers.contains(&EvidenceTier::N),
            "the premise: tier N is not admitted to the MED+ band"
        );
        apply(std::slice::from_mut(&mut result), &policy);

        assert_eq!(
            result.severity,
            Severity::Low,
            "capped by tier, not by parse"
        );
        assert!(
            stops_the_line(&result, &policy.severity),
            "and the firing still stops the line"
        );
        assert!(counts_toward_iteration(&result, &policy));
    }

    #[test]
    fn a_quiet_detector_over_a_degraded_view_does_not_stop_the_line() {
        // The other direction, and the reason the rule is keyed on the flag and
        // not on the family: silence over a partial view is not a finding.
        let mut result = tamper_flag("tamper.test-removal", false);
        result.severity = Severity::Info;
        result.completeness = Completeness::ParseDegraded;
        assert!(!stops_the_line(&result, &SeverityPolicy::default()));
    }

    #[test]
    fn a_loosened_threshold_does_not_stop_the_line_on_the_flag_alone() {
        // PLAN round-1 B6: a tool that blocks on policy edits has made policy
        // evolution impossible. This one routes through `policy_change`.
        let result = tamper_flag("tamper.threshold-config-edit", true);
        assert!(!stops_the_line(&result, &SeverityPolicy::default()));
        assert_eq!(
            fired_signal(&result),
            Some(TamperSignal::ThresholdConfigEdit),
            "it is still reported as a fired signal"
        );
    }

    #[test]
    fn policy_can_switch_tamper_blocking_off() {
        let result = tamper_flag("tamper.test-removal", true);
        let permissive = SeverityPolicy {
            block_on_tamper: false,
            ..SeverityPolicy::default()
        };
        assert!(!stops_the_line(&result, &permissive));
        assert!(stops_the_line(&result, &SeverityPolicy::default()));
    }

    #[test]
    fn a_c_tier_claim_cannot_reach_the_med_plus_band() {
        let mut result = sample_result();
        result.evidence.tier = EvidenceTier::C;
        result.severity = Severity::Critical;
        apply(std::slice::from_mut(&mut result), &Policy::default());
        assert_eq!(result.severity, Severity::Low);
        assert!(!stops_the_line(&result, &SeverityPolicy::default()));
    }

    #[test]
    fn the_c_tier_rule_wins_where_both_rules_apply() {
        // An operator who admits C to `med_plus_tiers` has not thereby repealed
        // the ceiling that names C specifically.
        let mut policy = Policy::default();
        policy.severity.med_plus_tiers = vec![EvidenceTier::A, EvidenceTier::B, EvidenceTier::C];
        let mut result = sample_result();
        result.evidence.tier = EvidenceTier::C;
        result.severity = Severity::High;
        apply(std::slice::from_mut(&mut result), &policy);
        assert_eq!(result.severity, policy.severity.max_severity_for_c_tier);
    }

    #[test]
    fn a_context_informational_finding_cannot_block_by_default() {
        let mut result = sample_result();
        result.metric_class = MetricClass::ContextInformational;
        result.severity = Severity::Critical;
        apply(std::slice::from_mut(&mut result), &Policy::default());
        assert_eq!(result.severity, Severity::Low);
    }

    #[test]
    fn applying_the_ceilings_twice_changes_nothing() {
        let mut once = sample_result();
        once.severity = Severity::Critical;
        once.evidence.tier = EvidenceTier::C;
        let mut twice = once.clone();
        apply(std::slice::from_mut(&mut once), &Policy::default());
        apply(std::slice::from_mut(&mut twice), &Policy::default());
        apply(std::slice::from_mut(&mut twice), &Policy::default());
        assert_eq!(once.severity, twice.severity);
    }

    #[test]
    fn policy_never_raises_a_severity() {
        let mut result = sample_result();
        result.severity = Severity::Info;
        result.evidence.tier = EvidenceTier::A;
        apply(std::slice::from_mut(&mut result), &Policy::default());
        assert_eq!(result.severity, Severity::Info);
    }

    #[test]
    fn a_context_informational_finding_is_exempt_from_the_counter() {
        let mut result = sample_result();
        result.metric_class = MetricClass::ContextInformational;
        result.severity = Severity::Low;
        let mut policy = Policy::default();
        assert!(!counts_toward_iteration(&result, &policy));
        policy.loop_policy.count_context_informational = true;
        assert!(counts_toward_iteration(&result, &policy));
    }

    #[test]
    fn a_degraded_tamper_firing_still_counts_toward_the_iteration() {
        // Same muzzle, second consequence: if the capped severity decided this
        // too, a demoted firing would be invisible to the loop as well as to the
        // line — the agent would never be told to stop grinding on it.
        let mut result = tamper_flag("tamper.test-removal", true);
        result.severity = Severity::Info;
        result.completeness = Completeness::ParseDegraded;
        assert!(counts_toward_iteration(&result, &Policy::default()));
    }

    #[test]
    fn an_info_result_does_not_count_toward_the_iteration() {
        let mut result = sample_result();
        result.severity = Severity::Info;
        assert!(!counts_toward_iteration(&result, &Policy::default()));
    }
}
