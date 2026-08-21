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
//! # The one detector whose firing is conditional, and how wide the condition is
//!
//! `tamper.threshold-config-edit` fires on a loosened quality threshold. PLAN
//! round-1 B6 says a tool that blocks on policy edits has made legitimate policy
//! evolution impossible, and a project that cannot change its own thresholds
//! changes tools instead — so this one is not folded into the blanket
//! fired-flag rule.
//!
//! The first version of that exemption was keyed on the enum variant alone: a
//! `ThresholdConfigEdit` firing never stopped the line, full stop, and
//! [`super::policy_change`] was named as the route that would block an
//! unjustified loosening instead. But `policy_change` parses `.andon.toml` and
//! nothing else, while the detector fires over ESLint, tsconfig, mypy, ruff,
//! coverage configuration and a dozen more. So a real loosening in
//! `.eslintrc.json` fired, took the exemption, and could only ever advise —
//! there was no route behind the exemption for it to be handed to. Codex's probe
//! moved `error` to `warn` in `.eslintrc.json` and got `advise` where `block`
//! was required.
//!
//! The exemption is now keyed on the thing B6 actually cares about: **whether a
//! verified ledgered justification covers this change**. A loosening with one
//! advises, wherever it is; a loosening without one stops the line, wherever it
//! is. `.andon.toml` keeps its richer treatment on top — `policy_change` knows
//! the direction of every field and reports the delta — and the two now ask one
//! question ([`super::policy_change::PolicyChange::is_justified`]) rather than
//! two that could disagree.

use crate::parse_health;
use crate::policy::{Policy, SeverityPolicy};
use crate::schema::enums::{EngineFamily, EvidenceTier, MetricClass, Severity, TamperSignal};
use crate::schema::payload::{MeasurementResult, MetricValue};

use crate::payload::tamper_signals;
use crate::verdict::VerdictContext;

/// The tests engine's failure flag — the result `block_on_test_failure` keys
/// on. Declared beside the rule that reads it and re-exported by the engine
/// that emits it (`andon-sandbox`), so the two spell it once.
pub const SUITE_FAILURE_METRIC: &str = "tests.suite-failure";

/// The sentence result the tests engine emits beside the flag, read here only
/// to say *how* the suite failed in the verdict reason.
pub const SUITE_OUTCOME_METRIC: &str = "tests.suite-outcome";

/// The fired test-failure flag, if this result is one.
///
/// Keyed on family, metric id, and a `true` flag together — a `tests.*` metric
/// from another family, or the flag unfired, is nobody's failure.
pub fn fired_suite_failure(result: &MeasurementResult) -> bool {
    result.family == EngineFamily::Tests
        && result.metric_id == SUITE_FAILURE_METRIC
        && result.value == MetricValue::Flag(true)
}

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
/// Three disjoint routes, and only the last consults `severity`:
///
/// 1. **A fired tamper flag**, when policy blocks on tamper — with
///    `threshold-config-edit` conditional on a verified justification, per the
///    module documentation. Keyed on the flag so that a completeness demotion
///    cannot muzzle the suite.
/// 2. **A fired test-failure flag**, when policy blocks on test failure. The
///    same construction for the same reason: both tests-lane claims are tier
///    N, so the tier ceiling caps every suite result at `Low` and a
///    severity-keyed rule would never stop the line for a failed suite at
///    all. The knob spent its first six phases declared and unread — no
///    engine could produce a test result until the sandbox existed (P7) —
///    and this is the disposition its declaration note reserved for P7.
/// 3. **A MED+ finding**, after the ceilings above. Under the conservative
///    default that also requires a diff-actionable metric, which
///    [`ceiling`] has already enforced by capping everything else at `Low`.
///
/// Takes the whole [`VerdictContext`] rather than the severity policy alone
/// because the first route has a question policy cannot answer: whether this
/// *change* carries a justification. One implementation, read by the verdict and
/// by the iteration counter alike.
pub fn stops_the_line(result: &MeasurementResult, ctx: &VerdictContext) -> bool {
    if let Some(signal) = fired_signal(result) {
        return ctx.policy.severity.block_on_tamper && signal_stops_the_line(signal, ctx);
    }
    if fired_suite_failure(result) {
        return ctx.policy.severity.block_on_test_failure;
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

/// Whether a fired signal is one that stops the line, in this change.
///
/// Six of the seven do unconditionally. `ThresholdConfigEdit` stops the line
/// unless a **verified** ledgered justification covers the change — B6's rule,
/// applied to every configuration file the detector reads rather than only to
/// the one [`super::policy_change`] can parse. `BaseFabrication` is the
/// verifier's, raised by [`crate::compare`] rather than by a detector, and never
/// appears as a result here — it is listed so that adding a variant forces a
/// decision rather than silently taking a default.
pub fn signal_stops_the_line(signal: TamperSignal, ctx: &VerdictContext) -> bool {
    match signal {
        TamperSignal::SuppressionDensity
        | TamperSignal::TestRemoval
        | TamperSignal::CoverageExclusionDrift
        | TamperSignal::AssertionFreeTest
        | TamperSignal::LookupTableBlowup
        | TamperSignal::ParseErrorDelta
        | TamperSignal::BaseFabrication => true,
        // PLAN round-1 B6, with the exit B6 requires: a loosening a project can
        // account for is policy evolution, and one it cannot is a gate being
        // quietly moved. The exit is a justification somebody checked, not the
        // name of the file the threshold happened to live in.
        TamperSignal::ThresholdConfigEdit => !ctx
            .policy_change
            .is_some_and(super::policy_change::PolicyChange::is_justified),
    }
}

/// Whether this result advances the per-branch iteration counter.
///
/// PREMORTEM A4: an agent must not burn its loop budget on findings it cannot
/// act on inside its own change. Context-informational findings are exempt
/// unless the operator opts in with `loop.count_context_informational`.
///
/// # A fired flag counts when it stops the line, and not merely when it fired
///
/// This used to count **every** fired tamper flag, which quietly disagreed with
/// the verdict about one of them: a threshold edit the change had accounted for
/// advised rather than blocked, and still pushed the agent toward
/// `escalate_to_human` on a finding nobody was asking it to fix. The exemption
/// was honoured in one place and not the other.
///
/// So the question is [`stops_the_line`] — the same call the verdict makes, so
/// there is no second answer to keep in step. A degraded tamper firing still
/// counts, because the flag route still stops the line for it: the muzzle rule's
/// second consequence, and the reason this cannot simply read `severity`.
pub fn counts_toward_iteration(result: &MeasurementResult, ctx: &VerdictContext) -> bool {
    if fired_signal(result).is_some() {
        if !stops_the_line(result, ctx) {
            return false;
        }
    } else if result.severity == Severity::Info {
        return false;
    }
    match result.metric_class {
        MetricClass::DiffActionable => true,
        MetricClass::ContextInformational => ctx.policy.loop_policy.count_context_informational,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::enums::{Completeness, EngineFamily};
    use crate::testing::sample_result;
    use crate::verdict::policy_change::{Justification, PolicyChange};

    /// A context carrying nothing but the policy: no policy edit, no failures.
    fn ctx(policy: &Policy) -> VerdictContext<'_> {
        VerdictContext {
            policy,
            policy_change: None,
            engine_failures: &[],
            stale_claim_ids: &[],
            iteration_state_recovered: false,
            completeness: crate::schema::enums::Completeness::Complete,
            registry_skew: &[],
            unreadable_paths: &[],
        }
    }

    /// A context carrying a policy edit and the justification offered for it.
    fn ctx_with<'a>(policy: &'a Policy, change: &'a PolicyChange) -> VerdictContext<'a> {
        VerdictContext {
            policy_change: Some(change),
            ..ctx(policy)
        }
    }

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
            stops_the_line(&result, &ctx(&Policy::default())),
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
            stops_the_line(&result, &ctx(&policy)),
            "and the firing still stops the line"
        );
        assert!(counts_toward_iteration(&result, &ctx(&policy)));
    }

    #[test]
    fn a_quiet_detector_over_a_degraded_view_does_not_stop_the_line() {
        // The other direction, and the reason the rule is keyed on the flag and
        // not on the family: silence over a partial view is not a finding.
        let mut result = tamper_flag("tamper.test-removal", false);
        result.severity = Severity::Info;
        result.completeness = Completeness::ParseDegraded;
        assert!(!stops_the_line(&result, &ctx(&Policy::default())));
    }

    #[test]
    fn a_loosened_threshold_stops_the_line_unless_something_accounts_for_it() {
        // PLAN round-1 B6 has two halves and the first version of this rule kept
        // only one. A tool that blocks on every policy edit has made policy
        // evolution impossible — but the exemption B6 asks for is "the project
        // can account for this", not "the signal is called
        // ThresholdConfigEdit". Keyed on the variant alone, a real loosening in
        // `.eslintrc.json` took the exemption and could only ever advise,
        // because the route it was nominally handed to parses `.andon.toml` and
        // nothing else.
        let policy = Policy::default();
        let result = tamper_flag("tamper.threshold-config-edit", true);
        assert!(
            stops_the_line(&result, &ctx(&policy)),
            "a loosening nobody has accounted for stops the line"
        );
        assert_eq!(
            fired_signal(&result),
            Some(TamperSignal::ThresholdConfigEdit),
            "it is still reported as a fired signal"
        );

        // And the exit B6 requires, which is a justification somebody checked.
        let unverified = PolicyChange {
            deltas: Vec::new(),
            justification: Some(Justification::Unverified {
                reference: "trust me".to_string(),
                summary: "not checked against any ledger".to_string(),
            }),
        };
        assert!(
            stops_the_line(&result, &ctx_with(&policy, &unverified)),
            "an unverified claim is not an account of anything"
        );

        let verified = PolicyChange {
            deltas: Vec::new(),
            justification: Some(Justification::Verified {
                reference: "andon-ledger#12".to_string(),
                summary: "eslint rule relaxed for the codemod, restored in #13".to_string(),
            }),
        };
        assert!(
            !stops_the_line(&result, &ctx_with(&policy, &verified)),
            "policy evolution the ledger records must stay possible"
        );
    }

    #[test]
    fn a_justified_threshold_edit_does_not_burn_the_loop_budget_either() {
        // The exemption used to be honoured at the verdict and not at the
        // counter: the edit advised rather than blocked, and still pushed the
        // agent toward `escalate_to_human` on a finding nobody was asking it to
        // fix. Both now ask `stops_the_line`, so there is no second answer.
        let policy = Policy::default();
        let result = tamper_flag("tamper.threshold-config-edit", true);
        let verified = PolicyChange {
            deltas: Vec::new(),
            justification: Some(Justification::Verified {
                reference: "andon-ledger#12".to_string(),
                summary: "accounted for".to_string(),
            }),
        };
        assert!(counts_toward_iteration(&result, &ctx(&policy)));
        assert!(!counts_toward_iteration(
            &result,
            &ctx_with(&policy, &verified)
        ));
    }

    #[test]
    fn the_other_six_detectors_are_not_excusable_by_a_justification() {
        // The exemption is one detector's, and it exists because policy
        // evolution is legitimate. Deleting a test is not policy evolution, and
        // a ledger entry saying it was must not turn the firing off.
        let policy = Policy::default();
        let verified = PolicyChange {
            deltas: Vec::new(),
            justification: Some(Justification::Verified {
                reference: "andon-ledger#12".to_string(),
                summary: "we meant to".to_string(),
            }),
        };
        for metric_id in [
            "tamper.test-removal",
            "tamper.suppression-density",
            "tamper.coverage-exclusion-drift",
            "tamper.assertion-free-test",
            "tamper.lookup-table-blowup",
            "tamper.parse-error-delta",
        ] {
            let result = tamper_flag(metric_id, true);
            assert!(
                stops_the_line(&result, &ctx_with(&policy, &verified)),
                "{metric_id} took an exemption that is not its"
            );
        }
    }

    /// The tests engine's failure flag, as `run_engine` would deliver it: tier
    /// N evidence, severity already capped by `apply`.
    fn suite_flag(fired: bool) -> MeasurementResult {
        let mut result = sample_result();
        result.metric_id = SUITE_FAILURE_METRIC.to_string();
        result.engine_id = "tests".to_string();
        result.family = EngineFamily::Tests;
        result.metric_class = MetricClass::DiffActionable;
        result.evidence.tier = EvidenceTier::N;
        result.value = MetricValue::Flag(fired);
        result.delta = None;
        result.severity = Severity::Critical;
        result
    }

    #[test]
    fn a_failed_suite_is_tier_capped_and_still_stops_the_line() {
        // The knob's first reader, in the same construction as the tamper
        // rule: tier N is not in the default MED+ band, so `apply` caps the
        // reported severity at Low — and a severity-keyed rule would
        // therefore never stop the line for a failed suite at all. The flag
        // decides; the capped severity stays honest.
        let mut result = suite_flag(true);
        let policy = Policy::default();
        assert!(policy.severity.block_on_test_failure, "the premise");
        apply(std::slice::from_mut(&mut result), &policy);
        assert_eq!(result.severity, Severity::Low, "capped by tier");
        assert!(stops_the_line(&result, &ctx(&policy)));
        assert!(counts_toward_iteration(&result, &ctx(&policy)));
    }

    #[test]
    fn policy_can_switch_test_failure_blocking_off() {
        // The knob, read in both directions — the pin that once asserted it
        // was unread now has a live counterpart.
        let result = suite_flag(true);
        let permissive = Policy {
            severity: SeverityPolicy {
                block_on_test_failure: false,
                ..SeverityPolicy::default()
            },
            ..Policy::default()
        };
        assert!(!stops_the_line(&result, &ctx(&permissive)));
        assert!(stops_the_line(&result, &ctx(&Policy::default())));
    }

    #[test]
    fn a_passing_suite_stops_nothing() {
        let mut result = suite_flag(false);
        apply(std::slice::from_mut(&mut result), &Policy::default());
        assert!(!stops_the_line(&result, &ctx(&Policy::default())));
    }

    #[test]
    fn a_suite_flag_from_another_family_is_not_a_suite_flag() {
        // The rule keys on family AND metric id together, so a hostile or
        // buggy engine spelling `tests.suite-failure` in another family does
        // not reach the test-failure route (assembly refuses the mis-stamp
        // long before, but this rule must not be the layer that trusts it).
        let mut result = suite_flag(true);
        result.family = EngineFamily::Static;
        assert!(!fired_suite_failure(&result));
    }

    #[test]
    fn policy_can_switch_tamper_blocking_off() {
        let result = tamper_flag("tamper.test-removal", true);
        let permissive_policy = Policy {
            severity: SeverityPolicy {
                block_on_tamper: false,
                ..SeverityPolicy::default()
            },
            ..Policy::default()
        };
        assert!(!stops_the_line(&result, &ctx(&permissive_policy)));
        assert!(stops_the_line(&result, &ctx(&Policy::default())));
    }

    #[test]
    fn a_c_tier_claim_cannot_reach_the_med_plus_band() {
        let mut result = sample_result();
        result.evidence.tier = EvidenceTier::C;
        result.severity = Severity::Critical;
        apply(std::slice::from_mut(&mut result), &Policy::default());
        assert_eq!(result.severity, Severity::Low);
        assert!(!stops_the_line(&result, &ctx(&Policy::default())));
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
        assert!(!counts_toward_iteration(&result, &ctx(&policy)));
        policy.loop_policy.count_context_informational = true;
        assert!(counts_toward_iteration(&result, &ctx(&policy)));
    }

    #[test]
    fn a_degraded_tamper_firing_still_counts_toward_the_iteration() {
        // Same muzzle, second consequence: if the capped severity decided this
        // too, a demoted firing would be invisible to the loop as well as to the
        // line — the agent would never be told to stop grinding on it.
        let mut result = tamper_flag("tamper.test-removal", true);
        result.severity = Severity::Info;
        result.completeness = Completeness::ParseDegraded;
        assert!(counts_toward_iteration(&result, &ctx(&Policy::default())));
    }

    #[test]
    fn an_info_result_does_not_count_toward_the_iteration() {
        let mut result = sample_result();
        result.severity = Severity::Info;
        assert!(!counts_toward_iteration(&result, &ctx(&Policy::default())));
    }
}
