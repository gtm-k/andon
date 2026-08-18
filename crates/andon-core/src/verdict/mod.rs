//! The categorical verdict: what an actor is told to do about a change.
//!
//! # There is no number here, and there never will be
//!
//! PRE-DECISIONS non-goal 1, and the product's identity: **no composite score,
//! ever**. A verdict is one of four words. Nothing in this module adds severities
//! up, weights families, or produces a quality figure an agent could optimize
//! against — that is the anti-Goodhart position the whole tool exists to hold,
//! and it is a design constraint rather than a preference.
//!
//! # How the four words are reached
//!
//! Reasons are collected first, each carrying its own severity and the metrics
//! that drove it. Then, in this order:
//!
//! 1. **`escalate_to_human`** — the per-branch iteration cap has been passed and
//!    there is still something to act on. It outranks `block` deliberately: both
//!    stop the line, and this one additionally says *the agent must stop trying*,
//!    which is the information PREMORTEM A4 needs delivered.
//! 2. **`block`** — a tamper signal fired, or a finding reached MED+ after
//!    policy, or a policy loosening arrived without a justification.
//! 3. **`advise`** — findings worth reporting that must not stop the line.
//! 4. **`pass`** — nothing above the advisory floor. A clean run is a pass
//!    whatever the counter says; the loop is over, and escalating a clean
//!    measurement would be noise at exactly the moment the agent got it right.
//!
//! # What blocking is keyed on
//!
//! [`severity::stops_the_line`], and its module documentation carries the
//! argument that matters most in this phase: a fired tamper flag stops the line
//! on **the flag**, never on a severity that a completeness demotion may have
//! capped. One parked parse error must not be able to muzzle the tamper suite.

pub mod iteration;
pub mod ladder;
pub mod policy_change;
pub mod severity;

use crate::policy::Policy;
use crate::schema::enums::{Completeness, Severity, TamperSignal, Verdict};
use crate::schema::payload::{IterationState, MeasurementResult, VerdictReason, VerdictSummary};

use policy_change::PolicyChange;

/// Stable machine codes for [`VerdictReason::code`].
///
/// Consumers branch on these — P5b's report, P6's agent surface, P9's
/// check-conclusion mapping — so they are constants rather than string literals
/// scattered through the assembly.
pub mod reason {
    /// A tamper detector fired and policy stops the line for it.
    pub const TAMPER_SIGNAL: &str = "tamper-signal";
    /// A tamper detector fired and policy does not stop the line for it.
    pub const TAMPER_SIGNAL_ADVISORY: &str = "tamper-signal-advisory";
    /// One or more findings reached MED+ after policy.
    pub const SEVERITY_MED_PLUS: &str = "severity-med-plus";
    /// Findings below the MED+ band, reported and not blocking.
    pub const FINDING_ADVISORY: &str = "finding-advisory";
    /// `.andon.toml` was edited inside the measured change.
    pub const POLICY_CHANGE: &str = "policy-change";
    /// The edit loosened policy and cited no ledgered justification.
    pub const POLICY_CHANGE_LOOSENING: &str = "policy-change-loosening";
    /// The per-branch iteration cap has been passed.
    pub const ITERATION_CAP: &str = "iteration-cap";
    /// An engine could not run. Its metrics are absent, not zero.
    pub const ENGINE_UNAVAILABLE: &str = "engine-unavailable";
    /// A reported finding stands on a claim that is past its re-review date.
    pub const EVIDENCE_STALE: &str = "evidence-stale";
    /// The iteration counter restarted because its state was unusable.
    pub const ITERATION_STATE_RESET: &str = "iteration-state-reset";
    /// The measurement did not see everything it set out to.
    pub const MEASUREMENT_INCOMPLETE: &str = "measurement-incomplete";
    /// The binary's compiled registry and the loaded one disagree about a claim.
    pub const EVIDENCE_REGISTRY_SKEW: &str = "evidence-registry-skew";
}

/// An engine that was asked to measure and could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineFailure {
    /// Which engine.
    pub engine_id: String,
    /// What it said, in its own words.
    pub reason: String,
}

/// Everything the verdict needs besides the results themselves.
#[derive(Debug, Clone, Copy)]
pub struct VerdictContext<'a> {
    /// Record-level completeness, the weakest of the results'.
    ///
    /// Read so the verdict can *say* the measurement was partial. It used to be
    /// computed beside the verdict and never reach it, so a run that could not
    /// see — a deleted coverage report, a file the parser gave up on — produced
    /// a verdict indistinguishable from one that looked and found nothing.
    pub completeness: Completeness,
    /// Policy in force. The verifier's copy comes from the base commit.
    pub policy: &'a Policy,
    /// The `.andon.toml` edit inside this change, if there was one.
    pub policy_change: Option<&'a PolicyChange>,
    /// Engines that could not run.
    pub engine_failures: &'a [EngineFailure],
    /// Claim ids the registry loader marked stale.
    pub stale_claim_ids: &'a [String],
    /// True when the iteration counter restarted from unusable state.
    pub iteration_state_recovered: bool,
    /// Claims the binary's compiled registry and the loaded registry grade
    /// differently. Reported, never blocking — see
    /// [`crate::payload::prepare`]'s evidence resolution.
    pub registry_skew: &'a [String],
}

/// Whether this measurement gives the agent something to act on.
///
/// The input to [`iteration::IterationStore::advance`], and the reason the
/// counter is a *loop* counter: a run with nothing actionable means the loop
/// finished, so the count resets rather than accumulating across unrelated work.
///
/// Findings the agent cannot fix inside its own change are exempt (PREMORTEM
/// A4), and so is an engine that failed to run — grinding on someone else's
/// broken engine is the purest form of the loop this cap exists to stop.
pub fn has_countable_finding(results: &[MeasurementResult], ctx: &VerdictContext) -> bool {
    results
        .iter()
        .any(|r| severity::counts_toward_iteration(r, ctx))
        || ctx.policy_change.is_some_and(|c| c.stops_the_line())
}

/// Reach a verdict.
///
/// `results` must already have been through [`severity::apply`] — the severities
/// read here are post-policy ones. [`crate::payload::prepare`] sequences that
/// for callers; this entry point exists for the verifier, which composes its own
/// axis on top (PLAN P9's two-axis rule).
///
/// The link used to point at `crate::payload::assemble`, which has never
/// existed: the entry point is `prepare` and it always was. A broken intra-doc
/// link is a reader sent to a function that is not there, on the one sentence
/// that says which order these two steps go in.
pub fn evaluate(
    results: &[MeasurementResult],
    ctx: &VerdictContext,
    iteration: IterationState,
) -> VerdictSummary {
    let mut reasons = Vec::new();

    // --- tamper flags -------------------------------------------------------
    // One reason per fired detector, because "which one fired" is the first
    // thing every actor asks and a merged reason throws it away.
    let mut fired: Vec<&MeasurementResult> = results
        .iter()
        .filter(|r| severity::fired_signal(r).is_some())
        .collect();
    fired.sort_by(|a, b| a.metric_id.cmp(&b.metric_id));
    for result in fired {
        // Through `stops_the_line`, never re-derived from the signal here. The
        // muzzle rule has exactly one implementation; a second copy of it in
        // this loop would be a copy that could drift, and the drift would be
        // silent — the tests for one would keep passing while the other decided
        // the verdict.
        let blocking = severity::stops_the_line(result, ctx);
        let mut message = format!(
            "{} fired: {}",
            result.metric_id,
            if blocking {
                "the line stops"
            } else {
                "reported, advisory by policy"
            }
        );
        // A threshold edit that did not stop the line did so for a reason, and
        // the reason is a ledger entry somebody can go and read. Naming it is the
        // difference between "the tool let this through" and "the tool let this
        // through because of this".
        if !blocking {
            if let Some(justification) = ctx
                .policy_change
                .and_then(|c| c.justification.as_ref())
                .filter(|_| {
                    severity::fired_signal(result) == Some(TamperSignal::ThresholdConfigEdit)
                })
            {
                message.push_str(&format!("; {}", justification.describe()));
            }
        }
        // The muzzle, said out loud. Without this line a reader sees a `Low`
        // severity beside a blocking verdict and reads it as a bug.
        if blocking && result.completeness != Completeness::Complete {
            message.push_str(
                "; the detector read a partial view, so its reported severity is capped \
                 and its finding is a lower bound — a firing is still a firing",
            );
        }
        reasons.push(VerdictReason {
            code: if blocking {
                reason::TAMPER_SIGNAL
            } else {
                reason::TAMPER_SIGNAL_ADVISORY
            }
            .to_string(),
            // Blocking is keyed on the flag, so the reason says `critical` even
            // where the result's own severity was capped. The result keeps its
            // honest, capped severity; the reason states the consequence.
            severity: if blocking {
                Severity::Critical
            } else {
                result.severity
            },
            message,
            metric_ids: vec![result.metric_id.clone()],
        });
    }

    // --- metric findings ----------------------------------------------------
    let blocking_metrics = metric_ids(
        results
            .iter()
            .filter(|r| severity::fired_signal(r).is_none() && severity::stops_the_line(r, ctx)),
    );
    if !blocking_metrics.is_empty() {
        let worst = worst_severity(results, &blocking_metrics);
        reasons.push(VerdictReason {
            code: reason::SEVERITY_MED_PLUS.to_string(),
            severity: worst,
            message: format!(
                "{} metric(s) reached {worst:?} on diff-actionable findings after policy",
                blocking_metrics.len()
            ),
            metric_ids: blocking_metrics,
        });
    }

    let advisory_metrics = metric_ids(results.iter().filter(|r| {
        severity::fired_signal(r).is_none()
            && !severity::stops_the_line(r, ctx)
            && r.severity > Severity::Info
    }));
    if !advisory_metrics.is_empty() {
        reasons.push(VerdictReason {
            code: reason::FINDING_ADVISORY.to_string(),
            severity: worst_severity(results, &advisory_metrics),
            message: format!(
                "{} metric(s) worth reporting that do not stop the line",
                advisory_metrics.len()
            ),
            metric_ids: advisory_metrics,
        });
    }

    // --- policy edits -------------------------------------------------------
    if let Some(change) = ctx.policy_change.filter(|c| !c.is_empty()) {
        let deltas: Vec<String> = change.deltas.iter().map(|d| d.describe()).collect();
        // The justification rides on every policy-change reason, verified or
        // not. It used to appear in none of them: a caller could suppress a
        // block with a string, and the payload did not even record what the
        // string was — so a reader had no way to see that a loosening had been
        // excused, let alone by what.
        let cited = change
            .justification
            .as_ref()
            .map(|j| format!("; {}", j.describe()))
            .unwrap_or_default();
        reasons.push(VerdictReason {
            code: reason::POLICY_CHANGE.to_string(),
            severity: Severity::Low,
            message: format!("policy edited in this change: {}{cited}", deltas.join("; ")),
            metric_ids: Vec::new(),
        });
        if change.stops_the_line() {
            let loosened: Vec<String> = change.loosenings().map(|d| d.describe()).collect();
            let why = match change.justification.as_ref() {
                Some(unverified) => format!(
                    "policy loosened and the justification offered has not been checked: {}; {}",
                    loosened.join("; "),
                    unverified.describe()
                ),
                None => format!(
                    "policy loosened with no ledgered justification: {}",
                    loosened.join("; ")
                ),
            };
            reasons.push(VerdictReason {
                code: reason::POLICY_CHANGE_LOOSENING.to_string(),
                severity: Severity::High,
                message: why,
                metric_ids: Vec::new(),
            });
        }
    }

    // --- engines that could not run -----------------------------------------
    //
    // Never blocking. An engine that failed is not evidence against the change,
    // and a flaky engine that stopped the line would be uninstalled within a
    // week. What it *does* do is demote record completeness to `partial`
    // (`crate::payload`), and an incomplete record cannot be `confirmed` — so a
    // change does not launder itself past a detector by breaking it.
    if !ctx.engine_failures.is_empty() {
        let detail: Vec<String> = ctx
            .engine_failures
            .iter()
            .map(|f| format!("{}: {}", f.engine_id, f.reason))
            .collect();
        reasons.push(VerdictReason {
            code: reason::ENGINE_UNAVAILABLE.to_string(),
            severity: Severity::Medium,
            message: format!(
                "{} engine(s) produced no results, so their metrics are absent rather than \
                 zero; this record cannot be confirmed downstream: {}",
                ctx.engine_failures.len(),
                detail.join("; ")
            ),
            metric_ids: Vec::new(),
        });
    }

    // --- notices ------------------------------------------------------------
    let stale_cited = cited_stale_claims(results, ctx.stale_claim_ids);
    if !stale_cited.is_empty() {
        reasons.push(VerdictReason {
            code: reason::EVIDENCE_STALE.to_string(),
            severity: Severity::Info,
            message: format!(
                "reported findings stand on {} claim(s) past their re-review date: {}",
                stale_cited.len(),
                stale_cited.join(", ")
            ),
            metric_ids: Vec::new(),
        });
    }
    if !ctx.registry_skew.is_empty() {
        // A notice, because a tier disagreement means the binary is older or
        // newer than the checkout and not that any number is wrong. What it must
        // not be is invisible: the severity ceiling is computed from the tier
        // the *binary* resolved, so a reader comparing a payload against the
        // registry in the tree would otherwise find a ceiling they cannot
        // account for.
        reasons.push(VerdictReason {
            code: reason::EVIDENCE_REGISTRY_SKEW.to_string(),
            severity: Severity::Info,
            message: format!(
                "this binary and the registry in the checkout grade {} claim(s) differently, \
                 and the ceilings below were computed from the binary's own: {}",
                ctx.registry_skew.len(),
                ctx.registry_skew.join("; ")
            ),
            metric_ids: Vec::new(),
        });
    }
    if ctx.completeness != Completeness::Complete {
        // A notice rather than an advisory, and the severity is the whole of the
        // argument. Saying "incomplete" out loud is what an actor who can only
        // see the verdict needs; *escalating* on it would fire on nearly every
        // change, because a file added in this change has no history for the
        // process family to read and reports `unwitnessed` by design. Blocking
        // on the expected absence of a number nobody could have measured is
        // PREMORTEM A4's uninstall loop.
        //
        // What that leaves open is real and worth naming rather than papering
        // over: record completeness collapses "this file is new, so it has no
        // history" together with "a detector's input was removed", and only the
        // second is a gap. Separating them is an emission-rule question that
        // spans the engines and the schema, and it is recorded as such rather
        // than guessed at here.
        reasons.push(VerdictReason {
            code: reason::MEASUREMENT_INCOMPLETE.to_string(),
            severity: Severity::Info,
            message: format!(
                "this measurement is {:?}: some of what it set out to measure was not \
                 measured, and the results say which",
                ctx.completeness
            )
            .to_lowercase(),
            metric_ids: Vec::new(),
        });
    }
    if ctx.iteration_state_recovered {
        reasons.push(VerdictReason {
            code: reason::ITERATION_STATE_RESET.to_string(),
            severity: Severity::Info,
            message: "the per-branch iteration counter restarted: its stored state could not \
                      be used, so this run counts as the first pass"
                .to_string(),
            metric_ids: Vec::new(),
        });
    }

    // --- the four words -----------------------------------------------------
    let countable = has_countable_finding(results, ctx);
    if iteration.escalated && countable {
        reasons.push(VerdictReason {
            code: reason::ITERATION_CAP.to_string(),
            severity: Severity::High,
            message: format!(
                "pass {} of a cap of {} on this branch with findings still open; a human decides \
                 from here",
                iteration.count, iteration.cap
            ),
            metric_ids: Vec::new(),
        });
    }

    let blocking = reasons.iter().any(|r| {
        matches!(
            r.code.as_str(),
            reason::TAMPER_SIGNAL | reason::SEVERITY_MED_PLUS | reason::POLICY_CHANGE_LOOSENING
        )
    });
    let anything_worth_saying = reasons.iter().any(|r| r.severity > Severity::Info);

    let verdict = if iteration.escalated && countable {
        Verdict::EscalateToHuman
    } else if blocking {
        Verdict::Block
    } else if anything_worth_saying {
        Verdict::Advise
    } else {
        Verdict::Pass
    };

    VerdictSummary {
        verdict,
        reasons,
        iteration,
    }
}

/// Sorted, deduplicated metric ids from a set of results.
fn metric_ids<'a>(results: impl Iterator<Item = &'a MeasurementResult>) -> Vec<String> {
    let mut ids: Vec<String> = results.map(|r| r.metric_id.clone()).collect();
    ids.sort();
    ids.dedup();
    ids
}

/// The strongest severity among the results naming any of these metrics.
fn worst_severity(results: &[MeasurementResult], metric_ids: &[String]) -> Severity {
    results
        .iter()
        .filter(|r| metric_ids.contains(&r.metric_id))
        .map(|r| r.severity)
        .max()
        .unwrap_or(Severity::Info)
}

/// Stale claims that a *reported* finding actually cites.
///
/// Only findings above `Info`: every claim in the registry expires eventually,
/// and listing the stale ones behind results nobody is being asked to act on
/// would bury the case that matters — a blocking finding standing on evidence
/// whose re-review is overdue (PREMORTEM S2).
fn cited_stale_claims(results: &[MeasurementResult], stale_claim_ids: &[String]) -> Vec<String> {
    let mut cited: Vec<String> = results
        .iter()
        .filter(|r| r.severity > Severity::Info || severity::fired_signal(r).is_some())
        .map(|r| r.claim_id.clone())
        .filter(|claim_id| stale_claim_ids.contains(claim_id))
        .collect();
    cited.sort();
    cited.dedup();
    cited
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::enums::{EngineFamily, EvidenceTier, MetricClass};
    use crate::schema::payload::MetricValue;
    use crate::testing::sample_result;

    fn ctx<'a>(policy: &'a Policy) -> VerdictContext<'a> {
        VerdictContext {
            policy,
            policy_change: None,
            engine_failures: &[],
            stale_claim_ids: &[],
            iteration_state_recovered: false,
            completeness: Completeness::Complete,
            registry_skew: &[],
        }
    }

    fn iteration(count: u32, cap: u32) -> IterationState {
        IterationState {
            count,
            cap,
            escalated: count > cap,
        }
    }

    fn clean_result() -> MeasurementResult {
        let mut result = sample_result();
        result.severity = Severity::Info;
        result
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
        result.severity = if fired {
            Severity::High
        } else {
            Severity::Info
        };
        result
    }

    #[test]
    fn a_clean_change_passes() {
        let policy = Policy::default();
        let summary = evaluate(&[clean_result()], &ctx(&policy), iteration(0, 3));
        assert_eq!(summary.verdict, Verdict::Pass);
        assert!(summary.reasons.is_empty());
    }

    #[test]
    fn a_med_plus_finding_blocks() {
        let policy = Policy::default();
        let mut result = sample_result();
        result.severity = Severity::High;
        let summary = evaluate(&[result], &ctx(&policy), iteration(1, 3));
        assert_eq!(summary.verdict, Verdict::Block);
        assert_eq!(summary.reasons[0].code, reason::SEVERITY_MED_PLUS);
        assert_eq!(summary.reasons[0].metric_ids, vec!["sample.metric"]);
    }

    #[test]
    fn a_low_finding_advises() {
        let policy = Policy::default();
        let mut result = sample_result();
        result.severity = Severity::Low;
        let summary = evaluate(&[result], &ctx(&policy), iteration(1, 3));
        assert_eq!(summary.verdict, Verdict::Advise);
        assert_eq!(summary.reasons[0].code, reason::FINDING_ADVISORY);
    }

    #[test]
    fn a_fired_tamper_flag_blocks_and_names_itself() {
        let policy = Policy::default();
        let results = vec![
            tamper_flag("tamper.test-removal", true),
            tamper_flag("tamper.suppression-density", false),
        ];
        let summary = evaluate(&results, &ctx(&policy), iteration(1, 3));
        assert_eq!(summary.verdict, Verdict::Block);
        let tamper: Vec<&VerdictReason> = summary
            .reasons
            .iter()
            .filter(|r| r.code == reason::TAMPER_SIGNAL)
            .collect();
        assert_eq!(tamper.len(), 1, "one reason per fired detector");
        assert_eq!(tamper[0].metric_ids, vec!["tamper.test-removal"]);
    }

    #[test]
    fn a_degraded_tamper_firing_blocks_and_the_reason_explains_the_capped_severity() {
        // The muzzle rule, end to end at the verdict. A reader who sees `Low` on
        // the result and `block` on the verdict has to be told why.
        let policy = Policy::default();
        let mut result = tamper_flag("tamper.test-removal", true);
        result.completeness = Completeness::ParseDegraded;
        result.severity = Severity::Low;
        let summary = evaluate(&[result], &ctx(&policy), iteration(1, 3));
        assert_eq!(summary.verdict, Verdict::Block);
        let tamper = summary
            .reasons
            .iter()
            .find(|r| r.code == reason::TAMPER_SIGNAL)
            .expect("the firing stops the line");
        assert_eq!(tamper.severity, Severity::Critical);
        assert!(tamper.message.contains("lower bound"), "{}", tamper.message);
    }

    #[test]
    fn one_parked_parse_error_does_not_muzzle_the_suite() {
        // The failure this phase was warned about: every detector demoted by a
        // pre-existing parse error, and the whole suite silenced with it.
        let policy = Policy::default();
        let results: Vec<MeasurementResult> = ["tamper.test-removal", "tamper.assertion-free-test"]
            .into_iter()
            .map(|id| {
                let mut result = tamper_flag(id, true);
                result.completeness = Completeness::ParseDegraded;
                result.severity = Severity::Low;
                result
            })
            .collect();
        let summary = evaluate(&results, &ctx(&policy), iteration(1, 3));
        assert_eq!(summary.verdict, Verdict::Block);
        assert_eq!(
            summary
                .reasons
                .iter()
                .filter(|r| r.code == reason::TAMPER_SIGNAL)
                .count(),
            2
        );
    }

    #[test]
    fn a_loosened_threshold_edit_blocks_until_something_accounts_for_it() {
        // CODEX'S PROBE, at the verdict. `tamper.threshold-config-edit` fires on
        // a real loosening in `.eslintrc.json`; nothing else does. The probe
        // reported `left: Advise, right: Block` — the exemption was keyed on the
        // enum variant, and the justification route behind it only ever read
        // `.andon.toml`, so a loosening in any other configuration file could
        // take the exemption with nowhere to be ruled on.
        let policy = Policy::default();
        let result = tamper_flag("tamper.threshold-config-edit", true);
        let summary = evaluate(
            std::slice::from_ref(&result),
            &ctx(&policy),
            iteration(1, 3),
        );
        assert_eq!(summary.verdict, Verdict::Block);
        assert_eq!(summary.reasons[0].code, reason::TAMPER_SIGNAL);

        // B6's exit, and the message says what it was.
        let change = policy_change::PolicyChange {
            deltas: Vec::new(),
            justification: Some(policy_change::Justification::Verified {
                reference: "andon-ledger#12".to_string(),
                summary: "eslint rule relaxed for the codemod".to_string(),
            }),
        };
        let mut context = ctx(&policy);
        context.policy_change = Some(&change);
        let excused = evaluate(&[result], &context, iteration(1, 3));
        assert_eq!(excused.verdict, Verdict::Advise);
        assert_eq!(excused.reasons[0].code, reason::TAMPER_SIGNAL_ADVISORY);
        assert!(
            excused.reasons[0].message.contains("andon-ledger#12"),
            "the reason names what excused it: {}",
            excused.reasons[0].message
        );
    }

    #[test]
    fn an_unjustified_policy_loosening_blocks() {
        let policy = Policy::default();
        let mut head = policy.clone();
        head.severity.block_on_tamper = false;
        let change = policy_change::evaluate(&policy, &head, None);
        let mut context = ctx(&policy);
        context.policy_change = Some(&change);
        let summary = evaluate(&[clean_result()], &context, iteration(1, 3));
        assert_eq!(summary.verdict, Verdict::Block);
        assert!(summary
            .reasons
            .iter()
            .any(|r| r.code == reason::POLICY_CHANGE_LOOSENING));
        assert!(
            summary
                .reasons
                .iter()
                .any(|r| r.code == reason::POLICY_CHANGE),
            "the advisory finding with the delta is emitted either way"
        );
    }

    #[test]
    fn a_justified_policy_loosening_advises() {
        let policy = Policy::default();
        let mut head = policy.clone();
        head.severity.block_on_tamper = false;
        let change = policy_change::evaluate(
            &policy,
            &head,
            Some(policy_change::Justification::Verified {
                reference: "andon-ledger#12".to_string(),
                summary: "tamper blocking suspended for the corpus refresh".to_string(),
            }),
        );
        let mut context = ctx(&policy);
        context.policy_change = Some(&change);
        let summary = evaluate(&[clean_result()], &context, iteration(1, 3));
        assert_eq!(summary.verdict, Verdict::Advise);
        assert!(!summary
            .reasons
            .iter()
            .any(|r| r.code == reason::POLICY_CHANGE_LOOSENING));
        let advisory = summary
            .reasons
            .iter()
            .find(|r| r.code == reason::POLICY_CHANGE)
            .expect("the delta is reported either way");
        assert!(
            advisory.message.contains("andon-ledger#12"),
            "the payload has to say what excused the loosening: {}",
            advisory.message
        );
    }

    #[test]
    fn an_unverified_justification_is_reported_and_suppresses_nothing() {
        // CODEX'S PROBE. The reference `trust me` and the summary `not checked
        // against any ledger` turned a block into an advise, and neither string
        // reached the emitted reason — so the payload could not even show a
        // reader that a loosening had been excused, let alone by what.
        let policy = Policy::default();
        let mut head = policy.clone();
        head.severity.block_on_tamper = false;
        let change = policy_change::evaluate(
            &policy,
            &head,
            Some(policy_change::Justification::Unverified {
                reference: "trust me".to_string(),
                summary: "not checked against any ledger".to_string(),
            }),
        );
        assert!(change.stops_the_line());

        let mut context = ctx(&policy);
        context.policy_change = Some(&change);
        let summary = evaluate(&[clean_result()], &context, iteration(1, 3));
        assert_eq!(summary.verdict, Verdict::Block);
        let loosening = summary
            .reasons
            .iter()
            .find(|r| r.code == reason::POLICY_CHANGE_LOOSENING)
            .expect("an unchecked claim does not suppress");
        assert!(
            loosening.message.contains("trust me"),
            "{}",
            loosening.message
        );
        assert!(
            loosening.message.contains("UNVERIFIED"),
            "the reader has to be told nobody checked it: {}",
            loosening.message
        );
    }

    #[test]
    fn the_cap_escalates_and_outranks_a_block() {
        let policy = Policy::default();
        let mut result = sample_result();
        result.severity = Severity::High;
        let summary = evaluate(&[result], &ctx(&policy), iteration(4, 3));
        assert_eq!(summary.verdict, Verdict::EscalateToHuman);
        assert!(summary
            .reasons
            .iter()
            .any(|r| r.code == reason::SEVERITY_MED_PLUS));
        assert!(summary
            .reasons
            .iter()
            .any(|r| r.code == reason::ITERATION_CAP));
    }

    #[test]
    fn a_clean_run_past_the_cap_still_passes() {
        // The loop ended because the agent fixed it. Escalating there would
        // punish the pass.
        let policy = Policy::default();
        let summary = evaluate(&[clean_result()], &ctx(&policy), iteration(9, 3));
        assert_eq!(summary.verdict, Verdict::Pass);
        assert!(!summary
            .reasons
            .iter()
            .any(|r| r.code == reason::ITERATION_CAP));
    }

    #[test]
    fn a_context_informational_finding_never_blocks_and_never_counts() {
        let policy = Policy::default();
        let mut result = sample_result();
        result.metric_class = MetricClass::ContextInformational;
        result.severity = Severity::Low;
        let context = ctx(&policy);
        assert!(!has_countable_finding(&[result.clone()], &context));
        let summary = evaluate(&[result], &context, iteration(9, 3));
        assert_eq!(
            summary.verdict,
            Verdict::Advise,
            "reported, but not a reason to escalate"
        );
    }

    #[test]
    fn a_failed_engine_advises_and_never_blocks() {
        let policy = Policy::default();
        let failures = [EngineFailure {
            engine_id: "clones".to_string(),
            reason: "index lock held".to_string(),
        }];
        let mut context = ctx(&policy);
        context.engine_failures = &failures;
        let summary = evaluate(&[clean_result()], &context, iteration(0, 3));
        assert_eq!(summary.verdict, Verdict::Advise);
        let unavailable = summary
            .reasons
            .iter()
            .find(|r| r.code == reason::ENGINE_UNAVAILABLE)
            .expect("said out loud");
        assert!(unavailable.message.contains("absent rather than"));
        assert!(
            !has_countable_finding(&[clean_result()], &context),
            "an agent must not grind on someone else's broken engine"
        );
    }

    #[test]
    fn a_stale_claim_behind_a_reported_finding_is_named() {
        let policy = Policy::default();
        let mut result = sample_result();
        result.severity = Severity::High;
        let stale = vec![result.claim_id.clone()];
        let mut context = ctx(&policy);
        context.stale_claim_ids = &stale;
        let summary = evaluate(&[result], &context, iteration(1, 3));
        let notice = summary
            .reasons
            .iter()
            .find(|r| r.code == reason::EVIDENCE_STALE)
            .expect("staleness is never silent");
        assert_eq!(notice.severity, Severity::Info);
    }

    #[test]
    fn a_stale_claim_behind_nothing_reported_is_not_named() {
        let policy = Policy::default();
        let result = clean_result();
        let stale = vec![result.claim_id.clone()];
        let mut context = ctx(&policy);
        context.stale_claim_ids = &stale;
        let summary = evaluate(&[result], &context, iteration(0, 3));
        assert_eq!(summary.verdict, Verdict::Pass);
        assert!(summary.reasons.is_empty(), "{:?}", summary.reasons);
    }

    #[test]
    fn a_notice_alone_does_not_turn_a_pass_into_an_advisory() {
        let policy = Policy::default();
        let mut context = ctx(&policy);
        context.iteration_state_recovered = true;
        let summary = evaluate(&[clean_result()], &context, iteration(1, 3));
        assert_eq!(summary.verdict, Verdict::Pass);
        assert_eq!(summary.reasons.len(), 1);
        assert_eq!(summary.reasons[0].code, reason::ITERATION_STATE_RESET);
    }

    #[test]
    fn reasons_do_not_depend_on_the_order_results_arrived_in() {
        let policy = Policy::default();
        let a = tamper_flag("tamper.test-removal", true);
        let b = tamper_flag("tamper.assertion-free-test", true);
        let forwards = evaluate(&[a.clone(), b.clone()], &ctx(&policy), iteration(1, 3));
        let backwards = evaluate(&[b, a], &ctx(&policy), iteration(1, 3));
        assert_eq!(forwards, backwards);
    }

    #[test]
    fn there_is_no_number_in_a_verdict() {
        // PRE-DECISIONS non-goal 1, pinned. `IterationState` counts passes around
        // a loop; nothing here scores the change.
        let policy = Policy::default();
        let mut result = sample_result();
        result.severity = Severity::High;
        let summary = evaluate(&[result], &ctx(&policy), iteration(1, 3));
        let rendered = serde_json::to_string(&summary).expect("serializes");
        for forbidden in ["score", "grade", "rating", "points", "total"] {
            assert!(
                !rendered.contains(forbidden),
                "a composite score is a v1 non-goal, forever: found {forbidden}"
            );
        }
    }
}
