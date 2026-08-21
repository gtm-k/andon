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
use crate::schema::payload::{
    IterationState, MeasurementRecord, MeasurementResult, VerdictReason, VerdictSummary,
};

use policy_change::PolicyChange;

/// Stable machine codes for [`VerdictReason::code`].
///
/// Consumers branch on these — P5b's report, P6's agent surface, P9's
/// check-conclusion mapping — so they are constants rather than string literals
/// scattered through the assembly.
pub mod reason {
    /// A tamper detector fired and policy stops the line for it.
    pub const TAMPER_SIGNAL: &str = "tamper-signal";

    /// The user test command failed and policy blocks on that.
    pub const TEST_FAILURE: &str = "test-failure";

    /// The user test command failed and policy chose not to block.
    pub const TEST_FAILURE_ADVISORY: &str = "test-failure-advisory";
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
    /// A changed path could not be read, so no result describes it.
    pub const CHANGE_NOT_READ: &str = "change-not-read";
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
    /// Changed paths nothing could read, so no result describes them.
    ///
    /// Read here because carrying the fact on the record was not enough. The
    /// record grew [`crate::schema::payload::MeasurementRecord::unreadable_paths`]
    /// and every renderer learned to print it, and the verdict still did not
    /// ask: a measurement whose change could not be read reached `pass`, was
    /// saved as `pass`, and was re-served as `pass` by `ledger show` beside the
    /// list of what it had not read. Carrying a fact is not the same as acting
    /// on it, and a record that says `pass` while naming what it could not read
    /// contradicts itself in the direction that passes.
    pub unreadable_paths: &'a [String],
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

/// Whether a record's stored verdict contradicts the record's own fields.
///
/// # The rule this checks, and why it is checked at read time
///
/// [`evaluate`] holds one invariant about unread paths: a change with a path
/// nobody read cannot be a `pass`, because `pass` means "nothing above the
/// advisory floor" and there is no floor under bytes nobody looked at. Records
/// sealed before that rule existed carry both halves of the contradiction —
/// `unreadable_paths` naming what was not read, and `verdict: pass` beside it —
/// and they are still on disk and still in `refs/notes/andon-measure`.
///
/// # Reject, migrate, or label, and why this is label
///
/// The reviewer's framing: *"A durable artifact need not be silently
/// recomputed, but an internally inconsistent legacy record must be rejected,
/// migrated, or explicitly labeled invalid."* Three options and this is the
/// third.
///
/// **Not recompute.** A verdict is a function of the policy, the registry and
/// the iteration state in force when it was reached, none of which a reader
/// months later has. Computing a new word and printing it in the old one's place
/// would make two renderings of one record disagree, which is the defect class
/// this phase has spent three rounds closing.
///
/// **Not reject.** `ledger show` exists to re-serve records months later, and a
/// query surface that refuses the rows it does not like has lost the history it
/// was built to keep.
///
/// **Not migrate.** The bytes are sealed. Rewriting a stored verdict in place is
/// the shape of the laundering path the whole trust boundary is built to keep
/// shut, and it would do it in the tool's own hand.
///
/// So the bytes are served exactly as they were written, and every surface says
/// the stored verdict is not a fact about this change. One predicate, because
/// the last time a rule about unread paths was taught surface by surface, five
/// learned it and `ledger show` did not.
pub fn stored_verdict_is_contradicted(record: &MeasurementRecord) -> bool {
    !record.unreadable_paths.is_empty() && record.verdict.verdict == Verdict::Pass
}

/// The sentence every surface says about a record [`stored_verdict_is_contradicted`]
/// answers true for.
///
/// A function rather than a constant because it names the count, and a reader
/// deciding whether to trust a stored verdict needs to know how much of the
/// change it is silent about.
///
/// It says nothing about where the record came from. The obvious sentence —
/// "a build before that rule existed wrote it" — is the likely history and not
/// something this can read, and a record doctored by hand a minute ago is a
/// counterexample to it. The contradiction is the fact; its origin is a guess,
/// and this phase has blocked three times on messages that stated one as the
/// other.
pub fn contradiction_label(record: &MeasurementRecord) -> String {
    format!(
        "this record stores `pass` beside {} changed path(s) it could not read. The two cannot \
         both be true, so the stored word is not a verdict about this change. It is served here \
         unaltered because the record is evidence; re-run `andon measure` on the change to get \
         a verdict that is.",
        record.unreadable_paths.len()
    )
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

    // --- the failed test suite ----------------------------------------------
    // Its own reason, not a row in the generic metric findings: the block keys
    // on the flag while the tier ceiling holds the reported severity at `Low`,
    // so the generic "reached {severity} after policy" sentence would describe
    // a `block` with a word that cannot block. The tamper loop above has the
    // same split for the same reason.
    for result in results.iter().filter(|r| severity::fired_suite_failure(r)) {
        let blocking = severity::stops_the_line(result, ctx);
        // The sibling sentence says how it failed; the engine emits the pair
        // together, so its absence means a hand-built record — the reason
        // still stands, just without the detail.
        let outcome = results
            .iter()
            .find(|r| {
                r.family == crate::schema::enums::EngineFamily::Tests
                    && r.metric_id == severity::SUITE_OUTCOME_METRIC
            })
            .and_then(|r| match &r.value {
                crate::schema::payload::MetricValue::Text(text) => Some(text.as_str()),
                _ => None,
            })
            .unwrap_or("exited non-zero");
        reasons.push(VerdictReason {
            code: if blocking {
                reason::TEST_FAILURE
            } else {
                reason::TEST_FAILURE_ADVISORY
            }
            .to_string(),
            // Keyed on the flag, so the reason says `critical` even though the
            // result's own severity is tier-capped — the same wording rule as
            // the tamper reasons above.
            severity: if blocking {
                Severity::Critical
            } else {
                result.severity
            },
            message: format!(
                "the user test command failed ({outcome}): {}",
                if blocking {
                    "the line stops"
                } else {
                    "reported; policy does not block on test failure"
                }
            ),
            metric_ids: vec![result.metric_id.clone()],
        });
    }

    // --- metric findings ----------------------------------------------------
    let blocking_metrics = metric_ids(results.iter().filter(|r| {
        severity::fired_signal(r).is_none()
            && !severity::fired_suite_failure(r)
            && severity::stops_the_line(r, ctx)
    }));
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
            && !severity::fired_suite_failure(r)
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
    // week. What it *does* do is hold record completeness at never stronger than
    // `partial` (`crate::payload::record_completeness`) and say which engine was
    // missing, so that a reader can see what the measurement did not cover.
    //
    // The message states that completeness by reading `ctx.completeness` rather
    // than by naming a value. Naming one was wrong: a failed engine only *floors*
    // the record, so a result carrying an honest `unwitnessed` marker keeps the
    // weaker value and a sentence that said "partial" contradicted the record it
    // was attached to. A sentence that reads the field it describes cannot drift
    // from it. Worded as `MEASUREMENT_INCOMPLETE` words the same value; on this
    // branch the reachable set is `partial` and `unwitnessed`, for which that
    // wording and the payload's own serialisation are the same two words.
    //
    // What it does NOT do is decide the attestation. `compare::classify` does
    // not read `completeness`, and this reason must not claim it does — PLAN
    // P9's confirmation-completeness criterion owns the rule that a record
    // missing an engine on both sides cannot be `confirmed`, keyed on per-engine
    // presence rather than on this roll-up (E20).
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
                 zero and this record is {}: {}",
                ctx.engine_failures.len(),
                format!("{:?}", ctx.completeness).to_lowercase(),
                detail.join("; ")
            ),
            metric_ids: Vec::new(),
        });
    }

    // --- a change that could not be read ------------------------------------
    //
    // The other side of the engine-failure coin, and it belongs beside it: an
    // engine that could not run leaves a metric unmeasured, and a path that
    // could not be read leaves *everything* about that path unmeasured. Both
    // mean the record covers less than the caller asked about, and neither is
    // evidence against the change.
    //
    // # Why this reason exists rather than a rule about the four words
    //
    // `main`'s exit-code table already says a `pass` requires that the change
    // was actually read, and the CLI enforced it on the way out: `measure` exits
    // 1 over unreadable paths whatever the verdict says. What it could not do is
    // fix the *record*, which is the durable artifact — so a failed-read
    // measurement was saved with `verdict: pass`, and `ledger show` re-served it
    // months later with the headline `PASS` printed directly above the list of
    // paths it had not read. The exit code is this process's; the verdict is
    // everybody's.
    //
    // # Why `Medium`, which is to say why `advise` and not `block`
    //
    // Severity above `Info` is what lifts the verdict off `pass`, which is the
    // whole requirement. It stops there deliberately. `block` is the word for
    // "something in this change has to be dealt with", exit code 2, and this is
    // not that: nothing was found, because nothing was read. The distinction
    // between 1 and 2 is the one the CLI documentation calls the one that
    // matters — "Andon found something" against "Andon could not look" — and
    // `code_for_record` returns 1 here in either case, so a `block` verdict
    // would make the published exit-code table false rather than stricter.
    // `advise` is the only word that leaves it true, and row 1 of that table
    // already names this case.
    //
    // # Why it does not touch the iteration counter
    //
    // [`has_countable_finding`] does not read this field, for the reason engine
    // failures are exempt: an unreadable path is not something the agent's next
    // edit answers, and counting it would grind the loop to escalation over a
    // permission bit. It is also what keeps the count honest across the
    // round-trip — `payload::prepare` computes countability once and `finish`
    // recomputes it, and a field only one of them read would let them disagree.
    if !ctx.unreadable_paths.is_empty() {
        reasons.push(VerdictReason {
            code: reason::CHANGE_NOT_READ.to_string(),
            severity: Severity::Medium,
            message: format!(
                "{} changed path(s) could not be read, so no result here describes them and \
                 this verdict is about the rest of the change: {}",
                ctx.unreadable_paths.len(),
                ctx.unreadable_paths.join(", ")
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
            reason::TAMPER_SIGNAL
                | reason::TEST_FAILURE
                | reason::SEVERITY_MED_PLUS
                | reason::POLICY_CHANGE_LOOSENING
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
            unreadable_paths: &[],
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
    fn a_change_with_an_unread_path_cannot_pass() {
        // The same results that pass above, over a change one path of which was
        // never read. `pass` means "nothing above the advisory floor", and there
        // is no floor under bytes nobody looked at.
        let policy = Policy::default();
        let unread = vec!["src/calc.ts".to_string()];
        let summary = evaluate(
            &[clean_result()],
            &VerdictContext {
                unreadable_paths: &unread,
                ..ctx(&policy)
            },
            iteration(0, 3),
        );
        assert_eq!(summary.verdict, Verdict::Advise);
        let reason = summary
            .reasons
            .iter()
            .find(|r| r.code == reason::CHANGE_NOT_READ)
            .expect("the verdict says which paths it could not read");
        assert!(reason.message.contains("src/calc.ts"), "{reason:?}");
        assert_eq!(reason.severity, Severity::Medium);
    }

    #[test]
    fn an_unread_path_does_not_advance_the_loop_counter() {
        // The counter counts attempts an agent made at this change. A path the
        // tool could not open is not one, and counting it would grind a branch to
        // `escalate_to_human` over a permission bit — the exemption engine
        // failures already have.
        let policy = Policy::default();
        let unread = vec!["src/calc.ts".to_string()];
        assert!(!has_countable_finding(
            &[clean_result()],
            &VerdictContext {
                unreadable_paths: &unread,
                ..ctx(&policy)
            }
        ));
    }

    #[test]
    fn an_unread_path_does_not_soften_a_block() {
        // The reason is additive and non-blocking, which must not mean it can
        // stand in front of one. A real finding still stops the line.
        let policy = Policy::default();
        let unread = vec!["src/calc.ts".to_string()];
        let mut result = sample_result();
        result.severity = Severity::High;
        let summary = evaluate(
            &[result],
            &VerdictContext {
                unreadable_paths: &unread,
                ..ctx(&policy)
            },
            iteration(1, 3),
        );
        assert_eq!(summary.verdict, Verdict::Block);
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
        // Both completeness values a failed engine can leave behind, because the
        // reason has to say the one the record actually carries.
        // `payload::record_completeness` floors the record at `partial` only when
        // nothing weaker is already there, so a result carrying an honest
        // `unwitnessed` marker keeps `unwitnessed` — and the message used to say
        // "partial" regardless, which put two contradicting sentences on one
        // verdict. The words are written out here rather than recomputed from
        // `ctx.completeness`, which would assert the emission against itself.
        let policy = Policy::default();
        let failures = [EngineFailure {
            engine_id: "clones".to_string(),
            reason: "index lock held".to_string(),
        }];
        for (completeness, word) in [
            (Completeness::Partial, "partial"),
            (Completeness::Unwitnessed, "unwitnessed"),
        ] {
            let mut context = ctx(&policy);
            context.engine_failures = &failures;
            context.completeness = completeness;
            let summary = evaluate(&[clean_result()], &context, iteration(0, 3));
            assert_eq!(summary.verdict, Verdict::Advise);
            let unavailable = summary
                .reasons
                .iter()
                .find(|r| r.code == reason::ENGINE_UNAVAILABLE)
                .expect("said out loud");
            assert!(unavailable.message.contains("absent rather than"));
            assert!(
                unavailable
                    .message
                    .contains(&format!("this record is {word}")),
                "the reason states what is true of the record it is attached to, \
                 and this record is {completeness:?}: {}",
                unavailable.message
            );
            assert!(
                !unavailable.message.contains("confirmed"),
                "and it does not promise a downstream guarantee `compare::classify` \
                 does not provide — that rule is PLAN P9's (E20)"
            );
            assert!(
                !has_countable_finding(&[clean_result()], &context),
                "an agent must not grind on someone else's broken engine"
            );
        }
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
