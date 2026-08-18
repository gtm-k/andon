//! The compare pipeline: how a self-report and a verifier recompute become an
//! attestation value.
//!
//! The **order of the three checks is the contract**, and it exists because
//! reordering them produces false tamper accusations:
//!
//! 1. **Tuple equality first.** An unequal `(base_oid, head_oid)` means the two
//!    sides measured different things, so their digests were never expected to
//!    agree. Classified per PLAN R2-4: a base that is an *ancestor* of the
//!    trusted branch is a stale base or a rebase — `unwitnessed-base-mismatch`,
//!    a non-tamper outcome that is still not a pass. A base that is *not* an
//!    ancestor, or is an unknown OID, is `base-fabrication` and forces
//!    `divergent`. Inside this step the base relation is settled *before* the
//!    head is looked at, so a fabricated base whose head also moved is still
//!    `base-fabrication` — fabricating two halves of the tuple must not earn
//!    the gentler outcome that fabricating one earns.
//! 2. **Regime equality second.** Different engine, grammar, or git versions
//!    produce legitimately different numbers. `unwitnessed-version-skew`, never
//!    `divergent` (PREMORTEM S4).
//! 3. **Digest compare last**, over the deterministic results — as the
//!    *verifier* marks them. Reaching this step means both sides measured the
//!    same change with the same tooling, so a disagreement is a real one.
//!    Compare-set membership is deliberately not the report's to decide: the
//!    `deterministic` flag is outside the digest input and so unsigned, and
//!    honouring a self-report's `false` would let any result buy its way out of
//!    the compare with one boolean. Where the two sides disagree about the flag,
//!    the verifier's answer is used and the disagreement is recorded.
//!
//! Passing all three is necessary but not sufficient. Every check above is
//! phrased over the results the two sides have *in common*, so a self-report
//! that has nothing in common with the recompute passes all of them vacuously.
//! `confirmed` therefore also requires that a comparison actually happened and
//! that the verifier's own deterministic results were all witnessed — see
//! [`classify`]'s step 4.
//!
//! P1.5 and P9 implement the git and CI sides against this function rather than
//! re-deriving the order from prose. What they supply that this module cannot
//! compute is [`BaseRelation`] — ancestry is a git question.

use crate::schema::enums::{Attestation, TamperSignal};
use crate::schema::payload::{CompareOutcome, MeasurementRecord, MeasurementResult};

/// How a claimed base commit relates to the branch the verifier trusts.
///
/// Resolved by the verifier from its own checkout — never taken from the record
/// under examination, which is the whole point of an independent verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseRelation {
    /// The claimed base is the base the verifier resolved.
    Equal,
    /// The claimed base is an ancestor of the trusted branch: stale base or
    /// pre-rebase measurement. Explainable, not hostile.
    Ancestor,
    /// The claimed base exists but is not an ancestor of the trusted branch.
    NotAncestor,
    /// The claimed base is not an OID this repository knows.
    Unknown,
}

/// Everything the verifier knows going into a classification.
#[derive(Debug, Clone, Copy)]
pub struct CompareInputs {
    /// How the record's claimed base relates to the trusted branch.
    pub base_relation: BaseRelation,
    /// Whether the head OIDs agree.
    pub head_equal: bool,
    /// True for an unprivileged fork job, where notes refs do not travel and no
    /// self-report may be available (PREMORTEM T5, PLAN P9 fork transport).
    pub fork_tier: bool,
}

/// The outcome of classifying one record pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// The attestation value this pair earned.
    pub attestation: Attestation,
    /// Signals raised by the classification itself, as opposed to by a content
    /// detector. Only ever `base-fabrication` at present.
    pub tamper_signals: Vec<TamperSignal>,
    /// Per-result compare detail, absent when no compare was attempted.
    pub compare: Option<CompareOutcome>,
}

/// Classify a self-report against a verifier recompute.
///
/// `self_report` is `None` when no self-reported record could be found — an
/// agent that never ran, or a fork PR whose notes did not travel.
///
/// This returns the **attestation axis only**. PLAN P9's two-axis rule composes
/// it with the verdict the verifier computed from its own recompute and takes
/// the worse of the two, so that a missing self-report can never launder a
/// CI-side tamper finding into a neutral notice (advisor F2).
pub fn classify(
    self_report: Option<&MeasurementRecord>,
    recompute: &MeasurementRecord,
    inputs: CompareInputs,
) -> Classification {
    let Some(report) = self_report else {
        // Nothing to compare. A fork job still recomputed statically, which is a
        // real if weaker pass; anywhere else this is simply unwitnessed.
        return Classification {
            attestation: if inputs.fork_tier {
                Attestation::ConfirmedStatic
            } else {
                Attestation::Unwitnessed
            },
            tamper_signals: Vec::new(),
            compare: None,
        };
    };

    // Step 1 — tuple equality. The base relation is settled before the head is
    // looked at, because tamper evidence outranks a mismatch (PLAN R2-4): a
    // fabricated base is a fabricated base whether or not the head also moved,
    // and checking the head first let the loudest signal in the tuple be
    // absorbed by the quieter one. Fabricating both is not a way to be treated
    // more gently than fabricating one.
    match inputs.base_relation {
        BaseRelation::NotAncestor | BaseRelation::Unknown => {
            return Classification {
                attestation: Attestation::Divergent,
                tamper_signals: vec![TamperSignal::BaseFabrication],
                compare: Some(tuple_failure_outcome()),
            };
        }
        BaseRelation::Ancestor => {
            return Classification {
                attestation: Attestation::UnwitnessedBaseMismatch,
                tamper_signals: Vec::new(),
                compare: Some(tuple_failure_outcome()),
            };
        }
        BaseRelation::Equal => {}
    }
    if !inputs.head_equal {
        // A different head on an equal base is a different change entirely;
        // treat it as a mismatch rather than guessing at intent.
        return Classification {
            attestation: Attestation::UnwitnessedBaseMismatch,
            tamper_signals: Vec::new(),
            compare: Some(tuple_failure_outcome()),
        };
    }

    // Step 2 — regime equality, over results both sides produced.
    let pairs = pair_results(report, recompute);
    let regime_equal = pairs
        .iter()
        .all(|(a, b)| a.measurement_regime == b.measurement_regime);
    if !regime_equal {
        return Classification {
            attestation: Attestation::UnwitnessedVersionSkew,
            tamper_signals: Vec::new(),
            compare: Some(CompareOutcome {
                tuple_equal: true,
                regime_equal: false,
                matched: Vec::new(),
                mismatched: Vec::new(),
                unpaired: unpaired_ids(report, recompute),
                // The compare stopped at the regime, before any pair's flags
                // were examined.
                flag_disagreements: Vec::new(),
            }),
        };
    }

    // Step 3 — digest compare. Seeded and timing-dependent results are
    // CI-authoritative and never compared (APPROACH graft 2), but **which
    // results those are is the verifier's call, never the report's**.
    //
    // `deterministic` sits outside `ResultDigestInput`, so nothing signs it and
    // a self-report can say anything it likes. Skipping a pair because the
    // *report* claimed non-determinism handed every result an opt-out from the
    // compare for the price of one boolean: flip the flags, forge the numbers,
    // write garbage digests, and the loop walks past all of it leaving matched,
    // mismatched and unpaired empty — a `confirmed` with no trace of what was
    // never checked.
    //
    // Keying the skip on the recompute alone closes it. The verifier knows
    // whether it produced a seed-free number, because it produced it. A pair the
    // verifier calls deterministic is compared whatever the report claims, and a
    // digest disagreement there is a real one.
    let mut matched = Vec::new();
    let mut mismatched = Vec::new();
    let mut flag_disagreements = Vec::new();
    for (reported, recomputed) in &pairs {
        // Recorded before the skip, so the disagreement is visible in both
        // directions rather than only on the pairs that go on to be compared.
        if reported.deterministic != recomputed.deterministic {
            flag_disagreements.push(reported.metric_id.clone());
        }
        if !recomputed.deterministic {
            continue;
        }
        if reported.digest == recomputed.digest {
            matched.push(reported.metric_id.clone());
        } else {
            mismatched.push(reported.metric_id.clone());
        }
    }
    matched.sort();
    mismatched.sort();
    flag_disagreements.sort();

    // Step 4 — a confirmation has to be earned, and there are two ways to reach
    // this line having earned nothing.
    //
    // The first is a self-report that pairs *nothing*: empty, or scoped so that
    // no `(metric_id, scope)` meets the recompute. Every check above is written
    // over `pairs`, so with no pairs the regime `.all()` is vacuously true and
    // `mismatched` is empty because nothing was ever compared — a forged record
    // could name a scope the verifier never measures and collect a `confirmed`
    // for it.
    //
    // The second is a self-report that pairs some results while omitting others
    // the verifier deterministically produced. Those results are recomputed but
    // unwitnessed; treating the record as confirmed would extend the pass to
    // ground nobody attested.
    //
    // Both demote to `unwitnessed` and never to `divergent`. Unpaired results
    // have honest causes — an async lane still running, `completeness: partial`
    // — so the bar is to withhold the pass, not to make an accusation
    // (PREMORTEM T1). A digest that was actually compared and disagreed is
    // evidence of a different kind, and still outranks both.
    let recompute_result_unwitnessed = recompute.results.iter().any(|recomputed| {
        recomputed.deterministic
            && !report
                .results
                .iter()
                .any(|r| r.metric_id == recomputed.metric_id && r.scope == recomputed.scope)
    });

    // There is a third way to earn nothing — an engine that produced no results
    // at all on both sides, so that the surviving results pair cleanly over a
    // measurement neither side finished — and it is deliberately NOT checked
    // here. **PLAN P9 owns it** (acceptance criterion "confirmation-completeness
    // rule", routed out of this phase by the E20 ruling).
    //
    // The reason it is not a one-line completeness check, recorded so the next
    // reader does not re-add one: `completeness` is the record-level roll-up of
    // `parse_health::weakest`, and every engine emits per-result `unwitnessed`
    // by design for an honest absence — a `.png` has no complexity, a `README`
    // no coverage, a new file no history. Keying on the roll-up therefore
    // withholds the pass from ordinary, honest, byte-identical records: two
    // real five-engine measurements agreeing on 61 results and disagreeing on
    // none classified `unwitnessed`. The rule has to key on per-ENGINE presence
    // in `results`, which is the verifier's question and needs the verifier's
    // roster of expected engines.
    let attestation = if !mismatched.is_empty() {
        Attestation::Divergent
    } else if pairs.is_empty() || recompute_result_unwitnessed {
        Attestation::Unwitnessed
    } else {
        Attestation::Confirmed
    };
    Classification {
        attestation,
        tamper_signals: Vec::new(),
        compare: Some(CompareOutcome {
            tuple_equal: true,
            regime_equal: true,
            matched,
            mismatched,
            unpaired: unpaired_ids(report, recompute),
            flag_disagreements,
        }),
    }
}

fn tuple_failure_outcome() -> CompareOutcome {
    CompareOutcome {
        tuple_equal: false,
        regime_equal: false,
        matched: Vec::new(),
        mismatched: Vec::new(),
        unpaired: Vec::new(),
        // Nothing was paired, so nothing could disagree.
        flag_disagreements: Vec::new(),
    }
}

fn pair_results<'a>(
    report: &'a MeasurementRecord,
    recompute: &'a MeasurementRecord,
) -> Vec<(&'a MeasurementResult, &'a MeasurementResult)> {
    let mut pairs = Vec::new();
    for reported in &report.results {
        if let Some(recomputed) = recompute
            .results
            .iter()
            .find(|r| r.metric_id == reported.metric_id && r.scope == reported.scope)
        {
            pairs.push((reported, recomputed));
        }
    }
    pairs
}

fn unpaired_ids(report: &MeasurementRecord, recompute: &MeasurementRecord) -> Vec<String> {
    let mut ids: Vec<String> = report
        .results
        .iter()
        .filter(|a| {
            !recompute
                .results
                .iter()
                .any(|b| b.metric_id == a.metric_id && b.scope == a.scope)
        })
        .map(|a| a.metric_id.clone())
        .chain(
            recompute
                .results
                .iter()
                .filter(|b| {
                    !report
                        .results
                        .iter()
                        .any(|a| a.metric_id == b.metric_id && a.scope == b.scope)
                })
                .map(|b| b.metric_id.clone()),
        )
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::payload::MetricValue;
    use crate::testing::sample_record;

    fn inputs(base_relation: BaseRelation) -> CompareInputs {
        CompareInputs {
            base_relation,
            head_equal: true,
            fork_tier: false,
        }
    }

    #[test]
    fn identical_records_confirm() {
        let report = sample_record();
        let recompute = sample_record();
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::Confirmed);
        assert!(out.tamper_signals.is_empty());
    }

    #[test]
    fn a_changed_number_diverges() {
        let report = sample_record();
        let mut recompute = sample_record();
        recompute.results[0].digest = "0".repeat(64);
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::Divergent);
    }

    #[test]
    fn an_ancestor_base_is_a_mismatch_not_an_accusation() {
        let report = sample_record();
        let recompute = sample_record();
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Ancestor));
        assert_eq!(out.attestation, Attestation::UnwitnessedBaseMismatch);
        assert!(
            out.tamper_signals.is_empty(),
            "a rebase must never raise a tamper signal"
        );
        assert!(!out.attestation.counts_downstream());
    }

    #[test]
    fn a_fabricated_base_diverges_with_a_tamper_signal() {
        let report = sample_record();
        let recompute = sample_record();
        for relation in [BaseRelation::NotAncestor, BaseRelation::Unknown] {
            let out = classify(Some(&report), &recompute, inputs(relation));
            assert_eq!(out.attestation, Attestation::Divergent, "{relation:?}");
            assert_eq!(out.tamper_signals, vec![TamperSignal::BaseFabrication]);
        }
    }

    #[test]
    fn version_skew_is_never_divergent() {
        let report = sample_record();
        let mut recompute = sample_record();
        // Same change, older grammar, and a digest that therefore disagrees.
        if let crate::schema::regime::MeasurementRegime::Static { engine_version, .. } =
            &mut recompute.results[0].measurement_regime
        {
            *engine_version = "0.0.1-old".to_string();
        }
        recompute.results[0].digest = "0".repeat(64);
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::UnwitnessedVersionSkew);
        assert!(out.tamper_signals.is_empty());
    }

    #[test]
    fn a_missing_self_report_is_unwitnessed_but_confirmed_static_on_forks() {
        let recompute = sample_record();
        assert_eq!(
            classify(None, &recompute, inputs(BaseRelation::Equal)).attestation,
            Attestation::Unwitnessed
        );
        let fork = CompareInputs {
            fork_tier: true,
            ..inputs(BaseRelation::Equal)
        };
        assert_eq!(
            classify(None, &recompute, fork).attestation,
            Attestation::ConfirmedStatic
        );
    }

    #[test]
    fn a_fabricated_base_outranks_a_mismatched_head() {
        // The precedence corner. With the head checked first, moving the head
        // as well as forging the base bought the record the non-tamper outcome
        // — the mismatch demotion absorbed the accusation.
        let report = sample_record();
        let recompute = sample_record();
        for relation in [BaseRelation::NotAncestor, BaseRelation::Unknown] {
            let out = classify(
                Some(&report),
                &recompute,
                CompareInputs {
                    base_relation: relation,
                    head_equal: false,
                    fork_tier: false,
                },
            );
            assert_eq!(out.attestation, Attestation::Divergent, "{relation:?}");
            assert_eq!(
                out.tamper_signals,
                vec![TamperSignal::BaseFabrication],
                "{relation:?}"
            );
        }
    }

    #[test]
    fn a_mismatched_head_on_an_equal_base_is_still_a_mismatch() {
        let report = sample_record();
        let recompute = sample_record();
        let out = classify(
            Some(&report),
            &recompute,
            CompareInputs {
                base_relation: BaseRelation::Equal,
                head_equal: false,
                fork_tier: false,
            },
        );
        assert_eq!(out.attestation, Attestation::UnwitnessedBaseMismatch);
        assert!(out.tamper_signals.is_empty());
    }

    /// Give a result a scope the other side will not match, so it cannot pair.
    fn make_unpairable(result: &mut MeasurementResult) {
        result.scope.path = Some("src/never-measured.ts".to_string());
        result.scope.symbol = Some("ghost".to_string());
    }

    /// A second, distinct result the recompute produces and the report may omit.
    fn second_result() -> MeasurementResult {
        let mut result = crate::testing::sample_result();
        result.metric_id = "static.cyclomatic-complexity".to_string();
        result
    }

    #[test]
    fn an_empty_self_report_cannot_confirm() {
        let mut report = sample_record();
        report.results.clear();
        let recompute = sample_record();
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(
            out.attestation,
            Attestation::Unwitnessed,
            "a report with nothing in it compares nothing and confirms nothing"
        );
        assert!(
            out.tamper_signals.is_empty(),
            "silence is not an accusation"
        );
        assert!(!out.attestation.counts_downstream());
    }

    #[test]
    fn a_report_that_pairs_nothing_cannot_confirm() {
        // Unpairable scope *and* a wrong digest: with the compare phrased over
        // pairs alone, both go unnoticed and the record collects a `confirmed`.
        let mut report = sample_record();
        make_unpairable(&mut report.results[0]);
        report.results[0].digest = "0".repeat(64);
        let recompute = sample_record();
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::Unwitnessed);
        assert!(out.tamper_signals.is_empty());
        let compare = out.compare.expect("a demotion still reports what it saw");
        assert!(compare.matched.is_empty() && compare.mismatched.is_empty());
        assert!(
            !compare.unpaired.is_empty(),
            "the unpaired ids are the evidence for the demotion"
        );
    }

    #[test]
    fn a_forged_regime_on_an_unpairable_scope_cannot_confirm() {
        // The regime check is also phrased over pairs, so an unpairable scope
        // makes a fabricated regime vacuously equal too.
        let mut report = sample_record();
        make_unpairable(&mut report.results[0]);
        if let crate::schema::regime::MeasurementRegime::Static { engine_version, .. } =
            &mut report.results[0].measurement_regime
        {
            *engine_version = "99.99.99-forged".to_string();
        }
        let recompute = sample_record();
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_ne!(out.attestation, Attestation::Confirmed);
        assert_eq!(out.attestation, Attestation::Unwitnessed);
    }

    #[test]
    fn a_recompute_result_the_report_omits_blocks_confirmation() {
        // The report attests one metric honestly and simply never mentions the
        // second. The first pairs and matches; the second is measured by the
        // verifier and witnessed by nobody.
        let report = sample_record();
        let mut recompute = sample_record();
        recompute.results.push(second_result());
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::Unwitnessed);
        assert!(
            out.tamper_signals.is_empty(),
            "an omission is not tampering"
        );
        let compare = out.compare.expect("compare detail survives the demotion");
        assert_eq!(compare.matched, vec!["sample.metric"]);
        assert_eq!(compare.unpaired, vec!["static.cyclomatic-complexity"]);
    }

    #[test]
    fn a_non_deterministic_recompute_result_does_not_block_confirmation() {
        // The mirror image: a result outside the compare set by design is not
        // something a self-report can be expected to have witnessed.
        let report = sample_record();
        let mut recompute = sample_record();
        let mut extra = second_result();
        extra.deterministic = false;
        recompute.results.push(extra);
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::Confirmed);
    }

    #[test]
    fn a_real_mismatch_outranks_an_unpaired_result() {
        // Divergence is evidence of disagreement; unpaired is absence of
        // evidence. When both are present the accusation is the true one.
        let report = sample_record();
        let mut recompute = sample_record();
        recompute.results[0].digest = "0".repeat(64);
        recompute.results.push(second_result());
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::Divergent);
    }

    #[test]
    fn an_empty_report_on_a_fork_is_still_unwitnessed() {
        // The fork carve-out is for a report that never arrived, not for one
        // that arrived empty: an empty report is a claim, and it compares
        // nothing.
        let mut report = sample_record();
        report.results.clear();
        let recompute = sample_record();
        let fork = CompareInputs {
            fork_tier: true,
            ..inputs(BaseRelation::Equal)
        };
        assert_eq!(
            classify(Some(&report), &recompute, fork).attestation,
            Attestation::Unwitnessed
        );
    }

    /// PROBE8: every result flipped to non-deterministic, values forged.
    ///
    /// The whole self-report opts out of the compare by setting one unsigned
    /// boolean per result. Before the verifier's flag became authoritative, this
    /// returned `confirmed` with matched, mismatched and unpaired all empty —
    /// a pass whose compare detail recorded nothing at all, so the record did
    /// not even look suspicious.
    #[test]
    fn a_report_that_flips_every_deterministic_flag_cannot_confirm() {
        let mut report = sample_record();
        report.results.push(second_result());
        for result in &mut report.results {
            result.deterministic = false;
            result.value = MetricValue::Count(1);
            result.digest = "0".repeat(64);
        }
        let mut recompute = sample_record();
        recompute.results.push(second_result());

        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::Divergent);
        let compare = out.compare.expect("the compare happened");
        assert_eq!(
            compare.mismatched,
            vec!["sample.metric", "static.cyclomatic-complexity"],
            "the forged results must be named, not silently skipped"
        );
        assert_eq!(
            compare.flag_disagreements,
            vec!["sample.metric", "static.cyclomatic-complexity"],
            "the dodge itself must be visible"
        );
    }

    /// PROBE9: one honest result, one flipped and forged alongside it.
    ///
    /// The subtler shape — the record carries a genuine matching pair, so the
    /// compare has something to show, and the forged number hides in the results
    /// the loop used to walk past.
    #[test]
    fn one_flipped_result_beside_an_honest_one_is_still_caught() {
        let mut report = sample_record();
        let mut forged = second_result();
        forged.deterministic = false;
        forged.value = MetricValue::Count(1);
        forged.digest = "0".repeat(64);
        report.results.push(forged);

        let mut recompute = sample_record();
        recompute.results.push(second_result());

        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::Divergent);
        let compare = out.compare.expect("the compare happened");
        assert_eq!(compare.matched, vec!["sample.metric"]);
        assert_eq!(compare.mismatched, vec!["static.cyclomatic-complexity"]);
        assert_eq!(
            compare.flag_disagreements,
            vec!["static.cyclomatic-complexity"]
        );
    }

    /// A flipped flag over an honest number is surfaced without being accused.
    ///
    /// Constructible only because `deterministic` is outside `ResultDigestInput`:
    /// the digest stays valid when the flag flips, so this is the case where the
    /// dodge leaves no trace in the digests at all. The pass is still correct —
    /// the number is right — and `flag_disagreements` is the only thing that
    /// makes the attempt observable.
    #[test]
    fn a_flipped_flag_over_an_honest_digest_confirms_and_is_recorded() {
        let mut report = sample_record();
        report.results[0].deterministic = false;
        let recompute = sample_record();

        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(
            out.attestation,
            Attestation::Confirmed,
            "an honest number is an honest number"
        );
        let compare = out.compare.expect("the compare happened");
        assert_eq!(
            compare.matched,
            vec!["sample.metric"],
            "the verifier's flag decides membership, so the pair is compared"
        );
        assert!(compare.mismatched.is_empty());
        assert_eq!(
            compare.flag_disagreements,
            vec!["sample.metric"],
            "and the disagreement is visible even though nothing else moved"
        );
    }

    /// The honest direction of the same disagreement, recorded and no more.
    ///
    /// The verifier calls a result non-deterministic and the report calls it
    /// deterministic — an engine upgrade can do this legitimately. It stays out
    /// of the compare, on the verifier's word, and confirms.
    #[test]
    fn the_verifier_may_exclude_a_result_the_report_calls_deterministic() {
        let report = sample_record();
        let mut recompute = sample_record();
        recompute.results[0].deterministic = false;
        recompute.results[0].digest = "0".repeat(64);

        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::Confirmed);
        let compare = out.compare.expect("the compare happened");
        assert!(compare.matched.is_empty() && compare.mismatched.is_empty());
        assert_eq!(compare.flag_disagreements, vec!["sample.metric"]);
    }

    #[test]
    fn non_deterministic_results_stay_out_of_the_compare() {
        let mut report = sample_record();
        let mut recompute = sample_record();
        report.results[0].deterministic = false;
        recompute.results[0].deterministic = false;
        recompute.results[0].digest = "0".repeat(64);
        let out = classify(Some(&report), &recompute, inputs(BaseRelation::Equal));
        assert_eq!(out.attestation, Attestation::Confirmed);
        let compare = out.compare.unwrap();
        assert!(compare.matched.is_empty() && compare.mismatched.is_empty());
        assert!(
            compare.flag_disagreements.is_empty(),
            "both sides agree the result is seeded; there is nothing to flag"
        );
    }
}
