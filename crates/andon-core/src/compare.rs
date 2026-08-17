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
//!    `divergent`.
//! 2. **Regime equality second.** Different engine, grammar, or git versions
//!    produce legitimately different numbers. `unwitnessed-version-skew`, never
//!    `divergent` (PREMORTEM S4).
//! 3. **Digest compare last**, and only over deterministic results. Reaching
//!    this step means both sides measured the same change with the same tooling,
//!    so a disagreement is a real one.
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

    // Step 1 — tuple equality.
    if !inputs.head_equal {
        // A different head is a different change entirely; treat it as the
        // strongest form of mismatch rather than guessing at intent.
        return Classification {
            attestation: Attestation::UnwitnessedBaseMismatch,
            tamper_signals: Vec::new(),
            compare: Some(tuple_failure_outcome()),
        };
    }
    match inputs.base_relation {
        BaseRelation::Equal => {}
        BaseRelation::Ancestor => {
            return Classification {
                attestation: Attestation::UnwitnessedBaseMismatch,
                tamper_signals: Vec::new(),
                compare: Some(tuple_failure_outcome()),
            };
        }
        BaseRelation::NotAncestor | BaseRelation::Unknown => {
            return Classification {
                attestation: Attestation::Divergent,
                tamper_signals: vec![TamperSignal::BaseFabrication],
                compare: Some(tuple_failure_outcome()),
            };
        }
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
            }),
        };
    }

    // Step 3 — digest compare, deterministic results only. Seeded and
    // timing-dependent results are CI-authoritative and never compared
    // (APPROACH graft 2).
    let mut matched = Vec::new();
    let mut mismatched = Vec::new();
    for (reported, recomputed) in &pairs {
        if !reported.deterministic || !recomputed.deterministic {
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

    let attestation = if mismatched.is_empty() {
        Attestation::Confirmed
    } else {
        Attestation::Divergent
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
        if let crate::schema::regime::MeasurementRegime::Static {
            engine_version, ..
        } = &mut recompute.results[0].measurement_regime
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
    }
}
