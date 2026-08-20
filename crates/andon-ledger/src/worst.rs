//! The durable consumption rule: worst-of, never latest-wins.
//!
//! # Why the rule exists (decision log, P1.5 execution note (a))
//!
//! A head can carry several records at once: two engines, a retry, a
//! measurement re-run after a rebase, an attestation appended beside an older
//! one. A consumer that reads "the" record by taking the newest one hands an
//! agent an obvious move — measure again until a better record is on top. The
//! ledger's append-only discipline (`cat_sort_uniq`, `append` not `add -f`)
//! deliberately never deletes the earlier record, so the consumption rule has
//! to be the other half: **when several records describe one head, the worst
//! one is the answer.** A divergence cannot be buried by confirming beside it.
//!
//! # One ordering, one owner
//!
//! The ordering itself is [`attestation_rank`], defined beside the verifier's
//! own worst-of in `andon_ledger_min::verify` and re-exported here unchanged —
//! restating the table would be a second copy that could drift from the one the
//! verifier applies in-run. P9's check-conclusion mapping consumes this rule;
//! P9b's cross-harness story reads slices of a ledger already reduced by it.

pub use andon_ledger_min::verify::attestation_rank;

use andon_core::schema::enums::Attestation;
use andon_core::schema::payload::MeasurementRecord;

/// The worst attestation value among `values`, or `None` for an empty slice.
pub fn worst_attestation(values: &[Attestation]) -> Option<Attestation> {
    values
        .iter()
        .copied()
        .max_by_key(|value| attestation_rank(*value))
}

/// The record a consumer must treat as decisive for one head.
///
/// The worst by attestation. Ties go to the record that comes **first in
/// note-body order** — which is deterministic for a given body but **not
/// temporal**: a `cat_sort_uniq` merge re-sorts the body's lines
/// lexicographically, while a fast-forward adoption preserves append order, so
/// which equally-ranked record is "first" depends on the merge topology the
/// body came through. That is sound today because ties are exactly-equal
/// ranks and nothing here reads any other field off the winner; a consumer
/// that starts acting on the decisive record's *other* fields (P9's
/// check-conclusion mapping is the candidate) must not treat the tie-winner
/// as "the earliest" or "the latest" measurement — only as "one of the
/// equally-worst, chosen deterministically". What stays true under every
/// topology: preferring anything else would reward re-measuring, and the
/// whole point of this module is that re-measuring buys nothing.
pub fn decisive<'a>(records: &'a [MeasurementRecord]) -> Option<&'a MeasurementRecord> {
    let mut worst: Option<&'a MeasurementRecord> = None;
    for record in records {
        let replace = match worst {
            None => true,
            Some(current) => {
                attestation_rank(record.attestation.value)
                    > attestation_rank(current.attestation.value)
            }
        };
        if replace {
            worst = Some(record);
        }
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;
    use andon_core::testing::sample_record;

    fn with_attestation(value: Attestation) -> MeasurementRecord {
        let mut record = sample_record();
        record.attestation.value = value;
        record
    }

    #[test]
    fn worst_of_is_not_latest_wins() {
        // The exact move the rule exists to close: a divergent record followed
        // by a confirmed one. Latest-wins would answer `Confirmed`.
        let records = vec![
            with_attestation(Attestation::Divergent),
            with_attestation(Attestation::Confirmed),
        ];
        let decisive = decisive(&records).expect("two records");
        assert_eq!(decisive.attestation.value, Attestation::Divergent);
    }

    #[test]
    fn a_tie_keeps_the_first_record_in_body_order() {
        let mut first = with_attestation(Attestation::Unwitnessed);
        first.invocation.iteration = 1;
        let mut second = with_attestation(Attestation::Unwitnessed);
        second.invocation.iteration = 2;
        let records = vec![first, second];
        assert_eq!(
            decisive(&records)
                .expect("two records")
                .invocation
                .iteration,
            1,
            "between equal records, re-measuring must buy nothing"
        );
    }

    #[test]
    fn worst_attestation_over_values_matches_the_rank() {
        assert_eq!(
            worst_attestation(&[
                Attestation::Confirmed,
                Attestation::UnwitnessedVersionSkew,
                Attestation::ConfirmedStatic,
            ]),
            Some(Attestation::UnwitnessedVersionSkew)
        );
        assert_eq!(worst_attestation(&[]), None);
    }
}
