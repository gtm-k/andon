//! What a degraded parse does to a number (PREMORTEM T3).
//!
//! # Three demotions, because three actors have to see it
//!
//! "Degraded files never drive MED+ nor carry full-confidence claims" is one
//! sentence and three mechanisms, because the actors who need to know are
//! different actors who read different things:
//!
//! | Actor | Reads | Mechanism |
//! |---|---|---|
//! | the verifier, and the policy engine at P5a | `completeness` | [`Completeness::ParseDegraded`], which is **inside** the per-result digest input |
//! | the agent in its loop | `severity` | capped by [`severity_ceiling`] |
//! | the human reading the report | `evidence.does_not_predict` | the caveat from [`caveat`] |
//!
//! A demotion visible to only one of them is a silent failure for the other two.
//! Only the first is digest-bound, which is deliberate: `severity` and
//! `evidence` are excluded from [`andon_core::schema::payload::ResultDigestInput`]
//! by P0 and must stay so, while `completeness` is inside it — so the agent and
//! the verifier are *required* to agree that a file was degraded, and the
//! cross-OS matrix proves they do on every leg.
//!
//! # The parse-health metrics are not themselves demoted
//!
//! `static.parse-errors` and `static.parse-missing` report the degradation.
//! Counting ERROR nodes over a tree full of ERROR nodes is an exact measurement,
//! not an approximate one — and capping *its* severity would silence the one
//! signal T3 wants loud, which is the evasion this whole apparatus exists to
//! catch. So [`demote`] is applied to numbers computed **over** a degraded tree
//! and never to the report of the degradation itself.

use andon_core::schema::enums::{Completeness, Severity};
use andon_core::schema::payload::MeasurementResult;

use crate::parse::ParseHealth;

/// Opening words of the caveat added to a degraded result's evidence.
///
/// A constant so the test that pins the mechanism cannot pass against prose that
/// has quietly changed meaning.
pub const PARSE_DEGRADED_CAVEAT: &str =
    "anything at all, on this file: the parser did not understand";

/// The honesty line a degraded result carries into `does_not_predict`.
pub fn caveat(health: ParseHealth) -> String {
    format!(
        "{PARSE_DEGRADED_CAVEAT} all of it ({} ERROR, {} MISSING node(s)); \
         this number was computed over a partial tree",
        health.error_nodes, health.missing_nodes
    )
}

/// The strongest severity a result of this completeness may reach.
///
/// A ceiling, not a severity: policy still decides how serious a finding is, and
/// this only says how serious it is allowed to become. Public because P5a's
/// verdict assembly has to apply it after policy evaluation — the fact it keys
/// on (whether the parser understood the file) is the engine's to know, and the
/// decision it constrains is P5a's to make.
pub fn severity_ceiling(completeness: Completeness) -> Severity {
    match completeness {
        Completeness::Complete => Severity::Critical,
        // Every incomplete state caps below the MED+ band. A number computed
        // over data that is partly missing must not stop the line, whichever way
        // it went missing.
        Completeness::ParseDegraded | Completeness::Partial | Completeness::Unwitnessed => {
            Severity::Low
        }
    }
}

/// Apply all three demotions to a result computed over a degraded parse.
///
/// Idempotent: demoting twice adds one caveat, not two, so a caller that
/// re-marks a result cannot inflate the honesty field into noise.
pub fn demote(result: &mut MeasurementResult, health: ParseHealth) {
    if !health.is_degraded() {
        return;
    }
    result.completeness = Completeness::ParseDegraded;
    result.severity = result
        .severity
        .min(severity_ceiling(Completeness::ParseDegraded));
    let caveat = caveat(health);
    if !result.evidence.does_not_predict.contains(&caveat) {
        // First, so a reader who stops after one line reads the one that
        // changes how to read the number.
        result.evidence.does_not_predict.insert(0, caveat);
    }
}

/// How weak a completeness value is; the record-level value is the weakest of
/// its results'.
///
/// Ordered worst-first: `unwitnessed` (the inputs were not there at all), then
/// `partial` (some results are missing entirely), then `parse-degraded` (the
/// results are present and were computed over an incomplete tree), then
/// `complete`. The middle two are a judgement: a missing result is worse than a
/// qualified one, because a qualified one is still a number somebody can read.
pub fn weakness_rank(completeness: Completeness) -> u8 {
    match completeness {
        Completeness::Unwitnessed => 0,
        Completeness::Partial => 1,
        Completeness::ParseDegraded => 2,
        Completeness::Complete => 3,
    }
}

/// The weakest completeness among some results, or `complete` when there are
/// none.
pub fn weakest(results: &[MeasurementResult]) -> Completeness {
    results
        .iter()
        .map(|result| result.completeness)
        .min_by_key(|completeness| weakness_rank(*completeness))
        .unwrap_or(Completeness::Complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use andon_core::testing::sample_result;

    fn degraded_health() -> ParseHealth {
        ParseHealth {
            error_nodes: 2,
            missing_nodes: 1,
            total_nodes: 100,
        }
    }

    fn a_result() -> MeasurementResult {
        let mut result = sample_result();
        result.severity = Severity::Critical;
        result.completeness = Completeness::Complete;
        result
    }

    #[test]
    fn all_three_demotions_fire_together() {
        // One test, three assertions, on purpose: each mechanism serves an actor
        // who cannot see the other two, so a change that keeps one and drops
        // another has to fail here.
        let mut result = a_result();
        demote(&mut result, degraded_health());
        assert_eq!(result.completeness, Completeness::ParseDegraded);
        assert!(!result.severity.is_med_plus(), "{:?}", result.severity);
        assert!(
            result.evidence.does_not_predict[0].contains(PARSE_DEGRADED_CAVEAT),
            "{:?}",
            result.evidence.does_not_predict
        );
        assert!(result.evidence.does_not_predict[0].contains("2 ERROR"));
        assert!(result.evidence.does_not_predict[0].contains("1 MISSING"));
    }

    #[test]
    fn a_clean_parse_demotes_nothing() {
        let mut result = a_result();
        let before = result.clone();
        demote(&mut result, ParseHealth::default());
        assert_eq!(result, before);
    }

    #[test]
    fn demoting_twice_adds_one_caveat() {
        let mut result = a_result();
        demote(&mut result, degraded_health());
        let after_once = result.evidence.does_not_predict.len();
        demote(&mut result, degraded_health());
        assert_eq!(result.evidence.does_not_predict.len(), after_once);
    }

    #[test]
    fn demotion_never_raises_a_severity() {
        let mut result = a_result();
        result.severity = Severity::Info;
        demote(&mut result, degraded_health());
        assert_eq!(result.severity, Severity::Info);
    }

    #[test]
    fn every_incomplete_state_caps_below_the_med_plus_band() {
        for completeness in [
            Completeness::ParseDegraded,
            Completeness::Partial,
            Completeness::Unwitnessed,
        ] {
            assert!(
                !severity_ceiling(completeness).is_med_plus(),
                "{completeness:?}"
            );
        }
        assert!(severity_ceiling(Completeness::Complete).is_med_plus());
    }

    #[test]
    fn the_record_takes_the_weakest_completeness_of_its_results() {
        let mut complete = a_result();
        complete.completeness = Completeness::Complete;
        let mut degraded = a_result();
        degraded.completeness = Completeness::ParseDegraded;
        let mut unwitnessed = a_result();
        unwitnessed.completeness = Completeness::Unwitnessed;

        assert_eq!(weakest(&[complete.clone()]), Completeness::Complete);
        assert_eq!(
            weakest(&[complete.clone(), degraded.clone()]),
            Completeness::ParseDegraded
        );
        assert_eq!(
            weakest(&[complete, degraded, unwitnessed]),
            Completeness::Unwitnessed
        );
        assert_eq!(weakest(&[]), Completeness::Complete);
    }
}
