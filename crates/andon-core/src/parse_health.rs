//! Parse health, and what a degraded parse does to a number (PREMORTEM T3).
//!
//! # Why this is in the contract crate rather than in an engine
//!
//! It was written in `andon-static-metrics`, where the first parser was. Three
//! engines parse now — static metrics, clones, and the tamper suite — and they
//! reached identical grammar pins at the wave-1 integration, which means the
//! *same* half-understood file is reachable by all three. A demotion rule
//! carried separately by three crates is three rules that agree until one of
//! them is edited, and the field it writes is inside the digest input: two
//! engines disagreeing about whether a file was degraded is a disagreement the
//! verifier reads as tampering.
//!
//! What lives here is the part that has no parser in it: the counts, the three
//! demotions, and the ordering. Walking a tree to *produce* the counts stays in
//! each engine's own tree-sitter facade, because this crate depends on no
//! grammar and must not start.
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
//! `evidence` are excluded from [`crate::schema::payload::ResultDigestInput`] by
//! P0 and must stay so, while `completeness` is inside it — so the agent and the
//! verifier are *required* to agree that a file was degraded, and the cross-OS
//! matrix proves they do on every leg.
//!
//! # The report of the degradation is never itself demoted
//!
//! Counting ERROR nodes over a tree full of ERROR nodes is an exact measurement,
//! not an approximate one, and capping *its* severity would silence the one
//! signal T3 wants loud — which is the evasion this whole apparatus exists to
//! catch. So [`demote`] is applied to numbers computed **over** a degraded tree
//! and never to the report of the degradation itself: not to
//! `static.parse-errors` and `static.parse-missing`, and not to
//! `tamper.parse-error-delta`.
//!
//! # A degraded result is worth something to whoever produced it
//!
//! Demotion caps severity, so *being degraded is a thing an attacker can want*.
//! The way to collect it is not to break a file inside the change under review —
//! that moves the parse-error delta — but to have broken it in an earlier change
//! nobody examined, and add the complexity now. At that second step the delta is
//! zero and every number from the file arrives `parse-degraded` and capped below
//! MED+. `andon-static-metrics`'s `tests/preseeded_degradation.rs` reproduces
//! it, including a route that needs no invalid syntax at all.
//!
//! Two consequences are recorded rather than left to be rediscovered:
//!
//! 1. The absolute per-file ERROR and MISSING counts are emitted whether or not
//!    a delta moved, so a delta-blind consumer has something to key on.
//! 2. Deciding what a long-degraded file is allowed to do to a *verdict* is
//!    P5a's, not an engine's. That is where the case of a tamper detector that
//!    fired on visible evidence inside a change that also contains a degraded
//!    file has to be settled: the flag and the magnitude survive demotion
//!    untouched and are digest-bound, and only the pre-policy severity is
//!    capped, so the information P5a needs is all in the record.

use crate::schema::enums::{Completeness, Severity};
use crate::schema::payload::MeasurementResult;

use serde::{Deserialize, Serialize};

/// How completely a parser understood a file.
///
/// Two counts rather than one because they mean different things. An `ERROR`
/// node is a region the parser could not fit to the grammar at all — it is the
/// hiding place. A `MISSING` node is a token the parser *inserted* to keep
/// going: the tree is structurally complete and one symbol of it was never
/// written. A file with three ERRORs and a file with three MISSINGs are not in
/// the same condition, and reporting their sum alone would say they were.
///
/// Serializable because the clone engine's incremental index stores one per
/// file: an entry is keyed by blob OID, so a carried-over health and a
/// recomputed one are equal by construction, and re-deriving it would mean
/// re-parsing every file the index exists to avoid re-parsing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, PartialOrd, Ord, Hash,
)]
pub struct ParseHealth {
    /// `ERROR` nodes in the tree.
    pub error_nodes: u64,
    /// `MISSING` nodes the parser inserted.
    pub missing_nodes: u64,
    /// Every node in the tree, named and anonymous. The denominator of the
    /// corpus ERROR-node rate; meaningless on its own, which is why it is not a
    /// reported metric.
    pub total_nodes: u64,
}

impl ParseHealth {
    /// Whether results from this parse must be demoted.
    ///
    /// One ERROR or one MISSING is enough. There is no tolerance band: a
    /// threshold here would be a number an evasion could sit underneath, and
    /// the demotion costs nothing but honesty — the number is still reported,
    /// it just stops being allowed to stop the line.
    pub fn is_degraded(self) -> bool {
        self.error_nodes > 0 || self.missing_nodes > 0
    }

    /// ERROR plus MISSING nodes as a fraction of all nodes.
    ///
    /// The corpus budget is expressed against this rather than against absolute
    /// counts, so adding a file to a pinned repository cannot fail the gate by
    /// arithmetic alone.
    pub fn error_rate(self) -> f64 {
        if self.total_nodes == 0 {
            return 0.0;
        }
        (self.error_nodes + self.missing_nodes) as f64 / self.total_nodes as f64
    }

    /// The health of two parses taken together.
    ///
    /// Saturating, because a result whose inputs overflowed a `u64` of nodes is
    /// not a result anyone is reading and wrapping to a small number would say
    /// the parse went well. Used where one result covers more than one file —
    /// a change-scoped aggregate, or a detector that read both sides of a diff.
    pub fn merge(self, other: ParseHealth) -> ParseHealth {
        ParseHealth {
            error_nodes: self.error_nodes.saturating_add(other.error_nodes),
            missing_nodes: self.missing_nodes.saturating_add(other.missing_nodes),
            total_nodes: self.total_nodes.saturating_add(other.total_nodes),
        }
    }
}

/// Opening words of the caveat added to a degraded result's evidence.
///
/// A constant so the test that pins the mechanism cannot pass against prose that
/// has quietly changed meaning.
pub const PARSE_DEGRADED_CAVEAT: &str =
    "anything at all, on this file: the parser did not understand";

/// Opening words of the caveat for a result that covers more than one file.
///
/// Separate prose rather than a reuse of [`PARSE_DEGRADED_CAVEAT`], because
/// "on this file" is false for a change-scoped number and a caveat that
/// misdescribes its own scope is worse than no caveat: it tells a reader to
/// distrust the wrong thing.
pub const PARSE_DEGRADED_SET_CAVEAT: &str =
    "anything at all, on the files behind this number: the parser did not understand";

/// The honesty line a degraded file-scoped result carries into
/// `does_not_predict`.
pub fn caveat(health: ParseHealth) -> String {
    format!(
        "{PARSE_DEGRADED_CAVEAT} all of it ({} ERROR, {} MISSING node(s)); \
         this number was computed over a partial tree",
        health.error_nodes, health.missing_nodes
    )
}

/// The honesty line for a result computed over a set of files, some degraded.
///
/// Names how many of how many, because "one file of ninety was unreadable" and
/// "eighty of ninety were" are the same `parse-degraded` to the digest and very
/// different things to a person deciding what to do about the number.
pub fn caveat_over_set(
    health: ParseHealth,
    degraded_files: usize,
    measured_files: usize,
) -> String {
    format!(
        "{PARSE_DEGRADED_SET_CAVEAT} all of them ({} ERROR, {} MISSING node(s) in \
         {degraded_files} of {measured_files} file(s) it covers); this number was computed \
         over a partial view",
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
    demote_with_caveat(result, health, caveat(health));
}

/// [`demote`], with the caveat supplied by the caller.
///
/// The primitive the other two are written in terms of. A result that covers a
/// set of files needs different words from one that covers a file, and the
/// wording is the only part that differs — keeping the mechanism single is what
/// stops a second demotion path from drifting into two of the three actors.
pub fn demote_with_caveat(result: &mut MeasurementResult, health: ParseHealth, caveat: String) {
    if !health.is_degraded() {
        return;
    }
    result.completeness = Completeness::ParseDegraded;
    result.severity = result
        .severity
        .min(severity_ceiling(Completeness::ParseDegraded));
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
    use crate::testing::sample_result;

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
    fn a_set_scoped_caveat_says_how_much_of_the_set_was_unreadable() {
        let mut result = a_result();
        demote_with_caveat(
            &mut result,
            degraded_health(),
            caveat_over_set(degraded_health(), 1, 9),
        );
        let line = &result.evidence.does_not_predict[0];
        assert!(line.contains(PARSE_DEGRADED_SET_CAVEAT), "{line}");
        assert!(line.contains("1 of 9 file(s)"), "{line}");
        // The file-scoped wording must not appear on a set-scoped result: it
        // would name a file the number is not about.
        assert!(!line.contains(PARSE_DEGRADED_CAVEAT), "{line}");
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

    #[test]
    fn merged_health_adds_up_and_a_clean_merge_stays_clean() {
        let clean = ParseHealth {
            error_nodes: 0,
            missing_nodes: 0,
            total_nodes: 40,
        };
        assert!(!clean.merge(ParseHealth::default()).is_degraded());
        let merged = clean.merge(degraded_health());
        assert!(merged.is_degraded());
        assert_eq!(merged.error_nodes, 2);
        assert_eq!(merged.missing_nodes, 1);
        assert_eq!(merged.total_nodes, 140);
    }

    #[test]
    fn the_error_rate_is_a_fraction_of_the_whole_tree() {
        assert_eq!(degraded_health().error_rate(), 0.03);
        assert_eq!(ParseHealth::default().error_rate(), 0.0);
    }
}
