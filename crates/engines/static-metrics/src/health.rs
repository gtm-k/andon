//! What a degraded parse does to a number (PREMORTEM T3).
//!
//! # This is now the contract crate's rule, and this module is the path to it
//!
//! The three-way demotion was written here, for the first engine that held a
//! grammar. The wave-1 integration converged the tree-sitter pins across static
//! metrics, clones, and the tamper suite, which means the *same* half-understood
//! file is now reachable by all three — and a demotion rule carried separately
//! by three crates is three rules that agree until one of them is edited. It
//! writes `completeness`, which is inside the per-result digest input, so two
//! engines disagreeing about whether a file was degraded is a disagreement the
//! verifier reads as tampering.
//!
//! So the mechanism moved to [`andon_core::parse_health`] unchanged — the three
//! demotions, the caveat prose, the ceiling, and the ordering — and this module
//! re-exports it. The docs that explain *why* it is three mechanisms for three
//! actors are there, on the definition.
//!
//! # What stayed here, because it is this engine's
//!
//! ## Consumer warning: pre-seeded degradation
//!
//! Demotion caps severity, so *being degraded is worth something to an
//! attacker*. The way to collect it is not to break a file inside the change
//! under review — that moves the parse-error delta — but to have broken it in an
//! earlier change nobody examined, and add the complexity now:
//!
//! 1. land a file with one unparsable region, in a change too small to look at;
//! 2. later, add whatever you like to that file.
//!
//! At step 2 the parse-error **delta is zero** and every number from the file
//! arrives `parse-degraded` and capped below MED+. A consumer keyed on deltas
//! alone sees nothing. `tests/preseeded_degradation.rs` reproduces it, including
//! a route that needs no invalid syntax at all: `tree-sitter-python` gives up
//! past [`crate::lang::INDENT_STACK_LIMIT_PYTHON`] levels of indentation, so a
//! Python file can be degraded with whitespace.
//!
//! What this engine owes is evidence a delta-blind consumer can key on, and it
//! provides it: the **absolute** per-file ERROR and MISSING counts are emitted
//! for every parsed file, path-attributed, whether or not the delta moved — a
//! zero included, so "no errors" is distinguishable from "not reported". The
//! rest of the answer is not this engine's: keying a detector on absolutes as
//! well as deltas belongs to P3's tamper suite, where
//! `tamper.parse-error-delta`'s state arm now does it, and deciding what a
//! long-degraded file is allowed to do to a verdict belongs to P5a's policy.
//! Named here because a warning that lives only in a review comment is a warning
//! that expires with the review.
//!
//! ## The parse-health metrics are not themselves demoted
//!
//! `static.parse-errors` and `static.parse-missing` report the degradation.
//! Counting ERROR nodes over a tree full of ERROR nodes is an exact measurement,
//! not an approximate one — and capping *its* severity would silence the one
//! signal T3 wants loud, which is the evasion this whole apparatus exists to
//! catch. So [`demote`] is applied to numbers computed **over** a degraded tree
//! and never to the report of the degradation itself. The clone and tamper
//! engines follow the same rule for their own equivalents.

pub use andon_core::parse_health::{
    caveat, demote, severity_ceiling, weakest, weakness_rank, PARSE_DEGRADED_CAVEAT,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{parse, ParseHealth};
    use andon_core::schema::enums::{Completeness, Severity};
    use andon_core::testing::sample_result;

    /// The demotion tests live on the definition in `andon-core`. What is worth
    /// asserting *here* is the join the contract crate cannot make: that a real
    /// parse of a real file, through this crate's parser, produces health that
    /// this crate's path demotes on. A re-export that pointed somewhere else, or
    /// a parser that stopped reporting faults, fails here.
    #[test]
    fn a_real_degraded_parse_demotes_through_this_path() {
        let parsed = parse(crate::lang::Language::TypeScript, b"function f( { !!! \n")
            .expect("tree-sitter recovers from anything and still returns a tree");
        assert!(parsed.health.is_degraded(), "{:?}", parsed.health);

        let mut result = sample_result();
        result.severity = Severity::Critical;
        result.completeness = Completeness::Complete;
        demote(&mut result, parsed.health);

        assert_eq!(result.completeness, Completeness::ParseDegraded);
        assert!(!result.severity.is_med_plus(), "{:?}", result.severity);
        assert!(
            result.evidence.does_not_predict[0].contains(PARSE_DEGRADED_CAVEAT),
            "{:?}",
            result.evidence.does_not_predict
        );
    }

    #[test]
    fn a_real_clean_parse_demotes_nothing() {
        let parsed = parse(
            crate::lang::Language::TypeScript,
            b"export const x: number = 1;\n",
        )
        .expect("clean TypeScript parses");
        assert_eq!(parsed.health.error_nodes, 0);
        assert_eq!(parsed.health.missing_nodes, 0);

        let mut result = sample_result();
        let before = result.clone();
        demote(&mut result, parsed.health);
        assert_eq!(result, before);
    }

    #[test]
    fn the_ceiling_this_crate_exports_is_the_contract_crates() {
        // `severity_ceiling` is what P5a applies after policy, and the path P2
        // documented is this one. A re-export that shadowed it with a local
        // copy would pass every other test in this crate.
        assert_eq!(
            severity_ceiling(Completeness::ParseDegraded),
            andon_core::parse_health::severity_ceiling(Completeness::ParseDegraded)
        );
        assert_eq!(weakness_rank(Completeness::ParseDegraded), 2);
        assert!(caveat(ParseHealth::default()).contains(PARSE_DEGRADED_CAVEAT));
    }
}
