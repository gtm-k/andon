//! The metrics this engine emits, and the claims they stand on.
//!
//! # Why complexity metric ids carry a language
//!
//! `registry/README.md` illustrates the registry with a single
//! `static.cognitive-complexity` citing a TypeScript claim. That illustration
//! cannot survive contact with three languages: a metric declaration maps to
//! exactly **one** `claim_id`, and the evidence for cognitive complexity is
//! claim-scoped — `implementation@version|language|outcome` — because
//! PRE-DECISIONS bars family-wide claims. One id citing one language's claim
//! while emitting numbers for three would be precisely the overstatement the
//! registry exists to prevent.
//!
//! So the ids are language-suffixed: `static.cognitive-complexity.python` cites
//! the Python claim and nothing else. The cost is three ids where a reader might
//! expect one; the benefit is that a consumer can see, from the metric id alone,
//! which claim a number is standing on.
//!
//! Size and parse health are not suffixed. Both are language-agnostic by
//! construction — a source line is a line, and an ERROR node is an ERROR node —
//! and both cite a `language = "any"` claim. Three metrics share the parse-health
//! claim, which the lint permits and which is correct here: they are three views
//! of one instrument, not three predictions.

use andon_core::engine::MetricDescriptor;
use andon_core::schema::enums::MetricClass;

use crate::lang::Language;

/// Engine id. Matches the `engine` field of `registry/static.toml` and the
/// crate directory name.
pub const ENGINE_ID: &str = "static-metrics";

/// Source lines of code. File scope and function scope.
pub const METRIC_SLOC: &str = "static.sloc";
/// `ERROR` nodes in a file's parse tree.
pub const METRIC_PARSE_ERRORS: &str = "static.parse-errors";
/// `MISSING` nodes the parser inserted.
pub const METRIC_PARSE_MISSING: &str = "static.parse-missing";
/// Changed files the static family should have measured and could not.
pub const METRIC_UNMEASURED_FILES: &str = "static.unmeasured-files";

/// Claim behind [`METRIC_SLOC`].
pub const CLAIM_SLOC: &str = "andon.static.sloc@1|any|maintenance-effort";
/// Claim behind the three parse-health metrics.
pub const CLAIM_PARSE_HEALTH: &str = "andon.static.parse-health@1|any|parse-completeness";

/// Metric id for cyclomatic complexity in a language.
pub fn cyclomatic_metric_id(language: Language) -> String {
    format!("static.cyclomatic-complexity.{}", language.claim_language())
}

/// Metric id for cognitive complexity in a language.
pub fn cognitive_metric_id(language: Language) -> String {
    format!("static.cognitive-complexity.{}", language.claim_language())
}

/// Claim id for cyclomatic complexity in a language.
pub fn cyclomatic_claim_id(language: Language) -> String {
    format!(
        "andon.static.cyclomatic@1|{}|minimum-test-paths",
        language.claim_language()
    )
}

/// Claim id for cognitive complexity in a language.
pub fn cognitive_claim_id(language: Language) -> String {
    format!(
        "andon.static.cognitive@1|{}|comprehension-time",
        language.claim_language()
    )
}

/// The languages that carry complexity claims: the parsed tier.
///
/// TSX is absent because it shares TypeScript's claim — `claim_language`
/// collapses the two — and a second declaration of the same id would fail the
/// lint's duplicate check.
pub fn complexity_languages() -> [Language; 3] {
    [Language::TypeScript, Language::JavaScript, Language::Python]
}

/// Every metric this engine can emit.
///
/// The order is stable and the registry file lists them in the same order, which
/// is what makes a diff of either readable. `Registry::check_engine` compares the
/// two as sets, so order is a courtesy rather than a contract — but an engine
/// whose declaration order drifts produces diffs nobody reads.
pub fn descriptors() -> Vec<MetricDescriptor> {
    let mut descriptors = vec![
        MetricDescriptor {
            metric_id: METRIC_SLOC.to_string(),
            claim_id: CLAIM_SLOC.to_string(),
            // Size is a control variable, never a target: `metric-families.csv`
            // is explicit that almost every "sophisticated" metric is partly
            // re-measuring it. An agent asked to reduce a line count optimizes
            // the confound (PREMORTEM A4).
            class: MetricClass::ContextInformational,
            deterministic: true,
        },
        MetricDescriptor {
            metric_id: METRIC_PARSE_ERRORS.to_string(),
            claim_id: CLAIM_PARSE_HEALTH.to_string(),
            // Diff-actionable, and deliberately: a file the change made
            // unparsable is the agent's to fix, and it is the T3 evasion route.
            // This is the one static metric that must be allowed to reach MED+
            // on a degraded file — see `crate::health`.
            class: MetricClass::DiffActionable,
            deterministic: true,
        },
        MetricDescriptor {
            metric_id: METRIC_PARSE_MISSING.to_string(),
            claim_id: CLAIM_PARSE_HEALTH.to_string(),
            class: MetricClass::DiffActionable,
            deterministic: true,
        },
        MetricDescriptor {
            metric_id: METRIC_UNMEASURED_FILES.to_string(),
            claim_id: CLAIM_PARSE_HEALTH.to_string(),
            // A file this engine could not read is usually a fact about the
            // repository, not about the change. It is reported so the undercount
            // is visible; it is not something to block on.
            class: MetricClass::ContextInformational,
            deterministic: true,
        },
    ];
    for language in complexity_languages() {
        descriptors.push(MetricDescriptor {
            metric_id: cyclomatic_metric_id(language),
            claim_id: cyclomatic_claim_id(language),
            class: MetricClass::DiffActionable,
            deterministic: true,
        });
    }
    for language in complexity_languages() {
        descriptors.push(MetricDescriptor {
            metric_id: cognitive_metric_id(language),
            claim_id: cognitive_claim_id(language),
            class: MetricClass::DiffActionable,
            deterministic: true,
        });
    }
    descriptors
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_metric_id_is_distinct() {
        let declared = descriptors();
        let ids: BTreeSet<&str> = declared.iter().map(|d| d.metric_id.as_str()).collect();
        assert_eq!(ids.len(), declared.len());
    }

    #[test]
    fn tsx_shares_typescripts_ids_rather_than_declaring_its_own() {
        assert_eq!(
            cognitive_metric_id(Language::Tsx),
            cognitive_metric_id(Language::TypeScript)
        );
        assert_eq!(
            cyclomatic_claim_id(Language::Tsx),
            cyclomatic_claim_id(Language::TypeScript)
        );
        assert!(!complexity_languages().contains(&Language::Tsx));
    }

    #[test]
    fn the_three_parse_health_metrics_share_one_claim() {
        // Three views of one instrument, not three predictions. The lint permits
        // it; the budget of 24 makes it worth doing.
        let sharing = descriptors()
            .into_iter()
            .filter(|d| d.claim_id == CLAIM_PARSE_HEALTH)
            .count();
        assert_eq!(sharing, 3);
    }

    #[test]
    fn every_metric_is_in_the_digest_compare_set() {
        // Nothing here is seeded or timing-dependent: the inputs are blob bytes
        // and a pinned grammar. A `false` would be a claim that some static
        // number cannot be reproduced, which would need explaining.
        assert!(descriptors().iter().all(|d| d.deterministic));
    }

    #[test]
    fn size_never_becomes_a_target() {
        let sloc = descriptors()
            .into_iter()
            .find(|d| d.metric_id == METRIC_SLOC)
            .expect("sloc is declared");
        assert_eq!(sloc.class, MetricClass::ContextInformational);
    }

    #[test]
    fn claim_ids_are_canonical_tuples() {
        // `implementation@version|language|outcome`, which the lint re-derives
        // and rejects on mismatch. Asserted here so a typo fails in the crate's
        // own tests rather than only in the lint job.
        for language in complexity_languages() {
            for claim in [cyclomatic_claim_id(language), cognitive_claim_id(language)] {
                let (implementation, rest) = claim.split_once('@').expect("has a version");
                let parts: Vec<&str> = rest.split('|').collect();
                assert!(implementation.starts_with("andon.static."), "{claim}");
                assert_eq!(parts.len(), 3, "{claim}");
                assert_eq!(parts[1], language.claim_language(), "{claim}");
            }
        }
    }
}
