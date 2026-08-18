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
//! and both cite a `language = "any"` claim. Four metrics share the parse-health
//! claim, which the lint permits and which is correct here: they are four views
//! of one instrument, not four predictions.

use std::collections::BTreeMap;

use andon_core::engine::MetricDescriptor;
use andon_core::schema::enums::{MetricClass, Severity};
use andon_core::verdict::ladder::{Rung, SeverityLadder, Threshold};

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
/// One named file the static family should have measured and could not.
pub const METRIC_UNMEASURED_FILE: &str = "static.unmeasured-file";

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
        MetricDescriptor {
            metric_id: METRIC_UNMEASURED_FILE.to_string(),
            claim_id: CLAIM_PARSE_HEALTH.to_string(),
            // Diff-actionable, unlike the change-scope count beside it: this one
            // names a specific file in the change, and a file the change made
            // unreadable is the change's to fix.
            class: MetricClass::DiffActionable,
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

/// Cyclomatic complexity, in the units the claim is scoped to.
///
/// The claim's outcome is `minimum-test-paths`: the number is the count of
/// linearly independent paths through a function, which is the floor on how many
/// test cases can cover it. The rungs rank that floor, and nothing else — the
/// claim's own `does_not_predict` rules out reading them as defect density,
/// comprehension time, or maintenance effort.
///
/// **The boundaries are the conventional McCabe bands (11, 21, 51), adopted as
/// tool convention and not as a finding.** The cited paper (Landman et al. 2016)
/// establishes that the metric is not redundant with size at method level; it
/// does not publish a risk table, and no threshold here should be read as
/// carrying its authority. What the rungs are is a declaration of how loud this
/// engine is willing to be about a function needing eleven, twenty-one, or
/// fifty-one test paths.
const CYCLOMATIC: &[Rung] = &[
    Rung {
        at: Threshold::Count(11),
        severity: Severity::Medium,
    },
    Rung {
        at: Threshold::Count(21),
        severity: Severity::High,
    },
    Rung {
        at: Threshold::Count(51),
        severity: Severity::Critical,
    },
];

/// Cognitive complexity, in the units the claim is scoped to.
///
/// The claim's outcome is `comprehension-time`, validated by the cited
/// meta-analysis against how long humans take to understand a snippet. The rungs
/// rank how far into that scale a function has gone.
///
/// **15 is the SonarSource implementation's default threshold — a tool default,
/// not a result from the literature — and 25 and 50 are project-declared
/// extensions of it.** The meta-analysis reports a correlation, not a cut point.
/// Recorded here rather than in the registry because a threshold is a judgement
/// about loudness and the registry is for what the evidence says.
const COGNITIVE: &[Rung] = &[
    Rung {
        at: Threshold::Count(15),
        severity: Severity::Medium,
    },
    Rung {
        at: Threshold::Count(25),
        severity: Severity::High,
    },
    Rung {
        at: Threshold::Count(50),
        severity: Severity::Critical,
    },
];

/// How each metric's own number becomes a pre-policy severity.
///
/// One entry per [`descriptors`] entry, and the only place this engine states a
/// severity: `crate::engine`'s result constructor writes the `Info` floor and
/// `andon_core::engine::run_engine` assigns from here on the way out.
///
/// Three of the five unsuffixed metrics decline to rank themselves, each for its
/// own reason rather than by omission:
///
/// - **`static.sloc`** is a control variable, never a target. It is already
///   `context-informational` for the reason `metric-families.csv` gives — almost
///   every sophisticated metric is partly re-measuring it — and a severity
///   ladder over a line count is an instruction to an agent to delete lines.
/// - **`static.parse-errors` and `static.parse-missing`** are the *report of* a
///   degradation. Ranking the report is the mistake `andon_core::parse_health`
///   names: these counts are exact, they must stay loud, and the question of
///   whether a rise in them is an evasion belongs to `tamper.parse-error-delta`,
///   which is the detector written for it.
/// - **`static.unmeasured-files`** counts what the per-file markers name. The
///   markers carry `completeness: unwitnessed` and so cap below MED+ whatever
///   they say; ranking the count as well would be the same fact twice.
pub fn severity_ladders() -> BTreeMap<String, SeverityLadder> {
    let mut ladders: BTreeMap<String, SeverityLadder> = [
        (METRIC_SLOC, SeverityLadder::NoOpinion),
        (METRIC_PARSE_ERRORS, SeverityLadder::NoOpinion),
        (METRIC_PARSE_MISSING, SeverityLadder::NoOpinion),
        (METRIC_UNMEASURED_FILES, SeverityLadder::NoOpinion),
        (METRIC_UNMEASURED_FILE, SeverityLadder::NoOpinion),
    ]
    .into_iter()
    .map(|(id, ladder)| (id.to_string(), ladder))
    .collect();
    for language in complexity_languages() {
        ladders.insert(
            cyclomatic_metric_id(language),
            SeverityLadder::Thresholds(CYCLOMATIC),
        );
        ladders.insert(
            cognitive_metric_id(language),
            SeverityLadder::Thresholds(COGNITIVE),
        );
    }
    ladders
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
        assert_eq!(sharing, 4);
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
    fn every_declared_metric_declares_a_ladder_and_nothing_else_does() {
        // The drift this pairs against: a metric added to `descriptors()` and
        // forgotten here reaches `run_engine` with no declaration and is refused
        // at the boundary — but only if it is ever emitted. This fails at build
        // time instead.
        let declared: BTreeSet<String> = descriptors().into_iter().map(|d| d.metric_id).collect();
        let ranked: BTreeSet<String> = severity_ladders().into_keys().collect();
        assert_eq!(declared, ranked);
    }

    #[test]
    fn the_complexity_ladders_are_the_only_route_to_the_med_plus_band() {
        // The shipped fact this engine is responsible for, and the one the whole
        // repair round turns on: under the default policy `static` is the only
        // family that can reach MED+ at all, and inside it only these six
        // metrics can. A ladder quietly reduced to `NoOpinion` would take the
        // band away from the entire tool.
        let reaching: BTreeSet<String> = severity_ladders()
            .into_iter()
            .filter(|(_, ladder)| ladder.strongest().is_med_plus())
            .map(|(id, _)| id)
            .collect();
        let expected: BTreeSet<String> = complexity_languages()
            .into_iter()
            .flat_map(|l| [cyclomatic_metric_id(l), cognitive_metric_id(l)])
            .collect();
        assert_eq!(reaching, expected);
    }

    #[test]
    fn a_line_count_is_never_ranked() {
        // Size as a target is PREMORTEM A4's uninstall loop with the tool's own
        // name on it: an agent told that 400 lines is `High` deletes lines.
        assert_eq!(
            severity_ladders().get(METRIC_SLOC),
            Some(&SeverityLadder::NoOpinion)
        );
    }

    #[test]
    fn the_parse_health_counts_are_never_ranked() {
        // `andon_core::parse_health`: the report of a degradation is exact and
        // must stay loud. Whether a rise in it is an evasion is
        // `tamper.parse-error-delta`'s question, and answering it twice in two
        // engines is how the two answers start to disagree.
        for metric in [METRIC_PARSE_ERRORS, METRIC_PARSE_MISSING] {
            assert_eq!(
                severity_ladders().get(metric),
                Some(&SeverityLadder::NoOpinion),
                "{metric}"
            );
        }
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
