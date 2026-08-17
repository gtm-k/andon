//! The cross-OS determinism probe's data model and its comparison rule.
//!
//! # What the matrix can honestly assert about this family, and what it cannot
//!
//! `MeasurementRegime::Process` binds `git_version`, because git's date-limited
//! traversal and its diff machinery are part of how these numbers were produced
//! (PLAN P4's regime requirement, and P0's schema). The three matrix runners
//! ship three different gits. So a naive "all legs must produce identical
//! digests" assertion is not merely strict, it is **wrong**: two legs at
//! different git versions are two regimes, and `andon_core::compare` stops at
//! step 2 with `unwitnessed-version-skew` before any digest is examined.
//!
//! PLAN P4 anticipated this — its matrix criterion says process and artifact
//! outputs join "where deterministic", unlike P2's and P3's unconditional
//! wording. So the comparison here has two halves, and both are assertions
//! rather than concessions:
//!
//! 1. **Within a regime group, every leg must be byte-identical.** This is the
//!    real determinism claim, and it is the one that catches a wall clock, a
//!    hash-map iteration order, or a platform `log2` reaching a value. The
//!    Linux agent leg and the Linux verifier leg are always in one group — same
//!    runner image, same git — so the agent-versus-verifier comparison that the
//!    trust kernel actually depends on is always exercised.
//! 2. **Across regime groups, the regimes must differ.** That is PREMORTEM S4's
//!    prevention line, demonstrated live: legs whose numbers were produced by
//!    different tooling are visibly incomparable rather than silently compared,
//!    which is what stops a version difference from being reported as tampering.
//!
//! A run where all three legs happen to ship the same git collapses to one group
//! and asserts the strong form. Neither outcome is a pass by default: an
//! identical *regime* with differing digests is a failure in either arrangement,
//! and that is the only thing this comparison can be asked to decide.

use std::collections::BTreeMap;

use andon_core::canonical;
use andon_core::schema::enums::Completeness;
use andon_core::schema::payload::{MeasurementResult, MetricValue, ScopeKind};
use andon_core::schema::regime::MeasurementRegime;
use serde::{Deserialize, Serialize};

/// One measured result, reduced to the fields a determinism comparison is about.
///
/// Deliberately not the whole [`MeasurementResult`]: `freshness.measured_at` is
/// a wall clock and `evidence.stale` moves with the calendar, and both differ
/// between honest legs by construction. They are outside `ResultDigestInput` for
/// the same reason, so a table built from them would be testing something the
/// product does not claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeRow {
    /// Which metric.
    pub metric_id: String,
    /// Granularity — `file` for a measured path, `change` for a truncation
    /// marker.
    pub scope_kind: ScopeKind,
    /// The path, where the result has one.
    pub path: Option<String>,
    /// The value, so a mismatch report can say what differed and not only that
    /// something did.
    pub value: MetricValue,
    /// Complete, partial, or unwitnessed.
    pub completeness: Completeness,
    /// The per-result digest — the thing under test.
    pub digest: String,
}

impl ProbeRow {
    /// Reduce a measured result to a row.
    pub fn from_result(result: &MeasurementResult) -> Self {
        ProbeRow {
            metric_id: result.metric_id.clone(),
            scope_kind: result.scope.kind,
            path: result.scope.path.clone(),
            value: result.value.clone(),
            completeness: result.completeness,
            digest: result.digest.clone(),
        }
    }

    /// Sort key: metric, then path. A stable order that is a property of the
    /// data rather than of enumeration.
    pub fn sort_key(&self) -> (String, String) {
        (
            self.metric_id.clone(),
            self.path.clone().unwrap_or_default(),
        )
    }
}

/// One leg's output: what it measured, under which regime.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegReport {
    /// Base of the measured change.
    pub base_oid: String,
    /// Head of the measured change.
    pub head_oid: String,
    /// The engine version, spec revision included.
    pub engine_version: String,
    /// The regime the numbers were produced under.
    pub regime: MeasurementRegime,
    /// How many paths the change touched.
    pub changed_paths: usize,
    /// Whether the window was truncated on this leg.
    pub truncated: bool,
    /// The rows, sorted.
    pub results: Vec<ProbeRow>,
}

impl LegReport {
    /// Build a report from a run's results.
    pub fn new(
        base_oid: String,
        head_oid: String,
        engine_version: String,
        regime: MeasurementRegime,
        changed_paths: usize,
        truncated: bool,
        results: &[MeasurementResult],
    ) -> Self {
        let mut rows: Vec<ProbeRow> = results.iter().map(ProbeRow::from_result).collect();
        rows.sort_by_key(ProbeRow::sort_key);
        LegReport {
            base_oid,
            head_oid,
            engine_version,
            regime,
            changed_paths,
            truncated,
            results: rows,
        }
    }

    /// The regime, as a stable grouping key.
    pub fn regime_key(&self) -> String {
        canonical::digest(&self.regime).unwrap_or_else(|_| format!("{:?}", self.regime))
    }
}

/// What the comparison found.
#[derive(Debug, Clone, Default)]
pub struct Comparison {
    /// Leg names grouped by regime, in a stable order.
    pub groups: Vec<(String, Vec<String>)>,
    /// Everything that fails the gate. Empty means green.
    pub failures: Vec<String>,
    /// Regime differences across groups. Expected, and reported so a reader can
    /// see *which* legs were skewed rather than inferring it from a pass.
    pub skews: Vec<String>,
}

/// Compare the legs. See the module docs for the rule.
pub fn compare_legs(legs: &[(String, LegReport)]) -> Comparison {
    let mut comparison = Comparison::default();
    if legs.is_empty() {
        comparison
            .failures
            .push("no legs were supplied, so nothing was compared".to_string());
        return comparison;
    }

    // Every leg must have measured the same change. A tuple difference means the
    // fixture, not the engine, differed between runners — and a green matrix
    // over two different changes would prove nothing at all.
    let (first_name, first) = &legs[0];
    for (name, leg) in legs {
        if leg.base_oid != first.base_oid || leg.head_oid != first.head_oid {
            comparison.failures.push(format!(
                "{name} measured ({}, {}) but {first_name} measured ({}, {}): the legs did not \
                 measure the same change",
                leg.base_oid, leg.head_oid, first.base_oid, first.head_oid
            ));
        }
        if leg.results.is_empty() {
            comparison.failures.push(format!(
                "{name} produced no results, so its digests prove nothing"
            ));
        }
        if leg.truncated {
            comparison.failures.push(format!(
                "{name} reported a truncated history window: the matrix fixture must be cloned \
                 with full history, or the process family measures nothing there"
            ));
        }
    }

    let mut grouped: BTreeMap<String, Vec<(&String, &LegReport)>> = BTreeMap::new();
    for (name, leg) in legs {
        grouped
            .entry(leg.regime_key())
            .or_default()
            .push((name, leg));
    }

    for (key, members) in &grouped {
        let (reference_name, reference) = members[0];
        for (name, leg) in members.iter().skip(1) {
            if leg.results != reference.results {
                comparison.failures.push(format!(
                    "{name} and {reference_name} share a measurement regime and disagree: {}",
                    describe_difference(&reference.results, &leg.results)
                ));
            }
        }
        comparison.groups.push((
            key.clone(),
            members.iter().map(|(name, _)| (*name).clone()).collect(),
        ));
    }

    if grouped.len() > 1 {
        for (key, members) in &grouped {
            let names: Vec<&str> = members.iter().map(|(n, _)| n.as_str()).collect();
            comparison.skews.push(format!(
                "regime {}: {} — {}",
                &key[..8.min(key.len())],
                names.join(", "),
                regime_summary(members[0].1)
            ));
        }
    }

    comparison
}

impl Comparison {
    /// Whether the gate passes.
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

fn regime_summary(leg: &LegReport) -> String {
    match &leg.regime {
        MeasurementRegime::Process {
            engine_version,
            git_version,
            history_window_days,
        } => format!("engine {engine_version}, {git_version}, window {history_window_days}d"),
        other => format!("{other:?}"),
    }
}

/// The first row that differs, named. A diff of two hundred digests is unusable;
/// the one row that moved is the whole finding.
fn describe_difference(reference: &[ProbeRow], other: &[ProbeRow]) -> String {
    for (a, b) in reference.iter().zip(other.iter()) {
        if a != b {
            return format!(
                "{} on {} — {:?}/{:?}/{} vs {:?}/{:?}/{}",
                a.metric_id,
                a.path.clone().unwrap_or_else(|| "<change>".to_string()),
                a.value,
                a.completeness,
                &a.digest[..8.min(a.digest.len())],
                b.value,
                b.completeness,
                &b.digest[..8.min(b.digest.len())],
            );
        }
    }
    format!(
        "different result counts: {} vs {}",
        reference.len(),
        other.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(metric: &str, digest: &str) -> ProbeRow {
        ProbeRow {
            metric_id: metric.to_string(),
            scope_kind: ScopeKind::File,
            path: Some("src/a.ts".to_string()),
            value: MetricValue::Count(4),
            completeness: Completeness::Complete,
            digest: digest.to_string(),
        }
    }

    fn leg(git_version: &str, rows: Vec<ProbeRow>) -> LegReport {
        LegReport {
            base_oid: "1".repeat(40),
            head_oid: "2".repeat(40),
            engine_version: "0.1.0+p4-process-1".to_string(),
            regime: MeasurementRegime::Process {
                engine_version: "0.1.0+p4-process-1".to_string(),
                git_version: git_version.to_string(),
                history_window_days: 365,
            },
            changed_paths: 1,
            truncated: false,
            results: rows,
        }
    }

    #[test]
    fn legs_at_one_regime_must_agree() {
        let comparison = compare_legs(&[
            ("linux".to_string(), leg("2.43.0", vec![row("m", "aa")])),
            ("verifier".to_string(), leg("2.43.0", vec![row("m", "aa")])),
        ]);
        assert!(comparison.passed(), "{:?}", comparison.failures);
        assert_eq!(comparison.groups.len(), 1);
        assert!(comparison.skews.is_empty());
    }

    #[test]
    fn a_disagreement_inside_one_regime_fails_the_gate() {
        // The failure this whole workflow exists to catch.
        let comparison = compare_legs(&[
            ("linux".to_string(), leg("2.43.0", vec![row("m", "aa")])),
            ("verifier".to_string(), leg("2.43.0", vec![row("m", "bb")])),
        ]);
        assert!(!comparison.passed());
        assert!(comparison.failures[0].contains("share a measurement regime and disagree"));
    }

    #[test]
    fn two_git_versions_are_two_regimes_and_are_not_compared() {
        // Not a pass by default: the digests below differ, and that is correct
        // rather than concealed, because the two legs measured under different
        // tooling and `compare` would say `unwitnessed-version-skew`.
        let comparison = compare_legs(&[
            ("linux".to_string(), leg("2.43.0", vec![row("m", "aa")])),
            ("macos".to_string(), leg("2.39.3", vec![row("m", "bb")])),
        ]);
        assert!(comparison.passed());
        assert_eq!(comparison.groups.len(), 2);
        assert_eq!(comparison.skews.len(), 2);
    }

    #[test]
    fn a_leg_that_measured_a_different_change_fails_before_any_digest_is_read() {
        let mut other = leg("2.43.0", vec![row("m", "aa")]);
        other.head_oid = "9".repeat(40);
        let comparison = compare_legs(&[
            ("linux".to_string(), leg("2.43.0", vec![row("m", "aa")])),
            ("macos".to_string(), other),
        ]);
        assert!(!comparison.passed());
        assert!(comparison.failures[0].contains("did not measure the same change"));
    }

    #[test]
    fn a_truncated_leg_fails_rather_than_passing_vacuously() {
        // A shallow clone emits change-scoped markers, and two shallow legs
        // agree with each other perfectly. Green on markers that say nothing was
        // measured is the vacuous pass this check exists to refuse.
        let mut truncated = leg("2.43.0", vec![row("m", "aa")]);
        truncated.truncated = true;
        let comparison = compare_legs(&[("linux".to_string(), truncated)]);
        assert!(!comparison.passed());
        assert!(comparison.failures[0].contains("truncated"));
    }

    #[test]
    fn a_leg_with_no_results_fails_rather_than_passing_vacuously() {
        let comparison = compare_legs(&[("linux".to_string(), leg("2.43.0", Vec::new()))]);
        assert!(!comparison.passed());
        assert!(comparison.failures[0].contains("no results"));
    }
}
