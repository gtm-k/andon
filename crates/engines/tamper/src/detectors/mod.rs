//! The seven detectors, and the contract they share.
//!
//! PLAN.md P3: six gaming detectors from the metric catalogue plus the
//! parse-error delta of PREMORTEM T3. Each answers one question about a change,
//! each is a pure function of the bytes on both sides, and each is measured
//! against a frozen corpus with an ex-ante precision and recall floor.
//!
//! | Detector | Signal | Fires when |
//! |---|---|---|
//! | [`test_removal`] | `test-removal` | the change has fewer tests than it started with, or newly skips some |
//! | [`suppression_density`] | `suppression-density` | linter suppressions rise, both in count and in density |
//! | [`assertion_free_test`] | `assertion-free-test` | a test is added or edited into one that asserts nothing |
//! | [`coverage_exclusion_drift`] | `coverage-exclusion-drift` | a coverage configuration excludes more than it did |
//! | [`threshold_config_edit`] | `threshold-config-edit` | a quality threshold in tool config is loosened |
//! | [`lookup_table_blowup`] | `lookup-table-blowup` | a large literal table appears inside logic |
//! | [`parse_error_delta`] | `parse-error-delta` | more of the change is unparseable than was before |
//!
//! # Net, not per-file
//!
//! Every detector reads the whole [`ChangeView`]. The honest answers are net
//! answers: tests moved between files are not tests deleted, and a suppression
//! added here while two are dropped there is not a rising suppression density.
//! Per-file detectors would fire on refactorings, which is the false-positive
//! class the should-pass corpus exists to catch (PLAN B5/B6).
//!
//! # Firing is not accusing
//!
//! A detector reports what it saw; policy decides what it is worth, from the
//! base commit, in the verifier. In particular
//! [`threshold_config_edit`] is advisory by PLAN round-1 B6 — legitimate policy
//! evolution must not be blocked — and says so in its severity.

use crate::change::ChangeView;
use andon_core::schema::enums::{Severity, TamperSignal};

pub mod assertion_free_test;
pub mod coverage_exclusion_drift;
pub mod lookup_table_blowup;
pub mod parse_error_delta;
pub mod suppression_density;
pub mod test_removal;
pub mod threshold_config_edit;

/// One thing a detector saw.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// Path the finding is about.
    pub path: String,
    /// 1-based line, where the finding has one.
    pub line: Option<u32>,
    /// What was seen, in the detector's own words.
    pub detail: String,
}

impl Finding {
    /// A finding with a line.
    pub fn at(path: &str, line: u32, detail: impl Into<String>) -> Finding {
        Finding {
            path: path.to_string(),
            line: Some(line),
            detail: detail.into(),
        }
    }

    /// A finding about a file as a whole.
    pub fn in_file(path: &str, detail: impl Into<String>) -> Finding {
        Finding {
            path: path.to_string(),
            line: None,
            detail: detail.into(),
        }
    }
}

/// What a detector concluded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    /// Whether the signal fired.
    pub fired: bool,
    /// How much, in the detector's own units. Signed, because several of these
    /// are deltas and a negative one — suppressions removed, parse errors fixed
    /// — is worth reporting rather than clamping to zero.
    pub magnitude: i64,
    /// What was seen, sorted.
    pub findings: Vec<Finding>,
}

impl Outcome {
    /// A quiet detector.
    pub fn quiet(magnitude: i64) -> Outcome {
        Outcome {
            fired: false,
            magnitude,
            findings: Vec::new(),
        }
    }

    /// A detector that fired.
    pub fn fired(magnitude: i64, mut findings: Vec<Finding>) -> Outcome {
        findings.sort();
        Outcome {
            fired: true,
            magnitude,
            findings,
        }
    }
}

/// One detector.
pub trait Detector: Sync {
    /// The tamper-signal vocabulary entry this detector raises. P0 owns the
    /// enum; the mapping here is one-to-one so P5a's verdict assembly needs no
    /// translation table.
    fn signal(&self) -> TamperSignal;

    /// The metric id of the fired/not-fired flag.
    fn metric_id(&self) -> &'static str;

    /// The metric id of the magnitude.
    fn magnitude_metric_id(&self) -> &'static str;

    /// One line saying what this detector looks for, shown in reports.
    fn describes(&self) -> &'static str;

    /// How serious a firing is, before policy.
    ///
    /// `High` for the six that describe evidence being removed; `Low` for the
    /// threshold edit, which PLAN round-1 B6 makes advisory because a project
    /// that cannot change its own thresholds is a project the tool has broken.
    fn severity_when_fired(&self) -> Severity {
        Severity::High
    }

    /// Run it.
    fn run(&self, change: &ChangeView) -> Outcome;
}

/// Every detector, in a fixed order.
///
/// The order is the report order and the metric order, so it is defined here
/// once rather than emerging from a directory listing.
pub fn all() -> Vec<&'static dyn Detector> {
    vec![
        &test_removal::TestRemoval,
        &suppression_density::SuppressionDensity,
        &assertion_free_test::AssertionFreeTest,
        &coverage_exclusion_drift::CoverageExclusionDrift,
        &threshold_config_edit::ThresholdConfigEdit,
        &lookup_table_blowup::LookupTableBlowup,
        &parse_error_delta::ParseErrorDelta,
    ]
}

/// A detector by the name its corpus cases use — the tamper-signal spelling.
pub fn by_signal(signal: &str) -> Option<&'static dyn Detector> {
    all()
        .into_iter()
        .find(|d| signal_name(d.signal()) == signal)
}

/// The kebab-case wire spelling of a tamper signal, as P0's enum serializes it.
pub fn signal_name(signal: TamperSignal) -> &'static str {
    match signal {
        TamperSignal::SuppressionDensity => "suppression-density",
        TamperSignal::TestRemoval => "test-removal",
        TamperSignal::CoverageExclusionDrift => "coverage-exclusion-drift",
        TamperSignal::AssertionFreeTest => "assertion-free-test",
        TamperSignal::ThresholdConfigEdit => "threshold-config-edit",
        TamperSignal::LookupTableBlowup => "lookup-table-blowup",
        TamperSignal::ParseErrorDelta => "parse-error-delta",
        TamperSignal::BaseFabrication => "base-fabrication",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_are_seven_and_they_are_distinct() {
        let detectors = all();
        assert_eq!(detectors.len(), 7, "PLAN P3 specifies seven detectors");
        let mut signals: Vec<&str> = detectors.iter().map(|d| signal_name(d.signal())).collect();
        signals.sort_unstable();
        signals.dedup();
        assert_eq!(signals.len(), 7, "two detectors share a signal");
        let mut metrics: Vec<&str> = detectors
            .iter()
            .flat_map(|d| [d.metric_id(), d.magnitude_metric_id()])
            .collect();
        metrics.sort_unstable();
        metrics.dedup();
        assert_eq!(metrics.len(), 14, "two detectors share a metric id");
    }

    #[test]
    fn base_fabrication_is_not_one_of_ours() {
        // It is raised by the attest lane when a record claims a base that is
        // not an ancestor (PLAN R2-4), not by anything that reads content.
        assert!(all()
            .iter()
            .all(|d| d.signal() != TamperSignal::BaseFabrication));
        assert!(by_signal("base-fabrication").is_none());
    }

    #[test]
    fn every_detector_is_reachable_by_its_signal_name() {
        for detector in all() {
            let name = signal_name(detector.signal());
            assert_eq!(
                by_signal(name).map(|d| d.metric_id()),
                Some(detector.metric_id()),
                "{name} does not round-trip"
            );
        }
    }

    #[test]
    fn an_empty_change_fires_nothing() {
        let empty = ChangeView::default();
        for detector in all() {
            let outcome = detector.run(&empty);
            assert!(
                !outcome.fired,
                "{} fired on an empty change",
                detector.metric_id()
            );
            assert_eq!(outcome.magnitude, 0);
        }
    }
}
