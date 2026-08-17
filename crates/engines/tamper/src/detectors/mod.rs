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
//! # Three of them can be blinded, and say so
//!
//! `test_removal`, `assertion_free_test` and `lookup_table_blowup` read trees;
//! the rest read bytes. A file the parser could not finish is therefore a
//! partial view for exactly three of the seven, and each of those carries the
//! health of what it read in [`Outcome::view_health`], which the engine turns
//! into `completeness: parse-degraded` on that detector's two results. A firing
//! over a partial view is a lower bound and a silence is not evidence of
//! absence; `tests/parse_degraded_view.rs` measures one such silence against the
//! same deletion in a file that parses.
//!
//! # Firing is not accusing
//!
//! A detector reports what it saw; policy decides what it is worth, from the
//! base commit, in the verifier. In particular
//! [`threshold_config_edit`] is advisory by PLAN round-1 B6 — legitimate policy
//! evolution must not be blocked — and says so in its severity.

use crate::change::ChangeView;
use andon_core::parse_health::ParseHealth;
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
    /// Severity for *this* firing, where it differs from the detector's
    /// default.
    ///
    /// One detector needs two strengths. `parse-error-delta` fires hard when
    /// faults rose in this change and softly when a changed file was already
    /// degraded and stayed that way — the second is a real signal and a weak
    /// accusation, because an honest legacy file and a parked-error evasion are
    /// the same bytes. Keeping both under one signal rather than inventing an
    /// eighth is deliberate: `TamperSignal` is P0-owned schema.
    pub severity: Option<Severity>,
    /// How completely the parser read *what this detector looked at*.
    ///
    /// # Why the detector reports it and not the engine
    ///
    /// Three of the seven parse: [`test_removal`] and [`assertion_free_test`]
    /// read test files, [`lookup_table_blowup`] reads the rest of the source.
    /// The other three read bytes — suppression markers, coverage config,
    /// threshold config — and an ERROR node hides nothing from them. Marking all
    /// seven because one file in the change was unparseable would put a caveat
    /// on results a parse failure cannot touch, which is over-claiming a
    /// limitation rather than disclosing one.
    ///
    /// So the scope is per detector, and the only place that knows which files a
    /// detector read is the detector, while it reads them. Accumulated from the
    /// `Parsed` values `run` already builds — not recomputed from the change
    /// afterwards, which would be a second file filter to keep in step with the
    /// first, and a second parse of every file in a crate that has already had
    /// per-file cost turn into a denial of measurement.
    ///
    /// Left at its default by the four that do not parse, and deliberately by
    /// [`parse_error_delta`]: it *reports* the degradation, and a report of a
    /// blind spot demoted by the blind spot it reports is the one signal T3
    /// wants loud, silenced by its own finding.
    pub view_health: ParseHealth,
}

impl Outcome {
    /// A quiet detector.
    pub fn quiet(magnitude: i64) -> Outcome {
        Outcome {
            fired: false,
            magnitude,
            findings: Vec::new(),
            severity: None,
            view_health: ParseHealth::default(),
        }
    }

    /// A detector that fired, at its default severity.
    pub fn fired(magnitude: i64, mut findings: Vec<Finding>) -> Outcome {
        findings.sort();
        Outcome {
            fired: true,
            magnitude,
            findings,
            severity: None,
            view_health: ParseHealth::default(),
        }
    }

    /// A detector that fired at a severity other than its default.
    pub fn fired_at(severity: Severity, magnitude: i64, mut findings: Vec<Finding>) -> Outcome {
        findings.sort();
        Outcome {
            fired: true,
            magnitude,
            findings,
            severity: Some(severity),
            view_health: ParseHealth::default(),
        }
    }

    /// Record how completely the parser read what this detector looked at.
    ///
    /// A builder rather than a fourth constructor, because it applies equally to
    /// a firing and to a silence — and the silence is the case that matters. A
    /// detector that saw a partial tree and found nothing has not found nothing;
    /// it has found nothing *where it could see*. See [`Outcome::view_health`].
    pub fn over_view(mut self, health: ParseHealth) -> Outcome {
        self.view_health = health;
        self
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
    use crate::change::FileChange;

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
            assert!(
                !outcome.view_health.is_degraded(),
                "{} reported a degraded view of nothing",
                detector.metric_id()
            );
        }
    }

    #[test]
    fn a_detector_reports_a_view_only_over_files_it_actually_parsed() {
        // The three that parse must report a view over a file they read, and the
        // four that scan bytes must report none — an ERROR node hides nothing
        // from a search for `eslint-disable`, and saying it does would put a
        // caveat on a result a parse failure cannot touch.
        //
        // A change with one degraded file of each kind, so no detector can be
        // excused for having had nothing to look at.
        let view = ChangeView::new(vec![
            FileChange::modified(
                "src/a.spec.tsx",
                "export const F = <div>\nit('a', () => { expect(1).toBe(1); });\n",
                "export const F = <div>\n",
            ),
            FileChange::modified(
                "src/a.ts",
                "export const f = (n: number) => n;\n",
                "export const f = (n: number = > n;\n",
            ),
        ]);
        let parses: Vec<&str> = all()
            .into_iter()
            .filter(|d| d.run(&view).view_health.is_degraded())
            .map(|d| signal_name(d.signal()))
            .collect();
        assert_eq!(
            parses,
            vec!["test-removal", "assertion-free-test", "lookup-table-blowup"],
            "the set of detectors a parse failure can blind is a contract, not \
             an accident of which ones happen to import the facade"
        );
    }
}
