//! Which tamper signals fired, read back off the results.
//!
//! # Why this is derived rather than passed in
//!
//! The tamper engine knows perfectly well what fired — it has
//! `TamperEngine::signals()`. But `andon-core` cannot depend on an engine crate
//! (the contract is the thing every engine depends on, and nothing depends on
//! them), and more to the point the assembler must work on *records*: a payload
//! read back from a git note, or handed to the verifier, has results and no
//! engine behind it. A signal list that could only be built at measure time
//! would be absent exactly where the verifier needs it.
//!
//! # The mapping has no table
//!
//! A hand-written `metric_id -> TamperSignal` table is a table that drifts the
//! first time a detector is renamed, and it drifts *silently*: the signal simply
//! stops being reported. So the mapping is the enum's own wire spelling. Every
//! detector's flag metric is `tamper.<signal>`, where `<signal>` is the
//! kebab-case name [`TamperSignal`] serializes to, and this module resolves the
//! suffix through serde itself. Rename a detector without renaming its variant
//! and the resolution fails loudly at assembly rather than quietly dropping a
//! signal.

use crate::schema::enums::{EngineFamily, TamperSignal};
use crate::schema::payload::{MeasurementResult, MetricValue};

/// Prefix every tamper metric id carries.
pub const TAMPER_METRIC_PREFIX: &str = "tamper.";

/// Suffix marking the magnitude half of a detector's pair.
///
/// Magnitudes are `Integer`-valued and never enter the fired set; the suffix is
/// named so that [`is_tamper_flag`] can say *why* it skipped one.
pub const MAGNITUDE_SUFFIX: &str = ".magnitude";

/// Whether a result is a detector's fired/not-fired flag.
///
/// Family and value shape, not the id: a `Flag`-valued result in the tamper
/// family is a detector answer, and the magnitude beside it is an `Integer`.
pub fn is_tamper_flag(result: &MeasurementResult) -> bool {
    result.family == EngineFamily::Tamper
        && matches!(result.value, MetricValue::Flag(_))
        && !result.metric_id.ends_with(MAGNITUDE_SUFFIX)
}

/// The signal a tamper flag metric names, or `None` when the id does not name
/// one.
///
/// `None` is a drift report, not an absence: it means a metric in the tamper
/// family is spelled in a way [`TamperSignal`] does not know, and the assembler
/// turns it into a refusal rather than an omission.
pub fn signal_for(metric_id: &str) -> Option<TamperSignal> {
    let suffix = metric_id.strip_prefix(TAMPER_METRIC_PREFIX)?;
    if suffix.ends_with(MAGNITUDE_SUFFIX) {
        return None;
    }
    // Through serde, so the spelling this accepts is by construction the
    // spelling the enum writes to the wire.
    serde_json::from_value(serde_json::Value::String(suffix.to_string())).ok()
}

/// Every signal that fired, deduplicated, in enum order.
///
/// Enum order rather than result order: the array reaches the canonical
/// serializer, and a list whose order depends on which engine ran first is a
/// record that differs between two honest runs.
pub fn fired_signals(results: &[MeasurementResult]) -> Vec<TamperSignal> {
    // Through `severity::fired_signal`, which is the verdict's own answer to
    // "did this detector fire". Written out again here, the two agreed until one
    // was edited — and the record's signal list could then omit a detector the
    // verdict was naming, which is the payload contradicting itself about the
    // one field the trust model turns on.
    let mut fired: Vec<TamperSignal> = results
        .iter()
        .filter_map(crate::verdict::severity::fired_signal)
        .collect();
    fired.sort_by_key(|signal| signal_rank(*signal));
    fired.dedup();
    fired
}

/// Position of a signal in [`TamperSignal`]'s declaration order.
///
/// Written out rather than derived from `Ord`, because deriving `Ord` on the
/// enum would put an ordering into the public contract that nothing else needs
/// and that a future variant insertion would silently change.
fn signal_rank(signal: TamperSignal) -> u8 {
    match signal {
        TamperSignal::SuppressionDensity => 0,
        TamperSignal::TestRemoval => 1,
        TamperSignal::CoverageExclusionDrift => 2,
        TamperSignal::AssertionFreeTest => 3,
        TamperSignal::ThresholdConfigEdit => 4,
        TamperSignal::LookupTableBlowup => 5,
        TamperSignal::ParseErrorDelta => 6,
        TamperSignal::BaseFabrication => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::enums::Completeness;
    use crate::testing::sample_result;

    fn tamper_flag(metric_id: &str, fired: bool) -> MeasurementResult {
        let mut result = sample_result();
        result.metric_id = metric_id.to_string();
        result.engine_id = "tamper".to_string();
        result.family = EngineFamily::Tamper;
        result.value = MetricValue::Flag(fired);
        result.delta = None;
        result
    }

    #[test]
    fn every_signal_a_detector_can_raise_resolves_from_its_metric_id() {
        // The drift check. If a variant is added without a metric id in this
        // shape, or an id is renamed away from its variant, this fails — which
        // is the whole reason the mapping is not a table.
        for (metric_id, expected) in [
            (
                "tamper.suppression-density",
                TamperSignal::SuppressionDensity,
            ),
            ("tamper.test-removal", TamperSignal::TestRemoval),
            (
                "tamper.coverage-exclusion-drift",
                TamperSignal::CoverageExclusionDrift,
            ),
            (
                "tamper.assertion-free-test",
                TamperSignal::AssertionFreeTest,
            ),
            (
                "tamper.threshold-config-edit",
                TamperSignal::ThresholdConfigEdit,
            ),
            (
                "tamper.lookup-table-blowup",
                TamperSignal::LookupTableBlowup,
            ),
            ("tamper.parse-error-delta", TamperSignal::ParseErrorDelta),
        ] {
            assert_eq!(signal_for(metric_id), Some(expected), "{metric_id}");
        }
    }

    #[test]
    fn a_magnitude_is_not_a_signal() {
        assert_eq!(signal_for("tamper.test-removal.magnitude"), None);
        let mut magnitude = tamper_flag("tamper.test-removal.magnitude", true);
        magnitude.value = MetricValue::Integer(3);
        assert!(!is_tamper_flag(&magnitude));
    }

    #[test]
    fn an_unknown_detector_name_does_not_resolve() {
        assert_eq!(signal_for("tamper.something-new"), None);
        assert_eq!(signal_for("static.sloc"), None);
    }

    #[test]
    fn only_fired_flags_reach_the_signal_list() {
        let results = vec![
            tamper_flag("tamper.test-removal", true),
            tamper_flag("tamper.suppression-density", false),
            tamper_flag("tamper.parse-error-delta", true),
        ];
        assert_eq!(
            fired_signals(&results),
            vec![TamperSignal::TestRemoval, TamperSignal::ParseErrorDelta]
        );
    }

    #[test]
    fn a_degraded_flag_is_still_a_fired_flag() {
        // The severity-ceiling muzzle, at the point where the list is built:
        // completeness demotion caps severity and touches neither the value nor
        // this list (wave-1 close, P5a-entry note 2).
        let mut degraded = tamper_flag("tamper.test-removal", true);
        degraded.completeness = Completeness::ParseDegraded;
        degraded.severity = crate::schema::enums::Severity::Low;
        assert_eq!(fired_signals(&[degraded]), vec![TamperSignal::TestRemoval]);
    }

    #[test]
    fn the_order_does_not_depend_on_the_order_results_arrived_in() {
        let forwards = vec![
            tamper_flag("tamper.test-removal", true),
            tamper_flag("tamper.suppression-density", true),
        ];
        let backwards = vec![
            tamper_flag("tamper.suppression-density", true),
            tamper_flag("tamper.test-removal", true),
        ];
        assert_eq!(fired_signals(&forwards), fired_signals(&backwards));
    }
}
