//! A detector that read a config change and could not rank it does not report a
//! confident zero.
//!
//! # The hole this closes, in two changes
//!
//! Both were found by running the shipped binary, not by reading it, and both
//! came back as a **pass**:
//!
//! | change | before | true answer |
//! |---|---|---|
//! | `.nycrc.json` excludes `src/generated/**`, now excludes `src/**` | `{flag: false, magnitude: 0, completeness: "complete"}` | the whole source tree left coverage |
//! | `.eslintrc.json` `complexity: ["error", 10]` becomes `["error", 100]` | the same | the rule enforces a tenth as much |
//!
//! Neither is a parse failure. The identical `.nycrc.json` fires correctly when
//! an entry is *added*, and the identical `.eslintrc.json` fires correctly when
//! a severity is lowered — so the file was read and understood in both cases.
//! What was missing was a model: one detector measured how many patterns were
//! excluded rather than how much they excluded, and the other read a rule's
//! severity and not its options. `sibling_syntaxes_are_read_the_same_way` keeps
//! the controls beside the cases, because that difference is what decides
//! whether the right fix is a parser or a rule.
//!
//! # And where a model is still missing, the result says so
//!
//! Both detectors keep a genuine blind spot. Ranking `*/__init__.py` against
//! `*/conftest.py` needs a glob semantics that differs per tool; ranking
//! `indent: ["error", 2] -> ["error", 4]` needs to know which option of that
//! rule is a threshold. Neither is decidable from the text, and pretending
//! otherwise would trade a false negative for a false positive on an honest
//! change — one of these is a should-pass case in the frozen corpus.
//!
//! So the answer stays quiet and stops claiming to be complete. The flag and the
//! magnitude are the same numbers, still in the digest, still what a verifier
//! compares; what changes is `completeness`, which is the field a policy engine
//! reads first, and a caveat naming what went unranked and where. That is the
//! same shape as the parse-degraded demotion in `parse_degraded_view.rs` and it
//! is deliberate: a detector has two ways to be blind — it could not read the
//! bytes, or it read them and has no rule — and reporting only the first is
//! reporting half of what a reader needs.

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::policy::Policy;
use andon_core::schema::enums::{Completeness, Severity};
use andon_core::schema::payload::{CompareContext, MeasurementResult, MetricValue};
use andon_engine_tamper::change::{ChangeView, FileChange};
use andon_engine_tamper::TamperEngine;

fn context() -> MeasureContext {
    MeasureContext {
        compare_context: CompareContext {
            base_oid: "0".repeat(40),
            head_oid: "1".repeat(40),
            git_version: "git version 2.51.0".to_string(),
            base_resolution: "explicit".to_string(),
        },
        policy: Policy::default(),
        changed_paths: Vec::new(),
        sandbox_available: false,
    }
}

fn measure(path: &str, base: &str, head: &str) -> Vec<MeasurementResult> {
    let view = ChangeView::new(vec![FileChange::modified(path, base, head)]);
    run_engine(&TamperEngine::for_view(view), &context()).expect("measures")
}

fn result<'a>(results: &'a [MeasurementResult], metric_id: &str) -> &'a MeasurementResult {
    results
        .iter()
        .find(|r| r.metric_id == metric_id)
        .unwrap_or_else(|| panic!("{metric_id} is one of the fourteen"))
}

fn flag(results: &[MeasurementResult], metric_id: &str) -> bool {
    match result(results, metric_id).value {
        MetricValue::Flag(fired) => fired,
        ref other => panic!("{metric_id} is a flag, not {other:?}"),
    }
}

fn magnitude(results: &[MeasurementResult], metric_id: &str) -> i64 {
    match result(results, metric_id).value {
        MetricValue::Integer(value) => value,
        ref other => panic!("{metric_id} is an integer, not {other:?}"),
    }
}

#[test]
fn the_exclusion_that_swallowed_the_source_tree_fires() {
    let results = measure(
        ".nycrc.json",
        "{\n  \"exclude\": [\"src/generated/**\"]\n}\n",
        "{\n  \"exclude\": [\"src/**\"]\n}\n",
    );
    assert!(
        flag(&results, "tamper.coverage-exclusion-drift"),
        "the entry count did not move and the exclusion did"
    );
    assert_eq!(
        magnitude(&results, "tamper.coverage-exclusion-drift.magnitude"),
        1
    );
    let fired = result(&results, "tamper.coverage-exclusion-drift");
    assert_eq!(fired.completeness, Completeness::Complete);
    assert_eq!(
        fired.severity,
        Severity::High,
        "a widened exclusion is evidence being removed, like the other five"
    );
}

#[test]
fn the_rule_threshold_raised_behind_an_unchanged_severity_fires() {
    let results = measure(
        ".eslintrc.json",
        "{ \"rules\": { \"complexity\": [\"error\", 10] } }",
        "{ \"rules\": { \"complexity\": [\"error\", 100] } }",
    );
    assert!(
        flag(&results, "tamper.threshold-config-edit"),
        "{results:#?}"
    );
    assert_eq!(
        magnitude(&results, "tamper.threshold-config-edit.magnitude"),
        1
    );
    assert_eq!(
        result(&results, "tamper.threshold-config-edit").completeness,
        Completeness::Complete
    );
}

#[test]
fn sibling_syntaxes_are_read_the_same_way() {
    // The controls that make the diagnosis "a missing model" rather than "a
    // format it cannot parse". Every one of these is the SAME file name and the
    // same syntax as a case above, and every one of them already fired.
    let added_entry = measure(
        ".nycrc.json",
        "{\n  \"exclude\": [\"src/generated/**\"]\n}\n",
        "{\n  \"exclude\": [\"src/generated/**\", \"src/billing/**\"]\n}\n",
    );
    assert!(flag(&added_entry, "tamper.coverage-exclusion-drift"));

    let severity_lowered = measure(
        ".eslintrc.json",
        "{ \"rules\": { \"no-explicit-any\": \"error\" } }",
        "{ \"rules\": { \"no-explicit-any\": \"warn\" } }",
    );
    assert!(flag(&severity_lowered, "tamper.threshold-config-edit"));

    let ini_widened = measure(
        ".coveragerc",
        "[run]\nomit =\n    src/generated/*\n",
        "[run]\nomit =\n    src/*\n",
    );
    assert!(
        flag(&ini_widened, "tamper.coverage-exclusion-drift"),
        "the same model gap was reported in the INI syntax too"
    );

    let flat_config = measure(
        "eslint.config.js",
        "export default [{ rules: { complexity: [\"error\", { max: 10 }] } }];\n",
        "export default [{ rules: { complexity: [\"error\", { max: 100 }] } }];\n",
    );
    assert!(flag(&flat_config, "tamper.threshold-config-edit"));
}

#[test]
fn an_exclusion_replacement_nobody_can_rank_is_quiet_and_not_complete() {
    // A should-pass case in the frozen corpus. It must stay quiet — firing on
    // it would be the false positive PLAN B5/B6 exists to prevent — and it must
    // stop claiming that its zero is a complete answer.
    let results = measure(
        ".coveragerc",
        "[run]\nomit =\n    tests/*\n    */__init__.py\n",
        "[run]\nomit =\n    tests/*\n    */conftest.py\n",
    );
    assert!(!flag(&results, "tamper.coverage-exclusion-drift"));
    assert_eq!(
        magnitude(&results, "tamper.coverage-exclusion-drift.magnitude"),
        0
    );

    for metric in [
        "tamper.coverage-exclusion-drift",
        "tamper.coverage-exclusion-drift.magnitude",
    ] {
        let marked = result(&results, metric);
        assert_eq!(
            marked.completeness,
            Completeness::Partial,
            "{metric} is a zero over a change this detector read and did not decide"
        );
        assert!(
            !marked.severity.is_med_plus(),
            "{metric}: an incomplete answer must not stop the line ({:?})",
            marked.severity
        );
        let caveat = marked
            .evidence
            .does_not_predict
            .first()
            .expect("the caveat leads the honesty field");
        assert!(caveat.contains(".coveragerc"), "{caveat}");
        assert!(
            caveat.contains("*/conftest.py"),
            "the caveat must name what went unranked: {caveat}"
        );
    }
}

#[test]
fn a_rule_option_nobody_can_rank_is_quiet_and_not_complete() {
    // Telling `indent: 2 -> 4` from a threshold means knowing the rule.
    let results = measure(
        ".eslintrc.json",
        "{ \"rules\": { \"indent\": [\"error\", 2] } }",
        "{ \"rules\": { \"indent\": [\"error\", 4] } }",
    );
    assert!(!flag(&results, "tamper.threshold-config-edit"));
    assert_eq!(
        result(&results, "tamper.threshold-config-edit").completeness,
        Completeness::Partial
    );
    assert_eq!(
        result(&results, "tamper.threshold-config-edit.magnitude").completeness,
        Completeness::Partial
    );
}

#[test]
fn only_the_detector_that_could_not_decide_carries_the_caveat() {
    // The same narrowing `parse_degraded_view.rs` pins for the parse case, for
    // the same reason: marking all fourteen results because one detector was
    // stumped would put a caveat on twelve answers that are complete, which is
    // claiming a limitation rather than disclosing one — and a caveat that is
    // always on is one nobody reads.
    let results = measure(
        ".coveragerc",
        "[run]\nomit =\n    tests/*\n    */__init__.py\n",
        "[run]\nomit =\n    tests/*\n    */conftest.py\n",
    );
    let marked: Vec<&str> = results
        .iter()
        .filter(|r| r.completeness != Completeness::Complete)
        .map(|r| r.metric_id.as_str())
        .collect();
    assert_eq!(
        marked,
        vec![
            "tamper.coverage-exclusion-drift",
            "tamper.coverage-exclusion-drift.magnitude"
        ],
        "which detector could not decide is a property of what it read, not of \
         the change"
    );
}

#[test]
fn an_ordinary_config_edit_is_still_a_complete_answer() {
    // The other half of the narrowing, and the one that keeps `partial` worth
    // something. A bumped compiler target, a reordered omit list and a rule
    // promoted to error are all edits in files these detectors read, and none
    // of them is a change either detector failed to rank.
    for (path, base, head) in [
        (
            "tsconfig.json",
            "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2020\" } }",
            "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2022\" } }",
        ),
        (
            ".coveragerc",
            "[run]\nomit =\n    tests/*\n    src/vendor/*\n",
            "[run]\nomit =\n    src/vendor/*\n    tests/*\n",
        ),
        (
            ".eslintrc.json",
            "{ \"rules\": { \"complexity\": \"warn\" } }",
            "{ \"rules\": { \"complexity\": \"error\" } }",
        ),
        (
            ".coveragerc",
            "[run]\nomit =\n    tests/*\n    src/legacy/*\n",
            "[run]\nomit =\n    tests/*\n",
        ),
    ] {
        let results = measure(path, base, head);
        let marked: Vec<&str> = results
            .iter()
            .filter(|r| r.completeness != Completeness::Complete)
            .map(|r| r.metric_id.as_str())
            .collect();
        assert!(
            marked.is_empty(),
            "{path}: an honest edit this detector understands must not spend a \
             caveat — {marked:?}"
        );
    }
}

#[test]
fn a_firing_that_is_also_unranked_elsewhere_still_stops_the_line() {
    // The interaction the demotion could have broken, and the one an evasion
    // would aim at if it could: a change that widens an exclusion in one file
    // *and* rewrites the list in another, so the detector both fires and is
    // stumped. `demote_to_partial` caps the severity, which is the same thing
    // the parse-degraded path does — and blocking is keyed on the flag, never
    // on the severity, for the muzzle reason `verdict::severity` sets out. If
    // that ever stopped being true, an attacker could buy a pass with one
    // unrankable line beside a real widening.
    let view = ChangeView::new(vec![
        FileChange::modified(
            ".nycrc.json",
            "{\n  \"exclude\": [\"src/generated/**\"]\n}\n",
            "{\n  \"exclude\": [\"src/**\"]\n}\n",
        ),
        FileChange::modified(
            ".coveragerc",
            "[run]\nomit =\n    tests/*\n    */__init__.py\n",
            "[run]\nomit =\n    tests/*\n    */conftest.py\n",
        ),
    ]);
    let results = run_engine(&TamperEngine::for_view(view), &context()).expect("measures");
    let fired = result(&results, "tamper.coverage-exclusion-drift");
    assert_eq!(fired.value, MetricValue::Flag(true));
    assert_eq!(
        fired.completeness,
        Completeness::Partial,
        "it fired on one file and could not rank another"
    );
    assert_eq!(
        fired.severity,
        Severity::Low,
        "an incomplete answer is capped below the MED+ band"
    );

    let policy = Policy::default();
    let ctx = andon_core::verdict::VerdictContext {
        completeness: andon_core::parse_health::weakest(&results),
        policy: &policy,
        policy_change: None,
        engine_failures: &[],
        stale_claim_ids: &[],
        iteration_state_recovered: false,
        registry_skew: &[],
    };
    assert!(
        andon_core::verdict::severity::stops_the_line(fired, &ctx),
        "the capped severity must not buy a pass: the flag is the blocking \
         route and it is still true"
    );
}
