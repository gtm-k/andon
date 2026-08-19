//! Every sentence the gate-loosening claim makes about its own limits, run.
//!
//! # Why a test and not a careful reading
//!
//! `registry/tamper.toml` shipped a sentence saying that a file these detectors
//! recognise and cannot rank is reported `completeness: partial` naming what
//! went undecided, "and never as a silence". Six executed case families
//! contradicted it. The sentence was not careless — it described the axis that
//! had just been built — but it generalised from the shapes that axis covers to
//! every shape there is, and nothing in the repository could tell it apart from
//! a true one.
//!
//! So the claim now enumerates rather than promises, and each entry in the
//! enumeration is executed here against the same engine a caller runs. The test
//! reads the prose out of the compiled-in registry rather than restating it, so
//! it fails from either side: change the behaviour and the assertion breaks;
//! soften the prose and the phrase lookup breaks.
//!
//! The disclosures are asserted as firmly as the guarantees. A gap that is
//! written down and then quietly closed leaves the claim overstating its own
//! blindness, which is a smaller failure than the one this file exists for but
//! is still the evidence disagreeing with the code.

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::policy::Policy;
use andon_core::schema::enums::Completeness;
use andon_core::schema::payload::{CompareContext, MeasurementResult, MetricValue};
use andon_engine_tamper::change::{ChangeView, FileChange};
use andon_engine_tamper::TamperEngine;

const THRESHOLD: &str = "tamper.threshold-config-edit";
const COVERAGE: &str = "tamper.coverage-exclusion-drift";

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

fn measure(files: Vec<FileChange>) -> Vec<MeasurementResult> {
    run_engine(&TamperEngine::for_view(ChangeView::new(files)), &context()).expect("measures")
}

fn one(path: &str, base: &str, head: &str) -> Vec<MeasurementResult> {
    measure(vec![FileChange::modified(path, base, head)])
}

fn result<'a>(results: &'a [MeasurementResult], metric_id: &str) -> &'a MeasurementResult {
    results
        .iter()
        .find(|r| r.metric_id == metric_id)
        .unwrap_or_else(|| panic!("{metric_id} is one of the fourteen"))
}

/// The `(flag, magnitude, completeness)` triple a reader of the record sees.
fn triple(results: &[MeasurementResult], stem: &str) -> (bool, i64, Completeness) {
    let flag = match result(results, stem).value {
        MetricValue::Flag(fired) => fired,
        ref other => panic!("{stem} is a flag, not {other:?}"),
    };
    let magnitude = match result(results, &format!("{stem}.magnitude")).value {
        MetricValue::Integer(value) => value,
        ref other => panic!("{stem}.magnitude is an integer, not {other:?}"),
    };
    (flag, magnitude, result(results, stem).completeness)
}

/// What the shipped claim says it does not predict, as the caller receives it.
fn disclosures() -> Vec<String> {
    let results = one(
        ".eslintrc.json",
        "{ \"rules\": { \"eqeqeq\": \"error\" } }",
        "{ \"rules\": { \"eqeqeq\": \"warn\" } }",
    );
    result(&results, THRESHOLD)
        .evidence
        .does_not_predict
        .clone()
}

/// Asserts the shipped prose carries `phrase`, so a guarantee cannot be
/// asserted here after it has been dropped from the claim.
fn disclosed(phrase: &str) {
    let lines = disclosures();
    assert!(
        lines.iter().any(|line| line.contains(phrase)),
        "the gate-loosening claim no longer says {phrase:?}, so this test is \
         asserting a guarantee nobody is offered:\n{lines:#?}"
    );
}

#[test]
fn the_claim_no_longer_promises_that_a_recognised_file_is_never_silent() {
    // The sentence this whole file replaces. It is asserted absent by its two
    // load-bearing halves rather than verbatim, so re-wording it back in does
    // not slip past.
    for promise in ["never as a silence", "in any syntax"] {
        for line in disclosures() {
            assert!(
                !line.contains(promise),
                "{promise:?} is a universal the code does not honour: {line}"
            );
        }
    }
}

#[test]
fn a_rule_option_that_moved_behind_a_held_severity_is_partial_and_names_the_key() {
    disclosed("a rule option that moved while its severity held");
    let results = one(
        ".eslintrc.json",
        "{ \"rules\": { \"indent\": [\"error\", 2] } }",
        "{ \"rules\": { \"indent\": [\"error\", 4] } }",
    );
    let (flag, magnitude, completeness) = triple(&results, THRESHOLD);
    assert!(!flag);
    assert_eq!(magnitude, 0);
    assert_eq!(completeness, Completeness::Partial);
    let caveat = &result(&results, THRESHOLD).evidence.does_not_predict[0];
    assert!(caveat.contains("indent"), "{caveat}");
}

#[test]
fn a_modelled_setting_deleted_rather_than_changed_is_partial_and_names_the_key() {
    disclosed("deleted rather than changed");
    // The claim calls this one out by name — "a rule deleted rather than
    // downgraded" — so it is run as a deleted rule and not only as a deleted
    // compiler flag.
    let results = one(
        ".eslintrc.json",
        "{ \"rules\": { \"no-explicit-any\": \"error\", \"eqeqeq\": \"error\" } }",
        "{ \"rules\": { \"eqeqeq\": \"error\" } }",
    );
    let (flag, magnitude, completeness) = triple(&results, THRESHOLD);
    assert!(!flag, "unranked is not a firing");
    assert_eq!(magnitude, 0);
    assert_eq!(completeness, Completeness::Partial);
    let caveat = &result(&results, THRESHOLD).evidence.does_not_predict[0];
    assert!(caveat.contains("no-explicit-any"), "{caveat}");
}

#[test]
fn a_changed_line_the_scanner_took_no_setting_from_is_partial() {
    disclosed("a changed line the scanner took no setting from");
    // A YAML block sequence: no brackets to follow, no separator on the line
    // carrying the number, and the token on it is exactly the kind this
    // detector ranks.
    let results = one(
        ".eslintrc.yml",
        "rules:\n  complexity:\n    - error\n    - 10\n",
        "rules:\n  complexity:\n    - error\n    - 100\n",
    );
    let (_, _, completeness) = triple(&results, THRESHOLD);
    assert_eq!(completeness, Completeness::Partial);
}

#[test]
fn the_default_stem_is_read_in_every_executable_spelling_its_tool_loads() {
    disclosed("every syntax of a known tool's configuration file");
    for path in [
        "eslint.config.js",
        "eslint.config.cjs",
        "eslint.config.mjs",
        "eslint.config.ts",
        "eslint.config.mts",
        "eslint.config.cts",
    ] {
        let results = one(
            path,
            "export default { rules: { complexity: [\"error\", 10] } };\n",
            "export default { rules: { complexity: [\"error\", 100] } };\n",
        );
        assert_eq!(
            triple(&results, THRESHOLD),
            (true, 1, Completeness::Complete),
            "{path}"
        );
    }
}

#[test]
fn a_variant_in_a_data_syntax_is_read_and_the_same_variant_in_source_is_not() {
    disclosed("is outside the subject");
    disclosed("are read");

    // Read: `.json` and `.properties` are not syntaxes anything executes, so a
    // further name segment there cannot be somebody's module.
    let results = one(
        "tsconfig.ci.json",
        "{ \"compilerOptions\": { \"strict\": true } }\n",
        "{ \"compilerOptions\": { \"strict\": false } }\n",
    );
    assert_eq!(
        triple(&results, THRESHOLD),
        (true, 1, Completeness::Complete)
    );
    let results = one(
        "sonar-project.ci.properties",
        "sonar.projectKey=demo\n",
        "sonar.projectKey=demo\nsonar.coverage.exclusions=src/payments/**\n",
    );
    assert_eq!(
        triple(&results, COVERAGE),
        (true, 1, Completeness::Complete)
    );

    // Not read, and disclosed: the same variant in a spelling a runtime
    // executes is a name an ordinary module carries.
    let results = one(
        "eslint.config.ci.ts",
        "export default { rules: { complexity: [\"error\", 10] } };\n",
        "export default { rules: { complexity: [\"error\", 100] } };\n",
    );
    assert_eq!(
        triple(&results, THRESHOLD),
        (false, 0, Completeness::Complete),
        "out of subject is a quiet zero, not a caveat"
    );
}

#[test]
fn a_spec_module_beside_a_config_is_not_the_config_it_asserts_about() {
    // The accusation that made the narrowing necessary: a test module holding a
    // config's expected values as literals, whose expectations move when the
    // config it pins moves.
    let results = one(
        "src/eslint.config.spec.ts",
        "export const expected = {\n  rules: { complexity: [\"error\", 10] },\n};\n",
        "export const expected = {\n  rules: { complexity: [\"error\", 100] },\n};\n",
    );
    assert_eq!(
        triple(&results, THRESHOLD),
        (false, 0, Completeness::Complete),
        "an honest test module was accused of loosening the rule it pins"
    );
}

#[test]
fn a_properties_value_is_read_only_as_far_as_its_first_comma() {
    disclosed("read only as far as its first comma");
    let results = one(
        "sonar-project.properties",
        "sonar.coverage.exclusions=src/a/**\n",
        "sonar.coverage.exclusions=src/a/**,src/b/**,src/c/**,src/d/**\n",
    );
    assert_eq!(
        triple(&results, COVERAGE),
        (false, 0, Completeness::Complete),
        "four exclusions were added and the scanner saw one value"
    );
}

#[test]
fn an_addition_and_an_unrelated_removal_net_to_zero_across_the_change() {
    disclosed("net to zero across the change");
    let added = FileChange::modified(
        ".coveragerc",
        "[run]\nomit =\n    src/legacy/*\n",
        "[run]\nomit =\n    src/legacy/*\n    src/payments/*\n",
    );
    // On its own the addition is a firing, so the netting is what the second
    // file does and not a detector that never saw the first.
    assert_eq!(
        triple(&measure(vec![added.clone()]), COVERAGE),
        (true, 1, Completeness::Complete)
    );
    let removed = FileChange::modified(
        ".nycrc",
        "{ \"exclude\": [\"dist/**\", \"vendor/**\"] }\n",
        "{ \"exclude\": [\"dist/**\"] }\n",
    );
    assert_eq!(
        triple(&measure(vec![added, removed]), COVERAGE),
        (false, 0, Completeness::Complete)
    );
}

#[test]
fn a_re_inclusion_deleted_from_an_exclusion_list_is_a_quiet_zero() {
    disclosed("dropped from `exclude`");
    let results = one(
        ".nycrc",
        "{ \"exclude\": [\"src/**\", \"!src/api/**\"] }\n",
        "{ \"exclude\": [\"src/**\"] }\n",
    );
    assert_eq!(
        triple(&results, COVERAGE),
        (false, 0, Completeness::Complete),
        "src/api went back under a `src/**` exclusion and the entry count did not move"
    );
}

#[test]
fn a_positive_inclusion_narrowed_is_a_quiet_zero() {
    disclosed("inclusion narrowed");
    let results = one(
        "jest.config.js",
        "module.exports = {\n  collectCoverageFrom: [\"src/**\"],\n};\n",
        "module.exports = {\n  collectCoverageFrom: [\"src/core/**\"],\n};\n",
    );
    assert_eq!(
        triple(&results, COVERAGE),
        (false, 0, Completeness::Complete),
        "everything outside src/core stopped being measured"
    );
}

#[test]
fn the_three_directions_the_claim_says_do_fire_still_do() {
    disclosed("Adding a negation, widening one, and widening an ordinary exclusion all do fire");
    // The half of the negation work the reviewer credited and asked to keep,
    // asserted beside the half that is disclosed as missing so neither can be
    // read as covering the other.
    let added = one(
        "jest.config.js",
        "module.exports = {\n  collectCoverageFrom: [\"src/**\"],\n};\n",
        "module.exports = {\n  collectCoverageFrom: [\"src/**\", \"!src/api/**\"],\n};\n",
    );
    assert_eq!(triple(&added, COVERAGE), (true, 1, Completeness::Complete));

    let widened = one(
        "jest.config.js",
        "module.exports = {\n  collectCoverageFrom: [\"src/**\", \"!src/api/**\"],\n};\n",
        "module.exports = {\n  collectCoverageFrom: [\"src/**\", \"!src/**\"],\n};\n",
    );
    assert_eq!(
        triple(&widened, COVERAGE),
        (true, 1, Completeness::Complete)
    );

    let exclusion = one(
        ".nycrc",
        "{ \"exclude\": [\"src/legacy/**\"] }\n",
        "{ \"exclude\": [\"src/**\"] }\n",
    );
    assert_eq!(
        triple(&exclusion, COVERAGE),
        (true, 1, Completeness::Complete)
    );
}
