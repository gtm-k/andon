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

use std::path::Path;

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

/// The honesty line a `partial` result carries, which is the one the claim
/// makes promises about.
///
/// First, because that is where `demote_to_partial` inserts it — a reader who
/// stops after one line reads the one that changes how to read the number.
fn caveat<'a>(results: &'a [MeasurementResult], metric_id: &str) -> &'a str {
    assert_eq!(
        result(results, metric_id).completeness,
        Completeness::Partial,
        "{metric_id} carries no undecided-change caveat to read"
    );
    &result(results, metric_id).evidence.does_not_predict[0]
}

/// Asserts the caveat says each of `words`.
///
/// The reason this file has a helper for it: round 4 shipped a sentence
/// promising that a `partial` result names the key, and twelve probes that
/// asserted only that the status was `Partial` — so the sentence was wrong and
/// the suite meant to hold it was green. Status is not content, and a claim
/// about what a caveat *says* has to be read out of the caveat.
fn caveat_says(results: &[MeasurementResult], metric_id: &str, words: &[&str]) {
    let line = caveat(results, metric_id);
    for word in words {
        assert!(
            line.contains(word),
            "the caveat does not say {word:?}, which the claim promises it does:\n{line}"
        );
    }
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
fn a_rule_option_that_moved_behind_a_held_severity_is_quoted_with_both_values() {
    disclosed("a rule option that moved while its severity held");
    disclosed("the key and both values for an option that moved or that went behind a name");
    let results = one(
        ".eslintrc.json",
        "{ \"rules\": { \"indent\": [\"error\", 2] } }",
        "{ \"rules\": { \"indent\": [\"error\", 4] } }",
    );
    let (flag, magnitude, completeness) = triple(&results, THRESHOLD);
    assert!(!flag);
    assert_eq!(magnitude, 0);
    assert_eq!(completeness, Completeness::Partial);
    // The key and *both* values: a caveat naming only the key would leave a
    // reader unable to see which way the option went, which is the whole
    // question the result declined to answer.
    caveat_says(
        &results,
        THRESHOLD,
        &[
            ".eslintrc.json:1",
            "indent",
            "[\"error\", 2]",
            "[\"error\", 4]",
            "no per-linter rule table ships here",
        ],
    );
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
    disclosed("the key and the value it had for a deletion");
    caveat_says(
        &results,
        THRESHOLD,
        &[".eslintrc.json", "no-explicit-any", "error -> absent"],
    );
}

#[test]
fn a_changed_line_the_scanner_took_no_setting_from_is_quoted_as_the_line_it_is() {
    // The probe that was missing, and the reason this file grew a caveat
    // reader. Round 4's sentence said a `partial` result names *the key*; this
    // shape has no key on it — that is precisely what leaves it undecidable —
    // so the sentence was false of the third of the three shapes it covered —
    // and it covered three of the five there are. A probe asserting only
    // `Partial` could tell neither.
    disclosed("a changed line the scanner took no setting from");
    disclosed("the line's own text for an unread line");
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
    caveat_says(
        &results,
        THRESHOLD,
        &[
            ".eslintrc.yml:4",
            "`- 10`",
            "the scanner took no setting from it",
        ],
    );
    assert!(
        !caveat(&results, THRESHOLD).contains("complexity"),
        "there is no key on the line, and a caveat that named one would be \
         describing a setting the scanner never read"
    );
}

#[test]
fn where_several_changes_go_undecided_only_the_first_is_quoted() {
    // The general form of the same defect. `unassessed_caveat` quotes
    // `unassessed[0].detail` and locates the rest, so "the caveat names the
    // key" was never true of a change with two undecided settings in it — and
    // no probe looked at a change with two.
    disclosed("says how many went undecided");
    disclosed("The rest are located and not described");
    let results = one(
        ".eslintrc.json",
        "{ \"rules\": { \"indent\": [\"error\", 2], \"no-explicit-any\": \"error\" } }",
        "{ \"rules\": { \"indent\": [\"error\", 4] } }",
    );
    assert_eq!(
        triple(&results, THRESHOLD),
        (false, 0, Completeness::Partial)
    );
    // How many, and where each one is.
    caveat_says(
        &results,
        THRESHOLD,
        &["2 change(s)", ".eslintrc.json", ".eslintrc.json:1"],
    );
    // The first in the detector's own words.
    caveat_says(&results, THRESHOLD, &["no-explicit-any", "error -> absent"]);
    // And the second located and not described: `indent` is undecided here too
    // and its key does not appear. Disclosed rather than fixed — a reader who
    // needs it has the line number.
    assert!(
        !caveat(&results, THRESHOLD).contains("indent"),
        "the second undecided change is described after all, and the claim says \
         it is only located:\n{}",
        caveat(&results, THRESHOLD)
    );
}

#[test]
fn a_rule_option_hidden_behind_an_unbound_name_is_quoted_with_both_values() {
    // The fourth of the five, and one of two the hand-written enumeration
    // missed for three rounds although the mechanism and a lib test both had
    // it: `indirect` resolves a limit the same file binds, and reports rather
    // than guesses when the binding left the file.
    disclosed("a rule option written as a name that nothing in the file binds");
    let results = one(
        "eslint.config.js",
        "export default [{ rules: { complexity: [\"error\", 10] } }];\n",
        "import { LIMIT } from './limits';\nexport default [{ rules: { complexity: [\"error\", LIMIT] } }];\n",
    );
    assert_eq!(
        triple(&results, THRESHOLD),
        (false, 0, Completeness::Partial)
    );
    caveat_says(
        &results,
        THRESHOLD,
        &[
            "eslint.config.js:2",
            "complexity",
            "[\"error\", 10]",
            "[\"error\", LIMIT]",
            // The reason, and not only the key and the values: those are the
            // same for the shape above, so without this the probe passed with
            // `indirect`'s report removed and `unrankable` catching the case
            // instead. A probe that cannot tell two shapes apart cannot hold a
            // claim that enumerates them separately.
            "a name rather than a number and nothing in this file binds it",
        ],
    );
}

#[test]
fn an_exclusion_replacement_nobody_can_rank_quotes_the_replacing_pattern() {
    // The fifth, and the one the reviewer found. It is the other detector's,
    // which is why an enumeration written while working in the first one missed
    // it — and it has been documented at fixtures/adversarial/README.md:116 the
    // whole time.
    disclosed("a coverage exclusion replaced by a pattern neither anchored above the other");
    disclosed(
        "the replacing pattern alone for an exclusion replacement, never the pattern it replaced",
    );
    let results = one(
        ".coveragerc",
        "[run]\nomit =\n    tests/*\n    */__init__.py\n",
        "[run]\nomit =\n    tests/*\n    */conftest.py\n",
    );
    assert_eq!(
        triple(&results, COVERAGE),
        (false, 0, Completeness::Partial)
    );
    caveat_says(
        &results,
        COVERAGE,
        &[
            ".coveragerc:4",
            "*/conftest.py",
            "neither pattern is anchored above the other",
        ],
    );
    // Derived rather than assumed: the quote names what replaced the pattern
    // and not the pattern it replaced, so a claim saying "both patterns" would
    // have been the same defect again.
    assert!(
        !caveat(&results, COVERAGE).contains("__init__"),
        "the caveat names the pattern that was replaced after all:\n{}",
        caveat(&results, COVERAGE)
    );
}

#[test]
fn the_claims_five_shapes_are_every_shape_the_code_can_produce() {
    // The guard the last three rounds did not have, and the reason each of them
    // shipped an enumeration missing a member: a conformance suite can only
    // test the shapes its author thought of, so it checks the list against the
    // mechanism and never asks whether the list is complete.
    //
    // What makes the question answerable here is that the mechanism has exactly
    // one gate. `Completeness::Partial` is written to a tamper result in one
    // place — `demote_to_partial`, engine.rs — reached from one condition,
    // `if !outcome.unassessed.is_empty()`. So the shapes that can produce a
    // `partial` result are exactly the places a detector puts a finding into
    // `unassessed`, and those are countable from the source.
    //
    // This test counts them. It does not know what a new one would mean, and
    // that is the point: it fails, and whoever added it has to say.
    let detectors = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("detectors");
    let mut sites: Vec<String> = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&detectors)
        .expect("the detector directory is where it has always been")
        .map(|e| e.expect("readable").path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    entries.sort();
    for path in &entries {
        let text = std::fs::read_to_string(path).expect("a detector source reads");
        let name = path
            .file_name()
            .expect("named")
            .to_string_lossy()
            .to_string();
        for (index, line) in text.lines().enumerate() {
            // Anywhere on the line, not at the start of it: one of the five is
            // a match arm (`Err(unranked) => unassessed.push(`), and a scan
            // anchored at the first token found four of five — this guard
            // undercounting is the same defect it exists to catch, so it is
            // written to over-report and let a comment be excluded by hand.
            let trimmed = line.trim();
            let counted = !trimmed.starts_with("//")
                && (line.contains("unassessed.push(") || line.contains("unassessed.extend("));
            if counted {
                sites.push(format!("{name}:{}", index + 1));
            }
        }
    }
    assert_eq!(
        sites.len(),
        5,
        "the number of ways a tamper result can come back `partial` has changed, and the \
         gate-loosening claim in registry/tamper.toml enumerates five. Found: {sites:?}. \
         Add the new shape to that enumeration and give it a probe here, or take the \
         removed one out of both."
    );
    // And they live in the two detectors the claim is about. The other five
    // never mark anything unassessed, which is why the claim can speak for the
    // whole of its own subject.
    let files: std::collections::BTreeSet<&str> = sites
        .iter()
        .map(|s| s.split(':').next().expect("named"))
        .collect();
    assert_eq!(
        files.into_iter().collect::<Vec<_>>(),
        vec!["coverage_exclusion_drift.rs", "threshold_config_edit.rs"],
        "a detector outside this claim's subject can now return `partial`, so the claim \
         no longer covers every shape a reader of these two metrics will meet"
    );
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
