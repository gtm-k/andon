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
//! enumeration is executed here against the same engine a caller runs. Each
//! probe reads the prose out of the compiled-in registry rather than restating
//! it, so it fails from either side: change the behaviour of a shape the claim
//! names and the assertion breaks; soften the words the claim uses for it and
//! the phrase lookup breaks.
//!
//! # What this file does not do, stated because the last version implied it did
//!
//! It holds the five shapes the claim enumerates. It does not hold the claim to
//! *five*. **If a sixth way to produce a `partial` result is added, nothing
//! here fails.**
//!
//! That the five are all of them is an argument, not an invariant: the write is
//! one line (`demote_to_partial`), the gate above it is one condition
//! (`if !outcome.unassessed.is_empty()`), and the producers are the places a
//! detector puts a finding into `unassessed` — five of them, in two of the seven
//! detectors. It was verified by inspection twice, once here and once by
//! review, and both inspections read the commit you are reading. That is the
//! scope of the verification and not a property of the commit: the fact is not
//! claimed to tell this commit apart from its neighbours — only to have been
//! checked here, and to be unchecked wherever a later commit moves the
//! producers or the gate.
//!
//! A test that counted those places stood here and was removed. It matched the
//! spellings `unassessed.push(` and `unassessed.extend(`, and a reachable
//! producer written `unassessed.append(` walked straight past it — the third
//! blind spot found in one mechanism, after a first draft that missed a match
//! arm and a disclosed hole where a site present but unreachable still counted.
//! A test that recognises the members of a set by how they are spelled cannot
//! decide whether the set is complete; it is the hand-written list again, one
//! layer down, and it is worse than nothing because it reads like a guarantee.
//! Deciding this properly is a design question about what a producer *is* — not
//! how it is written — and it belongs with the systemic work item, not here.
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
            head_kind: andon_core::schema::payload::HeadKind::Commit,
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

/// A detector's two results, read as the pair the claim answers for.
///
/// Every promise this file holds is a promise about *both* of them. The gate
/// sentence says so outright — "both of its results come back
/// `completeness: partial` instead" — and the caveat sentence describes the
/// honesty line those results carry without singling either one out. So the
/// properties the claim states of both are asserted of both here, once, before
/// any probe is handed a value to compare.
///
/// The reason it is a helper and not a line in each probe: round 7 read the
/// magnitude's *value* and the flag's *completeness*, and the magnitude's
/// demotion — the second `demote_to_partial` call in `engine.rs` — could be
/// deleted outright with all fifteen probes still green. An assertion that
/// reads one result cannot hold a promise about two. It is the same defect as
/// the twelve probes that asserted a status where the sentence was about
/// content, moved one field over; putting it in the shared reader is what stops
/// it moving one field over again, because a probe cannot reach a value here
/// without the pair having been checked.
fn pair<'a>(
    results: &'a [MeasurementResult],
    stem: &str,
) -> (&'a MeasurementResult, &'a MeasurementResult) {
    let flag = result(results, stem);
    let magnitude = result(results, &format!("{stem}.magnitude"));
    assert_eq!(
        flag.completeness, magnitude.completeness,
        "the claim answers for both of {stem}'s results together, so a reader \
         told the flag is decided and the magnitude is not — or the reverse — \
         has been given two answers to one question"
    );
    // The whole list rather than the caveat alone: the two results resolve to
    // one claim, so a caller reading either is promised the same prose, and a
    // probe that reads one holds the claim for both only while that is true.
    assert_eq!(
        flag.evidence.does_not_predict, magnitude.evidence.does_not_predict,
        "{stem} and its magnitude ship different prose, so each probe below \
         holds the claim only for whichever of the two it happens to read"
    );
    (flag, magnitude)
}

/// The `(flag, magnitude, completeness)` triple a reader of the record sees.
fn triple(results: &[MeasurementResult], stem: &str) -> (bool, i64, Completeness) {
    let (flag_result, magnitude_result) = pair(results, stem);
    let flag = match flag_result.value {
        MetricValue::Flag(fired) => fired,
        ref other => panic!("{stem} is a flag, not {other:?}"),
    };
    let magnitude = match magnitude_result.value {
        MetricValue::Integer(value) => value,
        ref other => panic!("{stem}.magnitude is an integer, not {other:?}"),
    };
    // Either one, having been asserted equal to the other.
    (flag, magnitude, flag_result.completeness)
}

/// What the shipped claim says it does not predict, as the caller receives it.
fn disclosures() -> Vec<String> {
    let results = one(
        ".eslintrc.json",
        "{ \"rules\": { \"eqeqeq\": \"error\" } }",
        "{ \"rules\": { \"eqeqeq\": \"warn\" } }",
    );
    // Through the pair reader, so that "the claim ships in every result" is
    // asserted where the claim is lifted rather than assumed of the one result
    // this happens to lift it from.
    let (flag, _) = pair(&results, THRESHOLD);
    flag.evidence.does_not_predict.clone()
}

/// The honesty line a `partial` result carries, which is the one the claim
/// makes promises about.
///
/// First, because that is where `demote_to_partial` inserts it — a reader who
/// stops after one line reads the one that changes how to read the number.
///
/// Read through `pair`, and not off the flag directly, so that every promise
/// `caveat_says` goes on to hold is held for the magnitude too: the pair reader
/// has already established that the two results carry the same prose in the
/// same order, which is what makes reading one of them an answer about both.
fn caveat<'a>(results: &'a [MeasurementResult], stem: &str) -> &'a str {
    let (flag, _) = pair(results, stem);
    assert_eq!(
        flag.completeness,
        Completeness::Partial,
        "{stem} carries no undecided-change caveat to read"
    );
    &flag.evidence.does_not_predict[0]
}

/// Asserts the caveat says each of `words`.
///
/// The reason this file has a helper for it: round 4 shipped a sentence
/// promising that a `partial` result names the key, and twelve probes that
/// asserted only that the status was `Partial` — so the sentence was wrong and
/// the suite meant to hold it was green. Status is not content, and a claim
/// about what a caveat *says* has to be read out of the caveat.
fn caveat_says(results: &[MeasurementResult], stem: &str, words: &[&str]) {
    let line = caveat(results, stem);
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
    // The whole triple and not the completeness alone: the four probes around
    // this one assert what the flag and the magnitude say as well as how far
    // they were decided, and a shape held to less than its neighbours is where
    // the next gap goes.
    assert_eq!(
        triple(&results, THRESHOLD),
        (false, 0, Completeness::Partial)
    );
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
