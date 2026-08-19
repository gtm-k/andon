//! Every spelling of every format these detectors say they read, and the one
//! answer none of them may give.
//!
//! # The property, and why the cases are not it
//!
//! Two rounds of review found the same defect in seventeen places: a detector
//! that never opens the file, or opens it and has no name for the key that
//! moved, and then reports `{flag: false, magnitude: 0, completeness:
//! "complete"}`. Every one of them was a missing entry in an array of exact
//! spellings — `.nycrc` and `.nycrc.json` were in the file list and `.nycrc.yml`
//! was not; `exclude` was in the key list and tarpaulin's own `exclude_files`
//! was not. Adding seventeen entries closes seventeen cases and leaves the
//! class exactly where it was, because there is always an eighteenth.
//!
//! So what is asserted here is the property:
//!
//! > a file one of these detectors recognises must never answer a loosening
//! > with `fired: false`, `magnitude: 0` **and** nothing recorded as unranked.
//!
//! Fired is the best answer, "I read this and cannot rank it" is an honest one,
//! and silence is the only one that is a lie. The last section runs the
//! property against spellings nobody has reported — `.nycrc.json5`,
//! `.c8rc.yaml`, `eslint.config.mts`, `.golangci.json` — which is what makes it
//! a property rather than a longer list.
//!
//! The negative half matters as much and is here too: a detector that answered
//! this property by treating every file as its subject would pass it and be
//! useless. `src/exclude.ts` and `src/setup.ts` are code.

use andon_engine_tamper::change::{ChangeView, FileChange};
use andon_engine_tamper::detectors::{self, Outcome};

const COVERAGE: &str = "coverage-exclusion-drift";
const THRESHOLD: &str = "threshold-config-edit";

fn run(signal: &str, path: &str, base: &str, head: &str) -> Outcome {
    detectors::by_signal(signal)
        .expect("a known signal")
        .run(&ChangeView::new(vec![FileChange::modified(
            path, base, head,
        )]))
}

/// `(signal, path, base, head)` for one loosening.
type Case = (&'static str, &'static str, &'static str, &'static str);

/// The exclusion widening, in the syntaxes these files are written in.
const JSON_WIDEN: (&str, &str) = (
    "{\n  \"exclude\": [\"src/generated/**\"]\n}\n",
    "{\n  \"exclude\": [\"src/**\"]\n}\n",
);
const YAML_WIDEN: (&str, &str) = ("exclude:\n  - src/generated/**\n", "exclude:\n  - src/**\n");

/// Every case the two review rounds reported, at the spelling they reported it.
fn reported() -> Vec<Case> {
    vec![
        // The sharpest one: a file the detector reads, and the key that is
        // tarpaulin's actual file-exclusion setting.
        (
            COVERAGE,
            "tarpaulin.toml",
            "[report]\nexclude_files = [\"src/generated/*\"]\n",
            "[report]\nexclude_files = [\"src/*\"]\n",
        ),
        (
            COVERAGE,
            "tarpaulin.toml",
            "[report]\nexclude-files = [\"src/generated/*\"]\n",
            "[report]\nexclude-files = [\"src/*\"]\n",
        ),
        // nyc reads YAML rc files; `.nycrc` and `.nycrc.json` both fired on the
        // identical edit.
        (COVERAGE, ".nycrc.yml", YAML_WIDEN.0, YAML_WIDEN.1),
        (COVERAGE, ".nycrc.yaml", YAML_WIDEN.0, YAML_WIDEN.1),
        // coverage.py officially reads `[coverage:run]` out of tox.ini; the
        // identical block in setup.cfg fired.
        (
            COVERAGE,
            "tox.ini",
            "[coverage:run]\nomit =\n    tests/*\n",
            "[coverage:run]\nomit =\n    tests/*\n    src/payments/*\n",
        ),
        // `.c8rc.json` was listed and the bare rc file was not.
        (COVERAGE, ".c8rc", JSON_WIDEN.0, JSON_WIDEN.1),
        (
            COVERAGE,
            "sonar-project.properties",
            "sonar.coverage.exclusions=src/generated/**\n",
            "sonar.coverage.exclusions=src/**\n",
        ),
        // `.eslintrc.js` fires on byte-identical content.
        (
            THRESHOLD,
            ".eslintrc.cjs",
            "module.exports = { rules: { \"no-explicit-any\": \"error\" } };\n",
            "module.exports = { rules: { \"no-explicit-any\": \"warn\" } };\n",
        ),
        // `.eslintrc.yml` fires.
        (
            THRESHOLD,
            ".eslintrc.yaml",
            "rules:\n  no-explicit-any: error\n",
            "rules:\n  no-explicit-any: warn\n",
        ),
        // `.js`, `.mjs` and `.ts` all fire.
        (
            THRESHOLD,
            "eslint.config.cjs",
            "module.exports = [{ rules: { complexity: [\"error\", 10] } }];\n",
            "module.exports = [{ rules: { complexity: [\"error\", 100] } }];\n",
        ),
        // `.golangci.yml` fires.
        (
            THRESHOLD,
            ".golangci.toml",
            "[linters-settings.gocyclo]\nmin-complexity = 10\n",
            "[linters-settings.gocyclo]\nmin-complexity = 100\n",
        ),
        // A strictness flag deleted rather than turned off.
        (
            THRESHOLD,
            "tsconfig.json",
            "{ \"compilerOptions\": { \"noImplicitAny\": true, \"target\": \"es2022\" } }",
            "{ \"compilerOptions\": { \"target\": \"es2022\" } }",
        ),
        // A strictness flag whose strict value is `false`.
        (
            THRESHOLD,
            "tsconfig.json",
            "{ \"compilerOptions\": { \"skipLibCheck\": false } }",
            "{ \"compilerOptions\": { \"skipLibCheck\": true } }",
        ),
        // A coverage floor inside a coverage config the threshold detector was
        // not opening.
        (
            THRESHOLD,
            ".nycrc.json",
            "{ \"lines\": 90 }",
            "{ \"lines\": 10 }",
        ),
    ]
}

/// The ESLint `max-*` family, which the `complexity` rationale covers verbatim:
/// compared where the rule's own name says the number is a ceiling.
fn the_max_family() -> Vec<(String, String, String)> {
    [
        "max-lines-per-function",
        "max-depth",
        "max-params",
        "max-statements",
        "max-lines",
    ]
    .into_iter()
    .map(|rule| {
        (
            rule.to_string(),
            format!("{{ \"rules\": {{ \"{rule}\": [\"error\", 10] }} }}"),
            format!("{{ \"rules\": {{ \"{rule}\": [\"error\", 100] }} }}"),
        )
    })
    .collect()
}

/// Spellings nobody has reported, which is the point of a property.
fn unreported() -> Vec<Case> {
    vec![
        (COVERAGE, ".nycrc.json5", JSON_WIDEN.0, JSON_WIDEN.1),
        (COVERAGE, ".c8rc.yaml", YAML_WIDEN.0, YAML_WIDEN.1),
        (
            COVERAGE,
            "packages/api/.coveragerc",
            JSON_WIDEN.0,
            JSON_WIDEN.1,
        ),
        (
            THRESHOLD,
            "eslint.config.mts",
            "export default [{ rules: { complexity: [\"error\", 10] } }];\n",
            "export default [{ rules: { complexity: [\"error\", 100] } }];\n",
        ),
        (
            THRESHOLD,
            ".golangci.json",
            "{ \"linters-settings\": { \"gocyclo\": { \"min-complexity\": 10 } } }",
            "{ \"linters-settings\": { \"gocyclo\": { \"min-complexity\": 100 } } }",
        ),
        (
            THRESHOLD,
            "tsconfig.base.json",
            "{ \"compilerOptions\": { \"strict\": true } }",
            "{ \"compilerOptions\": { \"strict\": false } }",
        ),
    ]
}

fn assert_not_a_confident_zero(signal: &str, path: &str, outcome: &Outcome) {
    assert!(
        outcome.fired || !outcome.unassessed.is_empty(),
        "{signal} on {path} answered a loosening with {{fired: false, magnitude: {}, \
         unassessed: []}} — a confident zero on a format it says it reads. Firing is the \
         best answer and 'I read this and cannot rank it' is an honest one; silence is the \
         only one that is a lie",
        outcome.magnitude
    );
}

#[test]
fn no_reported_format_answers_a_loosening_with_silence() {
    for (signal, path, base, head) in reported() {
        assert_not_a_confident_zero(signal, path, &run(signal, path, base, head));
    }
}

#[test]
fn every_reported_format_but_the_deletion_is_ranked_rather_than_merely_noticed() {
    // The stronger half. Thirteen of the fourteen are decided outright; only the
    // deleted setting is left unranked, and that one is unrankable rather than
    // unread — `noImplicitAny` deleted from a config whose extended base sets
    // `strict` is no change at all, and no answer in the text says which it was.
    let mut unranked = Vec::new();
    for (signal, path, base, head) in reported() {
        let outcome = run(signal, path, base, head);
        if outcome.fired {
            assert_eq!(outcome.magnitude, 1, "{signal} on {path}");
        } else {
            unranked.push(path);
        }
    }
    assert_eq!(unranked, vec!["tsconfig.json"], "{unranked:?}");
}

#[test]
fn the_max_family_is_ranked_the_way_complexity_is() {
    for (rule, base, head) in the_max_family() {
        let outcome = run(THRESHOLD, ".eslintrc.json", &base, &head);
        assert!(
            outcome.fired,
            "{rule}: the rule's own name says the number is a ceiling, which is the \
             sentence that put `complexity` in the table"
        );
        assert!(
            outcome.findings[0].detail.contains("rule allowance raised"),
            "{rule}: {:?}",
            outcome.findings
        );
    }
}

#[test]
fn a_spelling_nobody_reported_is_covered_before_it_is_reported() {
    for (signal, path, base, head) in unreported() {
        let outcome = run(signal, path, base, head);
        assert_not_a_confident_zero(signal, path, &outcome);
        assert!(
            outcome.fired,
            "{signal} on {path}: an unlisted extension of a tool these detectors know is \
             that tool's configuration, and this edit is one they can rank"
        );
    }
}

#[test]
fn code_is_still_code() {
    // The half a detector that recognised everything would fail. `exclude` and
    // `omit` are ordinary identifiers, and `setup` is a stem an ordinary file
    // carries — which is why `setup.cfg` is configuration by name and
    // `setup.ts` is not.
    for (signal, path, base, head) in [
        (
            COVERAGE,
            "src/exclude.ts",
            "export const exclude = ['a'];\n",
            "export const exclude = ['a', 'b', 'c'];\n",
        ),
        (
            COVERAGE,
            "src/setup.ts",
            "export const omit = ['a'];\n",
            "export const omit = ['a', 'b'];\n",
        ),
        (
            THRESHOLD,
            "src/limits.ts",
            "export const maxComplexity = 10;\n",
            "export const maxComplexity = 40;\n",
        ),
        (
            THRESHOLD,
            "src/tsconfig-loader.ts",
            "export const strict = true;\n",
            "export const strict = false;\n",
        ),
    ] {
        let outcome = run(signal, path, base, head);
        assert!(!outcome.fired, "{signal} fired on {path}: {outcome:?}");
        assert!(
            outcome.unassessed.is_empty(),
            "{signal} spent a caveat on {path}, which is code: {outcome:?}"
        );
    }
}

#[test]
fn an_ordinary_config_edit_does_not_become_a_caveat() {
    // The counterweight to the property. A detector could satisfy every
    // assertion above by marking every config file unassessed, and the caveat
    // would then be on every change in every repository and worth nothing to
    // anybody. None of these is a threshold or an exclusion.
    for (signal, path, base, head) in [
        (
            THRESHOLD,
            "tsconfig.json",
            "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2020\" } }",
            "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2022\" } }",
        ),
        (
            THRESHOLD,
            "tsconfig.json",
            "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2020\" } }",
            "{ \"compilerOptions\": { \"strict\": true } }",
        ),
        (
            COVERAGE,
            ".coveragerc",
            "[run]\nbranch = true\nomit =\n    tests/*\n",
            "[run]\nbranch = false\nsource = src\nomit =\n    tests/*\n",
        ),
        (
            COVERAGE,
            ".coveragerc",
            "[report]\nignore_errors = True\nshow_missing = True\n",
            "[report]\nignore_errors = True\nshow_missing = False\n",
        ),
    ] {
        let outcome = run(signal, path, base, head);
        assert!(!outcome.fired, "{signal} fired on {path}: {outcome:?}");
        assert!(
            outcome.unassessed.is_empty(),
            "{signal} could not rank an ordinary edit to {path}, which would put a caveat \
             on every config change there is: {outcome:?}"
        );
    }
}
