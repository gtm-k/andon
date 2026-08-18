//! Quality thresholds loosened inside the change being measured.
//!
//! # This one is conditional, and the condition is not the file it found
//!
//! PLAN round-1 B6: a tool that blocks on policy edits has made legitimate
//! policy evolution impossible, and a project that cannot change its own
//! thresholds will change tools instead. So this is the one of the seven whose
//! firing is not an unconditional stop, and P5a's verdict assembly is where the
//! "loosening without a ledgered justification" rule lives.
//!
//! **It is not, however, advisory.** That was the first version of the rule and
//! it was wrong in a way this detector is uniquely placed to cause: the
//! exemption was keyed on the signal's enum variant, so *every* firing was a
//! note rather than a stop — while the justification route it was nominally
//! handed to parses `.andon.toml` and nothing else. This detector reads ESLint,
//! tsconfig, mypy, ruff, coverage configuration and a dozen more, so a real
//! loosening in any of them took an exemption with nowhere behind it to be ruled
//! on. Since then a firing stops the line unless a **verified** ledgered
//! justification covers the change, wherever the threshold lived
//! (`andon_core::verdict::severity::signal_stops_the_line`).
//!
//! The reported severity stays `Low`, and that is not a contradiction: blocking
//! is keyed on the flag and never on the severity, for the muzzle reason
//! `andon_core::verdict::severity` sets out. `Low` says how strong this finding
//! is, not whether the line stops.
//!
//! What the detector still owes is an accurate *delta*: which threshold moved,
//! in which direction. A `policy-change` finding that cannot say what changed is
//! not worth reporting.
//!
//! # Only loosening counts
//!
//! Tightening a rule is the opposite of gaming it. `error` -> `warn` fires,
//! `warn` -> `error` does not; a coverage minimum falling fires, one rising does
//! not; `strict: true` -> `false` fires, the reverse does not.

use std::collections::BTreeMap;

use crate::change::ChangeView;
use crate::config;
use crate::detectors::{Detector, Finding, Outcome};
use andon_core::schema::enums::{Severity, TamperSignal};

/// The detector.
pub struct ThresholdConfigEdit;

/// Configuration files that carry quality thresholds.
const CONFIG_NAMES: &[&str] = &[
    ".andon.toml",
    "tsconfig.json",
    "tsconfig.base.json",
    ".eslintrc",
    ".eslintrc.json",
    ".eslintrc.js",
    ".eslintrc.yml",
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.ts",
    "biome.json",
    ".flake8",
    "setup.cfg",
    "pyproject.toml",
    "mypy.ini",
    ".mypy.ini",
    "ruff.toml",
    ".ruff.toml",
    "clippy.toml",
    "sonar-project.properties",
    ".golangci.yml",
    ".golangci.yaml",
    "package.json",
];

/// Filename fragments that are threshold configuration.
const CONFIG_FRAGMENTS: &[&str] = &["jest.config", "vitest.config", "sonar-project"];

/// Whether a path is threshold configuration.
pub fn is_threshold_config(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    CONFIG_NAMES.contains(&name)
        || CONFIG_FRAGMENTS
            .iter()
            .any(|fragment| name.starts_with(fragment))
}

/// Severity words, weakest first. A move down this list is a loosening.
const SEVERITY_WORDS: &[&str] = &[
    "off", "none", "ignore", "info", "hint", "warn", "warning", "error", "deny", "forbid",
];

/// Keys whose numeric value is a floor: lowering one loosens.
const FLOOR_KEY_FRAGMENTS: &[&str] = &[
    "threshold",
    "minimum",
    "min_",
    "min-",
    "branches",
    "functions",
    "lines",
    "statements",
    "coverage",
    "fail_under",
    "fail-under",
    "max_severity",
    "budget",
];

/// Keys whose numeric value is a ceiling: raising one loosens.
const CEILING_KEY_FRAGMENTS: &[&str] = &[
    "max_complexity",
    "max-complexity",
    "max_line_length",
    "max-line-length",
    "max_warnings",
    "max-warnings",
    "max_errors",
    "max-errors",
    "cognitive-complexity",
    "iteration_cap",
];

/// Boolean keys where `true` is the strict setting.
const STRICT_WHEN_TRUE: &[&str] = &[
    "strict",
    "strictnullchecks",
    "noimplicitany",
    "noimplicitreturns",
    "nounusedlocals",
    "nounusedparameters",
    "strictfunctiontypes",
    "strictbindcallapply",
    "alwaysstrict",
    "usedefineforclassfields",
    "block_on_tamper",
    "block_on_test_failure",
    // `med_plus_requires_diff_actionable` is deliberately absent, and it used to
    // be here. Read as a key name it looks like a strictness flag; read against
    // what the field does it is the opposite — it *restricts* the MED+ band to
    // metrics the agent can act on, so turning it off lets MORE findings block.
    // Turning it off is an unwise tightening (PREMORTEM A4's uninstall loop),
    // not a gaming move, and firing here put a tamper signal in the payload for
    // an honest edit. `andon_core::verdict::policy_change::direction_of` is
    // authoritative for `.andon.toml`, and
    // `the_detector_and_the_direction_table_agree_about_every_policy_field`
    // fails if this list ever contradicts it again.
    "disallow_untyped_defs",
    "check_untyped_defs",
    "warn_unused_ignores",
    "exclusion_drift_signal",
];

impl Detector for ThresholdConfigEdit {
    fn signal(&self) -> TamperSignal {
        TamperSignal::ThresholdConfigEdit
    }

    fn metric_id(&self) -> &'static str {
        "tamper.threshold-config-edit"
    }

    fn magnitude_metric_id(&self) -> &'static str {
        "tamper.threshold-config-edit.magnitude"
    }

    fn describes(&self) -> &'static str {
        "a quality threshold or strictness flag loosened inside the measured change"
    }

    fn severity_when_fired(&self) -> Severity {
        // The weakest of the seven, and it says how strong the finding is rather
        // than whether the line stops — blocking is keyed on the flag. B6's
        // exemption lives in `severity::signal_stops_the_line` and is
        // conditional on a verified justification, not on this number.
        Severity::Low
    }

    fn run(&self, change: &ChangeView) -> Outcome {
        let mut findings = Vec::new();
        for file in &change.files {
            if file.content_unchanged() || !is_threshold_config(&file.path) {
                continue;
            }
            let base = settings(file.base_bytes());
            let head = settings(file.head_bytes());
            for (key, (line, head_value)) in &head {
                let Some((_, base_value)) = base.get(key) else {
                    continue;
                };
                if base_value == head_value {
                    continue;
                }
                if let Some(reason) = loosening(key, base_value, head_value) {
                    findings.push(Finding::at(
                        &file.path,
                        *line,
                        format!("{key}: {base_value} -> {head_value} ({reason})"),
                    ));
                }
            }
        }
        let count = findings.len() as i64;
        if count > 0 {
            Outcome::fired(count, findings)
        } else {
            Outcome::quiet(0)
        }
    }
}

/// Why a value change is a loosening, or `None` when it is not one.
fn loosening(key: &str, before: &str, after: &str) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    let leaf = key.rsplit('.').next().unwrap_or(&key).to_string();
    // Booleans are spelled `true` in TOML and JSON, `True` in an INI file that
    // Python wrote, and `yes` in some YAML. Comparing them as written meant
    // `disallow_untyped_defs = True -> False` in mypy.ini read as an ordinary
    // string edit; the corpus caught it.
    let before_bool = boolean(before);
    let after_bool = boolean(after);

    if let (Some(b), Some(a)) = (rank(before), rank(after)) {
        return (a < b).then_some("severity lowered");
    }
    if STRICT_WHEN_TRUE.iter().any(|k| leaf == *k)
        && before_bool == Some(true)
        && after_bool == Some(false)
    {
        return Some("strictness turned off");
    }
    if let (Ok(b), Ok(a)) = (before.parse::<f64>(), after.parse::<f64>()) {
        if CEILING_KEY_FRAGMENTS.iter().any(|k| key.contains(k)) {
            return (a > b).then_some("allowance raised");
        }
        if FLOOR_KEY_FRAGMENTS.iter().any(|k| key.contains(k)) {
            return (a < b).then_some("floor lowered");
        }
    }
    None
}

/// A configuration boolean, however the file's syntax spells it.
fn boolean(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// Position in [`SEVERITY_WORDS`], for values that are severity words.
fn rank(value: &str) -> Option<usize> {
    let value = severity_token(value).to_ascii_lowercase();
    SEVERITY_WORDS.iter().position(|w| *w == value)
}

/// The severity out of a rule value, whichever of eslint's two forms it is in.
///
/// `"no-explicit-any": "error"` and
/// `"no-explicit-any": ["error", { "fixToUnknown": true }]` say the same thing,
/// and the second is the form every real configuration uses as soon as a rule
/// takes options. Reading the array as an opaque string meant the most common
/// downgrade in the ecosystem was invisible.
///
/// Only the severity is read. `["error", 10] -> ["error", 40]` raises an option
/// inside a rule and is *not* caught: knowing which option is a threshold means
/// knowing the rule, which is a per-linter rule table this detector does not
/// have. Recorded in the known-limitations list rather than left to be
/// discovered.
fn severity_token(value: &str) -> &str {
    let trimmed = value.trim();
    let Some(inner) = trimmed.strip_prefix('[') else {
        return trimmed;
    };
    inner
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches(['"', '\'', ']'])
        .trim()
}

/// Every `key = value` in a config file, as a flat map.
///
/// Keys are qualified by the enclosing bracketed section when there is one
/// (`[severity]` in TOML, `[run]` in INI), so `severity.max_severity_for_c_tier`
/// does not collide with a same-named key elsewhere. JSON and YAML nesting is
/// deliberately not tracked — see [`crate::config`] for why a leaf key is the
/// right granularity here.
fn settings(source: &[u8]) -> BTreeMap<String, (u32, String)> {
    let text = String::from_utf8_lossy(source);
    let mut out = BTreeMap::new();
    let mut section = String::new();
    for (index, raw) in text.lines().enumerate() {
        if config::is_noise(raw) {
            continue;
        }
        if let Some(found) = config::section(raw) {
            section = found;
            continue;
        }
        for pair in config::pairs(raw) {
            if pair.value.is_empty() {
                continue;
            }
            let qualified = if section.is_empty() {
                pair.key
            } else {
                format!("{section}.{}", pair.key)
            };
            out.insert(qualified, (index as u32 + 1, pair.value));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::FileChange;

    #[test]
    fn an_eslint_rule_downgraded_to_warn_fires() {
        let base = "{ \"rules\": { \"no-explicit-any\": \"error\" } }";
        let head = "{ \"rules\": { \"no-explicit-any\": \"warn\" } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("severity lowered"));
    }

    #[test]
    fn the_array_rule_form_is_read_too() {
        // The form every real eslint config uses once a rule takes options.
        let base =
            "{ \"rules\": { \"no-explicit-any\": [\"error\", { \"fixToUnknown\": true }] } }";
        let head = "{ \"rules\": { \"no-explicit-any\": [\"warn\", { \"fixToUnknown\": true }] } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("severity lowered"));
    }

    #[test]
    fn the_array_rule_form_is_directional_too() {
        let base = "{ \"rules\": { \"complexity\": [\"warn\", 10] } }";
        let head = "{ \"rules\": { \"complexity\": [\"error\", 10] } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn upgrading_a_rule_does_not_fire() {
        let base = "{ \"rules\": { \"no-explicit-any\": \"warn\" } }";
        let head = "{ \"rules\": { \"no-explicit-any\": \"error\" } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn turning_off_typescript_strictness_fires() {
        let base = "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2022\" } }";
        let head = "{ \"compilerOptions\": { \"strict\": false, \"target\": \"es2022\" } }";
        let view = ChangeView::new(vec![FileChange::modified("tsconfig.json", base, head)]);
        assert!(ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn lowering_a_coverage_floor_fires() {
        let base = "[tool.coverage.report]\nfail_under = 85\n";
        let head = "[tool.coverage.report]\nfail_under = 60\n";
        let view = ChangeView::new(vec![FileChange::modified("pyproject.toml", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("floor lowered"));
    }

    #[test]
    fn raising_a_complexity_allowance_fires() {
        let base = "[flake8]\nmax-complexity = 10\n";
        let head = "[flake8]\nmax-complexity = 40\n";
        let view = ChangeView::new(vec![FileChange::modified("setup.cfg", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("allowance raised"));
    }

    #[test]
    fn raising_a_coverage_floor_does_not_fire() {
        let base = "[tool.coverage.report]\nfail_under = 60\n";
        let head = "[tool.coverage.report]\nfail_under = 85\n";
        let view = ChangeView::new(vec![FileChange::modified("pyproject.toml", base, head)]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn an_unrelated_config_edit_does_not_fire() {
        let base = "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2020\" } }";
        let head = "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2022\" } }";
        let view = ChangeView::new(vec![FileChange::modified("tsconfig.json", base, head)]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn a_source_file_with_a_threshold_shaped_constant_does_not_fire() {
        let base = "export const maxComplexity = 10;\n";
        let head = "export const maxComplexity = 40;\n";
        let view = ChangeView::new(vec![FileChange::modified("src/limits.ts", base, head)]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn an_ini_written_boolean_is_still_a_boolean() {
        let base = "[mypy]
disallow_untyped_defs = True
";
        let head = "[mypy]
disallow_untyped_defs = False
";
        let view = ChangeView::new(vec![FileChange::modified("mypy.ini", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("strictness turned off"));
    }

    #[test]
    fn a_firing_is_the_weakest_of_the_seven_and_that_is_not_what_decides_the_line() {
        // Renamed from `firing_is_advisory_not_blocking`, which stopped being
        // true when the exemption was narrowed: an unjustified loosening stops
        // the line. What the severity says is how strong the finding is.
        assert_eq!(ThresholdConfigEdit.severity_when_fired(), Severity::Low);
        assert!(!ThresholdConfigEdit.severity_when_fired().is_med_plus());
    }
}
