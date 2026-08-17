//! Quality thresholds loosened inside the change being measured.
//!
//! # This one is advisory, and that is a design decision
//!
//! PLAN round-1 B6: a tool that blocks on policy edits has made legitimate
//! policy evolution impossible, and a project that cannot change its own
//! thresholds will change tools instead. So this detector reports at `Low` — it
//! is the one of the seven whose firing is a note rather than a stop, and P5a's
//! verdict assembly is where the "loosening without a ledgered justification"
//! rule lives.
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
    "med_plus_requires_diff_actionable",
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
        // Advisory by PLAN round-1 B6. Policy evolution must stay possible.
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

    if let (Some(b), Some(a)) = (rank(before), rank(after)) {
        return (a < b).then_some("severity lowered");
    }
    if STRICT_WHEN_TRUE.iter().any(|k| leaf == *k) && before == "true" && after == "false" {
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

/// Position in [`SEVERITY_WORDS`], for values that are severity words.
fn rank(value: &str) -> Option<usize> {
    let value = value.trim().to_ascii_lowercase();
    SEVERITY_WORDS.iter().position(|w| *w == value)
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
    fn firing_is_advisory_not_blocking() {
        assert_eq!(ThresholdConfigEdit.severity_when_fired(), Severity::Low);
    }
}
