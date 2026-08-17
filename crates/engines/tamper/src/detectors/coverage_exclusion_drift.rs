//! Coverage configuration that excludes more than it did.
//!
//! Widening an exclusion list raises the coverage number without testing
//! anything. It is the quietest of the seven: the diff is one line in a config
//! file nobody reviews closely, and the effect is on a metric everybody reads.
//!
//! # Scanned, not parsed
//!
//! Coverage exclusions live in `.coveragerc` (INI), `pyproject.toml`,
//! `package.json`, `jest.config.js` (JavaScript), `codecov.yml`, `.nycrc`, and
//! `vitest.config.ts` — six syntaxes for one idea. What the detector needs from
//! all six is the same: *how many patterns are excluded*, which is a count of
//! entries under a known key. [`crate::config`] does the reading and explains
//! why it is a scanner rather than six parsers.
//!
//! The bluntness is bounded by the file list: only files that are coverage
//! configuration are examined at all, so a `src/exclude.ts` cannot fire this.
//!
//! # Only widening fires
//!
//! Removing an exclusion is reported as a negative magnitude and does not fire.
//! A project tightening its coverage configuration is doing the opposite of
//! gaming it.

use crate::change::ChangeView;
use crate::config;
use crate::detectors::{Detector, Finding, Outcome};
use andon_core::schema::enums::TamperSignal;

/// The detector.
pub struct CoverageExclusionDrift;

/// Keys whose values are exclusion patterns.
const EXCLUSION_KEYS: &[&str] = &[
    "omit",
    "exclude",
    "excludes",
    "exclude_lines",
    "exclude_also",
    "ignore",
    "ignores",
    "skip_covered",
    "coveragepathignorepatterns",
    "coveragereporters",
    "testpathignorepatterns",
    "exclude_dirs",
];

/// Filenames that are coverage configuration.
const COVERAGE_CONFIG_NAMES: &[&str] = &[
    ".coveragerc",
    "codecov.yml",
    ".codecov.yml",
    "codecov.yaml",
    ".nycrc",
    ".nycrc.json",
    "tarpaulin.toml",
    "setup.cfg",
    "pyproject.toml",
    "package.json",
    ".c8rc.json",
];

/// Filename fragments that are coverage configuration.
const COVERAGE_CONFIG_FRAGMENTS: &[&str] = &["jest.config", "vitest.config", "nyc.config"];

/// Whether a path is a coverage configuration file.
pub fn is_coverage_config(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    COVERAGE_CONFIG_NAMES.contains(&name)
        || COVERAGE_CONFIG_FRAGMENTS
            .iter()
            .any(|fragment| name.starts_with(fragment))
}

impl Detector for CoverageExclusionDrift {
    fn signal(&self) -> TamperSignal {
        TamperSignal::CoverageExclusionDrift
    }

    fn metric_id(&self) -> &'static str {
        "tamper.coverage-exclusion-drift"
    }

    fn magnitude_metric_id(&self) -> &'static str {
        "tamper.coverage-exclusion-drift.magnitude"
    }

    fn describes(&self) -> &'static str {
        "coverage configuration excluding more paths or lines than it did"
    }

    fn run(&self, change: &ChangeView) -> Outcome {
        let mut delta = 0i64;
        let mut findings = Vec::new();
        for file in &change.files {
            if file.content_unchanged() || !is_coverage_config(&file.path) {
                continue;
            }
            let base = exclusions(file.base_bytes());
            let head = exclusions(file.head_bytes());
            let file_delta = head.len() as i64 - base.len() as i64;
            delta += file_delta;
            if file_delta > 0 {
                let mut remaining = base.clone();
                for (line, entry) in &head {
                    if let Some(pos) = remaining.iter().position(|(_, e)| e == entry) {
                        remaining.remove(pos);
                        continue;
                    }
                    findings.push(Finding::at(
                        &file.path,
                        *line,
                        format!("coverage exclusion added: {entry}"),
                    ));
                }
            }
        }
        if delta > 0 {
            Outcome::fired(delta, findings)
        } else {
            Outcome::quiet(delta)
        }
    }
}

/// `(1-based line, entry text)` for every exclusion pattern in a config file.
///
/// Three shapes, one reader: an inline list (`exclude = ["a", "b"]`, including
/// the single-line JSON these files are often written as), a continued block
/// (`omit =` followed by indented lines), and a YAML sequence (`ignore:`
/// followed by `- a`). See [`crate::config`] for why this is a scanner and not
/// five parsers.
fn exclusions(source: &[u8]) -> Vec<(u32, String)> {
    let text = String::from_utf8_lossy(source);
    let mut out = Vec::new();
    let mut block: Option<usize> = None;

    for (index, raw) in text.lines().enumerate() {
        let line_no = index as u32 + 1;
        let indent = raw.len() - raw.trim_start().len();
        if config::is_noise(raw) {
            continue;
        }

        // A block continues while the indentation stays deeper than the key's.
        if let Some(key_indent) = block {
            if indent > key_indent {
                out.extend(
                    config::entries(raw.trim())
                        .into_iter()
                        .map(|e| (line_no, e)),
                );
                continue;
            }
            block = None;
        }

        let mut opened_block = false;
        for pair in config::pairs(raw) {
            if !EXCLUSION_KEYS.contains(&pair.key.as_str()) {
                continue;
            }
            let entries = config::entries(&pair.value);
            if entries.is_empty() {
                // A key with nothing after it opens a block.
                opened_block = true;
            } else {
                out.extend(entries.into_iter().map(|e| (line_no, e)));
            }
        }
        if opened_block {
            block = Some(indent);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::FileChange;

    #[test]
    fn an_added_omit_pattern_fires() {
        let base = "[run]\nomit =\n    tests/*\n";
        let head = "[run]\nomit =\n    tests/*\n    src/payments/*\n";
        let view = ChangeView::new(vec![FileChange::modified(".coveragerc", base, head)]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 1);
        assert!(outcome.findings[0].detail.contains("src/payments/*"));
    }

    #[test]
    fn an_inline_list_is_read_too() {
        let base = "{ \"jest\": { \"coveragePathIgnorePatterns\": [\"/node_modules/\"] } }";
        let head =
            "{ \"jest\": { \"coveragePathIgnorePatterns\": [\"/node_modules/\", \"/src/legacy/\"] } }";
        let view = ChangeView::new(vec![FileChange::modified("package.json", base, head)]);
        assert!(CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn a_yaml_sequence_is_read_too() {
        let base = "coverage:\n  status: project\nignore:\n  - vendor/**\n";
        let head = "coverage:\n  status: project\nignore:\n  - vendor/**\n  - src/billing/**\n";
        let view = ChangeView::new(vec![FileChange::modified("codecov.yml", base, head)]);
        assert!(CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn removing_an_exclusion_is_quiet_and_negative() {
        let base = "[run]\nomit =\n    tests/*\n    src/legacy/*\n";
        let head = "[run]\nomit =\n    tests/*\n";
        let view = ChangeView::new(vec![FileChange::modified(".coveragerc", base, head)]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(!outcome.fired);
        assert_eq!(outcome.magnitude, -1);
    }

    #[test]
    fn a_non_coverage_file_named_exclude_does_not_fire() {
        let base = "export const exclude = ['a'];\n";
        let head = "export const exclude = ['a', 'b', 'c'];\n";
        let view = ChangeView::new(vec![FileChange::modified("src/exclude.ts", base, head)]);
        assert!(!CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn editing_a_non_exclusion_key_does_not_fire() {
        let base = "[run]\nbranch = true\nomit =\n    tests/*\n";
        let head = "[run]\nbranch = false\nsource = src\nomit =\n    tests/*\n";
        let view = ChangeView::new(vec![FileChange::modified(".coveragerc", base, head)]);
        assert!(!CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn a_new_config_with_no_exclusions_does_not_fire() {
        let view = ChangeView::new(vec![FileChange::added(
            ".coveragerc",
            "[run]\nbranch = true\nsource = src\n",
        )]);
        assert!(!CoverageExclusionDrift.run(&view).fired);
    }
}
