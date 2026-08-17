//! Linter suppressions rising faster than the code they sit in.
//!
//! # Why density, and why a floor as well
//!
//! A raw count fires on every honest file that grows. A raw density fires on
//! every file that shrinks. So the detector wants both to move the wrong way:
//! more suppressions than before **and** more of them per line of code than
//! before, with an absolute floor underneath so that one `@ts-expect-error` in
//! a change — the single most common legitimate suppression there is — never
//! fires on its own.
//!
//! The floor is the precision decision. Recall costs something for it: a change
//! that adds exactly one suppression to silence a real finding is not caught.
//! That is the deliberate side to be wrong on, because the alternative fires on
//! the ordinary working practice of a typed codebase, and a tamper signal
//! nobody believes is worse than one that occasionally misses (PREMORTEM Story
//! 1's lesson, applied to a content detector).
//!
//! Markers are matched textually rather than parsed. They live in comments,
//! comments are the one place every grammar agrees to ignore, and a suppression
//! spelled in a language this crate has no grammar for is still a suppression.

use crate::change::ChangeView;
use crate::detectors::{Detector, Finding, Outcome};
use andon_core::schema::enums::TamperSignal;

/// The detector.
pub struct SuppressionDensity;

/// Fewer than this many added suppressions never fires, whatever the density
/// says. Two is "a pattern", one is "a Tuesday".
pub const MIN_ADDED_SUPPRESSIONS: i64 = 2;

/// Suppression markers, lower-cased, matched as substrings of a line.
///
/// Deliberately the directive text and not a full pattern: `eslint-disable`
/// covers `eslint-disable`, `eslint-disable-next-line`, and the block form,
/// which is what a reader means by "an eslint suppression".
///
/// # This list is the claim
///
/// It is an enumeration of recognised tools, not a general rule, and the
/// registry claim says so rather than implying coverage this does not have. A
/// suppression from a linter absent here is not detected, and adding one is a
/// rule-pack change: `RULE_PACK_VERSION` moves, the regime moves, and old
/// numbers stop being comparable to new ones — which is the correct
/// consequence, since what counts as a suppression has changed.
///
/// `# pragma: no cover` is deliberately *not* here. It suppresses coverage
/// measurement rather than a linter, which is
/// [`crate::detectors::coverage_exclusion_drift`]'s outcome; counting it as a
/// lint suppression would put one behaviour under two signals and double-count
/// it in any report that showed both.
pub const MARKERS: &[&str] = &[
    "eslint-disable",
    "deno-lint-ignore",
    "oxlint-disable",
    "@ts-ignore",
    "@ts-expect-error",
    "@ts-nocheck",
    "biome-ignore",
    "prettier-ignore",
    "istanbul ignore",
    "c8 ignore",
    "v8 ignore",
    "noqa",
    "type: ignore",
    "pylint: disable",
    "pyright: ignore",
    "ruff: noqa",
    "flake8: noqa",
    "mypy: ignore-errors",
    "#[allow(",
    "nosec",
    "sonarignore",
    "no-inspection",
];

impl Detector for SuppressionDensity {
    fn signal(&self) -> TamperSignal {
        TamperSignal::SuppressionDensity
    }

    fn metric_id(&self) -> &'static str {
        "tamper.suppression-density"
    }

    fn magnitude_metric_id(&self) -> &'static str {
        "tamper.suppression-density.magnitude"
    }

    fn describes(&self) -> &'static str {
        "linter and type-checker suppressions added faster than the code around them"
    }

    fn run(&self, change: &ChangeView) -> Outcome {
        let mut base_markers = 0i64;
        let mut head_markers = 0i64;
        let mut base_lines = 0i64;
        let mut head_lines = 0i64;
        let mut findings = Vec::new();

        for file in &change.files {
            if file.content_unchanged() {
                continue;
            }
            let base = scan(file.base_bytes());
            let head = scan(file.head_bytes());
            base_markers += base.markers.len() as i64;
            head_markers += head.markers.len() as i64;
            base_lines += base.code_lines as i64;
            head_lines += head.code_lines as i64;

            let added = head.markers.len() as i64 - base.markers.len() as i64;
            if added > 0 {
                // Report the markers the head carries that the base did not, by
                // text, so the finding names the directive rather than a count.
                let mut base_texts = base.markers.iter().map(|m| m.1.clone()).collect::<Vec<_>>();
                for (line, text) in &head.markers {
                    if let Some(pos) = base_texts.iter().position(|t| t == text) {
                        base_texts.remove(pos);
                        continue;
                    }
                    findings.push(Finding::at(
                        &file.path,
                        *line,
                        format!("suppression: {text}"),
                    ));
                }
            }
        }

        let added = head_markers - base_markers;
        let base_density = density(base_markers, base_lines);
        let head_density = density(head_markers, head_lines);

        if added >= MIN_ADDED_SUPPRESSIONS && head_density > base_density {
            Outcome::fired(added, findings)
        } else {
            Outcome::quiet(added)
        }
    }
}

/// Suppressions per thousand lines, in fixed-point so no float reaches a
/// comparison. `0` when there is nothing to divide by, which reads as "no
/// density" and cannot be exceeded by a file that adds none.
fn density(markers: i64, lines: i64) -> i64 {
    if lines <= 0 {
        return if markers > 0 { i64::MAX } else { 0 };
    }
    markers.saturating_mul(1000) / lines
}

#[derive(Debug, Default)]
struct Scan {
    /// `(1-based line, the marker text)`.
    markers: Vec<(u32, String)>,
    /// Non-blank lines, the denominator.
    code_lines: u32,
}

fn scan(source: &[u8]) -> Scan {
    let text = String::from_utf8_lossy(source);
    let mut scan = Scan::default();
    for (index, line) in text.lines().enumerate() {
        if !line.trim().is_empty() {
            scan.code_lines += 1;
        }
        let lower = line.to_ascii_lowercase();
        for marker in MARKERS {
            if lower.contains(marker) {
                scan.markers.push((index as u32 + 1, (*marker).to_string()));
            }
        }
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::FileChange;

    fn lines(n: usize) -> String {
        (0..n)
            .map(|i| format!("const v{i} = {i};"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn several_added_suppressions_at_rising_density_fire() {
        let base = lines(40);
        let head = format!(
            "{}\n// eslint-disable-next-line no-explicit-any\nconst a: any = 1;\n// @ts-ignore\nconst b: any = 2;\n// @ts-nocheck\n",
            lines(40)
        );
        let view = ChangeView::new(vec![FileChange::modified("src/a.ts", &base, &head)]);
        let outcome = SuppressionDensity.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 3);
        assert_eq!(outcome.findings.len(), 3);
    }

    #[test]
    fn a_single_suppression_does_not_fire() {
        let base = lines(40);
        let head = format!(
            "{}\n// @ts-expect-error legacy shim\nconst a = 1;\n",
            lines(40)
        );
        let view = ChangeView::new(vec![FileChange::modified("src/a.ts", &base, &head)]);
        let outcome = SuppressionDensity.run(&view);
        assert!(!outcome.fired);
        assert_eq!(outcome.magnitude, 1);
    }

    #[test]
    fn suppressions_that_grow_slower_than_the_file_do_not_fire() {
        // Two added, but the file tripled: density fell.
        let base = format!("// noqa\n// noqa\n{}", lines(10));
        let head = format!("// noqa\n// noqa\n// noqa\n// noqa\n{}", lines(200));
        let view = ChangeView::new(vec![FileChange::modified("src/a.py", &base, &head)]);
        assert!(!SuppressionDensity.run(&view).fired);
    }

    #[test]
    fn removing_suppressions_is_quiet_and_negative() {
        let base = format!("// @ts-ignore\n// @ts-ignore\n{}", lines(20));
        let head = lines(20);
        let view = ChangeView::new(vec![FileChange::modified("src/a.ts", &base, &head)]);
        let outcome = SuppressionDensity.run(&view);
        assert!(!outcome.fired);
        assert_eq!(outcome.magnitude, -2);
    }

    #[test]
    fn markers_are_found_in_languages_with_no_grammar_here() {
        let base = "fn a() {}\n";
        let head = "#[allow(dead_code)]\nfn a() {}\n#[allow(unused)]\nfn b() {}\n";
        let view = ChangeView::new(vec![FileChange::modified("src/a.rs", base, head)]);
        assert!(SuppressionDensity.run(&view).fired);
    }

    #[test]
    fn a_net_across_files_does_not_fire_on_a_move() {
        let with = format!("// noqa\n// noqa\n{}", lines(20));
        let without = lines(20);
        let view = ChangeView::new(vec![
            FileChange::modified("src/a.py", &with, &without),
            FileChange::modified("src/b.py", &without, &with),
        ]);
        assert!(!SuppressionDensity.run(&view).fired);
    }
}
