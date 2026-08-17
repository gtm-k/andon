//! Tests deleted, or quietly skipped.
//!
//! # Why the count is net across the whole change
//!
//! The obvious implementation — "a test file lost tests, fire" — reports every
//! test refactoring as tampering. Splitting one suite into two, moving cases to
//! a better-named file, renaming a directory: all of them remove tests from a
//! file, and none of them removes a test. Counting across the change closes
//! that: the number that matters is how many test cases exist after against how
//! many existed before.
//!
//! What survives the net is what should: deleting a test file outright, deleting
//! cases from one, and adding a skip marker — which removes a test from the run
//! without removing it from the diff, and is the version of this that hopes
//! nobody reads the file.

use crate::change::{is_test_path, ChangeView};
use crate::detectors::{Detector, Finding, Outcome};
use crate::syntax::{callee_text, first_segment, last_segment, Parsed};
use andon_core::schema::enums::TamperSignal;

/// The detector.
pub struct TestRemoval;

/// JavaScript-family functions that declare one test case.
const JS_CASE: &[&str] = &["it", "test", "xit", "xtest", "fit", "bench"];

/// Suffixes that take a case out of the run without deleting it.
const JS_SKIP_SUFFIX: &[&str] = &["skip", "todo", "concurrent.skip"];

/// Python decorators that take a case out of the run.
const PY_SKIP: &[&str] = &["skip", "skipif", "skipunless", "skiptest"];

impl Detector for TestRemoval {
    fn signal(&self) -> TamperSignal {
        TamperSignal::TestRemoval
    }

    fn metric_id(&self) -> &'static str {
        "tamper.test-removal"
    }

    fn magnitude_metric_id(&self) -> &'static str {
        "tamper.test-removal.magnitude"
    }

    fn describes(&self) -> &'static str {
        "test cases deleted from the change, or newly marked skipped"
    }

    fn run(&self, change: &ChangeView) -> Outcome {
        let mut before = 0i64;
        let mut after = 0i64;
        let mut skips_added = 0i64;
        let mut findings = Vec::new();

        for file in &change.files {
            // A pure move carries its tests with it; counting both sides of it
            // would be counting the same cases twice in opposite directions,
            // which nets to zero anyway — skipping it keeps the findings clean.
            if file.content_unchanged() {
                continue;
            }

            let base_is_test = is_test_path(file.base_path());
            let head_is_test = is_test_path(&file.path);
            if !base_is_test && !head_is_test {
                continue;
            }

            let base = count(file.base_path(), file.base_bytes());
            let head = count(&file.path, file.head_bytes());
            before += base.cases as i64;
            after += head.cases as i64;

            let new_skips = head.skipped as i64 - base.skipped as i64;
            if new_skips > 0 {
                skips_added += new_skips;
                findings.push(Finding::in_file(
                    &file.path,
                    format!("{new_skips} test case(s) newly marked skipped"),
                ));
            }
            if head.cases < base.cases {
                findings.push(Finding::in_file(
                    &file.path,
                    format!(
                        "{} test case(s) present at the base are gone ({} -> {})",
                        base.cases - head.cases,
                        base.cases,
                        head.cases
                    ),
                ));
            }
        }

        let removed = (before - after).max(0);
        let magnitude = removed + skips_added;
        if magnitude > 0 {
            Outcome::fired(magnitude, findings)
        } else {
            // Reported as the net, negative included: a change that adds tests
            // is worth saying so about, and a magnitude that only ever went one
            // way would make "no removal" and "many additions" the same number.
            Outcome::quiet(after - before)
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    cases: u32,
    skipped: u32,
}

/// Count test cases and skipped cases in one file.
fn count(path: &str, source: &[u8]) -> Counts {
    let Some(parsed) = Parsed::new(path, source) else {
        return Counts::default();
    };
    if parsed.language().is_js_family() {
        count_js(&parsed)
    } else {
        count_python(&parsed)
    }
}

fn count_js(parsed: &Parsed) -> Counts {
    let mut counts = Counts::default();
    for node in parsed.nodes() {
        let Some(callee) = callee_text(parsed, node) else {
            continue;
        };
        let base = first_segment(&callee);
        if !JS_CASE.contains(&base) {
            continue;
        }
        counts.cases += 1;
        let tail = last_segment(&callee);
        // `xit`/`xtest` are the skip spelling that hides in the function name
        // rather than in a suffix.
        if JS_SKIP_SUFFIX.contains(&tail) || base.starts_with('x') {
            counts.skipped += 1;
        }
    }
    counts
}

fn count_python(parsed: &Parsed) -> Counts {
    let mut counts = Counts::default();
    for node in parsed.nodes() {
        if node.kind() != "function_definition" {
            continue;
        }
        let Some(name) = node.child_by_field_name("name") else {
            continue;
        };
        if !parsed.text(name).starts_with("test") {
            continue;
        }
        counts.cases += 1;

        // Decorators sit on the `decorated_definition` that wraps the function,
        // so the skip marker is found by looking up rather than down.
        let mut parent = node.parent();
        while let Some(node) = parent {
            if node.kind() == "decorated_definition" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() != "decorator" {
                        continue;
                    }
                    let text = parsed.text(child).to_ascii_lowercase();
                    let last =
                        last_segment(text.trim_start_matches('@').split('(').next().unwrap_or(""));
                    if PY_SKIP.contains(&last) {
                        counts.skipped += 1;
                        break;
                    }
                }
                break;
            }
            parent = node.parent();
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::FileChange;

    const TWO: &str =
        "it('a', () => { expect(1).toBe(1); });\nit('b', () => { expect(2).toBe(2); });\n";
    const ONE: &str = "it('a', () => { expect(1).toBe(1); });\n";

    #[test]
    fn deleting_a_case_fires() {
        let view = ChangeView::new(vec![FileChange::modified("src/a.test.ts", TWO, ONE)]);
        let outcome = TestRemoval.run(&view);
        assert!(outcome.fired);
        assert_eq!(outcome.magnitude, 1);
    }

    #[test]
    fn deleting_a_whole_test_file_fires() {
        let view = ChangeView::new(vec![FileChange::deleted("src/a.test.ts", TWO)]);
        let outcome = TestRemoval.run(&view);
        assert!(outcome.fired);
        assert_eq!(outcome.magnitude, 2);
    }

    #[test]
    fn moving_cases_between_files_does_not_fire() {
        let view = ChangeView::new(vec![
            FileChange::modified("src/a.test.ts", TWO, ONE),
            FileChange::modified("src/b.test.ts", "", ONE),
        ]);
        assert!(!TestRemoval.run(&view).fired);
    }

    #[test]
    fn renaming_a_test_file_does_not_fire() {
        let view = ChangeView::new(vec![FileChange::renamed(
            "src/a.test.ts",
            "src/user.test.ts",
            TWO,
            TWO,
        )]);
        assert!(!TestRemoval.run(&view).fired);
    }

    #[test]
    fn a_skip_marker_fires_even_though_the_case_is_still_there() {
        let head = "it.skip('a', () => { expect(1).toBe(1); });\n";
        let view = ChangeView::new(vec![FileChange::modified("src/a.test.ts", ONE, head)]);
        let outcome = TestRemoval.run(&view);
        assert!(outcome.fired);
        assert_eq!(outcome.magnitude, 1);
    }

    #[test]
    fn python_skips_are_found_on_the_decorator() {
        let base = "def test_a():\n    assert 1 == 1\n";
        let head = "import pytest\n\n@pytest.mark.skip(reason='flaky')\ndef test_a():\n    assert 1 == 1\n";
        let view = ChangeView::new(vec![FileChange::modified("tests/test_a.py", base, head)]);
        assert!(TestRemoval.run(&view).fired);
    }

    #[test]
    fn adding_tests_is_quiet_and_reports_a_positive_net() {
        let view = ChangeView::new(vec![FileChange::modified("src/a.test.ts", ONE, TWO)]);
        let outcome = TestRemoval.run(&view);
        assert!(!outcome.fired);
        assert_eq!(outcome.magnitude, 1);
    }

    #[test]
    fn non_test_files_are_not_counted() {
        let view = ChangeView::new(vec![FileChange::modified("src/app.ts", TWO, ONE)]);
        assert!(!TestRemoval.run(&view).fired);
    }
}
