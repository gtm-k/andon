//! More of the change unparseable than there was before.
//!
//! PREMORTEM T3, the seventh detector and the one that watches the other six.
//! A tree-sitter ERROR node is a region the static engines cannot read: no
//! complexity, no clone fingerprint, no assertion count. Code that does not
//! parse is code that does not appear in any number, so a rising parse-error
//! count is a rising blind spot — whether it was put there deliberately or
//! arrived with a syntax the vendored grammar does not know.
//!
//! # It is not an accusation, and the report says so
//!
//! Most rises are honest: a new language feature, a `.ts` file holding
//! something the pinned TypeScript grammar predates, a genuine syntax error on
//! a work-in-progress branch. The detector's job is to make the blind spot
//! visible, and PLAN P2's `parse-degraded` completeness is what stops those
//! files from carrying full-confidence numbers. This signal is what stops the
//! blind spot from being *silent*.
//!
//! # Files the grammars cannot read at all are not counted
//!
//! A `.rs` or `.go` file has no parse-error count here because it has no parse.
//! Counting it as zero would be a fabricated measurement; counting it as
//! degraded would fire on every polyglot repository.

use crate::change::ChangeView;
use crate::detectors::{Detector, Finding, Outcome};
use crate::syntax::Parsed;
use andon_core::schema::enums::TamperSignal;

/// The detector.
pub struct ParseErrorDelta;

impl Detector for ParseErrorDelta {
    fn signal(&self) -> TamperSignal {
        TamperSignal::ParseErrorDelta
    }

    fn metric_id(&self) -> &'static str {
        "tamper.parse-error-delta"
    }

    fn magnitude_metric_id(&self) -> &'static str {
        "tamper.parse-error-delta.magnitude"
    }

    fn describes(&self) -> &'static str {
        "parser ERROR and MISSING nodes rising across the change, hiding code from every static engine"
    }

    fn run(&self, change: &ChangeView) -> Outcome {
        let mut delta = 0i64;
        let mut findings = Vec::new();
        for file in &change.files {
            if file.content_unchanged() {
                continue;
            }
            let base = faults(file.base_path(), file.base_bytes());
            let head = faults(&file.path, file.head_bytes());
            let (Some(base), Some(head)) = (or_zero(base, file.head.is_some()), head) else {
                // No grammar reads this path on one side or the other, so there
                // is no comparison to make. Never a fabricated zero.
                continue;
            };
            delta += head as i64 - base as i64;
            if head > base {
                findings.push(Finding::in_file(
                    &file.path,
                    format!("parse faults rose from {base} to {head}"),
                ));
            }
        }
        if delta > 0 {
            Outcome::fired(delta, findings)
        } else {
            Outcome::quiet(delta)
        }
    }
}

/// Fault count for a file, or `None` when no grammar reads it.
fn faults(path: &str, source: &[u8]) -> Option<u32> {
    Parsed::new(path, source).map(|parsed| parsed.parse_faults())
}

/// A new file has no base side, and that is a zero rather than an absence: it
/// contributed no faults before because it did not exist.
fn or_zero(base: Option<u32>, head_exists: bool) -> Option<u32> {
    match base {
        Some(count) => Some(count),
        None if head_exists => Some(0),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::FileChange;

    const CLEAN: &str = "export function f(a: number): number {\n  return a + 1;\n}\n";
    const BROKEN: &str = "export function f(a: number: number {\n  return a + ;\n";

    #[test]
    fn code_that_stops_parsing_fires() {
        let view = ChangeView::new(vec![FileChange::modified("src/a.ts", CLEAN, BROKEN)]);
        let outcome = ParseErrorDelta.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.magnitude > 0);
    }

    #[test]
    fn a_new_unparseable_file_fires() {
        let view = ChangeView::new(vec![FileChange::added("src/a.ts", BROKEN)]);
        assert!(ParseErrorDelta.run(&view).fired);
    }

    #[test]
    fn clean_code_does_not_fire() {
        let view = ChangeView::new(vec![FileChange::modified(
            "src/a.ts",
            CLEAN,
            "export function f(a: number): number {\n  return a + 2;\n}\n",
        )]);
        let outcome = ParseErrorDelta.run(&view);
        assert!(!outcome.fired);
        assert_eq!(outcome.magnitude, 0);
    }

    #[test]
    fn fixing_a_parse_error_is_quiet_and_negative() {
        let view = ChangeView::new(vec![FileChange::modified("src/a.ts", BROKEN, CLEAN)]);
        let outcome = ParseErrorDelta.run(&view);
        assert!(!outcome.fired);
        assert!(outcome.magnitude < 0);
    }

    #[test]
    fn pre_existing_errors_left_alone_do_not_fire() {
        let head = format!("{BROKEN}\n");
        let view = ChangeView::new(vec![FileChange::modified("src/a.ts", BROKEN, &head)]);
        assert!(!ParseErrorDelta.run(&view).fired);
    }

    #[test]
    fn a_language_with_no_grammar_is_not_counted_as_zero() {
        // Deliberately not valid Rust either; if it were being parsed, this
        // would fire.
        let view = ChangeView::new(vec![FileChange::added("src/a.rs", "fn f( { !!! ")]);
        let outcome = ParseErrorDelta.run(&view);
        assert!(!outcome.fired);
        assert_eq!(outcome.magnitude, 0);
    }

    #[test]
    fn a_deleted_unparseable_file_does_not_fire() {
        let view = ChangeView::new(vec![FileChange::deleted("src/a.ts", BROKEN)]);
        let outcome = ParseErrorDelta.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
    }
}
