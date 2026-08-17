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
//!
//! # A delta alone can be walked around, so state is watched too
//!
//! Park the parse errors in one commit; add the evasive code to the same file in
//! the next. The fault count does not move, the delta reads zero, and the new
//! code is inside a region no static engine reads. P2's adversarial lens found
//! this shape and it applies here unchanged.
//!
//! The cleanest entry into that shape needs no invalid syntax at all. tree-sitter's
//! Python scanner keeps a fixed-size indent stack, so a file that is legal Python
//! at every line becomes unparseable past a certain nesting depth — pure
//! whitespace, nothing a reviewer would call a syntax error. See
//! `INDENT_STACK_LIMIT_PYTHON`.
//!
//! So there is a second arm: a **changed** file that is degraded at all fires,
//! at `Low`, even when the delta is zero. It is a weaker claim and says so —
//! an honest legacy file with an old syntax error and a deliberately parked one
//! are the same bytes, and no static rule separates them. What the arm buys is
//! that the blind spot is *visible* on every change that touches it, rather
//! than visible only on the commit that created it.
//!
//! The two arms are distinguishable without a new signal: the hard arm reports
//! `magnitude > 0`, the soft arm reports `magnitude <= 0` with a finding that
//! says so. `TamperSignal` is P0-owned schema, and an eighth value for a
//! second strength of the same observation would be a schema change for a
//! severity.

use crate::change::ChangeView;
use crate::detectors::{Detector, Finding, Outcome};
use crate::syntax::Parsed;
use andon_core::schema::enums::{Severity, TamperSignal};

/// The detector.
pub struct ParseErrorDelta;

/// Indentation levels past which the pinned Python grammar stops parsing.
///
/// # A blind spot that costs no invalid syntax
///
/// tree-sitter's Python external scanner keeps a fixed-size indent stack. Past
/// its capacity the parse fails — on a file that is legal Python on every line.
/// Whitespace alone makes a file unreadable to every static engine, which is the
/// most deniable possible way to prepare the pre-seeded-degradation shape above:
/// nothing in the diff looks like an error, because nothing is one.
///
/// Measured on this crate's pin, `tree-sitter-python 0.25.0`, by bisection:
/// **512 levels**, identical for four-space, one-space, and tab indentation —
/// so it is a count of levels rather than of columns or bytes. The static engine
/// reported ~64 on `0.23.6` — an eightfold difference between two pins of the
/// same grammar, and for one wave the two engines genuinely disagreed about
/// whether the same file was degraded. The wave-1 integration converged them
/// (PLAN.md P3 execution (e)); `andon-static-metrics` bisected the same 512
/// independently and holds it in `lang::INDENT_STACK_LIMIT_PYTHON`.
///
/// Two consequences worth stating rather than discovering:
///
/// 1. The constant is a property of the pinned grammar, not of Python, so it
///    belongs with the pins and moves with them. `tests/regime_pins.rs` holds the
///    pins against `Cargo.lock`; this is asserted directly against the parser.
/// 2. Two engines on different pins disagree about whether the same file is
///    degraded. That is exactly what `measurement_regime` exists to expose —
///    but only to a reader who compares regimes, which is a P5a concern once one
///    payload carries both engines' results.
pub const INDENT_STACK_LIMIT_PYTHON: usize = 512;

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
            return Outcome::fired(delta, findings);
        }

        // The delta did not rise. A changed file that is *already* degraded is
        // still a blind spot, and the pre-seeded evasion lives exactly here.
        let degraded: Vec<Finding> = change
            .files
            .iter()
            .filter(|file| !file.content_unchanged() && file.head.is_some())
            .filter_map(|file| {
                let faults = faults(&file.path, file.head_bytes())?;
                (faults > 0).then(|| {
                    Finding::in_file(
                        &file.path,
                        // One line, deliberately. Written across three source
                        // lines this string kept the indentation of the source
                        // inside the message, so the detail a reader saw had a
                        // run of thirty spaces in the middle of a sentence.
                        format!("changed file is parse-degraded: {faults} parse fault(s) present, no rise in this change — the region is unreadable to every static engine either way"),
                    )
                })
            })
            .collect();
        if degraded.is_empty() {
            Outcome::quiet(delta)
        } else {
            Outcome::fired_at(Severity::Low, delta, degraded)
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
    fn pre_existing_errors_in_a_touched_file_fire_softly_rather_than_not_at_all() {
        // This test asserted the opposite until the state arm existed, and the
        // change of answer is the point rather than a regression. A file that is
        // degraded and gets edited is a blind spot the change is working inside,
        // and Andon cannot tell an old syntax error from a parked one. The
        // honest reporting is "yes, and weakly" — not silence, and not an
        // accusation.
        let head = format!("{BROKEN}\n");
        let view = ChangeView::new(vec![FileChange::modified("src/a.ts", BROKEN, &head)]);
        let outcome = ParseErrorDelta.run(&view);
        assert!(outcome.fired);
        assert_eq!(outcome.severity, Some(Severity::Low));
        assert!(outcome.magnitude <= 0, "nothing got worse: {outcome:?}");
    }

    #[test]
    fn an_untouched_degraded_file_is_not_this_changes_business() {
        // Only *changed* files reach the state arm. A repository full of legacy
        // parse errors must not make every change a finding.
        let view = ChangeView::new(vec![
            FileChange::modified("src/a.ts", BROKEN, BROKEN),
            FileChange::modified("src/b.ts", CLEAN, CLEAN),
        ]);
        assert!(!ParseErrorDelta.run(&view).fired);
    }

    /// Legal Python at every line, nested past the grammar's indent stack.
    fn whitespace_degraded(levels: usize) -> String {
        let mut source = String::from(
            "def f():
",
        );
        for level in 0..levels {
            source.push_str(&"    ".repeat(level + 1));
            source.push_str(
                "if True:
",
            );
        }
        source.push_str(&"    ".repeat(levels + 1));
        source.push_str(
            "return 1
",
        );
        source
    }

    #[test]
    fn the_pinned_python_grammar_degrades_past_its_indent_stack() {
        // Asserted against the parser rather than trusted from a changelog: the
        // limit is a property of the pin and a grammar bump moves it. Both sides
        // of the boundary, so a bump in either direction shows up here.
        let below = whitespace_degraded(INDENT_STACK_LIMIT_PYTHON - 1);
        let at = whitespace_degraded(INDENT_STACK_LIMIT_PYTHON);
        assert_eq!(
            Parsed::new("t.py", below.as_bytes())
                .unwrap()
                .parse_faults(),
            0,
            "the indent stack now holds fewer than {INDENT_STACK_LIMIT_PYTHON} levels"
        );
        assert!(
            Parsed::new("t.py", at.as_bytes()).unwrap().parse_faults() > 0,
            "the indent stack now holds more than {INDENT_STACK_LIMIT_PYTHON} levels"
        );
        // And the file really is legal Python: no invalid token anywhere, which
        // is what makes this route deniable.
        assert!(at.is_ascii());
        assert!(!at.contains("!!!"));
    }

    #[test]
    fn a_whitespace_only_blind_spot_is_caught_on_the_next_change() {
        // The two-commit shape, second commit. The file was made unparseable by
        // indentation alone; this change adds a payload and the fault count does
        // not move. Cross-phase intel from P2's adversarial lens.
        let base = whitespace_degraded(INDENT_STACK_LIMIT_PYTHON);
        let head = format!(
            "{base}

def evasive(x):
    return x * 2
"
        );
        let view = ChangeView::new(vec![FileChange::modified("src/deep.py", &base, &head)]);
        let outcome = ParseErrorDelta.run(&view);
        assert!(
            outcome.fired,
            "a payload added to a whitespace-degraded file must not be silent: {outcome:?}"
        );
        assert_eq!(outcome.severity, Some(Severity::Low));
        assert!(outcome.findings[0].detail.contains("parse-degraded"));
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
