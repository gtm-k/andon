//! Tests that run code and check nothing.
//!
//! A test with no assertion passes whatever the code does. It moves coverage,
//! satisfies a "tests added" requirement, and verifies nothing — which makes it
//! the cheapest way to appear to have tested a change.
//!
//! # What counts as an assertion is deliberately generous
//!
//! Anything that looks like `expect(...)`, an `assert` in any spelling, a
//! `should`, a `.toBe`-family matcher, `pytest.raises`, a `throws`, or a
//! snapshot call. Projects write custom assertion helpers, and a detector that
//! only knew `expect` would fire on every codebase with a `expectUser()` wrapper
//! — a false positive on good practice. The should-pass corpus carries several
//! of those shapes.
//!
//! The cost is recall: a test whose only "assertion" is a helper named nothing
//! like an assertion is missed. That is the right side to be wrong on here, for
//! the same reason as the suppression floor.
//!
//! # Only newly-added and newly-emptied tests fire
//!
//! A test that asserted nothing before the change and still asserts nothing is
//! pre-existing debt, not something this change did. Firing on it would make
//! every change to a legacy test file a tamper report.

use std::collections::BTreeMap;

use crate::change::{is_test_path, ChangeView};
use crate::detectors::{Detector, Finding, Outcome};
use crate::syntax::{callee_text, first_segment, is_curried_inner, Parsed};
use andon_core::schema::enums::TamperSignal;
use tree_sitter::Node;

/// The detector.
pub struct AssertionFreeTest;

/// JavaScript-family functions that declare one test case.
const JS_CASE: &[&str] = &["it", "test", "xit", "xtest", "fit", "bench"];

/// Callee fragments that mean "this line checks something".
///
/// Matched against the **whole** callee text, not against its first or last
/// segment. The should-style idiom is the reason: `subtotal(lines).should.equal(0)`
/// has `subtotal` at the front and `equal` at the back, and the only thing in it
/// that says "assertion" is in the middle. A segment-wise match reported an
/// entire should-style suite as assertion-free, which the should-pass corpus
/// caught.
///
/// Correspondingly generic fragments are out. `check` matched `checkout(...)`
/// and `must` matches half the words in English; both would have made the
/// detector believe anything.
const ASSERTION_HINTS: &[&str] = &[
    "expect",
    "assert",
    "should",
    "verify",
    "raises",
    "throws",
    "rejects",
    "resolves",
    "matchsnapshot",
];

impl Detector for AssertionFreeTest {
    fn signal(&self) -> TamperSignal {
        TamperSignal::AssertionFreeTest
    }

    fn metric_id(&self) -> &'static str {
        "tamper.assertion-free-test"
    }

    fn magnitude_metric_id(&self) -> &'static str {
        "tamper.assertion-free-test.magnitude"
    }

    fn describes(&self) -> &'static str {
        "test cases added or edited in this change that assert nothing"
    }

    fn run(&self, change: &ChangeView) -> Outcome {
        let mut findings = Vec::new();
        for file in &change.files {
            if file.content_unchanged() || file.head.is_none() {
                continue;
            }
            if !is_test_path(&file.path) {
                continue;
            }
            let Some(head) = Parsed::new(&file.path, file.head_bytes()) else {
                continue;
            };
            // Cases that were already assertion-free on the base side are
            // pre-existing; only what this change introduced is reported.
            let already: Vec<String> = Parsed::new(file.base_path(), file.base_bytes())
                .map(|base| {
                    cases(&base)
                        .into_iter()
                        .filter(|(_, _, asserts)| *asserts == 0)
                        .map(|(name, _, _)| name)
                        .collect()
                })
                .unwrap_or_default();
            let mut seen: BTreeMap<String, usize> = BTreeMap::new();
            for (name, line, asserts) in cases(&head) {
                if asserts > 0 {
                    continue;
                }
                // Two cases can share a name; the nth assertion-free one is
                // pre-existing only if the base had at least n of them.
                let ordinal = seen.entry(name.clone()).or_default();
                *ordinal += 1;
                let previously = already.iter().filter(|n| **n == name).count();
                if *ordinal <= previously {
                    continue;
                }
                findings.push(Finding::at(
                    &file.path,
                    line,
                    format!("test {name} asserts nothing"),
                ));
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

/// `(case name, 1-based line, assertion count)` for every test case in a file.
fn cases(parsed: &Parsed) -> Vec<(String, u32, u32)> {
    if parsed.language().is_js_family() {
        js_cases(parsed)
    } else {
        python_cases(parsed)
    }
}

fn js_cases(parsed: &Parsed) -> Vec<(String, u32, u32)> {
    let mut out = Vec::new();
    for node in parsed.nodes() {
        // The inner half of `it.each(table)(name, fn)` names no body; the outer
        // one does, and counting both would report one case twice.
        if is_curried_inner(node) {
            continue;
        }
        let Some(callee) = callee_text(parsed, node) else {
            continue;
        };
        if !JS_CASE.contains(&first_segment(&callee)) {
            continue;
        }
        let name = node
            .child_by_field_name("arguments")
            .and_then(|args| args.child(1))
            .map(|first| parsed.text(first))
            .unwrap_or_else(|| "<unnamed>".to_string());
        out.push((
            name.trim_matches(['\'', '"', '`']).to_string(),
            parsed.line_of(node.start_byte()),
            assertions_within(parsed, node, Some(JS_CASE)),
        ));
    }
    out
}

fn python_cases(parsed: &Parsed) -> Vec<(String, u32, u32)> {
    let mut out = Vec::new();
    for node in parsed.nodes() {
        if node.kind() != "function_definition" {
            continue;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let name = parsed.text(name_node);
        if !name.starts_with("test") {
            continue;
        }
        let mut asserts = assertions_within(parsed, node, None);
        // `assert` is a statement in Python, not a call.
        asserts += descendants(node)
            .iter()
            .filter(|n| n.kind() == "assert_statement" || n.kind() == "raise_statement")
            .count() as u32;
        // `with pytest.raises(...)` reads as a call and is already counted; a
        // bare `with self.assertRaises(...)` likewise.
        out.push((name, parsed.line_of(node.start_byte()), asserts));
    }
    out
}

/// Assertion-shaped calls inside a node.
///
/// `nested_case_names` stops a `describe`-style wrapper from inheriting its
/// children's assertions: when a case contains another case, the inner one's
/// calls belong to the inner one.
fn assertions_within(parsed: &Parsed, node: Node<'_>, nested_case_names: Option<&[&str]>) -> u32 {
    let mut count = 0;
    let mut skip_until: Option<usize> = None;
    for descendant in descendants(node) {
        if let Some(end) = skip_until {
            if descendant.start_byte() < end {
                continue;
            }
            skip_until = None;
        }
        let Some(callee) = callee_text(parsed, descendant) else {
            continue;
        };
        if let Some(names) = nested_case_names {
            if descendant.id() != node.id() && names.contains(&first_segment(&callee)) {
                skip_until = Some(descendant.end_byte());
                continue;
            }
        }
        let lowered = callee.to_ascii_lowercase();
        if ASSERTION_HINTS.iter().any(|hint| lowered.contains(hint)) {
            count += 1;
        }
    }
    count
}

fn descendants<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        out.push(current);
        let mut children: Vec<Node> = current.children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    out.sort_by_key(|n| (n.start_byte(), std::cmp::Reverse(n.end_byte())));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::FileChange;

    #[test]
    fn a_new_test_with_no_assertion_fires() {
        let head = "it('creates a user', () => { createUser('a'); });\n";
        let view = ChangeView::new(vec![FileChange::added("src/user.test.ts", head)]);
        let outcome = AssertionFreeTest.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 1);
    }

    #[test]
    fn a_new_test_that_asserts_does_not_fire() {
        let head = "it('creates a user', () => { expect(createUser('a')).toBeDefined(); });\n";
        let view = ChangeView::new(vec![FileChange::added("src/user.test.ts", head)]);
        assert!(!AssertionFreeTest.run(&view).fired);
    }

    #[test]
    fn a_custom_assertion_helper_is_believed() {
        let head = "it('creates a user', () => { assertUserExists('a'); });\n";
        let view = ChangeView::new(vec![FileChange::added("src/user.test.ts", head)]);
        assert!(!AssertionFreeTest.run(&view).fired);
    }

    #[test]
    fn a_pre_existing_empty_test_is_not_this_changes_fault() {
        let source = "it('todo', () => { setup(); });\n";
        let head = format!("{source}const extra = 1;\n");
        let view = ChangeView::new(vec![FileChange::modified("src/a.test.ts", source, &head)]);
        assert!(!AssertionFreeTest.run(&view).fired);
    }

    #[test]
    fn adding_a_second_empty_test_beside_a_pre_existing_one_fires() {
        let base = "it('todo', () => { setup(); });\n";
        let head = "it('todo', () => { setup(); });\nit('also todo', () => { setup(); });\n";
        let view = ChangeView::new(vec![FileChange::modified("src/a.test.ts", base, head)]);
        assert!(AssertionFreeTest.run(&view).fired);
    }

    #[test]
    fn python_assert_statements_count() {
        let head = "def test_add():\n    assert add(1, 2) == 3\n";
        let view = ChangeView::new(vec![FileChange::added("tests/test_add.py", head)]);
        assert!(!AssertionFreeTest.run(&view).fired);

        let empty = "def test_add():\n    add(1, 2)\n";
        let view = ChangeView::new(vec![FileChange::added("tests/test_add.py", empty)]);
        assert!(AssertionFreeTest.run(&view).fired);
    }

    #[test]
    fn python_pytest_raises_counts_as_an_assertion() {
        let head = "import pytest\n\ndef test_bad():\n    with pytest.raises(ValueError):\n        parse('x')\n";
        let view = ChangeView::new(vec![FileChange::added("tests/test_bad.py", head)]);
        assert!(!AssertionFreeTest.run(&view).fired);
    }

    #[test]
    fn a_wrapper_does_not_lend_its_assertions_to_an_empty_sibling() {
        let head = "describe('user', () => {\n  it('checks', () => { expect(1).toBe(1); });\n  it('does not', () => { createUser(); });\n});\n";
        let view = ChangeView::new(vec![FileChange::added("src/a.test.ts", head)]);
        let outcome = AssertionFreeTest.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 1, "{:?}", outcome.findings);
    }

    #[test]
    fn should_style_assertions_are_believed() {
        let head = "it('sums an empty cart', () => { subtotal([]).should.equal(0); });
";
        let view = ChangeView::new(vec![FileChange::added("test/cart.spec.ts", head)]);
        assert!(!AssertionFreeTest.run(&view).fired);
    }

    #[test]
    fn a_call_that_merely_contains_a_hint_word_is_not_an_assertion() {
        // `checkout` used to match the `check` hint, which made the detector
        // believe any suite with a checkout call.
        let head = "it('checks out', () => { checkout(cart); });
";
        let view = ChangeView::new(vec![FileChange::added("test/cart.spec.ts", head)]);
        assert!(AssertionFreeTest.run(&view).fired);
    }

    #[test]
    fn a_function_outside_a_test_file_is_not_a_test() {
        let head = "export function createUser(name: string) { return { name }; }\n";
        let view = ChangeView::new(vec![FileChange::added("src/user.ts", head)]);
        assert!(!AssertionFreeTest.run(&view).fired);
    }
}
