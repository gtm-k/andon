//! A large literal table standing in for an implementation.
//!
//! The shape: a function that should compute something instead consults a
//! hard-coded table of the exact inputs the tests use. It passes the suite, it
//! reads as code, and it generalizes to nothing — the purest form of writing to
//! the test rather than to the problem.
//!
//! # Why the rule is "big literal *inside logic*", not "big literal"
//!
//! Data files exist. A locale bundle, a country list, a generated fixture, a
//! `.json` of anything — every one is a large literal collection, and none is
//! gaming. So the detector requires three things at once:
//!
//! 1. the literal is inside a **function or method body**, where computation
//!    was expected;
//! 2. it has at least [`MIN_ELEMENTS`] entries;
//! 3. the file is not a recognized data file or under a data directory.
//!
//! # Only what the change added
//!
//! A table that was already there is not this change's doing. The comparison is
//! the largest qualifying literal on each side, so growing an existing table
//! past the floor fires and inheriting one does not.

use crate::change::{is_test_path, ChangeView};
use crate::detectors::{Detector, Finding, Outcome};
use crate::syntax::Parsed;
use andon_core::schema::enums::TamperSignal;
use tree_sitter::Node;

/// The detector.
pub struct LookupTableBlowup;

/// Entries a literal needs before it reads as a table rather than a config
/// object. Twenty-four is a size nobody types by accident and a size no
/// reasonable options bag reaches.
pub const MIN_ELEMENTS: usize = 24;

/// Node kinds that are a literal collection.
const COLLECTION_KINDS: &[&str] = &[
    "array",
    "object",
    "list",
    "dictionary",
    "set",
    "tuple",
    "array_pattern",
];

/// Node kinds that are a function body's owner.
const FUNCTION_KINDS: &[&str] = &[
    "function_declaration",
    "function_expression",
    "function_definition",
    "arrow_function",
    "method_definition",
    "generator_function",
    "generator_function_declaration",
];

/// Path fragments that mean "this file is data".
const DATA_PATH_FRAGMENTS: &[&str] = &[
    "/data/",
    "/fixtures/",
    "/fixture/",
    "/locales/",
    "/locale/",
    "/i18n/",
    "/seeds/",
    "/seed/",
    "/generated/",
    "/__generated__/",
    "/snapshots/",
    "/__snapshots__/",
    "/migrations/",
];

/// Whether a path is a data file rather than an implementation file.
pub fn is_data_path(path: &str) -> bool {
    let lower = format!("/{}", path.to_ascii_lowercase());
    let name = lower.rsplit('/').next().unwrap_or(&lower).to_string();
    if name.ends_with(".json") || name.ends_with(".csv") || name.ends_with(".yaml") {
        return true;
    }
    if name.contains(".generated.") || name.contains(".gen.") || name.contains(".data.") {
        return true;
    }
    DATA_PATH_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

impl Detector for LookupTableBlowup {
    fn signal(&self) -> TamperSignal {
        TamperSignal::LookupTableBlowup
    }

    fn metric_id(&self) -> &'static str {
        "tamper.lookup-table-blowup"
    }

    fn magnitude_metric_id(&self) -> &'static str {
        "tamper.lookup-table-blowup.magnitude"
    }

    fn describes(&self) -> &'static str {
        "a hard-coded table of at least 24 entries added inside a function body"
    }

    fn run(&self, change: &ChangeView) -> Outcome {
        let mut findings = Vec::new();
        let mut largest = 0i64;
        for file in &change.files {
            // A big literal in a test *is* the fixture: a table of inputs and
            // expected outputs is what a table-driven test looks like, and firing
            // on it would report thorough testing as gaming.
            if file.content_unchanged()
                || file.head.is_none()
                || is_data_path(&file.path)
                || is_test_path(&file.path)
            {
                continue;
            }
            let Some(head) = Parsed::new(&file.path, file.head_bytes()) else {
                continue;
            };
            let base_largest = Parsed::new(file.base_path(), file.base_bytes())
                .map(|base| tables(&base).into_iter().map(|(_, n)| n).max().unwrap_or(0))
                .unwrap_or(0);
            for (line, size) in tables(&head) {
                if size <= base_largest {
                    continue;
                }
                largest = largest.max(size as i64);
                findings.push(Finding::at(
                    &file.path,
                    line,
                    format!("literal table of {size} entries inside a function body"),
                ));
            }
        }
        if findings.is_empty() {
            Outcome::quiet(0)
        } else {
            Outcome::fired(largest, findings)
        }
    }
}

/// `(1-based line, entry count)` for every qualifying literal in a file.
fn tables(parsed: &Parsed) -> Vec<(u32, usize)> {
    let mut out = Vec::new();
    for node in parsed.nodes() {
        if !COLLECTION_KINDS.contains(&node.kind()) {
            continue;
        }
        let entries = elements(node);
        if entries < MIN_ELEMENTS {
            continue;
        }
        if !inside_function(node) {
            continue;
        }
        // The outermost qualifying literal is the finding; its rows are not
        // separate tables.
        if out
            .iter()
            .any(|(line, _)| *line <= parsed.line_of(node.start_byte()) && encloses(node))
        {
            continue;
        }
        out.push((parsed.line_of(node.start_byte()), entries));
    }
    // Keep only the outermost: a table of 30 objects would otherwise report the
    // table and every object in it that happened to be large.
    out.sort();
    let mut kept: Vec<(u32, usize)> = Vec::new();
    for (line, size) in out {
        if kept.iter().any(|(l, s)| *l <= line && *s >= size) {
            continue;
        }
        kept.push((line, size));
    }
    kept
}

fn encloses(node: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if COLLECTION_KINDS.contains(&current.kind()) {
            return true;
        }
        if FUNCTION_KINDS.contains(&current.kind()) {
            return false;
        }
        parent = current.parent();
    }
    false
}

/// Named children of a collection: its entries, without the punctuation.
fn elements(node: Node<'_>) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !child.is_extra() && child.kind() != "comment")
        .count()
}

/// Whether a node sits inside a function body.
fn inside_function(node: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if FUNCTION_KINDS.contains(&current.kind()) {
            return true;
        }
        parent = current.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::FileChange;

    fn table(n: usize) -> String {
        let rows: Vec<String> = (0..n).map(|i| format!("  [{i}, {}]", i * i)).collect();
        rows.join(",\n")
    }

    fn in_function(n: usize) -> String {
        format!(
            "export function square(x: number): number {{\n  const answers = [\n{}\n  ];\n  return answers.find((row) => row[0] === x)![1];\n}}\n",
            table(n)
        )
    }

    #[test]
    fn a_big_table_inside_a_function_fires() {
        let view = ChangeView::new(vec![FileChange::added("src/square.ts", &in_function(40))]);
        let outcome = LookupTableBlowup.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 40);
    }

    #[test]
    fn a_small_options_object_does_not_fire() {
        let source = "export function make() {\n  return { retries: 3, timeout: 1000, verbose: false };\n}\n";
        let view = ChangeView::new(vec![FileChange::added("src/make.ts", source)]);
        assert!(!LookupTableBlowup.run(&view).fired);
    }

    #[test]
    fn a_module_level_data_constant_does_not_fire() {
        let source = format!("export const COUNTRIES = [\n{}\n];\n", table(40));
        let view = ChangeView::new(vec![FileChange::added("src/countries.ts", &source)]);
        assert!(!LookupTableBlowup.run(&view).fired);
    }

    #[test]
    fn a_data_directory_is_exempt_even_inside_a_function() {
        let view = ChangeView::new(vec![FileChange::added(
            "src/data/squares.ts",
            &in_function(40),
        )]);
        assert!(!LookupTableBlowup.run(&view).fired);
    }

    #[test]
    fn an_inline_fixture_table_in_a_spec_file_is_exempt() {
        let source = format!(
            "it('covers every case', () => {{
  const rows = [
{}
  ];
  rows.forEach(([a, b]) => expect(square(a)).toBe(b));
}});
",
            table(40)
        );
        let view = ChangeView::new(vec![FileChange::added("test/square.spec.ts", &source)]);
        assert!(!LookupTableBlowup.run(&view).fired);
    }

    #[test]
    fn a_json_file_is_exempt() {
        let rows: Vec<String> = (0..40).map(|i| format!("  \"k{i}\": {i}")).collect();
        let source = format!("{{\n{}\n}}\n", rows.join(",\n"));
        let view = ChangeView::new(vec![FileChange::added("src/lookup.json", &source)]);
        assert!(!LookupTableBlowup.run(&view).fired);
    }

    #[test]
    fn a_pre_existing_table_is_not_this_changes_fault() {
        let base = in_function(40);
        let head = format!("{base}export const version = 2;\n");
        let view = ChangeView::new(vec![FileChange::modified("src/square.ts", &base, &head)]);
        assert!(!LookupTableBlowup.run(&view).fired);
    }

    #[test]
    fn growing_a_table_past_the_previous_size_fires() {
        let view = ChangeView::new(vec![FileChange::modified(
            "src/square.ts",
            &in_function(30),
            &in_function(60),
        )]);
        assert!(LookupTableBlowup.run(&view).fired);
    }

    #[test]
    fn a_python_dictionary_inside_a_function_fires() {
        let rows: Vec<String> = (0..40).map(|i| format!("        {i}: {}", i * i)).collect();
        let source = format!(
            "def square(x):\n    answers = {{\n{}\n    }}\n    return answers[x]\n",
            rows.join(",\n")
        );
        let view = ChangeView::new(vec![FileChange::added("src/square.py", &source)]);
        assert!(LookupTableBlowup.run(&view).fired);
    }

    #[test]
    fn one_table_is_one_finding_not_one_per_row() {
        let rows: Vec<String> = (0..30)
            .map(|_| {
                let inner: Vec<String> = (0..30).map(|j| format!("{j}")).collect();
                format!("  [{}]", inner.join(", "))
            })
            .collect();
        let source = format!(
            "export function f(x: number) {{\n  const t = [\n{}\n  ];\n  return t[x];\n}}\n",
            rows.join(",\n")
        );
        let view = ChangeView::new(vec![FileChange::added("src/f.ts", &source)]);
        let outcome = LookupTableBlowup.run(&view);
        assert!(outcome.fired);
        assert_eq!(outcome.findings.len(), 1, "{:?}", outcome.findings);
    }
}
