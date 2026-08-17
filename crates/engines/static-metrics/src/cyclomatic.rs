//! Cyclomatic complexity (McCabe), counted from the syntax tree.
//!
//! # The definition this crate implements
//!
//! **1 + one for each decision point in the function**, where a decision point
//! is a construct that adds an independent path:
//!
//! | | TypeScript / TSX / JavaScript | Python |
//! |---|---|---|
//! | branch | `if` (each one, so `else if` counts) | `if`, `elif` |
//! | loop | `for`, `for…in`, `for…of`, `while`, `do…while` | `for`, `while`, comprehension `for` |
//! | conditional expression | `a ? b : c` | `b if a else c`, comprehension `if` |
//! | exception arm | each `catch` | each `except` |
//! | multi-way arm | each `case` | each non-wildcard `case` |
//! | short-circuit operator | each **binary** `&&`, `||`, `??` | each `and`, `or` |
//!
//! `else` is not a decision point — it is the absence of one — and neither is
//! `default` or an unguarded `case _`, for the same reason: the path exists
//! whether or not the arm is written. A guarded `case _ if c` **is** an arm that
//! can be skipped, and counts once: the guard and the arm are one choice, not
//! two.
//!
//! # Two boundaries this table does not cross
//!
//! **Logical-assignment operators.** `a &&= b`, `a ||= b` and `a ??= b` are not
//! counted. They short-circuit, so an argument for counting them exists — but
//! they are assignments rather than binary expressions, the published
//! definitions this crate implements speak of binary logical operators, and
//! inventing a rule is how a clean-room implementation stops matching the thing
//! it claims to implement. Named here so the row above reads as a boundary
//! rather than an oversight.
//!
//! **Comprehensions cost 3 here and 0 in cognitive complexity.** Not an
//! inconsistency: they are different metrics answering different questions.
//! `[x for x in xs if x]` genuinely adds independent paths, which is what
//! cyclomatic complexity counts; it does not add a flow break a reader has to
//! hold in mind, which is what cognitive complexity counts — a comprehension is
//! one idiom read at a glance. The gap between the two numbers on
//! comprehension-heavy Python is expected, and a consumer comparing them should
//! know that before drawing a conclusion from it.
//!
//! Nested functions are **included**. `crate::functions` reports one result per
//! outermost function, so a callback's branches have to land somewhere, and the
//! function they were written inside is where a reader looks for them.
//!
//! Every one of those choices is bound by [`crate::lang::SPEC_REVISION`]:
//! changing any of them makes old and new numbers incomparable rather than
//! silently different.
//!
//! # What the evidence supports
//!
//! Landman et al. 2016 measured 17.6M Java methods and 6.3M C functions and
//! found cyclomatic complexity correlated with SLOC but not so strongly as to be
//! redundant with it. That is the whole claim: a per-function gate that has to be
//! read against size. `docs/metric-families.csv` grades it **B**, and the
//! registry entry's `does_not_predict` says the rest.

use tree_sitter::Node;

use crate::lang::Language;
use crate::parse::Parsed;

/// Cyclomatic complexity of one function subtree.
pub fn complexity(parsed: &Parsed<'_>, function: Node<'_>) -> u64 {
    1 + decision_points(parsed, function)
}

fn decision_points(parsed: &Parsed<'_>, node: Node<'_>) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        total += u64::from(is_decision_point(parsed, current));
        let mut cursor = current.walk();
        stack.extend(current.children(&mut cursor));
    }
    total
}

fn is_decision_point(parsed: &Parsed<'_>, node: Node<'_>) -> bool {
    let kind = node.kind();
    match parsed.language {
        Language::Python => match kind {
            "if_statement"
            | "elif_clause"
            | "for_statement"
            | "while_statement"
            | "except_clause"
            | "except_group_clause"
            | "conditional_expression"
            | "for_in_clause" => true,
            // A comprehension filter is a decision. A `match` arm's guard is
            // spelled with the same node and is not a second one: `case _ if c`
            // is one choice — take this arm or do not — and the `case_clause`
            // below has already counted it.
            "if_clause" => node.parent().map(|p| p.kind()) != Some("case_clause"),
            "case_clause" => !is_wildcard_case(parsed, node),
            "boolean_operator" => true,
            _ => false,
        },
        Language::TypeScript | Language::Tsx | Language::JavaScript => match kind {
            "if_statement" | "for_statement" | "for_in_statement" | "while_statement"
            | "do_statement" | "ternary_expression" | "catch_clause" | "switch_case" => true,
            "binary_expression" => matches!(operator(parsed, node), Some("&&" | "||" | "??")),
            _ => false,
        },
        // The tokenization tier measures size and nothing else.
        Language::Rust => false,
    }
}

/// Whether a Python `case` arm is the unguarded wildcard — `default` by another
/// name, and not a decision point for the same reason.
fn is_wildcard_case(parsed: &Parsed<'_>, node: Node<'_>) -> bool {
    if node.child_by_field_name("guard").is_some() {
        return false;
    }
    let mut cursor = node.walk();
    let patterns: Vec<Node<'_>> = node
        .children(&mut cursor)
        .filter(|child| child.kind() == "case_pattern")
        .collect();
    match patterns.as_slice() {
        [only] => node_text(parsed, *only) == Some("_"),
        _ => false,
    }
}

fn operator<'a>(parsed: &'a Parsed<'_>, node: Node<'_>) -> Option<&'a str> {
    node.child_by_field_name("operator")
        .and_then(|op| node_text(parsed, op))
}

fn node_text<'a>(parsed: &'a Parsed<'_>, node: Node<'_>) -> Option<&'a str> {
    std::str::from_utf8(parsed.source.get(node.start_byte()..node.end_byte())?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::functions;
    use crate::parse::parse;

    /// Complexity of the first function in a snippet.
    fn first(language: Language, source: &str) -> u64 {
        let parsed = parse(language, source.as_bytes()).expect("parses");
        let sites = functions(&parsed);
        assert!(!sites.is_empty(), "the snippet has no function");
        complexity(&parsed, sites[0].node)
    }

    #[test]
    fn a_straight_line_function_is_one() {
        assert_eq!(first(Language::TypeScript, "function f() { return 1 }"), 1);
        assert_eq!(first(Language::Python, "def f():\n    return 1\n"), 1);
    }

    #[test]
    fn each_branch_adds_one_and_else_adds_none() {
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a) { if (a) { return 1 } else { return 2 } }"
            ),
            2
        );
        // `else if` is a second `if`, so it counts; the trailing `else` does not.
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a) { if (a) {} else if (a) {} else {} }"
            ),
            3
        );
        assert_eq!(
            first(
                Language::Python,
                "def f(a):\n    if a:\n        pass\n    elif a:\n        pass\n    else:\n        pass\n"
            ),
            3
        );
    }

    #[test]
    fn every_loop_form_counts_once() {
        assert_eq!(
            first(
                Language::JavaScript,
                "function f(xs) { for (const x of xs) {} for (const k in xs) {} \
                 for (let i = 0; i < 1; i++) {} while (xs) {} do {} while (xs); }"
            ),
            6
        );
    }

    #[test]
    fn short_circuit_operators_each_count() {
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a, b, c) { return a && b || c }"
            ),
            3
        );
        assert_eq!(
            first(Language::TypeScript, "function f(a, b) { return a ?? b }"),
            2
        );
        assert_eq!(
            first(
                Language::Python,
                "def f(a, b, c):\n    return a and b or c\n"
            ),
            3
        );
        // A comparison is not a decision point, even though it is a binary
        // expression — the operator is what matters.
        assert_eq!(
            first(Language::TypeScript, "function f(a, b) { return a < b }"),
            1
        );
    }

    #[test]
    fn switch_arms_count_and_default_does_not() {
        assert_eq!(
            first(
                Language::JavaScript,
                "function f(a) { switch (a) { case 1: break; case 2: break; default: break } }"
            ),
            3
        );
    }

    #[test]
    fn python_match_arms_count_and_the_bare_wildcard_does_not() {
        assert_eq!(
            first(
                Language::Python,
                "def f(a):\n    match a:\n        case 1:\n            pass\n        \
                 case 2:\n            pass\n        case _:\n            pass\n"
            ),
            3
        );
    }

    #[test]
    fn a_guarded_wildcard_is_a_real_arm() {
        // `case _ if cond` is a decision: the arm can be skipped.
        assert_eq!(
            first(
                Language::Python,
                "def f(a):\n    match a:\n        case _ if a > 1:\n            pass\n"
            ),
            2
        );
    }

    #[test]
    fn exception_arms_count_once_each() {
        assert_eq!(
            first(
                Language::TypeScript,
                "function f() { try { g() } catch (e) { } finally { } }"
            ),
            2
        );
        assert_eq!(
            first(
                Language::Python,
                "def f():\n    try:\n        g()\n    except ValueError:\n        pass\n    \
                 except KeyError:\n        pass\n    finally:\n        pass\n"
            ),
            3
        );
    }

    #[test]
    fn comprehension_clauses_are_decision_points() {
        assert_eq!(
            first(
                Language::Python,
                "def f(xs):\n    return [x for x in xs if x]\n"
            ),
            3
        );
    }

    #[test]
    fn a_nested_functions_branches_land_on_the_function_that_contains_it() {
        // `crate::functions` reports one result per outermost function, so these
        // have to be counted somewhere — and here is where a reader looks.
        assert_eq!(
            first(
                Language::JavaScript,
                "function outer(xs) { return xs.map(function (x) { return x ? 1 : 2 }) }"
            ),
            2
        );
    }

    #[test]
    fn the_tokenization_tier_produces_nothing_to_count() {
        // Rust never reaches here in production — it has no grammar, so it has
        // no tree. The arm is asserted anyway so it cannot be deleted as dead
        // code and turn a future Rust parse into a silent count of JavaScript
        // node kinds.
        let mut parsed =
            parse(Language::TypeScript, b"function f(a) { if (a) {} }").expect("parses");
        parsed.language = Language::Rust;
        let root = parsed.tree.root_node();
        assert_eq!(complexity(&parsed, root), 1);
    }
}
