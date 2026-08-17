//! Which nodes get their own function-scope result, and what they are called.
//!
//! # One result per outermost function
//!
//! A function-like node with no function-like ancestor gets a result. A nested
//! one does not — it contributes to the enclosing function instead, which is
//! what both metrics already do: cyclomatic counts its decision points, and
//! cognitive charges its body an extra nesting level.
//!
//! The alternative — a result for every function at every depth — double-counts.
//! A callback inside a method would appear once on its own and again inside the
//! method's number, and an agent told to reduce both would be told to reduce the
//! same code twice. Reporting at the outermost boundary matches how the
//! cognitive-complexity specification reports (per method, nested lambdas
//! folded in) and keeps the numbers additive-free.
//!
//! This rule is bound by [`crate::lang::SPEC_REVISION`]: changing it changes
//! every function-scope number, and old and new must become incomparable rather
//! than silently different.
//!
//! # Names are for humans; identity is the line span
//!
//! `ResultScope` carries `symbol` and `line_span`, and the *pair* is the
//! identity — two anonymous callbacks in one file are distinguished by where
//! they are, not by what they are called. So the name is allowed to be
//! `<anonymous>`, and a class-qualified name is used where one is available
//! because `Store.set` reads better in a report than `set`.

use tree_sitter::Node;

use crate::lang::Language;
use crate::parse::Parsed;

/// Placeholder name for a function with nothing to call it.
pub const ANONYMOUS: &str = "<anonymous>";

/// One function-scope measurement site.
#[derive(Debug, Clone)]
pub struct FunctionSite<'t> {
    /// The function-like node.
    pub node: Node<'t>,
    /// Class-qualified where a class is in scope, `<anonymous>` where nothing
    /// names it.
    pub name: String,
    /// First line, 1-based inclusive.
    pub start_line: u32,
    /// Last line, 1-based inclusive.
    pub end_line: u32,
}

/// True when a node is a function for the purpose of scope and nesting.
pub fn is_function(language: Language, kind: &str) -> bool {
    match language {
        Language::Python => matches!(kind, "function_definition" | "lambda"),
        Language::TypeScript | Language::Tsx | Language::JavaScript => matches!(
            kind,
            "function_declaration"
                | "function_expression"
                | "generator_function"
                | "generator_function_declaration"
                | "arrow_function"
                | "method_definition"
        ),
        // No parser, no functions.
        Language::Rust => false,
    }
}

/// Every outermost function in the file, in source order.
///
/// Source order is a property of the tree walk, not of a sort: results are
/// paired across legs by `(metric_id, scope)`, so order cannot change a verdict
/// — but an engine whose output order drifts produces diffs nobody can read.
/// The walk is an explicit `Vec` worklist rather than a recursive descent. The
/// tree's depth is chosen by whoever wrote the file being measured, and a
/// recursive walk over attacker-chosen depth aborts the process rather than
/// failing — see the note in [`crate::cognitive`]. Children are pushed in
/// reverse so that popping yields them in source order.
pub fn functions<'t>(parsed: &'t Parsed<'_>) -> Vec<FunctionSite<'t>> {
    let mut sites = Vec::new();
    let mut stack = vec![parsed.tree.root_node()];
    while let Some(node) = stack.pop() {
        if is_function(parsed.language, node.kind()) {
            sites.push(FunctionSite {
                name: name_of(parsed, node),
                start_line: node.start_position().row as u32 + 1,
                end_line: node.end_position().row as u32 + 1,
                node,
            });
            // Do not descend: a nested function belongs to this one's number.
            continue;
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'t>> = node.children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    sites
}

/// The name to report, qualified by an enclosing class where there is one.
fn name_of(parsed: &Parsed<'_>, node: Node<'_>) -> String {
    let own = simple_name(parsed, node).unwrap_or_else(|| ANONYMOUS.to_string());
    match enclosing_class(parsed, node) {
        Some(class) => format!("{class}.{own}"),
        None => own,
    }
}

/// The function's own name, unqualified: from its declaration, or from what it
/// is bound to.
///
/// Public because recursion detection needs the name a call site would write —
/// `this.walk()` names the method `walk`, not `C.walk`.
pub fn simple_name(parsed: &Parsed<'_>, node: Node<'_>) -> Option<String> {
    if let Some(name) = node.child_by_field_name("name") {
        return text(parsed, name);
    }
    // An expression function takes the name of whatever it is assigned to. Only
    // the immediate parent is consulted: `const a = cond ? () => 1 : () => 2`
    // has two functions and one name, and handing both the same one would be a
    // worse answer than `<anonymous>`.
    let parent = node.parent()?;
    let field = match parent.kind() {
        "variable_declarator" => "name",
        "pair" => "key",
        // Python `f = lambda: 1`.
        "assignment" => "left",
        _ => return None,
    };
    let named = parent.child_by_field_name(field)?;
    // Only take it when the function really is the value, not some other child.
    let value = parent
        .child_by_field_name("value")
        .or_else(|| parent.child_by_field_name("right"))?;
    (value.id() == node.id()).then(|| text(parsed, named))?
}

/// The nearest enclosing class name, if any.
fn enclosing_class(parsed: &Parsed<'_>, node: Node<'_>) -> Option<String> {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if is_function(parsed.language, ancestor.kind()) {
            // A class declared inside another function is out of scope for
            // naming: the enclosing function is already the reported unit.
            return None;
        }
        if matches!(ancestor.kind(), "class_declaration" | "class_definition") {
            return ancestor
                .child_by_field_name("name")
                .and_then(|name| text(parsed, name));
        }
        current = ancestor.parent();
    }
    None
}

fn text(parsed: &Parsed<'_>, node: Node<'_>) -> Option<String> {
    // Source was validated as UTF-8 before parsing, and node ranges are byte
    // offsets into it, so this only fails on a range that is not a character
    // boundary — which the grammar does not produce.
    std::str::from_utf8(parsed.source.get(node.start_byte()..node.end_byte())?)
        .ok()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    fn names(language: Language, source: &str) -> Vec<String> {
        let parsed = parse(language, source.as_bytes()).expect("parses");
        functions(&parsed).into_iter().map(|f| f.name).collect()
    }

    #[test]
    fn declarations_methods_and_bindings_are_named() {
        let names = names(
            Language::TypeScript,
            "function top(a: number) { return a }\n\
             const arrow = (b: number) => b;\n\
             class Store { set(v: number) { return v } }\n\
             const obj = { handler: function (c) { return c } };\n",
        );
        // `handler` and not `obj.handler`: the qualifier comes from an
        // enclosing *class*, which an object literal is not. Naming it after a
        // variable that happens to hold the object would be a guess.
        assert_eq!(names, vec!["top", "arrow", "Store.set", "handler"]);
    }

    #[test]
    fn a_nested_function_does_not_get_its_own_result() {
        // The double-count this rule exists to prevent: the callback's decision
        // points are already inside `outer`'s number.
        let names = names(
            Language::JavaScript,
            "function outer(xs) { return xs.map(function inner(x) { return x }) }\n",
        );
        assert_eq!(names, vec!["outer"]);
    }

    #[test]
    fn an_unnamed_function_is_reported_as_anonymous_with_its_lines() {
        let source = "export default function () { return 1 }\n";
        let parsed = parse(Language::TypeScript, source.as_bytes()).expect("parses");
        let sites = functions(&parsed);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].name, ANONYMOUS);
        assert_eq!((sites[0].start_line, sites[0].end_line), (1, 1));
    }

    #[test]
    fn two_anonymous_functions_are_told_apart_by_where_they_are() {
        let source = "const a = cond ? () => 1 : () => 2;\nconst b = () => 3;\n";
        let parsed = parse(Language::TypeScript, source.as_bytes()).expect("parses");
        let sites = functions(&parsed);
        assert_eq!(sites.len(), 3);
        // The pair inside the ternary shares a line and differs by column-free
        // identity only in that neither took `a`'s name — the third is `b`.
        assert_eq!(sites[0].name, ANONYMOUS);
        assert_eq!(sites[1].name, ANONYMOUS);
        assert_eq!(sites[2].name, "b");
    }

    #[test]
    fn python_definitions_lambdas_and_methods() {
        let names = names(
            Language::Python,
            "def top(a):\n    return a\n\
             f = lambda x: x\n\
             class Store:\n    def set(self, v):\n        return v\n",
        );
        assert_eq!(names, vec!["top", "f", "Store.set"]);
    }

    #[test]
    fn line_spans_are_one_based_and_inclusive() {
        let parsed = parse(Language::Python, b"x = 1\ndef f():\n    return 2\n").expect("parses");
        let sites = functions(&parsed);
        assert_eq!((sites[0].start_line, sites[0].end_line), (2, 3));
    }

    #[test]
    fn the_tokenization_tier_has_no_function_sites() {
        assert!(!is_function(Language::Rust, "function_declaration"));
    }
}
