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
//! # Code outside any function has no complexity result, and that is not
//! degradation
//!
//! Complexity is reported per function, so statements at module scope, class
//! static blocks, and immediately-invoked expressions produce **no** cyclomatic
//! or cognitive result. The file is parsed completely and its `static.sloc` and
//! parse-health results are exactly as trustworthy as any other file's — this is
//! a scoping limit, not a parse failure, and it is worth being precise about the
//! difference because the two look identical in a payload that only shows what
//! is present.
//!
//! A degraded parse says so: `completeness: parse-degraded`, capped severity, a
//! caveat, and a non-zero ERROR count naming the file. Module-scope code says
//! nothing at all, because nothing went wrong. The consumer consequence is the
//! same in both cases and worth stating once: **absence of a complexity result
//! is not evidence of low complexity.** An agent moving logic to module scope
//! would reduce the reported numbers without reducing the work a reader has to
//! do, and the defence is not in this engine — it is P3's tamper suite noticing
//! that function-scope coverage fell.
//!
//! # Names are for humans; identity is the name and where it is
//!
//! `ResultScope` carries `symbol` and `line_span`, and the *pair* is the
//! identity — two anonymous callbacks in one file are distinguished by where
//! they are, not by what they are called. So the name is allowed to be
//! `<anonymous>`, and a class-qualified name is used where one is available
//! because `Store.set` reads better in a report than `set`.
//!
//! # A line is not always a position
//!
//! One line can hold two functions with one name. `xs.map(x => x).filter(x => x)`
//! is the plainest case, `.then().catch()` is the next, a jQuery chain is the
//! third, and a minified bundle is thousands of them: same `<anonymous>`, same
//! start line, same end line, so the same scope bytes. Assembly refuses a
//! payload whose pairing key names two results — an ambiguous pairing is where a
//! forged result shadows an honest one
//! ([`andon_core::payload::AssemblyError::DuplicateResult`]) — so before
//! `disambiguate` existed, one such line ended the whole measurement with exit
//! 1 and nothing measured. The refusal is right and is untouched; what was wrong
//! is that ordinary code reached it.
//!
//! So a site whose name and line span do not tell it apart from another site in
//! the same file takes its start column: `<anonymous>@31`. Two outermost sites
//! are disjoint subtrees, so no two start at the same byte, and two that share a
//! start line therefore differ in column — the qualified name names exactly one
//! site. Every member of such a group is qualified, not just the second onward,
//! so a name depends on the set it is in and not on where the walk reached it.
//!
//! **Only colliding sites are qualified, and that is deliberate.** A file whose
//! names and spans already differ produces the byte-identical scope it always
//! did, so no digest moves, no [`crate::lang::SPEC_REVISION`] moves with it, and
//! no honest change is told its measurement diverged. Nothing is lost to the
//! asymmetry: a file that takes a column today produced no record at all before,
//! because it aborted the run it was in.

use std::collections::HashMap;

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
    /// names it, and column-qualified where the name and the line span do not
    /// tell this site apart from another in the same file (`disambiguate`).
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
    disambiguate(&mut sites);
    sites
}

/// Give every site in a name-and-span collision its start column.
///
/// Counted in one pass over a map rather than compared pairwise: a minified
/// bundle puts thousands of sites on one line, and the quadratic scan that reads
/// more naturally would be quadratic in exactly the file this function exists
/// for.
///
/// The column is 1-based, like [`FunctionSite::start_line`] and like every
/// editor a reader will open the file in. Tree-sitter counts from zero, and in
/// bytes rather than characters — a distinction with no consequence for
/// uniqueness, and one worth naming for anyone who compares the number against a
/// column an editor shows on a line with multi-byte text.
fn disambiguate(sites: &mut [FunctionSite<'_>]) {
    let mut occurrences: HashMap<(&str, u32, u32), usize> = HashMap::new();
    for site in sites.iter() {
        *occurrences
            .entry((site.name.as_str(), site.start_line, site.end_line))
            .or_insert(0) += 1;
    }
    let ambiguous: Vec<bool> = sites
        .iter()
        .map(|site| occurrences[&(site.name.as_str(), site.start_line, site.end_line)] > 1)
        .collect();

    for (site, ambiguous) in sites.iter_mut().zip(ambiguous) {
        if ambiguous {
            let column = site.node.start_position().column as u32 + 1;
            site.name = format!("{}@{column}", site.name);
        }
    }
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
        // The pair inside the ternary shares a name and a line span, so the line
        // span is not where they are — the column is. Before they carried it,
        // these two scopes were the same bytes and the payload they were in was
        // refused whole.
        assert_eq!(sites[0].name, "<anonymous>@18");
        assert_eq!(sites[1].name, "<anonymous>@28");
        // `b` is named and alone on its line: untouched, and byte-for-byte the
        // scope it always produced.
        assert_eq!(sites[2].name, "b");
    }

    /// The chain shapes this qualification exists for, in the languages a user
    /// reported them in. Each one used to end the run it was in.
    #[test]
    fn ordinary_method_chains_produce_distinguishable_sites() {
        for (language, source) in [
            (
                Language::TypeScript,
                "export const out = xs.map(x => x * 2).filter(x => x > 0);\n",
            ),
            (
                Language::JavaScript,
                "fetch(u).then(r => r.json()).catch(e => log(e));\n",
            ),
            (
                Language::JavaScript,
                "$(\".a\").on(\"click\", function () { hide(); }).on(\"blur\", function () { hide(); });\n",
            ),
            (
                Language::Python,
                "xs = list(map(lambda x: x + 1, filter(lambda x: x > 0, ys)))\n",
            ),
        ] {
            let parsed = parse(language, source.as_bytes()).expect("parses");
            let sites = functions(&parsed);
            assert_eq!(sites.len(), 2, "{source}");
            assert_ne!(sites[0].name, sites[1].name, "{source}");
            // Same line, so the name is the whole of what tells them apart.
            assert_eq!(sites[0].start_line, sites[1].start_line, "{source}");
            assert_eq!(sites[0].end_line, sites[1].end_line, "{source}");
        }
    }

    #[test]
    fn a_qualified_name_names_exactly_one_site() {
        // The property assembly needs: within one file, no two sites share a
        // `(name, line span)` — which is the scope, once the path and blob are
        // fixed. Twenty anonymous arrows on one line, as a minified bundle
        // writes them.
        let source = format!(
            "const fs = [{}];\n",
            (0..20).map(|_| "() => 1").collect::<Vec<_>>().join(", ")
        );
        let parsed = parse(Language::JavaScript, source.as_bytes()).expect("parses");
        let sites = functions(&parsed);
        assert_eq!(sites.len(), 20);
        let keys: std::collections::BTreeSet<_> = sites
            .iter()
            .map(|site| (site.name.clone(), site.start_line, site.end_line))
            .collect();
        assert_eq!(keys.len(), 20, "{keys:?}");
    }

    #[test]
    fn two_functions_with_one_name_on_one_line_are_told_apart() {
        // Not only anonymous ones: a name repeated on a line collides the same
        // way, and a minifier produces exactly this.
        let parsed = parse(
            Language::JavaScript,
            b"const o = { f: function () { return 1 } }, p = { f: function () { return 2 } };\n",
        )
        .expect("parses");
        let sites = functions(&parsed);
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].name, "f@16");
        assert_eq!(sites[1].name, "f@53");
    }

    #[test]
    fn same_name_on_different_lines_keeps_the_bare_name() {
        // The line span already tells these apart, so nothing is appended — the
        // scope bytes are the ones this engine has always produced for them.
        let parsed =
            parse(Language::Python, b"f = lambda x: x\ng = lambda x: x\n").expect("parses");
        let names: Vec<String> = functions(&parsed)
            .into_iter()
            .map(|site| site.name)
            .collect();
        assert_eq!(names, vec!["f", "g"]);
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
