//! Cognitive complexity — a clean-room implementation of the published
//! SonarSource specification.
//!
//! # Clean-room, and what that means here
//!
//! The rules below are implemented from the published specification (G. Ann
//! Campbell, *Cognitive Complexity: A new way of measuring understandability*),
//! which describes the model in prose and worked examples. No SonarSource source
//! code was consulted or copied; the tree-sitter node kinds, the traversal, and
//! the `else if` and operator-sequence handling are this crate's own. The metric
//! is a specification, and specifications are implementable — which is the point
//! of the exercise, since the *evidence* (Muñoz Barón et al., ESEM 2020) is
//! evidence about the model, and a re-implementation that scored differently
//! would not inherit it.
//!
//! That inheritance is conditional and the registry says so: the claim is scoped
//! to `andon.static.cognitive@1|<language>|comprehension-time`, per language,
//! per implementation version. If this implementation diverges from the model,
//! the claim is wrong — which is exactly what claim-scoped evidence is for.
//!
//! # The three rules
//!
//! **B1 — increment.** +1 for each break in the linear flow: `if`, `else`,
//! `else if`, ternary, `switch`/`match`, every loop, every `catch`/`except`,
//! each *sequence* of like binary logical operators, a jump to a label, and
//! direct recursion.
//!
//! **B2 — nesting penalty.** Structures that break flow *and* are nested add the
//! current nesting level on top of their +1: `if`, ternary, `switch`/`match`,
//! loops, `catch`. Deliberately **not** `else`/`else if`, not operator
//! sequences, not jumps, not recursion — the model charges for depth only where
//! depth is what makes the code hard.
//!
//! **B3 — nesting increment.** Structures that raise the nesting level for what
//! is inside them: the bodies of `if`/`else`/`else if`, ternary branches,
//! `switch`/`match`, loops, `catch`, and nested functions and lambdas. A nested
//! function adds no increment of its own — it is a container, not a branch.
//!
//! The canonical worked example, and the reason `else if` is the fiddly case:
//!
//! ```text
//! if (a) {          // +1
//!   if (b) { }      // +2  (+1, and +1 for being at nesting level 1)
//! } else if (c) {   // +1  (the `else`; the `if` after it adds nothing)
//! } else { }        // +1
//! ```                  = 5
//!
//! # What is deliberately not counted
//!
//! Type-level conditionals (`T extends U ? X : Y`) and other type expressions
//! are not control flow and add nothing. They are a real comprehension cost and
//! a real research question; charging for them here would be this crate
//! inventing a metric and citing someone else's study for it.

use tree_sitter::Node;

use crate::functions::is_function;
use crate::lang::Language;
use crate::parse::Parsed;

/// Cognitive complexity of one function.
///
/// The function node's own children are walked at nesting level zero: the unit
/// being measured is not itself nested inside anything.
pub fn complexity(parsed: &Parsed<'_>, function: Node<'_>) -> u64 {
    let mut walker = Walker {
        parsed,
        own_name: crate::functions::simple_name(parsed, function),
    };
    walker.children(function, 0)
}

struct Walker<'a, 'b> {
    parsed: &'a Parsed<'b>,
    /// Unqualified name of the function being measured, for recursion.
    own_name: Option<String>,
}

impl Walker<'_, '_> {
    /// Every child of `node`, at `nesting`.
    fn children(&mut self, node: Node<'_>, nesting: u32) -> u64 {
        let mut cursor = node.walk();
        node.children(&mut cursor)
            .map(|child| self.walk(child, nesting))
            .sum()
    }

    /// Every child of `node` at `nesting`, except its `body` field which goes a
    /// level deeper. The shape shared by every loop form.
    fn children_with_deeper_body(&mut self, node: Node<'_>, nesting: u32) -> u64 {
        let body = node.child_by_field_name("body").map(|b| b.id());
        let mut cursor = node.walk();
        let kids: Vec<Node<'_>> = node.children(&mut cursor).collect();
        kids.into_iter()
            .map(|child| {
                let deeper = Some(child.id()) == body;
                self.walk(child, nesting + u32::from(deeper))
            })
            .sum()
    }

    fn field(&mut self, node: Node<'_>, name: &str, nesting: u32) -> u64 {
        match node.child_by_field_name(name) {
            Some(child) => self.walk(child, nesting),
            None => 0,
        }
    }

    fn walk(&mut self, node: Node<'_>, nesting: u32) -> u64 {
        match self.parsed.language {
            Language::Python => self.walk_python(node, nesting),
            Language::TypeScript | Language::Tsx | Language::JavaScript => {
                self.walk_ecma(node, nesting)
            }
            // No parser, no tree. Asserted in tests so the arm cannot be
            // removed and turn a future Rust tree into a silent JavaScript walk.
            Language::Rust => 0,
        }
    }

    // ------------------------------------------------------------ ECMAScript

    fn walk_ecma(&mut self, node: Node<'_>, nesting: u32) -> u64 {
        match node.kind() {
            "if_statement" => {
                // An `if` directly under an `else` is the second half of
                // `else if`: the `else_clause` already charged the +1, and the
                // model explicitly does not charge nesting for it.
                let is_else_if = node.parent().is_some_and(|p| p.kind() == "else_clause");
                let own = if is_else_if {
                    0
                } else {
                    1 + u64::from(nesting)
                };
                own + self.field(node, "condition", nesting)
                    + self.field(node, "consequence", nesting + 1)
                    // The `else_clause` is walked at *this* level, so a long
                    // `else if` chain stays flat instead of deepening.
                    + self.field(node, "alternative", nesting)
            }
            "else_clause" => {
                let inner = node.named_child(0);
                let body = match inner {
                    // `else if` — hand the chain back at the same level.
                    Some(child) if child.kind() == "if_statement" => self.walk(child, nesting),
                    Some(child) => self.walk(child, nesting + 1),
                    None => 0,
                };
                1 + body
            }
            "ternary_expression" => {
                1 + u64::from(nesting)
                    + self.field(node, "condition", nesting)
                    + self.field(node, "consequence", nesting + 1)
                    + self.field(node, "alternative", nesting + 1)
            }
            "switch_statement" => {
                1 + u64::from(nesting)
                    + self.field(node, "value", nesting)
                    + self.field(node, "body", nesting + 1)
            }
            "for_statement" | "for_in_statement" | "while_statement" | "do_statement" => {
                1 + u64::from(nesting) + self.children_with_deeper_body(node, nesting)
            }
            "catch_clause" => {
                1 + u64::from(nesting) + self.children_with_deeper_body(node, nesting)
            }
            "binary_expression" if self.logical_operator(node).is_some() => {
                self.logical_region(node, nesting)
            }
            // A jump to a label. An unlabelled `break` or `continue` is
            // structured flow inside the construct that already charged for
            // itself, and the model does not charge it again.
            "break_statement" | "continue_statement"
                if node.child_by_field_name("label").is_some() =>
            {
                1
            }
            "call_expression" => {
                u64::from(self.is_self_call(node.child_by_field_name("function")))
                    + self.children(node, nesting)
            }
            kind if is_function(self.parsed.language, kind) => {
                // A container, not a branch: no increment, one more level for
                // everything inside.
                self.children(node, nesting + 1)
            }
            _ => self.children(node, nesting),
        }
    }

    // ---------------------------------------------------------------- Python

    fn walk_python(&mut self, node: Node<'_>, nesting: u32) -> u64 {
        match node.kind() {
            "if_statement" => {
                // `alternative` is a repeated field here — `elif_clause`s then an
                // optional `else_clause` — and each is walked at *this* level so
                // the chain stays flat.
                1 + u64::from(nesting)
                    + self.field(node, "condition", nesting)
                    + self.field(node, "consequence", nesting + 1)
                    + self.alternatives(node, nesting)
            }
            "elif_clause" => {
                1 + self.field(node, "condition", nesting)
                    + self.field(node, "consequence", nesting + 1)
            }
            "else_clause" => 1 + self.field(node, "body", nesting + 1),
            "conditional_expression" => {
                // `body if condition else alternative`: the branches are the
                // first and last children, the condition the middle one.
                let mut cursor = node.walk();
                let parts: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                let inner: u64 = match parts.as_slice() {
                    [consequence, condition, alternative] => {
                        self.walk(*condition, nesting)
                            + self.walk(*consequence, nesting + 1)
                            + self.walk(*alternative, nesting + 1)
                    }
                    _ => self.children(node, nesting + 1),
                };
                1 + u64::from(nesting) + inner
            }
            "for_statement" | "while_statement" => {
                1 + u64::from(nesting) + self.children_with_deeper_body(node, nesting)
            }
            "except_clause" | "except_group_clause" => {
                1 + u64::from(nesting) + self.children(node, nesting + 1)
            }
            "match_statement" => {
                1 + u64::from(nesting)
                    + self.field(node, "subject", nesting)
                    + self.field(node, "body", nesting + 1)
            }
            "boolean_operator" => self.logical_region(node, nesting),
            "call" => {
                u64::from(self.is_self_call(node.child_by_field_name("function")))
                    + self.children(node, nesting)
            }
            kind if is_function(self.parsed.language, kind) => self.children(node, nesting + 1),
            _ => self.children(node, nesting),
        }
    }

    /// Every `alternative` field of a Python `if_statement`, at `nesting`.
    fn alternatives(&mut self, node: Node<'_>, nesting: u32) -> u64 {
        let mut cursor = node.walk();
        let alternatives: Vec<Node<'_>> = node
            .children_by_field_name("alternative", &mut cursor)
            .collect();
        alternatives
            .into_iter()
            .map(|alternative| self.walk(alternative, nesting))
            .sum()
    }

    // ------------------------------------------------------- shared machinery

    /// `&&`, `||`, `??`, `and`, `or` — or `None` for any other operator.
    fn logical_operator(&self, node: Node<'_>) -> Option<&str> {
        let operator = node.child_by_field_name("operator")?;
        let text = std::str::from_utf8(
            self.parsed
                .source
                .get(operator.start_byte()..operator.end_byte())?,
        )
        .ok()?;
        matches!(text, "&&" | "||" | "??" | "and" | "or").then_some(text)
    }

    /// One run of like operators counts once; a change of operator starts a new
    /// run.
    ///
    /// `a && b && c` is one sequence and costs 1. `a && b || c` is two and costs
    /// 2. Parentheses break the chain by construction — a parenthesized
    /// expression is an operand, so its contents form their own region — which
    /// is what the model intends: the parentheses are the reader's aid, and the
    /// cost is charged for having needed them.
    fn logical_region(&mut self, node: Node<'_>, nesting: u32) -> u64 {
        let mut operators: Vec<String> = Vec::new();
        let mut operands: Vec<Node<'_>> = Vec::new();
        self.flatten_logical(node, &mut operators, &mut operands);

        let runs = operators
            .windows(2)
            .filter(|pair| pair[0] != pair[1])
            .count()
            + usize::from(!operators.is_empty());

        let inner: u64 = operands
            .into_iter()
            .map(|operand| self.walk(operand, nesting))
            .sum();
        runs as u64 + inner
    }

    /// Collect a logical region's operators in source order and its non-logical
    /// operands.
    fn flatten_logical<'t>(
        &self,
        node: Node<'t>,
        operators: &mut Vec<String>,
        operands: &mut Vec<Node<'t>>,
    ) {
        match self.logical_operator(node) {
            Some(operator) => {
                let operator = operator.to_string();
                if let Some(left) = node.child_by_field_name("left") {
                    self.flatten_logical(left, operators, operands);
                }
                operators.push(operator);
                if let Some(right) = node.child_by_field_name("right") {
                    self.flatten_logical(right, operators, operands);
                }
            }
            None => operands.push(node),
        }
    }

    /// Direct recursion: a call to the function being measured, by its own name
    /// or through `this`/`self`.
    ///
    /// Direct only. Mutual recursion needs a call graph, which needs symbol
    /// resolution across files, which the static family does not do — and a
    /// metric that caught some mutual recursion and not the rest would be worse
    /// than one that is clear about catching none.
    fn is_self_call(&self, callee: Option<Node<'_>>) -> bool {
        let (Some(callee), Some(own)) = (callee, self.own_name.as_deref()) else {
            return false;
        };
        let text = |node: Node<'_>| {
            std::str::from_utf8(
                self.parsed
                    .source
                    .get(node.start_byte()..node.end_byte())
                    .unwrap_or_default(),
            )
            .ok()
        };
        match callee.kind() {
            "identifier" => text(callee) == Some(own),
            // `this.method()` / `self.method()`.
            "member_expression" | "attribute" => {
                let object = callee
                    .child_by_field_name("object")
                    .and_then(text)
                    .unwrap_or_default();
                let property = callee
                    .child_by_field_name("property")
                    .or_else(|| callee.child_by_field_name("attribute"))
                    .and_then(text);
                matches!(object, "this" | "self") && property == Some(own)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::functions;
    use crate::parse::parse;

    fn first(language: Language, source: &str) -> u64 {
        let parsed = parse(language, source.as_bytes()).expect("parses");
        let sites = functions(&parsed);
        assert!(!sites.is_empty(), "the snippet has no function");
        complexity(&parsed, sites[0].node)
    }

    #[test]
    fn straight_line_code_costs_nothing() {
        assert_eq!(first(Language::TypeScript, "function f() { return 1 }"), 0);
        assert_eq!(first(Language::Python, "def f():\n    return 1\n"), 0);
    }

    #[test]
    fn the_specifications_worked_example() {
        // if +1; nested if +2; `else if` +1; `else` +1 = 5. The canonical case,
        // and the one every off-by-one in `else if` handling shows up in.
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a, b, c) {\n\
                 if (a) {\n\
                   if (b) { g() }\n\
                 } else if (c) {\n\
                 } else {\n\
                 }\n\
                 }"
            ),
            5
        );
    }

    #[test]
    fn python_elif_chains_stay_flat() {
        assert_eq!(
            first(
                Language::Python,
                "def f(a, b, c):\n\
                 \x20   if a:\n\
                 \x20       if b:\n\
                 \x20           g()\n\
                 \x20   elif c:\n\
                 \x20       pass\n\
                 \x20   else:\n\
                 \x20       pass\n"
            ),
            5
        );
    }

    #[test]
    fn nesting_compounds_with_depth() {
        // +1, +2, +3: the model's whole argument against cyclomatic complexity,
        // which would call this 4 whatever the shape.
        assert_eq!(
            first(
                Language::JavaScript,
                "function f(xs) { for (const x of xs) { if (x) { while (x) { g() } } } }"
            ),
            6
        );
    }

    #[test]
    fn a_sequence_of_like_operators_costs_one_and_a_change_costs_another() {
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a, b, c) { return a && b && c }"
            ),
            1
        );
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a, b, c) { return a && b || c }"
            ),
            2
        );
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a, b, c, d) { return a && b || c && d }"
            ),
            3
        );
        assert_eq!(
            first(
                Language::Python,
                "def f(a, b, c):\n    return a and b and c\n"
            ),
            1
        );
        assert_eq!(
            first(
                Language::Python,
                "def f(a, b, c):\n    return a and b or c\n"
            ),
            2
        );
    }

    #[test]
    fn parentheses_start_a_new_sequence() {
        // `a && (b || c)`: one `&&` sequence and one `||` sequence.
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a, b, c) { return a && (b || c) }"
            ),
            2
        );
    }

    #[test]
    fn an_operator_sequence_takes_no_nesting_penalty() {
        // Inside an `if`, the sequence still costs exactly 1 — B2 lists the
        // structures that take the penalty and sequences are not among them.
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a, b) { if (a) { if (a && b) { g() } } }"
            ),
            // if +1, nested if +2, sequence +1
            4
        );
    }

    #[test]
    fn a_nested_function_adds_a_level_and_no_increment() {
        // The callback itself costs nothing; the `if` inside it costs +2.
        assert_eq!(
            first(
                Language::JavaScript,
                "function outer(xs) { return xs.map(function (x) { if (x) { return 1 } return 2 }) }"
            ),
            2
        );
        assert_eq!(
            first(
                Language::Python,
                "def outer(xs):\n\
                 \x20   def inner(x):\n\
                 \x20       if x:\n\
                 \x20           return 1\n\
                 \x20   return inner\n"
            ),
            2
        );
    }

    #[test]
    fn ternaries_and_switches_take_the_penalty() {
        assert_eq!(
            first(Language::TypeScript, "function f(a) { return a ? 1 : 2 }"),
            1
        );
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a) { if (a) { return a ? 1 : 2 } return 0 }"
            ),
            3
        );
        assert_eq!(
            first(
                Language::JavaScript,
                "function f(a) { switch (a) { case 1: return 1; case 2: return 2; default: return 0 } }"
            ),
            1
        );
    }

    #[test]
    fn python_match_and_ternary() {
        assert_eq!(
            first(
                Language::Python,
                "def f(a):\n\
                 \x20   match a:\n\
                 \x20       case 1:\n\
                 \x20           return 1\n\
                 \x20       case _:\n\
                 \x20           return 0\n"
            ),
            1
        );
        assert_eq!(
            first(Language::Python, "def f(a):\n    return 1 if a else 2\n"),
            1
        );
    }

    #[test]
    fn catch_takes_the_penalty_and_try_does_not() {
        assert_eq!(
            first(
                Language::TypeScript,
                "function f() { try { g() } catch (e) { h() } finally { i() } }"
            ),
            1
        );
        assert_eq!(
            first(
                Language::Python,
                "def f():\n\
                 \x20   try:\n\
                 \x20       g()\n\
                 \x20   except ValueError:\n\
                 \x20       pass\n\
                 \x20   except KeyError:\n\
                 \x20       pass\n"
            ),
            2
        );
    }

    #[test]
    fn a_labelled_jump_costs_one_and_an_ordinary_break_costs_nothing() {
        assert_eq!(
            first(
                Language::JavaScript,
                "function f(xs) { outer: for (const x of xs) { for (const y of x) { break outer } } }"
            ),
            // outer loop +1, inner loop +2, labelled break +1
            4
        );
        assert_eq!(
            first(
                Language::JavaScript,
                "function f(xs) { for (const x of xs) { break } }"
            ),
            1
        );
    }

    #[test]
    fn direct_recursion_costs_one_however_deep_it_sits() {
        assert_eq!(
            first(
                Language::TypeScript,
                "function fact(n) { return n <= 1 ? 1 : n * fact(n - 1) }"
            ),
            // ternary +1, recursion +1 (no nesting penalty on recursion)
            2
        );
        assert_eq!(
            first(
                Language::Python,
                "def fact(n):\n    if n <= 1:\n        return 1\n    return n * fact(n - 1)\n"
            ),
            2
        );
    }

    #[test]
    fn recursion_through_this_and_self_is_still_recursion() {
        assert_eq!(
            first(
                Language::TypeScript,
                "class C { walk(n) { return this.walk(n - 1) } }"
            ),
            1
        );
        assert_eq!(
            first(
                Language::Python,
                "class C:\n    def walk(self, n):\n        return self.walk(n - 1)\n"
            ),
            1
        );
    }

    #[test]
    fn a_call_to_a_different_function_is_not_recursion() {
        assert_eq!(
            first(Language::TypeScript, "function f(n) { return g(n) }"),
            0
        );
    }

    #[test]
    fn a_type_level_conditional_is_not_control_flow() {
        // type-fest is built almost entirely of these. Charging for them would
        // be inventing a metric and citing someone else's study for it.
        assert_eq!(
            first(
                Language::TypeScript,
                "function f<T>(x: T) { type R = T extends string ? 1 : 2; return x }"
            ),
            0
        );
    }

    #[test]
    fn the_tokenization_tier_walks_nothing() {
        let mut parsed =
            parse(Language::TypeScript, b"function f(a) { if (a) {} }").expect("parses");
        parsed.language = Language::Rust;
        let root = parsed.tree.root_node();
        assert_eq!(complexity(&parsed, root), 0);
    }
}
