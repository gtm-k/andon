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
//! recursion — the last counted **once for the function**, however many times it
//! calls itself.
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
//! # No recursion in the walker
//!
//! The traversal is an explicit `Vec` worklist, not a recursive descent, and
//! that is a correctness property rather than a style choice: the input is a
//! syntax tree built from a file in the change under measurement, so its depth
//! is chosen by whoever wrote the file. Eleven kilobytes of nested `if`
//! statements overflowed the stack of a recursive walker — and a stack overflow
//! is not a failure this process can catch, report, or degrade: it aborts.
//! A measurement tool that a pull request can kill is a measurement tool whose
//! absence is indistinguishable from a pass.
//!
//! Every walk in this crate is iterative for the same reason. Depth is bounded
//! by heap, and the pin tests measure two-thousand-level nesting and check the
//! process is still alive to report it.
//!
//! # Language exceptions
//!
//! Appendix A of the specification carries language-specific exceptions and
//! Appendix B makes them normative. This crate implements the **Python
//! decorator** exception (see [`decorator_exempt`]) and does **not** implement
//! the JavaScript declarative-outer one, under which a function whose body is
//! wholly a nested declaration likewise adds no level. A JavaScript module
//! wrapper therefore reads one nesting level worse here than the model says,
//! and the registry claims for `javascript` and `typescript` carry that as a
//! stated caveat rather than leaving it for a reader to discover by disagreeing
//! with another tool.
//!
//! The deviation is disclosed rather than fixed because the Python idiom is
//! ubiquitous and the JavaScript one is not: the module-wrapper shape is largely
//! historical, and implementing an exception on a guess about which shapes
//! qualify would trade a known, bounded overcount for an unknown undercount.
//!
//! # What is deliberately not counted
//!
//! **Comprehensions.** `[x for x in xs if x]` adds nothing here, while
//! `crate::cyclomatic` scores it 3. The two metrics answer different questions:
//! a comprehension adds independent paths, but it is one idiom a reader takes in
//! at a glance rather than a break in the flow they have to hold. The gap is
//! expected on comprehension-heavy Python and is stated so nobody reads it as a
//! bug in one of the two.
//!
//! **Logical-assignment operators** (`&&=`, `||=`, `??=`) — see the boundary
//! note in `crate::cyclomatic`, which applies to both metrics.
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
    Walker {
        parsed,
        own_name: crate::functions::simple_name(parsed, function),
        decorator_exempt: decorator_exempt(parsed, function),
    }
    .run(function)
}

/// A node still to be measured, and the nesting level it is measured at.
type Pending<'t> = (Node<'t>, u32);

struct Walker<'a, 'b> {
    parsed: &'a Parsed<'b>,
    /// Unqualified name of the function being measured, for recursion.
    own_name: Option<String>,
    /// The nested function a decorator-shaped body exempts from adding a
    /// nesting level. See [`decorator_exempt`].
    decorator_exempt: Option<usize>,
}

impl Walker<'_, '_> {
    /// Measure one function.
    ///
    /// Order of visits does not matter — the result is a sum — so the worklist
    /// is a plain LIFO `Vec`. Each node contributes its own increment and pushes
    /// its children with the nesting levels *they* are measured at, which is
    /// where all of the model's structure lives.
    fn run(&self, function: Node<'_>) -> u64 {
        let mut total = 0u64;
        // Recursion is charged once per function, not once per call site, so it
        // is a flag rather than an increment. See `is_self_call`.
        let mut recursive = false;
        let mut stack: Vec<Pending<'_>> = Vec::new();
        push_children(function, 0, &mut stack);
        while let Some((node, nesting)) = stack.pop() {
            total += self.step(node, nesting, &mut stack, &mut recursive);
        }
        total + u64::from(recursive)
    }

    /// One node's own increment, pushing its children at their nesting levels.
    fn step<'t>(
        &self,
        node: Node<'t>,
        nesting: u32,
        stack: &mut Vec<Pending<'t>>,
        recursive: &mut bool,
    ) -> u64 {
        match self.parsed.language {
            Language::Python => self.step_python(node, nesting, stack, recursive),
            Language::TypeScript | Language::Tsx | Language::JavaScript => {
                self.step_ecma(node, nesting, stack, recursive)
            }
            // No parser, no tree. Asserted in tests so the arm cannot be
            // removed and turn a future Rust tree into a silent JavaScript walk.
            Language::Rust => 0,
        }
    }

    /// One more nesting level for what is inside a nested function — unless the
    /// decorator exception applies to this one.
    fn nested_function_level(&self, node: Node<'_>, nesting: u32) -> u32 {
        if self.decorator_exempt == Some(node.id()) {
            nesting
        } else {
            nesting + 1
        }
    }

    // ------------------------------------------------------------ ECMAScript

    fn step_ecma<'t>(
        &self,
        node: Node<'t>,
        nesting: u32,
        stack: &mut Vec<Pending<'t>>,
        recursive: &mut bool,
    ) -> u64 {
        match node.kind() {
            "if_statement" => {
                // An `if` directly under an `else` is the second half of
                // `else if`: the `else_clause` already charged the +1, and the
                // model explicitly does not charge nesting for it.
                let is_else_if = node.parent().is_some_and(|p| p.kind() == "else_clause");
                push_field(node, "condition", nesting, stack);
                push_field(node, "consequence", nesting + 1, stack);
                // The `else_clause` is measured at *this* level, so a long
                // `else if` chain stays flat instead of deepening.
                push_field(node, "alternative", nesting, stack);
                if is_else_if {
                    0
                } else {
                    1 + u64::from(nesting)
                }
            }
            "else_clause" => {
                match node.named_child(0) {
                    // `else if` — hand the chain back at the same level.
                    Some(child) if child.kind() == "if_statement" => stack.push((child, nesting)),
                    Some(child) => stack.push((child, nesting + 1)),
                    None => {}
                }
                1
            }
            "ternary_expression" => {
                push_field(node, "condition", nesting, stack);
                push_field(node, "consequence", nesting + 1, stack);
                push_field(node, "alternative", nesting + 1, stack);
                1 + u64::from(nesting)
            }
            "switch_statement" => {
                push_field(node, "value", nesting, stack);
                push_field(node, "body", nesting + 1, stack);
                1 + u64::from(nesting)
            }
            "for_statement" | "for_in_statement" | "while_statement" | "do_statement"
            | "catch_clause" => {
                push_children_with_deeper_body(node, nesting, stack);
                1 + u64::from(nesting)
            }
            "binary_expression" if self.logical_operator(node).is_some() => {
                self.logical_region(node, nesting, stack)
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
                if self.is_self_call(node.child_by_field_name("function")) {
                    *recursive = true;
                }
                push_children(node, nesting, stack);
                0
            }
            kind if is_function(self.parsed.language, kind) => {
                // A container, not a branch: no increment, one more level for
                // everything inside.
                push_children(node, self.nested_function_level(node, nesting), stack);
                0
            }
            _ => {
                push_children(node, nesting, stack);
                0
            }
        }
    }

    // ---------------------------------------------------------------- Python

    fn step_python<'t>(
        &self,
        node: Node<'t>,
        nesting: u32,
        stack: &mut Vec<Pending<'t>>,
        recursive: &mut bool,
    ) -> u64 {
        match node.kind() {
            "if_statement" => {
                // `alternative` is a repeated field here — `elif_clause`s then an
                // optional `else_clause` — and each is measured at *this* level
                // so the chain stays flat.
                push_field(node, "condition", nesting, stack);
                push_field(node, "consequence", nesting + 1, stack);
                let mut cursor = node.walk();
                for alternative in node.children_by_field_name("alternative", &mut cursor) {
                    stack.push((alternative, nesting));
                }
                1 + u64::from(nesting)
            }
            "elif_clause" => {
                push_field(node, "condition", nesting, stack);
                push_field(node, "consequence", nesting + 1, stack);
                1
            }
            "else_clause" => {
                push_field(node, "body", nesting + 1, stack);
                1
            }
            "conditional_expression" => {
                // `body if condition else alternative`: the branches are the
                // first and last children, the condition the middle one.
                let mut cursor = node.walk();
                let parts: Vec<Node<'t>> = node.named_children(&mut cursor).collect();
                match parts.as_slice() {
                    [consequence, condition, alternative] => {
                        stack.push((*condition, nesting));
                        stack.push((*consequence, nesting + 1));
                        stack.push((*alternative, nesting + 1));
                    }
                    _ => push_children(node, nesting + 1, stack),
                }
                1 + u64::from(nesting)
            }
            "for_statement" | "while_statement" => {
                push_children_with_deeper_body(node, nesting, stack);
                1 + u64::from(nesting)
            }
            "except_clause" | "except_group_clause" => {
                push_children(node, nesting + 1, stack);
                1 + u64::from(nesting)
            }
            "match_statement" => {
                push_field(node, "subject", nesting, stack);
                push_field(node, "body", nesting + 1, stack);
                1 + u64::from(nesting)
            }
            "boolean_operator" => self.logical_region(node, nesting, stack),
            "call" => {
                if self.is_self_call(node.child_by_field_name("function")) {
                    *recursive = true;
                }
                push_children(node, nesting, stack);
                0
            }
            kind if is_function(self.parsed.language, kind) => {
                push_children(node, self.nested_function_level(node, nesting), stack);
                0
            }
            _ => {
                push_children(node, nesting, stack);
                0
            }
        }
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
    ///
    /// The region is collected with its own worklist and the operators are then
    /// **sorted by source position**. For infix binary operators that is exactly
    /// the in-order sequence a reader sees, and reaching it by sorting rather
    /// than by an in-order traversal means a ten-thousand-term condition costs
    /// heap rather than stack.
    fn logical_region<'t>(
        &self,
        root: Node<'t>,
        nesting: u32,
        stack: &mut Vec<Pending<'t>>,
    ) -> u64 {
        let mut operators: Vec<(usize, String)> = Vec::new();
        let mut region = vec![root];
        while let Some(node) = region.pop() {
            match self.logical_operator(node) {
                Some(operator) => {
                    let operator = operator.to_string();
                    if let Some(token) = node.child_by_field_name("operator") {
                        operators.push((token.start_byte(), operator));
                    }
                    for field in ["left", "right"] {
                        if let Some(child) = node.child_by_field_name(field) {
                            region.push(child);
                        }
                    }
                }
                // A non-logical operand rejoins the main walk: it may hold a
                // ternary, a call, or a whole nested function.
                None => stack.push((node, nesting)),
            }
        }
        operators.sort_by(|a, b| a.0.cmp(&b.0));
        let runs = operators
            .windows(2)
            .filter(|pair| pair[0].1 != pair[1].1)
            .count()
            + usize::from(!operators.is_empty());
        runs as u64
    }

    /// Direct recursion: a call to the function being measured, by its own name
    /// or through `this`/`self`.
    ///
    /// Charged **once per function**, not once per call site. Specification
    /// v1.7 Appendix B B1 increments for "each method in a recursion cycle", so
    /// `fib`, whose body names itself twice, is one recursion and not two —
    /// `run` raises a flag here and adds a single increment at the end. The
    /// distinction is not pedantic: charging per site makes the metric grow with
    /// how many times a recursive call is written rather than with the fact that
    /// the function recurses, which is the thing a reader has to hold in mind.
    ///
    /// Direct only. Mutual recursion needs a call graph, which needs symbol
    /// resolution across files, which the static family does not do — and a
    /// metric that caught some mutual recursion and not the rest would be worse
    /// than one that is clear about catching none.
    fn is_self_call(&self, callee: Option<Node<'_>>) -> bool {
        let (Some(callee), Some(own)) = (callee, self.own_name.as_deref()) else {
            return false;
        };
        match callee.kind() {
            "identifier" => node_text(self.parsed, Some(callee)) == Some(own),
            // `this.method()` / `self.method()`.
            "member_expression" | "attribute" => {
                let object = node_text(self.parsed, callee.child_by_field_name("object"))
                    .unwrap_or_default();
                let property = node_text(
                    self.parsed,
                    callee
                        .child_by_field_name("property")
                        .or_else(|| callee.child_by_field_name("attribute")),
                );
                matches!(object, "this" | "self") && property == Some(own)
            }
            _ => false,
        }
    }
}

// ----------------------------------------------------------------- worklist

fn push_children<'t>(node: Node<'t>, nesting: u32, stack: &mut Vec<Pending<'t>>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        stack.push((child, nesting));
    }
}

/// Every child at `nesting`, except the `body` field which goes a level deeper.
/// The shape shared by every loop form and by `catch`.
fn push_children_with_deeper_body<'t>(node: Node<'t>, nesting: u32, stack: &mut Vec<Pending<'t>>) {
    let body = node.child_by_field_name("body").map(|b| b.id());
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let deeper = Some(child.id()) == body;
        stack.push((child, nesting + u32::from(deeper)));
    }
}

fn push_field<'t>(node: Node<'t>, name: &str, nesting: u32, stack: &mut Vec<Pending<'t>>) {
    if let Some(child) = node.child_by_field_name(name) {
        stack.push((child, nesting));
    }
}

/// The nested function a Python decorator body exempts from adding a nesting
/// level, if this function is decorator-shaped.
///
/// Specification Appendix A carries language-specific exceptions, and Appendix B
/// makes them normative — its increments are "subject to the exceptions". The
/// Python one matters more than its size suggests, because the decorator is the
/// single most common shape in which a Python function's whole body is another
/// function. Without the exception every decorator in a codebase reads one
/// nesting level worse than it is, and the penalty lands on the most idiomatic
/// code rather than on the worst.
///
/// The eligibility test is deliberately narrow: the body is *exactly* a nested
/// definition and a `return` of that definition's own name.
///
/// ```text
/// def decorator(function):
///     def wrapper(*args, **kwargs):
///         if condition:      # +1, not +2
///             ...
///     return wrapper
/// ```
///
/// `@functools.wraps` is admitted because it is part of the same idiom and
/// changes only the node kind. Anything else — two nested functions, a statement
/// before the definition, a `return` of something else — is not the shape the
/// exception is about, and widening the test would start excusing nesting the
/// model means to charge for.
fn decorator_exempt(parsed: &Parsed<'_>, function: Node<'_>) -> Option<usize> {
    if parsed.language != Language::Python {
        return None;
    }
    let body = function.child_by_field_name("body")?;
    let mut cursor = body.walk();
    let statements: Vec<Node<'_>> = body.named_children(&mut cursor).collect();
    let [definition, returned] = statements.as_slice() else {
        return None;
    };
    let inner = match definition.kind() {
        "function_definition" => *definition,
        "decorated_definition" => definition
            .child_by_field_name("definition")
            .filter(|d| d.kind() == "function_definition")?,
        _ => return None,
    };
    if returned.kind() != "return_statement" {
        return None;
    }
    let value = returned
        .named_child(0)
        .filter(|v| v.kind() == "identifier")?;
    let name = inner.child_by_field_name("name")?;
    (node_text(parsed, Some(value)) == node_text(parsed, Some(name))).then(|| inner.id())
}

/// The source text of a node, when it has one.
fn node_text<'a>(parsed: &'a Parsed<'_>, node: Option<Node<'_>>) -> Option<&'a str> {
    let node = node?;
    std::str::from_utf8(parsed.source.get(node.start_byte()..node.end_byte())?).ok()
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
    fn operator_runs_are_read_in_source_order() {
        // The property the sort replaces an in-order traversal with. Reading the
        // operators in tree order rather than source order would score this 2:
        // the region is `((a && b) || (c && d))`, whose operators in source
        // order are && || && — three runs.
        assert_eq!(
            first(
                Language::TypeScript,
                "function f(a, b, c, d) { return a && b || c && d }"
            ),
            3
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
                 \x20   return inner(xs)\n"
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
    fn recursion_is_charged() {
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
    fn recursion_is_charged_once_per_function_however_many_call_sites() {
        // Specification Appendix B B1: "each method in a recursion cycle". `fib`
        // names itself twice and is one recursion. Charging per site would make
        // the number grow with how the recursion is written rather than with the
        // fact that it recurses, which is the thing a reader has to hold.
        assert_eq!(
            first(
                Language::TypeScript,
                "function fib(n) { if (n < 2) { return n } return fib(n - 1) + fib(n - 2) }"
            ),
            // if +1, recursion +1
            2
        );
        assert_eq!(
            first(
                Language::Python,
                "def fib(n):\n    if n < 2:\n        return n\n    return fib(n - 1) + fib(n - 2)\n"
            ),
            2
        );
        // Three call sites, still one increment.
        assert_eq!(
            first(
                Language::TypeScript,
                "function t(n) { return t(n - 1) + t(n - 2) + t(n - 3) }"
            ),
            1
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
    fn the_python_decorator_exception_spares_the_wrapper_a_nesting_level() {
        // Appendix A's Python exception, and the specification's own worked
        // shape: the `if` inside the wrapper is +1, not +2, because the wrapper
        // is the decorator's whole body rather than a nested branch.
        assert_eq!(
            first(
                Language::Python,
                "def decorator(function):
                     def wrapper(*args, **kwargs):
                         if condition:
                             pass
                         return function(*args, **kwargs)
                     return wrapper
"
            ),
            1
        );
    }

    #[test]
    fn functools_wraps_is_still_the_decorator_idiom() {
        assert_eq!(
            first(
                Language::Python,
                "def decorator(function):
                     @functools.wraps(function)
                     def wrapper(*args, **kwargs):
                         if condition:
                             pass
                     return wrapper
"
            ),
            1
        );
    }

    #[test]
    fn a_body_that_merely_contains_a_nested_function_is_not_a_decorator() {
        // The eligibility test is narrow on purpose. A statement before the
        // definition, or a return of something else, is not the shape the
        // exception is about — and the nesting level is charged as usual.
        assert_eq!(
            first(
                Language::Python,
                "def outer(function):
                     log()
                     def wrapper():
                         if condition:
                             pass
                     return wrapper
"
            ),
            2
        );
        assert_eq!(
            first(
                Language::Python,
                "def outer(function):
                     def wrapper():
                         if condition:
                             pass
                     return other
"
            ),
            2
        );
    }

    #[test]
    fn the_exception_is_pythons_alone() {
        // The JavaScript declarative-outer exception is documented as a
        // deviation rather than implemented, so the equivalent shape still
        // charges its level. Asserted so the deviation cannot drift out of the
        // docs without a test noticing.
        assert_eq!(
            first(
                Language::JavaScript,
                "function decorator(fn) { function wrapper() { if (c) { g() } } return wrapper }"
            ),
            2
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
