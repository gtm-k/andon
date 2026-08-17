//! Depth pin: a syntax tree is attacker-chosen input, and no walk may recurse.
//!
//! Eleven kilobytes of nested `if` statements — a thousand levels — overflowed
//! the stack of the recursive cognitive walker. A stack overflow is not a
//! failure this process can catch, report, or degrade into
//! `completeness: unwitnessed`: on Windows it is `STATUS_STACK_OVERFLOW` and the
//! process is gone. That makes it strictly worse than every other failure mode
//! in this crate, because a measurement tool a pull request can kill leaves no
//! result at all — and no result is indistinguishable from a tool nobody ran.
//!
//! So the rule is structural rather than a cap: every tree walk over measured
//! input is an explicit `Vec` worklist, and depth is bounded by heap. These
//! tests run at **two thousand** levels — twice the depth that killed the old
//! walker — and the assertion that matters most is the quietest one: the process
//! is still alive to return a number.
//!
//! A cap would have been the other option and is the wrong one. It would turn a
//! deep file into a refusal, which is a measurement the change controls; the
//! worklist turns it into a measurement.

use andon_static_metrics::{measure_blob, Language};

/// Deep enough to have killed the recursive walker twice over.
const DEPTH: usize = 2000;

fn nested_ifs_ecma() -> String {
    let mut source = String::from("function f(a) {\n");
    for _ in 0..DEPTH {
        source.push_str("if (a) {\n");
    }
    source.push_str("g();\n");
    for _ in 0..DEPTH {
        source.push_str("}\n");
    }
    source.push_str("}\n");
    source
}

/// Python nests through *expressions* here rather than through indentation.
///
/// Not a stylistic choice: `tree-sitter-python`'s external scanner keeps a
/// fixed-size indent stack and stops understanding a file somewhere between 60
/// and 80 levels of indentation — long before any depth that would trouble a
/// walker. Chained conditional expressions reach the same tree depth on one
/// line, so this test measures what it is meant to measure (the walk) rather
/// than the grammar's limit. That limit has its own test below, because it is a
/// real property of the pinned grammar and somebody will otherwise rediscover it
/// as a mystery.
fn nested_ternaries_python() -> String {
    let mut source = String::from("def f(a):\n    return ");
    for _ in 0..DEPTH {
        source.push_str("1 if a else ");
    }
    source.push_str("0\n");
    source
}

#[test]
fn two_thousand_levels_measure_rather_than_abort() {
    for (language, source) in [
        (Language::TypeScript, nested_ifs_ecma()),
        (Language::JavaScript, nested_ifs_ecma()),
    ] {
        let facts = measure_blob(language, source.as_bytes()).unwrap_or_else(|e| {
            panic!("{} must parse {} bytes: {e}", language.name(), source.len())
        });
        let function = facts
            .functions
            .first()
            .unwrap_or_else(|| panic!("{}: no function found", language.name()));

        // The numbers are evidence the walk completed rather than the point.
        // Cognitive complexity compounds with depth, so at N levels it is the
        // triangular number; the assertion is only that it is large and finite.
        assert!(
            function.cognitive > DEPTH as u64,
            "{}: cognitive {} should compound with depth",
            language.name(),
            function.cognitive
        );
        assert_eq!(
            function.cyclomatic,
            DEPTH as u64 + 1,
            "{}: one decision point per `if`, plus one",
            language.name()
        );
    }

    let source = nested_ternaries_python();
    let facts = measure_blob(Language::Python, source.as_bytes()).expect("python parses");
    let function = &facts.functions[0];
    // Each ternary costs 1 + its nesting level, and the chain nests one level
    // per link, so the total is the triangular number of the depth.
    assert_eq!(
        function.cognitive,
        (DEPTH as u64 * (DEPTH as u64 + 1)) / 2,
        "python: nested ternaries compound"
    );
    assert!(!facts.health.expect("health").is_degraded());
}

#[test]
fn a_long_operator_chain_measures_rather_than_aborts() {
    // The other unbounded shape: the logical-region collector used to recurse
    // through the operator chain. Ten thousand terms is one expression.
    let terms = 10_000;
    let mut source = String::from("function f(a) { return a");
    for _ in 0..terms {
        source.push_str(" && a");
    }
    source.push_str(" }\n");

    let facts = measure_blob(Language::TypeScript, source.as_bytes()).expect("parses");
    // One run of like operators, however many terms are in it.
    assert_eq!(facts.functions[0].cognitive, 1);
    assert_eq!(facts.functions[0].cyclomatic, terms as u64 + 1);
}

#[test]
fn deeply_nested_functions_measure_rather_than_abort() {
    // Function discovery is a third walk, and nesting functions is the cheapest
    // way to make it deep.
    let depth = 1000;
    let mut source = String::new();
    for level in 0..depth {
        source.push_str(&format!("function f{level}() {{\n"));
    }
    source.push_str("return 1;\n");
    for _ in 0..depth {
        source.push_str("}\n");
    }

    let facts = measure_blob(Language::JavaScript, source.as_bytes()).expect("parses");
    // One outermost function; the rest are nested inside it and belong to its
    // number.
    assert_eq!(facts.functions.len(), 1);
    assert_eq!(facts.functions[0].name, "f0");
}

#[test]
fn the_python_grammar_has_an_indentation_limit_and_it_degrades_honestly() {
    // A property of `tree-sitter-python` 0.23.6, not of this crate: past roughly
    // 64 levels of indentation its external scanner's indent stack gives out and
    // the file stops parsing. Pinned because the failure is silent in the worst
    // way — the file still yields a tree, and without parse health it would still
    // yield numbers.
    //
    // What this crate owes such a file is what it owes any degraded parse: an
    // ERROR count, `parse-degraded` on everything computed from it, and a
    // process still running. Not a crash, and not a fabricated zero.
    let mut source = String::from("def f(a):\n");
    for level in 0..100 {
        source.push_str(&"    ".repeat(level + 1));
        source.push_str("if a:\n");
    }
    source.push_str(&"    ".repeat(101));
    source.push_str("g()\n");

    let facts = measure_blob(Language::Python, source.as_bytes()).expect("the parse still returns");
    let health = facts.health.expect("python reports health");
    assert!(
        health.is_degraded(),
        "the grammar gave up and parse health must say so: {health:?}"
    );
    assert!(health.error_nodes > 0);

    // Shallow enough to be inside the grammar's reach, for contrast: the same
    // shape at 40 levels is understood completely.
    let mut shallow = String::from("def f(a):\n");
    for level in 0..40 {
        shallow.push_str(&"    ".repeat(level + 1));
        shallow.push_str("if a:\n");
    }
    shallow.push_str(&"    ".repeat(41));
    shallow.push_str("g()\n");
    let facts = measure_blob(Language::Python, shallow.as_bytes()).expect("parses");
    assert!(!facts.health.expect("health").is_degraded());
    assert_eq!(facts.functions[0].cyclomatic, 41);
}
