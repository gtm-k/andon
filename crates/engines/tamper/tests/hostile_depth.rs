//! Deeply nested input is measured, quickly, without unwinding the stack.
//!
//! # What went wrong, and why it is not a micro-optimisation
//!
//! `Node::parent()` is not a pointer dereference. tree-sitter nodes carry no
//! parent link, so `parent()` walks down from the root to find the node again,
//! at O(depth). `is_curried_inner` was asked of every node in the tree, which
//! made the whole detector O(n·depth): a 10 KB TypeScript file of 5000 nested
//! array literals took **5.1 seconds per detector** in release, 67 seconds for
//! the suite in debug.
//!
//! The fast lane's cold cap is ten seconds for the entire measurement, and this
//! input is a file anyone who can open a pull request can write. A hang is a
//! denial of measurement, which for a tool whose job is to stop the line is
//! indistinguishable from being switched off.
//!
//! Two properties are asserted here, and the second is the one that regresses
//! quietly:
//!
//! 1. **No stack overflow.** Every tree walk in this crate is iterative, so
//!    depth costs memory in a `Vec` rather than frames. A stack overflow is not
//!    catchable in Rust — it aborts the process — so a recursive walker over
//!    PR-controlled input is an availability bug that no `Result` can express.
//! 2. **No quadratic blow-up.** Bounded wall-clock, and a growth check across
//!    two depths, because a constant-factor bound alone would pass on a
//!    quadratic implementation given a fast enough machine.

use std::time::{Duration, Instant};

use andon_engine_tamper::change::{ChangeView, FileChange};
use andon_engine_tamper::detectors;
use andon_engine_tamper::syntax::Parsed;

/// Nested array literals: the shape that found the bug, because every level is
/// a node the detectors ask questions about.
fn nested_arrays(depth: usize) -> String {
    let mut source = String::from("it('deep', () => {\n  const v = ");
    source.extend(std::iter::repeat_n('[', depth));
    source.push('1');
    source.extend(std::iter::repeat_n(']', depth));
    source.push_str(";\n  expect(v).toBeDefined();\n});\n");
    source
}

/// Nested parentheses in an expression, in a non-test file.
fn nested_parens(depth: usize) -> String {
    let mut source = String::from("export function f(x: number): number {\n  return ");
    source.extend(std::iter::repeat_n('(', depth));
    source.push('x');
    source.extend(std::iter::repeat_n(')', depth));
    source.push_str(";\n}\n");
    source
}

/// Nested Python lists.
fn nested_python(depth: usize) -> String {
    let mut source = String::from("def test_deep():\n    v = ");
    source.extend(std::iter::repeat_n('[', depth));
    source.push('1');
    source.extend(std::iter::repeat_n(']', depth));
    source.push_str("\n    assert v is not None\n");
    source
}

fn run_everything(path: &str, source: &str) -> Duration {
    let view = ChangeView::new(vec![FileChange::added(path, source)]);
    let started = Instant::now();
    for detector in detectors::all() {
        // The answer does not matter here; surviving and returning does.
        let _ = detector.run(&view);
    }
    started.elapsed()
}

#[test]
fn every_detector_survives_hostile_nesting() {
    for depth in [1_000usize, 5_000] {
        for (label, path, source) in [
            ("arrays", "src/deep.test.ts", nested_arrays(depth)),
            ("parens", "src/deep.ts", nested_parens(depth)),
            ("python", "tests/test_deep.py", nested_python(depth)),
        ] {
            let elapsed = run_everything(path, &source);
            println!("depth {depth:>5} {label:<7} {elapsed:?}");
            assert!(
                elapsed < Duration::from_secs(20),
                "the suite took {elapsed:?} on {label} at depth {depth}; the fast lane's cold cap \
                 is ten seconds for the whole measurement"
            );
        }
    }
}

/// Run the whole detector suite `reps` times and return the total elapsed.
///
/// Repetition rather than a bigger input, because the ratio has to stay a
/// statement about *depth*: the same `reps` on both sides cancels, so tripling
/// the depth is still the only variable.
fn run_everything_n(path: &str, source: &str, reps: u32) -> Duration {
    (0..reps).map(|_| run_everything(path, source)).sum()
}

#[test]
fn the_cost_does_not_grow_quadratically_with_depth() {
    // A wall-clock ceiling alone passes on a quadratic implementation given a
    // fast enough machine. Tripling the depth of a linear walk should cost far
    // less than the ninefold a quadratic one would.
    //
    // # Why the workload is scaled instead of the floor being trusted
    //
    // This assertion used to divide by `baseline.max(floor)` with a 20 ms floor,
    // which protected against dividing by a near-zero measurement — and, on any
    // machine where the real baseline came in under 20 ms, quietly stopped
    // testing anything. Substituting the floor makes the denominator a constant,
    // so the ratio becomes "how long did the deep run take" rather than "how did
    // cost grow", and a genuinely quadratic implementation passes: a 3 ms
    // baseline against a 27 ms deeper run is a ninefold blow-up and scores 1.35
    // against the floor.
    //
    // The failure mode is the vacuous-green shape this repository refuses
    // everywhere else, so the fix is the same one: make the measurement real
    // rather than make the check lenient. The workload is repeated until the
    // baseline genuinely clears the floor, both sides get the same repetition
    // count so it cancels out of the ratio, and clearing it is asserted rather
    // than assumed.
    let floor = Duration::from_millis(20);
    const MAX_REPS: u32 = 64;

    let mut reps = 1;
    let mut baseline = run_everything_n("src/deep.test.ts", &nested_arrays(1_000), reps);
    while baseline < floor && reps < MAX_REPS {
        reps *= 2;
        baseline = run_everything_n("src/deep.test.ts", &nested_arrays(1_000), reps);
    }
    let deeper = run_everything_n("src/deep.test.ts", &nested_arrays(3_000), reps);

    println!("{reps} rep(s): 1000 -> {baseline:?}, 3000 -> {deeper:?}");
    assert!(
        baseline >= floor,
        "the baseline is {baseline:?} after {MAX_REPS} repetitions, still under the {floor:?} \
         needed for the ratio below to mean anything. This machine is fast enough that the \
         measurement is noise; raise MAX_REPS or the depth rather than lowering the floor, \
         because a floor substituted for a real baseline turns this assertion into a \
         restatement of how long the deep run took"
    );

    let ratio = deeper.as_secs_f64() / baseline.as_secs_f64();
    println!("ratio {ratio:.1}x for 3x the depth");
    assert!(
        ratio < 6.0,
        "tripling the depth cost {ratio:.1}x ({baseline:?} -> {deeper:?} over {reps} rep(s)); \
         a quadratic walk costs about 9x and that is what `Node::parent()` per node used to do"
    );
}

#[test]
fn the_parse_itself_survives_and_the_node_walk_is_iterative() {
    // Below the detectors: tree-sitter's own parser and this crate's node walk,
    // on the same input. If either recursed, the process would abort rather
    // than fail, so there would be nothing to assert.
    let source = nested_arrays(10_000);
    let parsed = Parsed::new("src/deep.test.ts", source.as_bytes()).expect("parses");
    let nodes = parsed.nodes();
    assert!(nodes.len() > 10_000, "the tree is genuinely deep");
    // Ancestor walks are bounded, so this returns rather than climbing 10,000
    // levels at O(depth) each.
    let deepest = nodes.last().copied().expect("a node");
    assert!(andon_engine_tamper::syntax::ancestors(deepest).len() <= 256);
}
