//! The pre-seeded degradation shape, and the part of it this engine owns.
//!
//! # The gaming shape
//!
//! Degrading a file caps the severity of everything computed from it. So the
//! attack is not to degrade a file inside the change under review — that shows
//! up as a parse-error *delta* — but to have degraded it **earlier**, in a
//! change nobody was watching, and then add the complexity now:
//!
//! 1. land a file with one unparsable region, in a change too small to look at;
//! 2. later, add whatever you like to that file.
//!
//! In step 2 the parse-error delta is **zero** — the file was already broken —
//! and every complexity number from it arrives `parse-degraded` and capped below
//! MED+. A detector keyed on the delta alone sees nothing.
//!
//! Nothing about the engine's own numbers is wrong here. What is dangerous is a
//! consumer that reads only deltas, so most of this belongs to P3's detector
//! keying and P5a's policy, and is routed to them.
//!
//! # This engine's part
//!
//! The absolute per-file parse-error counts must be emitted for every degraded
//! file **whether or not the delta moved**, and they must carry the path — that
//! is what gives a delta-blind consumer something to key on instead. It is a
//! property worth a test rather than an inspection, because the natural way to
//! write a diff-first engine is to emit a result only when something changed,
//! and that would remove the evidence silently.

mod common;

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::git::{ChangedSet, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_core::schema::enums::Completeness;
use andon_core::schema::payload::{MeasurementResult, MetricValue, ScopeKind};
use andon_static_metrics::lang::INDENT_STACK_LIMIT_PYTHON;
use andon_static_metrics::metrics::{METRIC_PARSE_ERRORS, METRIC_PARSE_MISSING};
use andon_static_metrics::StaticMetricsEngine;

/// A file whose *tail* does not parse, with the caller's code added before it.
///
/// The added code goes before the unparsable region deliberately. Appending
/// after it would feed the new text into the same ERROR node and move the count,
/// which is the easy case — a detector keyed on the delta would catch that. The
/// shape worth pinning is the one where the delta stays put.
fn already_broken(extra: &str) -> Vec<u8> {
    format!(
        "export function ok(a: number): number {{\n  return a;\n}}\n\n{extra}\nfunction )( @@@ ][ {{\n"
    )
    .into_bytes()
}

fn measure(repo: &common::Repo, base: &str, head: &str) -> Vec<MeasurementResult> {
    let range = ResolvedRange::resolve(
        &repo.git,
        &Revision::Rev(base.to_string()),
        &Revision::Rev(head.to_string()),
    )
    .expect("the range resolves");
    let changed = ChangedSet::enumerate(&repo.git, &range).expect("the change enumerates");
    let engine = StaticMetricsEngine::for_change(&repo.git, &changed, "0.1.0")
        .expect("the engine reads its blobs");
    let ctx = MeasureContext {
        compare_context: andon_core::testing::sample_compare_context(),
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox_available: false,
    };
    run_engine(&engine, &ctx).expect("the engine measures")
}

fn file_result<'a>(
    results: &'a [MeasurementResult],
    metric: &str,
    path: &str,
) -> &'a MeasurementResult {
    results
        .iter()
        .find(|r| {
            r.metric_id == metric
                && r.scope.kind == ScopeKind::File
                && r.scope.path.as_deref() == Some(path)
        })
        .unwrap_or_else(|| panic!("no file-scope {metric} for {path}"))
}

#[test]
fn an_already_degraded_file_still_reports_its_absolute_error_count() {
    let mut repo = common::Repo::init();

    // Step 1, in an earlier change nobody is looking at.
    repo.write("src/seeded.ts", &already_broken(""));
    let base = repo.commit("seed the degradation");

    // Step 2: the change under review adds real complexity to that file.
    repo.write(
        "src/seeded.ts",
        &already_broken(
            "export function added(a: number): number {\n  \
             if (a > 1) { for (const x of [a]) { if (x) { return x } } }\n  return 0;\n}\n",
        ),
    );
    let head = repo.commit("add complexity to the already-degraded file");

    let results = measure(&repo, &base, &head);

    let errors = file_result(&results, METRIC_PARSE_ERRORS, "src/seeded.ts");
    let missing = file_result(&results, METRIC_PARSE_MISSING, "src/seeded.ts");

    // The point of the test: the ABSOLUTE count is present and non-zero even
    // though the delta did not move. A delta-blind consumer has something to key
    // on; a diff-first engine that only emitted changed values would not.
    assert!(
        matches!(errors.value, MetricValue::Count(n) if n > 0),
        "the absolute ERROR count must be emitted: {:?}",
        errors.value
    );
    assert_eq!(
        errors.delta,
        Some(MetricValue::Integer(0)),
        "the delta is zero — which is exactly why the absolute has to be there"
    );
    assert_eq!(errors.scope.path.as_deref(), Some("src/seeded.ts"));
    assert!(matches!(missing.value, MetricValue::Count(_)));

    // And the numbers computed from the degraded tree are still demoted, which
    // is what makes the shape worth naming: they cannot reach MED+ on their own.
    let complexity: Vec<&MeasurementResult> = results
        .iter()
        .filter(|r| {
            r.scope.path.as_deref() == Some("src/seeded.ts")
                && r.metric_id.starts_with("static.cognitive")
        })
        .collect();
    assert!(
        !complexity.is_empty(),
        "the added function is still measured"
    );
    for result in complexity {
        assert_eq!(result.completeness, Completeness::ParseDegraded);
        assert!(!result.severity.is_med_plus());
    }
}

#[test]
fn parse_health_results_are_emitted_for_a_clean_file_too() {
    // The other half of "always emitted": a zero is a measurement here, not an
    // absence, so a consumer can tell "no errors" from "not reported". Without
    // it, absence would mean both.
    let mut repo = common::Repo::init();
    repo.write("src/a.ts", b"export const x = 1;\n");
    let base = repo.commit("base");
    repo.write("src/a.ts", b"export const x = 2;\n");
    let head = repo.commit("edit");

    let results = measure(&repo, &base, &head);
    let errors = file_result(&results, METRIC_PARSE_ERRORS, "src/a.ts");
    assert_eq!(errors.value, MetricValue::Count(0));
    assert_eq!(errors.completeness, Completeness::Complete);
}

#[test]
fn indenting_python_past_the_grammars_limit_is_the_same_shape() {
    // A concrete route into the shape that needs no invalid syntax at all:
    // `tree-sitter-python` stops understanding a file past
    // `INDENT_STACK_LIMIT_PYTHON` levels of indentation, so an attacker can
    // degrade a Python file with whitespace and nothing else. The engine's
    // answer is the same — the ERROR count is reported and path-attributed —
    // and naming the route here is what stops it being rediscovered as a
    // surprise.
    //
    // The depth is taken from the constant rather than written out, because the
    // limit is a property of the pin: it moved from ~64 to 512 at the wave-1
    // convergence, and a literal here would have made this test go quiet at the
    // exact moment the route it describes changed shape.
    let mut repo = common::Repo::init();
    let levels = INDENT_STACK_LIMIT_PYTHON;
    let mut deep = String::from("def f(a):\n");
    for level in 0..levels {
        deep.push_str(&"    ".repeat(level + 1));
        deep.push_str("if a:\n");
    }
    deep.push_str(&"    ".repeat(levels + 1));
    deep.push_str("g()\n");

    repo.write("src/deep.py", deep.as_bytes());
    let base = repo.commit("seed with indentation alone");
    repo.write(
        "src/deep.py",
        format!("{deep}\ndef added(a):\n    return a\n").as_bytes(),
    );
    let head = repo.commit("add to it");

    let results = measure(&repo, &base, &head);
    let errors = file_result(&results, METRIC_PARSE_ERRORS, "src/deep.py");
    assert!(
        matches!(errors.value, MetricValue::Count(n) if n > 0),
        "whitespace alone degraded the file, and the count must say so: {:?}",
        errors.value
    );
}
