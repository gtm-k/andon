//! A detector that could not read all of the change does not claim it did.
//!
//! # The hole this closes, in one change
//!
//! The suite's headline detector reports on what it counted, and it counts what
//! the parser handed it. tree-sitter recovers from anything, so a file it only
//! half-understood still yields a tree, still yields counts, and — before this —
//! still yielded a result marked `complete`, indistinguishable from a result over
//! a file it read every byte of.
//!
//! [`the_deletion_the_parser_could_not_see`] is that hole with a number on it.
//! The same two-line deletion is measured twice: once in a test file that
//! parses, where `test-removal` fires and says one case is gone; and once in a
//! file whose first line is an unclosed JSX tag, where everything after it is
//! JSX *text* — the `it(` calls are not calls, the cases were never counted on
//! either side, and the detector reports **no removal at all**. That second
//! result used to carry `completeness: complete`, on the same file
//! `parse-error-delta` was simultaneously reporting as degraded. The two halves
//! of one payload disagreed, and the half a policy engine reads first was the
//! one that was wrong.
//!
//! What changes is not the count. The flag and the magnitude are the same
//! numbers, still in the digest, still what a verifier compares: no static rule
//! can find a case it cannot see, and pretending otherwise would be a worse fix
//! than the bug. What changes is that the answer stops claiming to be complete,
//! and the caveat says which direction the error runs — a firing is a lower
//! bound and a silence is not evidence of absence.
//!
//! # Why not every detector
//!
//! Three of the seven parse. The other four read bytes, and an ERROR node hides
//! nothing from a scan for `eslint-disable` or from a coverage config.
//! [`only_the_detectors_that_parse_carry_the_caveat`] pins that, because marking
//! all seven would be claiming a limitation rather than disclosing one — and
//! would hand a wider blast radius to anyone who works out that a degraded file
//! caps severity.

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::policy::Policy;
use andon_core::schema::enums::{Completeness, Severity};
use andon_core::schema::payload::{CompareContext, HeadKind, MeasurementResult, MetricValue};
use andon_engine_tamper::change::{ChangeView, FileChange};
use andon_engine_tamper::TamperEngine;

/// Two test cases. The second is the one that gets deleted.
const TWO_CASES: &str = "it('adds', () => { expect(add(1, 2)).toBe(3); });\n\
                         it('subtracts', () => { expect(sub(3, 1)).toBe(2); });\n";

/// The first case only — the same file after the deletion.
const ONE_CASE: &str = "it('adds', () => { expect(add(1, 2)).toBe(3); });\n";

/// An unclosed JSX element. Everything after it is JSX text rather than code:
/// the `it(` calls are not calls to a parser, and the region is an ERROR.
///
/// # This is one hiding shape, and the fix does not depend on knowing them all
///
/// It would be comfortable to claim that only a lexer-level swallow can hide a
/// test and that ordinary syntax errors recover. Measured, that is false, and
/// the two halves fail in different directions:
///
/// | shape | test-removal | degraded |
/// |---|---|---|
/// | `export const Fixture = <div>` — unclosed tag, rest becomes JSX text | silent | yes (8 ERROR) |
/// | `function f( {` — unclosed scope wrapping the rest of the file | **silent** | yes (3 ERROR, 2 MISSING) |
/// | `const y = foo(1, 2 ;` — a localized missing paren | fires, 1 case | yes (2 MISSING) |
///
/// So tree-sitter's recovery is not the safety property. It is *unreliable* in
/// both directions: it finds calls and definitions inside an ERROR subtree when
/// the damage is local, and loses them when the broken construct swallows the
/// scope the tests are in. Which of those happens is a property of the grammar's
/// recovery on that byte sequence, and nothing here should be written as though
/// it were predictable.
///
/// The invariant this fix rests on is the other one, and it is not shape-aware:
/// **any tree carrying an ERROR or a MISSING node demotes the results computed
/// over it.** The third row is the direction that error runs — a detector that
/// recovered fine and found the removal is still marked `parse-degraded`,
/// because the engine cannot know it got away with it. Conservative, and the
/// only version of this that is safe to be wrong about.
///
/// The unclosed tag is the fixture because it is the most deniable of the three:
/// it looks like a component, in a file where a component belongs.
const OPENS_JSX: &str = "export const Fixture = <div>\n";

fn context() -> MeasureContext {
    MeasureContext {
        compare_context: CompareContext {
            base_oid: "0".repeat(40),
            head_oid: "1".repeat(40),
            git_version: "git version 2.51.0".to_string(),
            head_kind: HeadKind::Commit,
            base_resolution: "explicit".to_string(),
        },
        policy: Policy::default(),
        changed_paths: Vec::new(),
        sandbox_available: false,
    }
}

fn measure(base: &str, head: &str) -> Vec<MeasurementResult> {
    measure_at("src/cart.spec.tsx", base, head)
}

fn measure_at(path: &str, base: &str, head: &str) -> Vec<MeasurementResult> {
    let view = ChangeView::new(vec![FileChange::modified(path, base, head)]);
    run_engine(&TamperEngine::for_view(view), &context()).expect("measures")
}

fn result<'a>(results: &'a [MeasurementResult], metric_id: &str) -> &'a MeasurementResult {
    results
        .iter()
        .find(|r| r.metric_id == metric_id)
        .unwrap_or_else(|| panic!("{metric_id} is always emitted"))
}

#[test]
fn the_deletion_the_parser_could_not_see() {
    // The control. A test file that parses: the deletion is found, and the
    // result is complete because the detector read every byte of both sides.
    let seen = measure(TWO_CASES, ONE_CASE);
    let flag = result(&seen, "tamper.test-removal");
    assert_eq!(flag.value, MetricValue::Flag(true));
    assert_eq!(
        result(&seen, "tamper.test-removal.magnitude").value,
        MetricValue::Integer(1)
    );
    assert_eq!(flag.completeness, Completeness::Complete);

    // The hole. The identical deletion, in a file whose cases are JSX text.
    let unseen = measure(
        &format!("{OPENS_JSX}{TWO_CASES}"),
        &format!("{OPENS_JSX}{ONE_CASE}"),
    );
    let flag = result(&unseen, "tamper.test-removal");
    assert_eq!(
        flag.value,
        MetricValue::Flag(false),
        "the detector genuinely cannot see the removal — that is the premise, \
         not the bug being fixed"
    );
    assert_eq!(
        result(&unseen, "tamper.test-removal.magnitude").value,
        MetricValue::Integer(0)
    );

    // ...and this is the fix: it no longer says the answer was complete.
    assert_eq!(
        flag.completeness,
        Completeness::ParseDegraded,
        "a quiet detector over a tree it could not finish reading claimed \
         `complete` on the same file parse-error-delta reported as degraded"
    );
    assert_eq!(
        result(&unseen, "tamper.test-removal.magnitude").completeness,
        Completeness::ParseDegraded,
        "the magnitude is a lower bound and has to say so too"
    );
    assert!(
        flag.evidence.does_not_predict[0].contains("not evidence of absence"),
        "the caveat has to name the direction of the error: {:?}",
        flag.evidence.does_not_predict
    );

    // The other half of the payload was always right, and still is: the file is
    // reported as a blind spot by the detector that watches for blind spots.
    assert_eq!(
        result(&unseen, "tamper.parse-error-delta").value,
        MetricValue::Flag(true)
    );
}

/// An unclosed block, in plain TypeScript, wrapping the cases below it.
///
/// The other half of the pair with [`OPENS_JSX`], and the reason it is here: no
/// JSX, no template literal, nothing that changes how a byte is *lexed*. This is
/// an ordinary syntax error of the kind anyone can commit by accident, and the
/// grammar's recovery loses the tests inside it anyway.
const OPENS_SCOPE: &str = "function f( {\n";

#[test]
fn the_demotion_is_not_a_property_of_the_jsx_route() {
    // The fix must not be readable as "JSX files get a caveat". What it keys on
    // is a tree carrying ERROR or MISSING nodes, whatever put them there — and a
    // refactor that narrowed it back to the shape the other test happens to use
    // would pass every assertion in this file except these.
    //
    // The shape matters because it is the one that looked safe. This file used
    // to claim a broken brace "leaves the cases perfectly visible", from a probe
    // that put the break at the end of the file where it wrapped nothing. Placed
    // before the cases it swallows them exactly as the unclosed tag does, and
    // the two failures share no mechanism: one is a lexer mode, this is a scope
    // the parser never sees closed.
    let unseen = measure_at(
        "src/cart.spec.ts",
        &format!("{OPENS_SCOPE}{TWO_CASES}"),
        &format!("{OPENS_SCOPE}{ONE_CASE}"),
    );
    let flag = result(&unseen, "tamper.test-removal");
    assert_eq!(
        flag.value,
        MetricValue::Flag(false),
        "the premise: a plain unclosed block hides the cases too"
    );
    assert_eq!(
        result(&unseen, "tamper.test-removal.magnitude").value,
        MetricValue::Integer(0)
    );
    assert_eq!(
        flag.completeness,
        Completeness::ParseDegraded,
        "the demotion keys on ERROR and MISSING nodes, not on which construct \
         produced them"
    );

    // And it is a genuinely different fault mix from the JSX route, which is
    // what makes this a second mechanism rather than a second spelling of the
    // first: an unclosed scope leaves MISSING nodes — tokens the parser inserted
    // to finish the tree — where the unclosed tag leaves only ERROR regions.
    let view = ChangeView::new(vec![FileChange::modified(
        "src/cart.spec.ts",
        &format!("{OPENS_SCOPE}{TWO_CASES}"),
        &format!("{OPENS_SCOPE}{ONE_CASE}"),
    )]);
    let health = TamperEngine::for_view(view)
        .outcomes()
        .into_iter()
        .find(|(detector, _)| detector.metric_id() == "tamper.test-removal")
        .map(|(_, outcome)| outcome.view_health)
        .expect("test-removal always runs");
    assert!(health.missing_nodes > 0, "{health:?}");
    assert!(health.error_nodes > 0, "{health:?}");
}

#[test]
fn only_the_detectors_that_parse_carry_the_caveat() {
    // One change: a degraded test file, a suppression added, and a coverage
    // config edited. The parse failure is in the first and cannot reach the
    // other two, which are byte scans.
    let view = ChangeView::new(vec![
        FileChange::modified(
            "src/cart.spec.tsx",
            &format!("{OPENS_JSX}{TWO_CASES}"),
            &format!("{OPENS_JSX}{ONE_CASE}"),
        ),
        FileChange::modified(
            "src/cart.ts",
            "export const total = (n: number) => n;\n",
            "// eslint-disable-next-line no-explicit-any\n\
             // eslint-disable-next-line no-unused-vars\n\
             // @ts-ignore\n\
             export const total = (n: any) => n;\n",
        ),
        FileChange::modified(
            ".coveragerc",
            "[run]\nomit =\n",
            "[run]\nomit =\n    src/*\n",
        ),
    ]);
    let results = run_engine(&TamperEngine::for_view(view), &context()).expect("measures");

    for metric in ["tamper.test-removal", "tamper.assertion-free-test"] {
        assert_eq!(
            result(&results, metric).completeness,
            Completeness::ParseDegraded,
            "{metric} reads test files with a parser"
        );
    }
    for metric in [
        "tamper.suppression-density",
        "tamper.coverage-exclusion-drift",
        "tamper.threshold-config-edit",
    ] {
        assert_eq!(
            result(&results, metric).completeness,
            Completeness::Complete,
            "{metric} counts bytes; an ERROR node hides nothing from it, and a \
             caveat saying otherwise would be a limitation this engine does not have"
        );
    }
}

#[test]
fn the_detector_that_reports_the_blind_spot_is_never_demoted_by_it() {
    // Both of its arms, because they are reached by different routes: the hard
    // arm when faults rise in this change, the soft arm when a changed file was
    // already degraded and stayed that way. Demoting either would cap the one
    // signal PREMORTEM T3 wants loud, at exactly the moment it fires — a file
    // broken badly enough would silence the detector that exists to say so.
    let rose = measure(
        "export const f = (a: number) => a;\n",
        "export const f = (a: number = > a;\n",
    );
    let hard = result(&rose, "tamper.parse-error-delta");
    assert_eq!(hard.value, MetricValue::Flag(true));
    assert_eq!(hard.completeness, Completeness::Complete);
    assert!(
        hard.severity.is_med_plus(),
        "a rise in unreadable code is a MED+ signal: {:?}",
        hard.severity
    );

    let already = measure(
        &format!("{OPENS_JSX}{TWO_CASES}"),
        &format!("{OPENS_JSX}{ONE_CASE}"),
    );
    let soft = result(&already, "tamper.parse-error-delta");
    assert_eq!(soft.value, MetricValue::Flag(true));
    assert_eq!(soft.completeness, Completeness::Complete);
    assert_eq!(
        soft.severity,
        Severity::Low,
        "the state arm is a weak claim"
    );
    for metric in [
        "tamper.parse-error-delta",
        "tamper.parse-error-delta.magnitude",
    ] {
        assert!(
            result(&already, metric)
                .evidence
                .does_not_predict
                .iter()
                .all(|line| !line.contains(andon_core::parse_health::PARSE_DEGRADED_SET_CAVEAT)),
            "{metric} must not carry a caveat about the thing it is reporting"
        );
    }
}

#[test]
fn a_change_the_parser_read_completely_claims_so() {
    let clean = measure(TWO_CASES, ONE_CASE);
    assert_eq!(clean.len(), 14);
    for result in &clean {
        assert_eq!(
            result.completeness,
            Completeness::Complete,
            "{} acquired a caveat on a change with nothing wrong with it",
            result.metric_id
        );
        assert!(result
            .evidence
            .does_not_predict
            .iter()
            .all(|line| !line.contains(andon_core::parse_health::PARSE_DEGRADED_SET_CAVEAT)));
    }
}

#[test]
fn a_degraded_view_never_changes_what_a_detector_found() {
    // Demotion qualifies an answer; it must not become an answer. If the flags
    // or the magnitudes moved, the corpus precision and recall floors would be
    // measuring something other than what they were frozen against.
    let view = ChangeView::new(vec![FileChange::modified(
        "src/cart.spec.tsx",
        &format!("{OPENS_JSX}{TWO_CASES}"),
        &format!("{OPENS_JSX}{ONE_CASE}"),
    )]);
    let engine = TamperEngine::for_view(view);
    let outcomes = engine.outcomes();
    let results = run_engine(&engine, &context()).expect("measures");

    assert!(
        outcomes.iter().any(|(_, o)| o.view_health.is_degraded()),
        "the fixture has to reach the demotion for this test to mean anything"
    );
    for (detector, outcome) in &outcomes {
        assert_eq!(
            result(&results, detector.metric_id()).value,
            MetricValue::Flag(outcome.fired)
        );
        assert_eq!(
            result(&results, detector.magnitude_metric_id()).value,
            MetricValue::Integer(outcome.magnitude)
        );
    }
    assert_eq!(
        engine.signals().len(),
        outcomes.iter().filter(|(_, o)| o.fired).count()
    );
}
