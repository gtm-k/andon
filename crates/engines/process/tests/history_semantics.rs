//! The process engine against real git history.
//!
//! Every assertion here is about a number's *meaning*: what the window includes,
//! what an absent input produces, and what a second run produces. The unit tests
//! cover the parsing and the arithmetic; these cover the semantics, which is
//! where a metric goes quietly wrong.

mod common;

use std::collections::BTreeMap;

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::git::{ChangedSet, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_core::schema::enums::Completeness;
use andon_core::schema::payload::{MeasurementResult, MetricValue, ScopeKind};
use andon_engine_process::complexity::NoComplexity;
use andon_engine_process::engine::*;
use common::TestRepo;

/// Build the standard fixture: four commits across a year, two authors.
///
/// | day | author | files                          |
/// |-----|--------|--------------------------------|
/// |   0 | alice  | src/a.ts, src/b.ts             |
/// | 100 | bob    | src/a.ts, src/b.ts             |
/// | 200 | alice  | src/a.ts, src/b.ts, src/c.ts   |
/// | 300 | alice  | src/a.ts                       |
///
/// `a.ts` and `b.ts` move together in three of the four commits; `c.ts` appears
/// once. The head is day 300 and the base is day 200.
fn fixture(name: &str) -> (TestRepo, String, String) {
    let repo = TestRepo::new(name);
    repo.write("src/a.ts", b"one\n");
    repo.write("src/b.ts", b"one\n");
    repo.commit_as("alice", 0, "day 0");

    repo.write("src/a.ts", b"one\ntwo\n");
    repo.write("src/b.ts", b"one\ntwo\n");
    repo.commit_as("bob", 100, "day 100");

    repo.write("src/a.ts", b"one\ntwo\nthree\n");
    repo.write("src/b.ts", b"one\ntwo\nthree\n");
    repo.write("src/c.ts", b"c\n");
    let base = repo.commit_as("alice", 200, "day 200");

    repo.write("src/a.ts", b"one\ntwo\nthree\nfour\n");
    let head = repo.commit_as("alice", 300, "day 300");
    (repo, base, head)
}

fn measure(repo: &TestRepo, base: &str, head: &str, window_days: u32) -> Vec<MeasurementResult> {
    measure_with(repo, base, head, window_days, &BTreeMap::new())
}

fn measure_with(
    repo: &TestRepo,
    base: &str,
    head: &str,
    window_days: u32,
    complexity: &BTreeMap<String, u64>,
) -> Vec<MeasurementResult> {
    let git = repo.git();
    let mut policy = Policy::default();
    policy.history.window_days = window_days;
    let range = ResolvedRange::resolve(
        git,
        &Revision::Rev(base.to_string()),
        &Revision::Rev(head.to_string()),
    )
    .expect("both endpoints are commits");
    let changed = ChangedSet::enumerate(git, &range).expect("enumerating the change");
    let engine = ProcessEngine::for_change(git, &range, &changed, &policy, complexity, None)
        .expect("history");
    let ctx = MeasureContext {
        compare_context: range.compare_context().expect("a commit range"),
        policy,
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox_available: false,
    };
    run_engine(&engine, &ctx).expect("the engine measures")
}

fn find<'a>(
    results: &'a [MeasurementResult],
    metric_id: &str,
    path: &str,
) -> &'a MeasurementResult {
    results
        .iter()
        .find(|r| r.metric_id == metric_id && r.scope.path.as_deref() == Some(path))
        .unwrap_or_else(|| panic!("no {metric_id} result for {path}"))
}

fn count_of(result: &MeasurementResult) -> u64 {
    match &result.value {
        MetricValue::Count(n) => *n,
        other => panic!("expected a count, got {other:?}"),
    }
}

#[test]
fn churn_counts_every_commit_in_the_window_that_touched_the_path() {
    let (repo, base, head) = fixture("churn");
    let results = measure(&repo, &base, &head, 365);
    // Four commits touch a.ts, and all four are inside a 365-day window that
    // ends at day 300.
    assert_eq!(
        count_of(find(&results, METRIC_CHURN_COMMITS, "src/a.ts")),
        4
    );
    // One line added per commit after the first, and the first added one line.
    assert!(count_of(find(&results, METRIC_CHURN_LINES, "src/a.ts")) >= 4);
}

#[test]
fn the_window_is_anchored_to_the_commit_and_not_to_the_clock() {
    // The load-bearing property of this engine. Every fixture commit is dated in
    // 2025; a window measured from *now* would hold none of them and every churn
    // count would be zero. A window measured from the head commit holds two of
    // the four at 150 days, and all four at 365.
    let (repo, base, head) = fixture("anchor");

    let narrow = measure(&repo, &base, &head, 150);
    assert_eq!(
        count_of(find(&narrow, METRIC_CHURN_COMMITS, "src/a.ts")),
        2,
        "a 150-day window ending at day 300 holds the day-200 and day-300 commits"
    );

    let wide = measure(&repo, &base, &head, 365);
    assert_eq!(count_of(find(&wide, METRIC_CHURN_COMMITS, "src/a.ts")), 4);
}

#[test]
fn the_window_width_reaches_the_regime_so_two_widths_are_not_comparable() {
    // PREMORTEM S4 in miniature: the same change measured under two windows is
    // two regimes, and the verifier says skew rather than divergence.
    let (repo, base, head) = fixture("regime");
    let narrow = measure(&repo, &base, &head, 150);
    let wide = measure(&repo, &base, &head, 365);
    let a = find(&narrow, METRIC_CHURN_COMMITS, "src/a.ts");
    let b = find(&wide, METRIC_CHURN_COMMITS, "src/a.ts");
    assert_ne!(a.measurement_regime, b.measurement_regime);
    assert_ne!(a.digest, b.digest);
}

#[test]
fn code_age_is_measured_from_the_anchor_commit() {
    let (repo, base, head) = fixture("age");
    let results = measure(&repo, &base, &head, 365);
    // a.ts was last changed by the head commit itself.
    assert_eq!(count_of(find(&results, METRIC_CODE_AGE, "src/a.ts")), 0);
}

#[test]
fn ownership_entropy_is_the_textbook_value_for_the_author_distribution() {
    let (repo, base, head) = fixture("ownership");
    let results = measure(&repo, &base, &head, 365);
    // a.ts: alice three commits, bob one. H(3/4, 1/4) = 0.811278 bits.
    match find(&results, METRIC_OWNERSHIP_ENTROPY, "src/a.ts").value {
        MetricValue::Ratio(bits) => assert!(
            (bits - 0.811_278).abs() < 1e-6,
            "expected 0.811278 bits, got {bits}"
        ),
        ref other => panic!("expected a ratio, got {other:?}"),
    }
}

#[test]
fn a_hotspot_without_a_complexity_input_is_unwitnessed_and_not_churn() {
    let (repo, base, head) = fixture("hotspot-absent");
    let results = measure(&repo, &base, &head, 365);
    let hotspot = find(&results, METRIC_HOTSPOT, "src/a.ts");
    assert_eq!(hotspot.completeness, Completeness::Unwitnessed);
    assert_eq!(
        hotspot.value,
        MetricValue::Text(REASON_NO_COMPLEXITY.to_string())
    );
}

#[test]
fn a_hotspot_with_a_complexity_input_is_the_product() {
    let (repo, base, head) = fixture("hotspot-present");
    let complexity = BTreeMap::from([("src/a.ts".to_string(), 7u64)]);
    let results = measure_with(&repo, &base, &head, 365, &complexity);
    let hotspot = find(&results, METRIC_HOTSPOT, "src/a.ts");
    assert_eq!(hotspot.completeness, Completeness::Complete);
    // Four commits × complexity 7.
    assert_eq!(count_of(hotspot), 28);
}

#[test]
fn change_coupling_names_the_partner_this_change_left_behind() {
    // b.ts moved with a.ts in three of the four commits and is not in this
    // change, which is exactly the finding the metric exists for.
    let (repo, base, head) = fixture("coupling");
    let results = measure(&repo, &base, &head, 365);
    assert_eq!(
        count_of(find(&results, METRIC_CHANGE_COUPLING, "src/a.ts")),
        1
    );
}

#[test]
fn a_binary_file_reports_no_line_churn_rather_than_zero_line_churn() {
    let repo = TestRepo::new("binary");
    repo.write("logo.png", &[0x89, b'P', b'N', b'G', 0x00, 0xff, 0xfe]);
    let base = repo.commit_as("alice", 0, "add binary");
    repo.write("logo.png", &[0x89, b'P', b'N', b'G', 0x00, 0x01, 0x02]);
    let head = repo.commit_as("alice", 10, "change binary");

    let results = measure(&repo, &base, &head, 365);
    let lines = find(&results, METRIC_CHURN_LINES, "logo.png");
    assert_eq!(lines.completeness, Completeness::Unwitnessed);
    assert_eq!(
        lines.value,
        MetricValue::Text(REASON_BINARY_ONLY.to_string()),
        "a binary file has no line counts; zero would be a fabricated number"
    );
    // The commits themselves are still counted: a binary edit is a real touch.
    assert_eq!(
        count_of(find(&results, METRIC_CHURN_COMMITS, "logo.png")),
        2
    );
}

#[test]
fn a_path_the_window_never_saw_reports_absence_and_not_zeroes() {
    // A window narrow enough to exclude every commit that touched b.ts, on a
    // change that touches it. Churn is a measured zero; age, ownership, and
    // coupling are absences.
    let repo = TestRepo::new("outside-window");
    repo.write("src/old.ts", b"one\n");
    repo.commit_as("alice", 0, "old file");
    repo.write("src/new.ts", b"new\n");
    let base = repo.commit_as("alice", 300, "base");
    repo.write("src/new.ts", b"new\nmore\n");
    let head = repo.commit_as("alice", 301, "head");

    // Ten days ending at day 301 excludes the day-0 commit entirely.
    let results = measure(&repo, &base, &head, 10);
    let old_churn = results.iter().find(|r| {
        r.metric_id == METRIC_CHURN_COMMITS && r.scope.path.as_deref() == Some("src/old.ts")
    });
    // old.ts is not in the change at all, so nothing is reported for it.
    assert!(old_churn.is_none());

    // new.ts is in the change, and the window holds its two commits.
    assert_eq!(
        count_of(find(&results, METRIC_CHURN_COMMITS, "src/new.ts")),
        2
    );
}

#[test]
fn a_shallow_clone_emits_change_scoped_markers_and_no_per_file_results() {
    // The emission rule that keeps a shallow verifier from accusing a complete
    // agent. See `andon_engine_process::engine`'s module documentation, and
    // `compare_asymmetry.rs` for the end-to-end proof.
    let (repo, _base, _head) = fixture("shallow-origin");
    let shallow_path = repo.path().parent().expect("temp dir").join(format!(
        "andon-p4-shallow-clone-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&shallow_path);
    let ok = repo
        .git()
        .cmd(["clone", "--quiet", "--depth", "1", &repo.file_url()])
        .arg(&shallow_path)
        .succeeds()
        .expect("git ran");
    assert!(
        ok,
        "the shallow clone must be creatable for this test to mean anything"
    );

    let clone = andon_core::git::Git::open(&shallow_path).expect("a repository");
    assert!(
        clone.facts().shallow,
        "the clone is not shallow, so this test would pass for the wrong reason"
    );

    // A one-commit clone has no range to enumerate, so the window is read
    // directly and the engine is built from it — which is the path the emission
    // rule lives on.
    let head = clone
        .cmd(["rev-parse", "HEAD"])
        .text()
        .expect("rev-parse")
        .trim()
        .to_string();
    let window = andon_engine_process::HistoryWindow::read(&clone, &head, 365)
        .expect("the walk succeeds even when truncated");
    assert!(window.truncated);

    let changed = ChangedSet {
        entries: Vec::new(),
    };
    let engine = ProcessEngine::from_window(&window, &changed, &NoComplexity);
    assert!(engine.is_truncated());

    let ctx = MeasureContext {
        compare_context: andon_core::testing::sample_compare_context(),
        policy: Policy::default(),
        changed_paths: Vec::new(),
        sandbox_available: false,
    };
    let results = run_engine(&engine, &ctx).expect("the engine measures");

    assert_eq!(results.len(), 6, "one marker per metric");
    for result in &results {
        assert_eq!(result.scope.kind, ScopeKind::Change);
        assert_eq!(result.completeness, Completeness::Unwitnessed);
        assert_eq!(
            result.value,
            MetricValue::Text(REASON_SHALLOW.to_string()),
            "the marker must carry the constant reason, never a machine-specific one"
        );
    }
}

#[test]
fn no_unwitnessed_result_ever_carries_a_number() {
    // The invariant that makes "never fabricated zeros" checkable rather than
    // aspirational: the two properties are asserted together over every result
    // the engine can produce, on a fixture built to trigger three of the four
    // unwitnessed reasons at once.
    let repo = TestRepo::new("no-zeroes");
    repo.write("src/a.ts", b"one\n");
    repo.write("logo.png", &[0x00, 0xff]);
    let base = repo.commit_as("alice", 0, "base");
    repo.write("src/a.ts", b"one\ntwo\n");
    repo.write("logo.png", &[0x00, 0xfe]);
    let head = repo.commit_as("bob", 5, "head");

    let results = measure(&repo, &base, &head, 365);
    assert!(!results.is_empty());
    let mut unwitnessed = 0;
    for result in &results {
        if result.completeness != Completeness::Unwitnessed {
            continue;
        }
        unwitnessed += 1;
        match &result.value {
            MetricValue::Text(reason) => assert!(
                UNWITNESSED_REASONS.contains(&reason.as_str()),
                "unwitnessed reasons must come from the closed set, got {reason:?}"
            ),
            other => panic!(
                "{} reported `unwitnessed` and still carried a number: {other:?}",
                result.metric_id
            ),
        }
    }
    assert!(
        unwitnessed > 0,
        "the fixture must actually produce unwitnessed results or this proves nothing"
    );
}

#[test]
fn two_runs_of_the_same_change_produce_identical_digests() {
    // The determinism claim, made locally. The cross-OS half is
    // `docs/patches/p4-spike-matrix-join.md`; this is the half that can be
    // asserted without three runners, and it is the one that catches an
    // iteration order or a wall clock creeping into a value.
    let (repo, base, head) = fixture("determinism");
    let first = measure(&repo, &base, &head, 365);
    let second = measure(&repo, &base, &head, 365);
    let digests = |results: &[MeasurementResult]| -> Vec<String> {
        let mut d: Vec<String> = results.iter().map(|r| r.digest.clone()).collect();
        d.sort();
        d
    };
    assert_eq!(digests(&first), digests(&second));
    assert!(first.iter().all(|r| !r.digest.is_empty()));
}

#[test]
fn every_metric_is_context_informational_so_none_of_them_can_block() {
    // PREMORTEM A4: policy may only escalate a diff-actionable metric to MED+.
    // No edit in a diff changes a file's history, so none of these may be one.
    //
    // The second assertion is the one that moved. It used to read
    // `severity == Info` on the raw engine output, which was true because this
    // engine hardcoded `Info` at its single result site and could not have said
    // anything else — an assertion that could never fail, on a phase where the
    // whole MED+ band turned out to be unreachable. Since the mini-G2 ruling the
    // engine ranks its own numbers, so the property worth pinning is the one the
    // test's name always claimed: whatever the ladder says, **policy** keeps
    // every result from this family out of the MED+ band, because the class
    // rule caps it. Delete the class rule from `severity::ceiling` and this
    // reddens; hardcode `Info` back into the engine and
    // `the_ladders_rank_what_the_claims_support` reddens instead.
    use andon_core::policy::Policy;
    use andon_core::schema::enums::MetricClass;

    let (repo, base, head) = fixture("class");
    let mut results = measure(&repo, &base, &head, 365);
    for result in &results {
        assert_eq!(
            result.metric_class,
            MetricClass::ContextInformational,
            "{} must stay context-informational",
            result.metric_id
        );
    }
    andon_core::verdict::severity::apply(&mut results, &Policy::default());
    for result in &results {
        assert!(
            !result.severity.is_med_plus(),
            "{} reached {:?} after policy; a history metric must never stop the line",
            result.metric_id,
            result.severity
        );
        assert!(
            !andon_core::verdict::severity::stops_the_line(result, &Policy::default().severity),
            "{} stops the line",
            result.metric_id
        );
    }
}

#[test]
fn the_ladders_rank_what_the_claims_support() {
    // The other half of the pair above, and the half that would have caught the
    // dead band: this engine's declarations must be able to say something other
    // than `Info`, or the cap being tested above is a cap over nothing.
    use andon_core::schema::enums::Severity;
    use andon_core::verdict::ladder::SeverityLadder;

    let ladders = andon_engine_process::engine::severity_ladders();
    let declared: std::collections::BTreeSet<String> =
        andon_engine_process::engine::metric_descriptors()
            .into_iter()
            .map(|d| d.metric_id)
            .collect();
    assert_eq!(
        declared,
        ladders
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<String>>(),
        "one ladder per declared metric, no more and no fewer"
    );

    let ranking: Vec<&String> = ladders
        .iter()
        .filter(|(_, ladder)| ladder.strongest() > Severity::Info)
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        ranking.len(),
        5,
        "five of the six rank their own numbers: {ranking:?}"
    );
    assert_eq!(
        ladders.get("process.code-age-days"),
        Some(&SeverityLadder::NoOpinion),
        "the one claim whose direction is not established stays unranked"
    );
}
