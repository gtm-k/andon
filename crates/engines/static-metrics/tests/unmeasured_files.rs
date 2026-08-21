//! A file cannot leave measurement without leaving its name behind.
//!
//! PREMORTEM T3 in its purest form: a single invalid UTF-8 byte anywhere in a
//! `.ts` file used to make the whole file vanish from the payload. The engine
//! incremented a change-scope counter and carried on, so the observable
//! difference between "this change touched nine files" and "this change touched
//! ten files and one of them is invisible" was one integer with no path
//! attached — and unlike the parse-error route, no degradation signal on
//! anything.
//!
//! The fix is a marker result per file, scoped to the path, carrying the reason
//! as its value so the reason is inside the per-result digest and both sides of
//! the compare must agree on why a file was skipped.

mod common;

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::git::{ChangedSet, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_core::schema::enums::Completeness;
use andon_core::schema::payload::{MeasurementResult, MetricValue, ScopeKind};
use andon_static_metrics::engine::{UNMEASURED_NOT_SOURCE, UNMEASURED_NO_BLOB};
use andon_static_metrics::metrics::{METRIC_UNMEASURED_FILE, METRIC_UNMEASURED_FILES};
use andon_static_metrics::StaticMetricsEngine;

fn measure(repo: &common::Repo, base: &str, head: Revision) -> Vec<MeasurementResult> {
    let range = ResolvedRange::resolve(&repo.git, &Revision::Rev(base.to_string()), &head)
        .expect("the range resolves");
    let changed = ChangedSet::enumerate(&repo.git, &range).expect("the change enumerates");
    let engine = StaticMetricsEngine::for_change(&repo.git, &changed, "0.1.0")
        .expect("the engine reads its blobs");
    let ctx = MeasureContext {
        compare_context: andon_core::testing::sample_compare_context(),
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox: None,
    };
    run_engine(&engine, &ctx).expect("the engine measures")
}

fn markers(results: &[MeasurementResult]) -> Vec<(String, String)> {
    results
        .iter()
        .filter(|r| r.metric_id == METRIC_UNMEASURED_FILE)
        .map(|r| {
            let reason = match &r.value {
                MetricValue::Text(text) => text.clone(),
                other => panic!("the reason should be text, got {other:?}"),
            };
            (r.scope.path.clone().unwrap_or_default(), reason)
        })
        .collect()
}

#[test]
fn one_invalid_byte_names_the_file_it_hid() {
    let mut repo = common::Repo::init();
    repo.write("src/a.ts", b"export function ok() { return 1 }\n");
    let base = repo.commit("base");

    // Valid TypeScript with one invalid UTF-8 byte in a string literal. The file
    // is in the change, it is a language this engine claims, and it cannot be
    // read as source.
    repo.write(
        "src/hidden.ts",
        b"export const marker = \"\xff\";\nexport function complicated(a) { if (a) { return 1 } return 2 }\n",
    );
    repo.write("src/a.ts", b"export function ok() { return 2 }\n");
    let head = repo.commit("add a file that is not source");

    let results = measure(&repo, &base, Revision::Rev(head));

    assert_eq!(
        markers(&results),
        vec![(
            "src/hidden.ts".to_string(),
            UNMEASURED_NOT_SOURCE.to_string()
        )],
        "the file that vanished has to say which file it was"
    );

    // The change-scope counter is kept as well: one says how many, the other
    // says which, and a consumer that only reads the summary still sees it.
    let count = results
        .iter()
        .find(|r| r.metric_id == METRIC_UNMEASURED_FILES)
        .expect("the change-scope count is always emitted");
    assert_eq!(count.value, MetricValue::Count(1));

    // Weakest completeness there is: nothing was measured for that file, so the
    // record cannot describe itself as complete.
    let marker = results
        .iter()
        .find(|r| r.metric_id == METRIC_UNMEASURED_FILE)
        .expect("marker present");
    assert_eq!(marker.completeness, Completeness::Unwitnessed);
    assert!(!marker.severity.is_med_plus());
    assert_eq!(marker.scope.kind, ScopeKind::File);
    assert_eq!(
        marker.scope.blob_oid, None,
        "naming a blob would imply it had been read"
    );

    // The rest of the change is measured as usual — one bad file does not take
    // the others with it.
    assert!(results
        .iter()
        .any(|r| r.scope.path.as_deref() == Some("src/a.ts")));
}

#[test]
fn an_uncommitted_file_is_named_too_and_for_a_different_reason() {
    // The advisory-lane case: the path is in the change and its bytes are not in
    // the object database, so the compared lane has nothing to read. The reason
    // distinguishes it from bytes that were read and rejected.
    let mut repo = common::Repo::init();
    repo.write("src/a.ts", b"export function ok() { return 1 }\n");
    let base = repo.commit("base");

    repo.write(
        "src/pending.ts",
        b"export function pending() { return 1 }\n",
    );

    let results = measure(&repo, &base, Revision::Worktree);
    assert_eq!(
        markers(&results),
        vec![("src/pending.ts".to_string(), UNMEASURED_NO_BLOB.to_string())]
    );
}

#[test]
fn a_deletion_and_an_unclaimed_extension_are_not_unmeasured() {
    // The two ways to make this number useless. A deletion has nothing to
    // measure; a markdown file was never claimed. Counting either would make the
    // count large on ordinary changes, and a number that is always large is a
    // number nobody reads.
    let mut repo = common::Repo::init();
    repo.write("src/gone.ts", b"export const x = 1;\n");
    repo.write("docs/notes.md", b"# notes\n");
    let base = repo.commit("base");

    repo.remove("src/gone.ts");
    repo.write("docs/notes.md", b"# notes, edited\n");
    let head = repo.commit("delete source, edit prose");

    let results = measure(&repo, &base, Revision::Rev(head));
    assert!(markers(&results).is_empty(), "{:?}", markers(&results));
    let count = results
        .iter()
        .find(|r| r.metric_id == METRIC_UNMEASURED_FILES)
        .expect("count present");
    assert_eq!(count.value, MetricValue::Count(0));
}
