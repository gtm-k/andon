//! The pin test PLAN's decision log asks P2 for.
//!
//! > **P1 execution (2026-08-17) (c) P2-entry notes:** rename-recreated
//! > source-path collision in `union()` needs a pin test when engines consume
//! > `ChangedSet`.
//!
//! This engine consumes `ChangedSet` **and** reads the base side of every entry
//! to compute file-scope deltas, so it is squarely sensitive to the
//! approximation `andon_core::git::diff::union` documents:
//!
//! > One case it gets wrong: a file renamed `old` → `new` in the committed
//! > segment whose `old` name is then recreated in the working tree. `old`
//! > appears only in the dirty segment, so it is reported `Added` although the
//! > base has it.
//!
//! The consequence, in this engine's output, is a **missing delta**: `src/old.ts`
//! is reported with no `static.sloc` delta although the base commit contains a
//! file at that exact path. The number itself is correct; what is absent is the
//! comparison.
//!
//! This test asserts the wrong answer on purpose. It is a pin, not an
//! endorsement: if `union()` is ever taught to key on source paths as well as
//! destination paths, this test fails, and whoever fixed it finds a note here
//! saying the new behaviour is the right one and this assertion should be
//! inverted rather than deleted.

mod common;

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::git::{ChangedSet, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_core::schema::payload::{MeasurementResult, ScopeKind};
use andon_static_metrics::metrics::METRIC_SLOC;
use andon_static_metrics::StaticMetricsEngine;

/// Measure `base..WORKTREE` and return every result.
fn measure_worktree(repo: &common::Repo, base: &str) -> Vec<MeasurementResult> {
    let range = ResolvedRange::resolve(
        &repo.git,
        &Revision::Rev(base.to_string()),
        &Revision::Worktree,
    )
    .expect("the range resolves");
    let changed = ChangedSet::enumerate(&repo.git, &range).expect("the change enumerates");
    let engine = StaticMetricsEngine::for_change(&repo.git, &changed, "0.1.0")
        .expect("the engine reads its blobs");
    // A worktree head has no commit id, so there is no wire tuple to seal
    // against — which is exactly why the harness in `crate::record` refuses this
    // range. Here the engine's output is the subject, so a synthetic context is
    // supplied for sealing and never written anywhere.
    let ctx = MeasureContext {
        compare_context: andon_core::testing::sample_compare_context(),
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox_available: false,
    };
    run_engine(&engine, &ctx).expect("the engine measures")
}

fn file_sloc<'a>(results: &'a [MeasurementResult], path: &str) -> &'a MeasurementResult {
    results
        .iter()
        .find(|r| {
            r.metric_id == METRIC_SLOC
                && r.scope.kind == ScopeKind::File
                && r.scope.path.as_deref() == Some(path)
        })
        .unwrap_or_else(|| panic!("no file-scope sloc for {path}"))
}

#[test]
fn a_rename_recreated_source_path_loses_its_delta() {
    let mut repo = common::Repo::init();

    // Base: one file at `src/old.ts`.
    repo.write(
        "src/old.ts",
        b"export function first(a: number) {\n  return a;\n}\n",
    );
    let base = repo.commit("base: src/old.ts exists");

    // Committed on the branch: renamed to `src/new.ts`, unchanged content, so
    // git scores it a rename rather than an add and a delete.
    repo.branch("feature");
    std::fs::create_dir_all(repo.path.join("src")).expect("src");
    std::fs::rename(repo.path.join("src/old.ts"), repo.path.join("src/new.ts"))
        .expect("rename on disk");
    repo.commit("branch: rename old.ts to new.ts");

    // In the working tree: `src/old.ts` comes back, staged so it has a blob the
    // compared lane can read. Unstaged it would have no blob at all and the
    // engine would count it in `static.unmeasured-files` — a different, and
    // correct, behaviour that would hide the case under test.
    repo.write(
        "src/old.ts",
        b"export function second(a: number) {\n  if (a) {\n    return a;\n  }\n  return 0;\n}\n",
    );
    repo.add_all();

    let results = measure_worktree(&repo, &base);

    // The renamed destination is fine: its base side comes from the committed
    // segment's `src_oid`, and the language is read from `old_path`.
    let renamed = file_sloc(&results, "src/new.ts");
    assert!(
        renamed.delta.is_some(),
        "the rename destination should still be compared against the base"
    );

    // The approximation, made visible. `src/old.ts` exists in the base commit
    // and the base is not consulted for it, because `union()` keys on
    // destination paths and the dirty segment reported it as an addition.
    let recreated = file_sloc(&results, "src/old.ts");
    assert_eq!(
        recreated.delta, None,
        "PIN: `union()` keys on destination paths, so a rename-recreated source \
         path is reported as an addition and loses its base comparison. If this \
         assertion has started failing, `union()` has probably been taught to \
         index source paths too — which is the better behaviour. Invert this \
         test (assert the delta is present) and delete the P2-entry note from \
         PLAN.md's decision log; do not delete the test."
    );
}
