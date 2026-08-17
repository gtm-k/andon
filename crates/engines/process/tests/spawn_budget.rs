//! What the process family costs in git spawns.
//!
//! PREMORTEM T6 is about the fast lane's cost model, and the plan's rule for
//! this phase is that the warm path must respect P1's perf budgets. The count is
//! the early warning and the clock is the late one: a refactor that reads the
//! window per changed file instead of once shows up here as a number long before
//! it shows up as a timeout on a hundred-thousand-file repository.
//!
//! The numbers asserted below are the ones
//! `docs/patches/p4-perf-scenarios.md` proposes adding to P1's perf gate, which
//! this phase may not edit.

mod common;

use andon_core::git::{ChangedSet, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_engine_process::cache::HistoryCache;
use andon_engine_process::complexity::NoComplexity;
use andon_engine_process::engine::ProcessEngine;
use common::TestRepo;

/// Cold: one `log -1` for the anchor's timestamp, one `log --numstat` for the
/// walk. Nothing else.
const COLD_SPAWNS: u64 = 2;

fn fixture(name: &str) -> TestRepo {
    let repo = TestRepo::new(name);
    for day in 0..12 {
        repo.write("src/a.ts", format!("line {day}\n").as_bytes());
        repo.write("src/b.ts", format!("line {day}\n").as_bytes());
        repo.commit_as(if day % 2 == 0 { "alice" } else { "bob" }, day, "commit");
    }
    repo
}

fn range_and_change(repo: &TestRepo) -> (ResolvedRange, ChangedSet) {
    let git = repo.git();
    let base = repo.rev_parse("HEAD~1");
    let head = repo.rev_parse("HEAD");
    let range = ResolvedRange::resolve(git, &Revision::Rev(base), &Revision::Rev(head))
        .expect("both endpoints are commits");
    let changed = ChangedSet::enumerate(git, &range).expect("enumerating the change");
    (range, changed)
}

#[test]
fn a_cold_read_costs_two_spawns_and_a_warm_one_costs_none() {
    let repo = fixture("spawns");
    let git = repo.git();
    let (range, changed) = range_and_change(&repo);
    let policy = Policy::default();
    let cache = HistoryCache::at(repo.path().join(".andon-test-cache")).expect("cache opens");

    git.reset_spawn_count();
    ProcessEngine::for_change(git, &range, &changed, &policy, &NoComplexity, Some(&cache))
        .expect("history");
    assert_eq!(
        git.spawn_count(),
        COLD_SPAWNS,
        "a cold history read must cost exactly the anchor timestamp and the walk"
    );

    git.reset_spawn_count();
    ProcessEngine::for_change(git, &range, &changed, &policy, &NoComplexity, Some(&cache))
        .expect("history");
    assert_eq!(
        git.spawn_count(),
        0,
        "a cache hit must not spawn git at all — this is what keeps the process \
         family off the warm path's budget (PREMORTEM T6)"
    );
}

#[test]
fn the_cost_does_not_scale_with_the_number_of_changed_files() {
    // The regression this test exists to catch is a loop that reads the window,
    // or asks git anything, once per changed path.
    let repo = TestRepo::new("many-files");
    for index in 0..40 {
        repo.write(&format!("src/f{index}.ts"), b"one\n");
    }
    repo.commit_as("alice", 0, "many files");
    for index in 0..40 {
        repo.write(&format!("src/f{index}.ts"), b"one\ntwo\n");
    }
    repo.commit_as("alice", 1, "touch them all");

    let git = repo.git();
    let (range, changed) = range_and_change(&repo);
    assert_eq!(changed.len(), 40, "the fixture must change forty files");

    git.reset_spawn_count();
    ProcessEngine::for_change(
        git,
        &range,
        &changed,
        &Policy::default(),
        &NoComplexity,
        None,
    )
    .expect("history");
    assert_eq!(git.spawn_count(), COLD_SPAWNS);
}

#[test]
fn a_cache_entry_is_not_served_to_a_different_window() {
    // The key carries the window width, so widening it is a miss rather than a
    // hit on numbers computed under the old width.
    let repo = fixture("window-key");
    let git = repo.git();
    let (range, changed) = range_and_change(&repo);
    let cache = HistoryCache::at(repo.path().join(".andon-window-cache")).expect("cache opens");

    let mut narrow = Policy::default();
    narrow.history.window_days = 5;
    let mut wide = Policy::default();
    wide.history.window_days = 400;

    ProcessEngine::for_change(git, &range, &changed, &narrow, &NoComplexity, Some(&cache))
        .expect("history");
    git.reset_spawn_count();
    ProcessEngine::for_change(git, &range, &changed, &wide, &NoComplexity, Some(&cache))
        .expect("history");
    assert_eq!(
        git.spawn_count(),
        COLD_SPAWNS,
        "a different window must miss the cache, not reuse the narrow entry"
    );
}
