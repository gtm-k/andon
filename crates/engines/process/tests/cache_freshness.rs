//! What the history cache is allowed to remember.
//!
//! The cache's whole licence to exist is that its key names one answer: an
//! anchor commit is immutable, so the history reachable from it under a fixed
//! window is a fixed value. That argument has one hole, and this file is about
//! it — **shallowness is not a property of the commit, it is a property of the
//! clone**. The same anchor in the same repository answers differently before
//! and after `git fetch --unshallow`, and an entry written before it is not a
//! cached answer to the question being asked afterwards.
//!
//! It is not a hypothetical: PLAN P9's verifier is required to unshallow before
//! recomputing (a requirement this phase created), and an agent measuring in a
//! `--depth 1` clone and then fetching is the ordinary developer path. A cache
//! that kept serving truncation markers would defeat the doctrine quietly, in
//! the one direction where quiet is worst — the payload would say "no history"
//! about a repository that has all of it.

mod common;

use andon_core::git::{ChangedSet, Git, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_engine_process::cache::HistoryCache;
use andon_engine_process::complexity::NoComplexity;
use andon_engine_process::engine::ProcessEngine;
use common::TestRepo;

/// A repository with enough history that a `--depth 2` clone is visibly a
/// truncation rather than the whole thing.
fn origin(name: &str) -> TestRepo {
    let repo = TestRepo::new(name);
    for day in 0..6 {
        repo.write("src/a.ts", format!("line {day}\n").as_bytes());
        repo.commit_as(if day % 2 == 0 { "alice" } else { "bob" }, day, "commit");
    }
    repo
}

/// Clone `origin` at depth 2 over `file://`, which is the only transport git
/// will make a shallow clone over.
fn shallow_clone(origin: &TestRepo, name: &str) -> Git {
    let path = std::env::temp_dir().join(format!(
        "andon-p4-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    let ok = origin
        .git()
        .cmd(["clone", "--quiet", "--depth", "2", &origin.file_url()])
        .arg(&path)
        .succeeds()
        .expect("git ran");
    assert!(ok, "the shallow clone must be creatable");
    let git = Git::open(&path).expect("a repository");
    assert!(
        git.facts().shallow,
        "the clone is not shallow, so this test would pass for the wrong reason"
    );
    git
}

/// Resolve and enumerate, which is where the spawns that are *not* the history
/// read are paid. Kept separate so a spawn assertion can be about the cache and
/// nothing else.
fn prepare(git: &Git) -> (ResolvedRange, ChangedSet) {
    let range = ResolvedRange::resolve(
        git,
        &Revision::Rev("HEAD~1".to_string()),
        &Revision::Rev("HEAD".to_string()),
    )
    .expect("both endpoints are commits");
    let changed = ChangedSet::enumerate(git, &range).expect("enumerating the change");
    (range, changed)
}

fn engine(
    git: &Git,
    range: &ResolvedRange,
    changed: &ChangedSet,
    cache: Option<&HistoryCache>,
) -> ProcessEngine {
    ProcessEngine::for_change(
        git,
        range,
        changed,
        &Policy::default(),
        &NoComplexity,
        cache,
    )
    .expect("history")
}

fn measure(git: &Git, cache: Option<&HistoryCache>) -> ProcessEngine {
    let (range, changed) = prepare(git);
    engine(git, &range, &changed, cache)
}

#[test]
fn unshallowing_invalidates_a_cached_truncated_window() {
    // The finding, pinned. Before the fix the third measurement below still
    // reported a truncated window — the payload said "shallow clone, history
    // window truncated" about a repository that had just fetched all of it, and
    // the only way to see the real numbers was to bypass the cache.
    let origin = origin("unshallow-origin");
    let git = shallow_clone(&origin, "unshallow-clone");
    let cache = HistoryCache::at(git.workdir().join(".andon-cache")).expect("cache opens");

    let truncated = measure(&git, Some(&cache));
    assert!(
        truncated.is_truncated(),
        "a depth-2 clone must measure as truncated"
    );

    let unshallowed = git
        .cmd(["fetch", "--unshallow", "--quiet"])
        .succeeds()
        .expect("git ran");
    assert!(
        unshallowed,
        "the fetch must succeed for this test to mean anything"
    );

    let git = Git::open(git.workdir()).expect("re-open, so the shallow fact is re-read");
    assert!(!git.facts().shallow, "the repository is no longer shallow");

    let after = measure(&git, Some(&cache));
    assert!(
        !after.is_truncated(),
        "the cache served a truncated window to a repository that is no longer shallow"
    );
    assert!(
        after.file_count() > 0,
        "an unshallowed repository must produce per-file results"
    );

    // And the recomputed answer replaced the stale one rather than sitting
    // beside it: a third call, which hits the cache, agrees with the second.
    let again = measure(&git, Some(&cache));
    assert!(!again.is_truncated());
    assert_eq!(again.file_count(), after.file_count());
}

#[test]
fn a_truncated_entry_is_still_served_to_a_repository_that_is_still_shallow() {
    // The other half of the rule. Invalidating on truncation alone would make
    // every measurement in a shallow clone a cold one, which is a cache that
    // never works in exactly the environment CI runs in.
    let origin = origin("still-shallow-origin");
    let git = shallow_clone(&origin, "still-shallow-clone");
    let cache = HistoryCache::at(git.workdir().join(".andon-cache")).expect("cache opens");

    let (range, changed) = prepare(&git);
    assert!(engine(&git, &range, &changed, Some(&cache)).is_truncated());
    git.reset_spawn_count();
    assert!(engine(&git, &range, &changed, Some(&cache)).is_truncated());
    assert_eq!(
        git.spawn_count(),
        0,
        "a still-shallow repository must still get its cached entry"
    );
}
