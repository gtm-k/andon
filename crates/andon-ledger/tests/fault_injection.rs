//! The fault-injection requirement (PLAN P8, round-1 loudness fix): exhausted
//! retries and rejected pushes produce a red, user-visible failure.
//!
//! The disqualifying shape is a silent give-up — a sync that runs out of
//! retries and exits as if it had synced. These tests inject a real fault (a
//! pre-receive hook that refuses every push; a remote that does not exist) and
//! assert the failure is loud, attributed, and actionable. The CLI half of the
//! same requirement — nonzero exit, message on stderr — lives in
//! `andon-cli/tests/ledger_cli.rs`, driving the shipped binary.

mod common;

use andon_ledger::sync::{sync_all, Backoff, Pushed, SyncError, SyncOptions};
use andon_ledger_min::notes::{Notes, NotesError, MEASURE_REF};

use common::*;

fn fast(attempts: u32) -> SyncOptions {
    SyncOptions {
        attempts,
        backoff: Backoff::none(),
    }
}

/// A repository with one measured PR head, its origin rigged to refuse pushes.
///
/// `name` keeps each test's fixture root distinct — tests run in parallel, and
/// a shared root would be cleared out from under a sibling mid-run.
fn rigged(name: &str) -> (std::path::PathBuf, andon_core::git::Git, String) {
    let root = root(name);
    let origin = root.join("origin.git");
    bare_origin(&origin);
    let a = clone_from(&origin, &root.join("clone-a"), &[]);
    write_and_commit(&a, "src/base.ts", "export const base = 1;\n", "base");
    a.cmd(["push", "--quiet", "origin", "main"])
        .output()
        .expect("push main");
    a.cmd(["checkout", "--quiet", "-b", "pr"])
        .output()
        .expect("branch");
    let pr = write_and_commit(&a, "src/pr.ts", "export const pr = 1;\n", "pr");
    self_report(&a, &pr);
    install_pre_receive(
        &origin,
        "#!/bin/sh\necho 'rejected by policy' >&2\nexit 1\n",
    );
    (origin, a, pr)
}

#[test]
fn exhausted_retries_are_a_red_failure_that_names_the_state_and_the_next_step() {
    let (_origin, a, pr) = rigged("fault-exhausted");

    let err = sync_all(&a, "origin", &fast(3)).expect_err(
        "a remote that rejects every push must fail the sync — a quiet give-up here is \
         the exact shape PLAN P8's fault-injection AC exists to rule out",
    );

    // The right variant, with the right count…
    let SyncError::PushExhausted {
        notes_ref,
        remote,
        attempts,
        ..
    } = &err
    else {
        panic!("expected PushExhausted, got: {err}");
    };
    assert_eq!(notes_ref, MEASURE_REF);
    assert_eq!(remote, "origin");
    assert_eq!(*attempts, 3);

    // …and the loud sentence: consequence, cause, recovery. This is what a
    // person sees in a red CI step, so the words are the interface.
    let text = err.to_string();
    for needle in [
        "LEDGER PUSH FAILED",
        MEASURE_REF,
        "all 3 attempt(s)",
        "nothing was lost",
        "unwitnessed",
        "andon ledger sync",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in: {text}");
    }

    // "nothing was lost" is a claim, so it is checked, not trusted: the record
    // is still in the local ref after the failed sync.
    let records = Notes::measure(&a).read(&pr).expect("the local ledger reads");
    assert_eq!(records.len(), 1, "the failure must not eat the local record");
}

#[test]
fn a_single_attempt_configuration_still_fails_loudly() {
    // --attempts 1 is a configuration a CI job in a hurry will pick; the
    // loudness must not depend on the retry loop having looped.
    let (_origin, a, _pr) = rigged("fault-single");
    let err = sync_all(&a, "origin", &fast(1)).expect_err("one rejected push is still a failure");
    assert!(matches!(
        err,
        SyncError::PushExhausted { attempts: 1, .. }
    ));
    assert!(err.to_string().contains("LEDGER PUSH FAILED"));
}

#[test]
fn an_unreachable_remote_is_a_transport_failure_not_an_empty_sync() {
    // The other half of loudness (the -min fetch doctrine, held by the full
    // machinery): a remote that cannot answer must not read as a remote with
    // no ledger. `sync` against a remote that does not exist fails with the
    // typed transport error, before any push is attempted.
    let root = root("fault-transport");
    let origin = root.join("origin.git");
    bare_origin(&origin);
    let a = clone_from(&origin, &root.join("clone-a"), &[]);
    write_and_commit(&a, "src/base.ts", "export const base = 1;\n", "base");

    let err = sync_all(&a, "no-such-remote", &fast(2))
        .expect_err("a dead remote must be a loud transport failure");
    match err {
        SyncError::Notes(NotesError::Transport { .. }) => {}
        other => panic!("expected a transport failure, got: {other}"),
    }
}

#[test]
fn an_empty_ledger_syncs_green_with_nothing_to_push() {
    // The complement that keeps the cron job green on a young repository: no
    // records anywhere is a no-op, not a failure. Loudness is for faults, and
    // an empty ledger is not a fault.
    let root = root("fault-empty");
    let origin = root.join("origin.git");
    bare_origin(&origin);
    let a = clone_from(&origin, &root.join("clone-a"), &[]);
    write_and_commit(&a, "src/base.ts", "export const base = 1;\n", "base");
    a.cmd(["push", "--quiet", "origin", "main"])
        .output()
        .expect("push main");

    for synced in sync_all(&a, "origin", &fast(2)).expect("an empty sync is green") {
        assert_eq!(synced.pushed, Pushed::NothingToPush, "{}", synced.notes_ref);
    }
}
