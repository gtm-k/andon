//! PREMORTEM T4, re-run against the full machinery.
//!
//! The P1.5 fixture (`andon-ledger-min/tests/concurrency_and_squash.rs`)
//! proved the *kernel* survives concurrent attest races, squash-orphaned
//! notes, and shallow checkouts — driving the plumbing by hand. This file
//! proves the same three legs through the operations a user actually runs:
//! [`sync_all`] for the transport (fetch → `cat_sort_uniq` merge → push with
//! retry and backoff) and [`migrate_squash`] for the squash migration. The -min
//! fixture stays: it pins the mechanism, this pins the product surface.

mod common;

use andon_core::schema::enums::{Attestation, RecordKind};
use andon_ledger::migrate::migrate_squash;
use andon_ledger::sync::{sync_all, Backoff, Pushed, SyncOptions};
use andon_ledger_min::notes::{Notes, ATTEST_REF, MEASURE_REF};
use andon_ledger_min::verify::{attest, VerifyRequest};

use common::*;

fn fast() -> SyncOptions {
    SyncOptions {
        attempts: 3,
        backoff: Backoff::none(),
    }
}

/// Attest a branch head from a pinned checkout, as CI would.
fn attest_head(git: &andon_core::git::Git, head_oid: &str) {
    git.cmd(["checkout", "--quiet", "--detach", head_oid])
        .output()
        .expect("pin the checkout to the head under verification");
    let outcome = attest(
        git,
        &VerifyRequest {
            head: head_oid.to_string(),
            trusted_branch: "origin/main".to_string(),
            fork_tier: false,
        },
    )
    .expect("attest");
    assert_eq!(
        outcome.attestation,
        Attestation::Confirmed,
        "an honest self-report must confirm"
    );
}

#[test]
fn two_writers_a_squash_and_a_shallow_clone_survive_the_supported_operations() {
    let root = root("t4-full");
    let origin = root.join("origin.git");
    bare_origin(&origin);

    // ---- one developer sets up main and two PR branches -------------------
    let a = clone_from(&origin, &root.join("clone-a"), &[]);
    write_and_commit(&a, "src/base.ts", "export const base = 1;\n", "base");
    a.cmd(["push", "--quiet", "origin", "main"])
        .output()
        .expect("push main");
    a.cmd(["checkout", "--quiet", "-b", "pr-one"])
        .output()
        .expect("branch pr-one");
    let pr_one = write_and_commit(&a, "src/one.ts", "export const one = 1;\n", "pr one");
    a.cmd(["push", "--quiet", "origin", "pr-one"])
        .output()
        .expect("push pr-one");
    a.cmd(["checkout", "--quiet", "-B", "pr-two", "main"])
        .output()
        .expect("branch pr-two from main");
    let pr_two = write_and_commit(&a, "src/two.ts", "export const two = 2;\n", "pr two");
    a.cmd(["push", "--quiet", "origin", "pr-two"])
        .output()
        .expect("push pr-two");

    // The second writer's clone exists before any note does, so its first sync
    // genuinely merges a remote ledger it has never seen.
    let b = clone_from(&origin, &root.join("clone-b"), &[]);

    // ---- A measures, attests, and syncs — nothing to race with yet --------
    self_report(&a, &pr_one);
    attest_head(&a, &pr_one);
    for synced in sync_all(&a, "origin", &fast()).expect("A's sync") {
        assert_eq!(
            synced.pushed,
            Pushed::OnAttempt(1),
            "{}: first writer, empty remote",
            synced.notes_ref
        );
    }

    // ---- B measures and syncs against a remote that has moved -------------
    self_report(&b, &pr_two);
    attest_head(&b, &pr_two);
    for synced in sync_all(&b, "origin", &fast()).expect("B's sync") {
        assert!(
            synced.fetched,
            "{}: the remote had A's ledger to fetch",
            synced.notes_ref
        );
        assert_eq!(synced.pushed, Pushed::OnAttempt(1), "{}", synced.notes_ref);
        // The merge is what makes attempt 1 possible: without cat_sort_uniq
        // combining A's note tree into B's before the push, the push would be
        // a non-fast-forward rejection. The assertion below — B can read A's
        // record locally — proves the merge really carried A's content.
        let others = Notes::new(&b, synced.notes_ref.as_str())
            .read(&pr_one)
            .expect("read A's record from B's merged ledger");
        assert_eq!(
            others.len(),
            1,
            "{}: the merge must carry the other writer's record",
            synced.notes_ref
        );
    }

    // ---- both PRs squash-merge; migration is the supported operation ------
    a.cmd(["checkout", "--quiet", "main"])
        .output()
        .expect("back to main");
    // A resyncs first so its migration sees B's records too.
    sync_all(&a, "origin", &fast()).expect("A resyncs before migrating");

    let mut landed = Vec::new();
    for branch in ["pr-one", "pr-two"] {
        identified(a.cmd(["merge", "--squash", branch]))
            .output()
            .unwrap_or_else(|e| panic!("squash-merge {branch}: {e}"));
        commit(&a, &format!("squash: {branch}"));
        landed.push(head(&a));
    }
    for (source, target) in [(&pr_one, &landed[0]), (&pr_two, &landed[1])] {
        let migrations = migrate_squash(&a, source, target).expect("migrate");
        for migration in &migrations {
            assert_eq!(
                migration.source_records, 1,
                "{}: the pre-squash head carries its record",
                migration.notes_ref
            );
            assert_eq!(
                migration.target_records, 1,
                "{}: the landed commit carries it after migration",
                migration.notes_ref
            );
        }
    }
    a.cmd(["push", "--quiet", "origin", "main"])
        .output()
        .expect("push the squashed main");
    sync_all(&a, "origin", &fast()).expect("publish the migrated ledger");

    // ---- a shallow clone gets the whole ledger through sync alone ----------
    // `actions/checkout` fetches depth 1; a notes tree references no commit in
    // history, so truncating history must not truncate the ledger. And unlike
    // the -min fixture, no manual `update-ref` adoption step: the sync's merge
    // creates the working ref in a clone that never had one.
    let shallow = clone_from(&origin, &root.join("clone-shallow"), &["--depth", "1"]);
    for synced in sync_all(&shallow, "origin", &fast()).expect("shallow sync") {
        assert!(synced.fetched, "{}", synced.notes_ref);
        assert!(
            synced.merged,
            "{}: the fetched ledger must merge into a working ref",
            synced.notes_ref
        );
    }
    for notes_ref in [MEASURE_REF, ATTEST_REF] {
        let notes = Notes::new(&shallow, notes_ref);
        let annotated = notes.annotated_commits().expect("list the ledger");
        assert_eq!(
            annotated.len(),
            4,
            "{notes_ref}: both PR heads and both landed commits must survive; saw {annotated:?}"
        );
        let tip = head(&shallow);
        assert_eq!(landed[1], tip, "the shallow tip is the last squash");
        let records = notes.read(&tip).expect("read the ledger at the tip");
        assert_eq!(
            records.len(),
            1,
            "{notes_ref}: the squash-migrated record is missing from the landed commit"
        );
        // The record still names what it measured: the pre-squash head, not
        // the commit it now hangs on.
        assert_eq!(records[0].compare_context.head_oid, pr_two);
    }
}

#[test]
fn a_rejected_push_recovers_on_the_next_attempt() {
    // The retry-with-backoff path, driven by a real rejection: a pre-receive
    // hook that refuses exactly one push. The first ref synced pays the
    // rejection and recovers on attempt 2; the second ref arrives after the
    // hook has disarmed and lands on attempt 1 — asserting BOTH proves the
    // retry loop ran exactly once, not that the test staged nothing.
    let root = root("t4-reject-once");
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
    attest_head(&a, &pr);

    install_pre_receive(
        &origin,
        "#!/bin/sh\n\
         if [ ! -f reject-once-fired ]; then\n\
         \x20 : > reject-once-fired\n\
         \x20 echo 'rejected: not this time' >&2\n\
         \x20 exit 1\n\
         fi\n\
         exit 0\n",
    );

    let synced = sync_all(&a, "origin", &fast()).expect("the retry recovers the sync");
    assert_eq!(synced[0].notes_ref, MEASURE_REF);
    assert_eq!(
        synced[0].pushed,
        Pushed::OnAttempt(2),
        "the first push must be rejected and the retry must recover it"
    );
    assert_eq!(
        synced[1].pushed,
        Pushed::OnAttempt(1),
        "the hook disarmed after one rejection"
    );

    // And what was pushed is really there: a fresh clone reads the record.
    let fresh = clone_from(&origin, &root.join("clone-fresh"), &[]);
    sync_all(&fresh, "origin", &fast()).expect("fresh sync");
    let records = Notes::measure(&fresh).read(&pr).expect("read");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_kind, RecordKind::SelfReport);
}
