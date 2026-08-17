//! PREMORTEM T4: git-notes operations under the conditions that break them.
//!
//! Three failure modes, one fixture, and every one of them asserted rather than
//! demonstrated:
//!
//! 1. **Concurrent attest races.** Two clones attest two PRs without seeing each
//!    other. The second push is rejected, and the retry loop must fetch, merge
//!    with `cat_sort_uniq`, and push again — with **neither record lost**. The
//!    test asserts the push succeeded *on the second attempt*, because a test
//!    that only checked the end state would pass just as happily if the race
//!    never happened, and then keep passing after someone removed the retry.
//! 2. **Squash-orphaned notes.** A squash merge lands a branch's content on a
//!    commit no note points at. The self-reports have to be migrated onto what
//!    actually landed, or every squash-merging repository — which is most of
//!    them — silently loses its ledger at the moment the work becomes permanent.
//! 3. **Shallow checkouts.** `actions/checkout` fetches depth 1 by default. A
//!    notes tree references no commit in history, so the ledger must arrive
//!    whole even when the history does not.
//!
//! The full machinery is P8's. What is proved here is that the shape works
//! before nine more phases are built on the assumption that it does.

use std::path::{Path, PathBuf};

use andon_core::git::{Git, GitCommand, Revision};
use andon_core::schema::enums::{Attestation, InvocationSource, RecordKind};
use andon_ledger_min::measure::measure;
use andon_ledger_min::notes::{Notes, ATTEST_REF, MEASURE_REF};
use andon_ledger_min::spike;
use andon_ledger_min::verify::{attest, VerifyRequest};

const WHO: &[(&str, &str)] = &[
    ("GIT_AUTHOR_NAME", "Andon Fixture"),
    ("GIT_AUTHOR_EMAIL", "fixture@andon.invalid"),
    ("GIT_COMMITTER_NAME", "Andon Fixture"),
    ("GIT_COMMITTER_EMAIL", "fixture@andon.invalid"),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("t4")
}

fn bootstrap() -> Git {
    Git::open(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("the crate lives in a repository")
}

/// Attach a committer identity to a git invocation.
///
/// The fixture repositories deliberately have **no** `user.name` or
/// `user.email` configured, because that is what a CI checkout looks like and
/// because `Git::cmd` sweeps every inherited `GIT_*` variable. Setting the
/// identity in each repository's config would be the easy fix and would also
/// stop testing the thing that matters: the notes module carries its own
/// identity precisely so the ledger works in a repository that has none. Left
/// configured, that would go untested and break the first time it ran on a
/// runner.
///
/// So the identity is attached here, at the fixture's own commit-writing
/// spawns, and nowhere else.
fn identified(mut cmd: GitCommand) -> GitCommand {
    for (key, value) in WHO {
        cmd = cmd.env(key, value);
    }
    cmd
}

fn commit(git: &Git, message: &str) {
    identified(git.cmd(["commit", "--quiet", "--allow-empty", "-m", message]))
        .output()
        .unwrap_or_else(|e| panic!("commit {message}: {e}"));
}

fn write_and_commit(git: &Git, path: &str, text: &str, message: &str) -> String {
    let full = git.workdir().join(path);
    std::fs::create_dir_all(full.parent().expect("a parent")).expect("mkdir");
    std::fs::write(&full, text).expect("write");
    git.cmd(["add", "--all", "."]).output().expect("add");
    commit(git, message);
    head(git)
}

fn head(git: &Git) -> String {
    git.cmd(["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"])
        .text()
        .expect("rev-parse HEAD")
        .trim()
        .to_string()
}

/// Measure a branch head and write the self-report, as an agent would.
fn self_report(git: &Git, head_oid: &str) {
    let (record, _) = measure(
        git,
        &Revision::merge_base("origin/main"),
        &Revision::Rev(head_oid.to_string()),
        RecordKind::SelfReport,
        InvocationSource::Hook,
        &spike::engine_version(),
    )
    .expect("measure");
    Notes::measure(git)
        .append(head_oid, &record)
        .expect("write the self-report");
}

/// Attest a branch head from a pinned checkout, as CI would.
fn attest_head(git: &Git, head_oid: &str) -> Attestation {
    git.cmd(["checkout", "--quiet", "--detach", head_oid])
        .output()
        .expect("pin the checkout to the head under verification");
    attest(
        git,
        &VerifyRequest {
            head: head_oid.to_string(),
            trusted_branch: "origin/main".to_string(),
            fork_tier: false,
        },
    )
    .expect("attest")
    .attestation
}

fn clone_from(origin: &Path, dest: &Path, extra: &[&str]) -> Git {
    if dest.exists() {
        std::fs::remove_dir_all(dest).expect("clear clone dir");
    }
    bootstrap()
        .cmd(["clone", "--quiet"])
        .args(extra)
        .arg(origin)
        .arg(dest)
        .output()
        .unwrap_or_else(|e| panic!("clone into {}: {e}", dest.display()));
    Git::open(dest).expect("the clone is a repository")
}

#[test]
fn two_concurrent_attestations_survive_a_squash_merge_and_a_shallow_clone() {
    let root = root();
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("clear the fixture root");
    }
    std::fs::create_dir_all(&root).expect("create the fixture root");
    let origin = root.join("origin.git");

    bootstrap()
        .cmd(["init", "--quiet", "--bare", "--initial-branch", "main"])
        .arg(&origin)
        .output()
        .expect("create the central repository");

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

    // ---- the second clone is made BEFORE any note exists ------------------
    // This is what makes the race real rather than staged: B's view of both
    // notes refs is empty, and stays empty until its own push is rejected.
    let b = clone_from(&origin, &root.join("clone-b"), &[]);

    // ---- A attests pr-one and pushes, unopposed ---------------------------
    self_report(&a, &pr_one);
    assert_eq!(
        attest_head(&a, &pr_one),
        Attestation::Confirmed,
        "an honest self-report on pr-one must confirm"
    );
    for notes_ref in [MEASURE_REF, ATTEST_REF] {
        let attempts = Notes::new(&a, notes_ref)
            .push_with_retry("origin", 3)
            .unwrap_or_else(|e| panic!("push {notes_ref}: {e}"));
        assert_eq!(attempts, 1, "{notes_ref}: nothing to race with yet");
    }

    // ---- B attests pr-two against a remote that has moved -----------------
    self_report(&b, &pr_two);
    assert_eq!(
        attest_head(&b, &pr_two),
        Attestation::Confirmed,
        "an honest self-report on pr-two must confirm"
    );
    for notes_ref in [MEASURE_REF, ATTEST_REF] {
        let attempts = Notes::new(&b, notes_ref)
            .push_with_retry("origin", 3)
            .unwrap_or_else(|e| panic!("push {notes_ref}: {e}"));
        assert_eq!(
            attempts, 2,
            "{notes_ref}: the first push must be rejected and the retry must \
             recover it — an assertion on the end state alone would pass \
             whether or not the race happened"
        );
    }

    // ---- a fresh clone resolves both ledger records -----------------------
    let c = clone_from(&origin, &root.join("clone-c"), &[]);
    for notes_ref in [MEASURE_REF, ATTEST_REF] {
        let notes = Notes::new(&c, notes_ref);
        assert!(
            notes.fetch("origin").expect("fetch notes"),
            "{notes_ref} must exist on the remote"
        );
        c.cmd(["update-ref", notes_ref, &notes.tracking_ref()])
            .output()
            .expect("adopt the fetched ledger");
        for (label, oid) in [("pr-one", &pr_one), ("pr-two", &pr_two)] {
            let records = notes.read(oid).expect("read the ledger");
            assert_eq!(
                records.len(),
                1,
                "{notes_ref}: {label}'s record was lost in the merge"
            );
        }
    }

    // ---- both PRs squash-merge; the records follow what landed ------------
    a.cmd(["checkout", "--quiet", "main"])
        .output()
        .expect("back to main");
    for notes_ref in [MEASURE_REF, ATTEST_REF] {
        let notes = Notes::new(&a, notes_ref);
        notes.fetch("origin").expect("fetch notes");
        notes.merge_tracking().expect("merge the remote ledger");
    }

    let mut landed = Vec::new();
    for (branch, source) in [("pr-one", &pr_one), ("pr-two", &pr_two)] {
        // `merge --squash` writes no commit, and still needs an identity: git
        // resolves the committer for the reflog entry before it discovers it
        // will not be committing. Found on a runner, not on a laptop — a
        // developer machine has a global identity and never sees it.
        identified(a.cmd(["merge", "--squash", branch]))
            .output()
            .unwrap_or_else(|e| panic!("squash-merge {branch}: {e}"));
        commit(&a, &format!("squash: {branch}"));
        let target = head(&a);
        // The migration. Without it the ledger points at commits that are not
        // in main's history and the record is orphaned the moment the work
        // becomes permanent.
        for notes_ref in [MEASURE_REF, ATTEST_REF] {
            Notes::new(&a, notes_ref)
                .migrate(source, &target)
                .unwrap_or_else(|e| panic!("migrate {notes_ref} onto {target}: {e}"));
        }
        landed.push(target);
    }
    a.cmd(["push", "--quiet", "origin", "main"])
        .output()
        .expect("push the squashed main");
    for notes_ref in [MEASURE_REF, ATTEST_REF] {
        Notes::new(&a, notes_ref)
            .push_with_retry("origin", 3)
            .expect("push the migrated ledger");
    }

    // ---- a shallow clone still gets the whole ledger -----------------------
    // `actions/checkout` fetches depth 1. A notes tree references no commit in
    // history, so truncating the history must not truncate the ledger.
    let shallow = clone_from(&origin, &root.join("clone-shallow"), &["--depth", "1"]);
    for notes_ref in [MEASURE_REF, ATTEST_REF] {
        let notes = Notes::new(&shallow, notes_ref);
        assert!(notes
            .fetch("origin")
            .expect("fetch notes into a shallow clone"));
        shallow
            .cmd(["update-ref", notes_ref, &notes.tracking_ref()])
            .output()
            .expect("adopt the fetched ledger");

        let annotated = notes.annotated_commits().expect("list the ledger");
        assert_eq!(
            annotated.len(),
            4,
            "{notes_ref}: the shallow clone sees {} annotated commit(s); both PR \
             heads and both landed commits must survive",
            annotated.len()
        );

        // The tip is the commit a depth-1 checkout actually has, and it is the
        // one CI would look at.
        let tip = head(&shallow);
        assert_eq!(
            *landed.last().expect("two landings"),
            tip,
            "the shallow clone's tip should be the last squash"
        );
        let records = notes.read(&tip).expect("read the ledger at the tip");
        assert_eq!(
            records.len(),
            1,
            "{notes_ref}: the squash-migrated record is missing from the landed commit"
        );
    }
}
