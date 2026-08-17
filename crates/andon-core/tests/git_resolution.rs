//! Base/head resolution and content access, against real repositories.
//!
//! PLAN P1 is explicit that documentation does not satisfy this criterion
//! (Codex #14): staged versus unstaged, rebase, shallow clone, renames, and
//! submodules each get an executable test. They are here rather than as unit
//! tests because every one of them is a claim about what *git* does, and a mock
//! that agreed with our reading of the manual would prove only that we can be
//! consistently wrong.

mod common;

use std::path::Path;

use andon_core::git::{
    BlobBatch, BlobError, ChangeStatus, ChangedSet, Content, ContentLane, DirtySnapshot, Endpoint,
    Git, ResolveError, ResolvedRange, Revision, SnapshotMode,
};
use common::TestRepo;

fn scratch(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("andon-{name}-"))
        .tempdir()
        .expect("temp dir")
}

/// A repository with two commits on `main` and a `feature` branch off the first.
fn forked_repo(root: &Path) -> (TestRepo, String, String, String) {
    let repo = TestRepo::init(root);
    let base = repo.commit_file("src/a.ts", b"export const a = 1;\n", "base");
    repo.run(&["checkout", "--quiet", "-b", "feature"]);
    let head = repo.commit_file("src/b.ts", b"export const b = 2;\n", "feature work");
    repo.run(&["checkout", "--quiet", "main"]);
    let main_advanced = repo.commit_file("src/c.ts", b"export const c = 3;\n", "main advances");
    repo.run(&["checkout", "--quiet", "feature"]);
    (repo, base, head, main_advanced)
}

#[test]
fn merge_base_is_the_fork_point_and_not_wherever_main_has_reached() {
    let dir = scratch("mergebase");
    let (repo, base, head, main_advanced) = forked_repo(dir.path());

    let range = ResolvedRange::resolve(
        repo.git(),
        &Revision::merge_base("main"),
        &Revision::Rev("HEAD".into()),
    )
    .expect("resolves");

    let ctx = range.compare_context().expect("both endpoints are commits");
    assert_eq!(ctx.base_oid, base, "the base is the fork point");
    assert_eq!(ctx.head_oid, head);
    assert_ne!(
        ctx.base_oid, main_advanced,
        "main advancing must not move it"
    );
    assert_eq!(ctx.base_resolution, "merge-base");
    assert!(ctx.git_version.starts_with("git version"));
}

#[test]
fn an_explicit_sha_a_ref_and_a_tag_all_resolve_to_the_same_commit() {
    let dir = scratch("explicit");
    let repo = TestRepo::init(dir.path());
    let base = repo.commit_file("a.ts", b"1\n", "base");
    let head = repo.commit_file("b.ts", b"2\n", "head");
    repo.run(&["tag", "-a", "v1", "-m", "release one"]);

    for rev in [head.as_str(), "HEAD", "v1"] {
        let range = ResolvedRange::resolve(
            repo.git(),
            &Revision::Rev(base.clone()),
            &Revision::Rev(rev.to_string()),
        )
        .expect("resolves");
        // An annotated tag resolves to the tag object unless peeled. A base_oid
        // that is not a commit would fail every downstream comparison in a way
        // that looks like tampering.
        assert_eq!(
            range.compare_context().unwrap().head_oid,
            head,
            "{rev} must peel to the commit"
        );
    }
}

#[test]
fn an_unknown_revision_is_refused_rather_than_guessed() {
    let dir = scratch("unknown");
    let repo = TestRepo::init(dir.path());
    repo.commit_file("a.ts", b"1\n", "base");
    let err = ResolvedRange::resolve(
        repo.git(),
        &Revision::Rev("no-such-branch".into()),
        &Revision::Rev("HEAD".into()),
    )
    .expect_err("must not resolve");
    assert!(matches!(err, ResolveError::UnknownRevision { .. }), "{err}");
}

// ---------------------------------------------------------------------------
// staged vs unstaged
// ---------------------------------------------------------------------------

#[test]
fn the_index_sentinel_sees_staged_content_and_the_worktree_sentinel_sees_both() {
    let dir = scratch("staged");
    let repo = TestRepo::init(dir.path());
    let base = repo.commit_file("src/a.ts", b"one\n", "base");

    repo.write("src/a.ts", b"two\n");
    repo.add(&["src/a.ts"]);
    repo.write("src/b.ts", b"unstaged\n");

    let head_oid = repo.rev_parse("HEAD");
    let staged = DirtySnapshot::incremental(repo.git(), &head_oid, true).expect("index snapshot");
    let both = DirtySnapshot::incremental(repo.git(), &head_oid, false).expect("worktree snapshot");

    assert!(
        staged.entries.contains_key("src/a.ts"),
        "a staged edit is in the index snapshot"
    );
    assert!(
        !staged.entries.contains_key("src/b.ts"),
        "an untracked, unstaged file is not staged content"
    );
    assert!(both.entries.contains_key("src/a.ts"));
    assert!(both.entries.contains_key("src/b.ts"));

    // The two sentinels describe different states, so they must not share a
    // cache entry even when they overlap.
    assert_ne!(staged.digest(), both.digest());
    assert_eq!(base, head_oid);
}

#[test]
fn staging_an_edit_does_not_move_the_worktree_snapshot() {
    // `hash-object` is run with check-in filters, so the OID a dirty file gets
    // is the OID `git add` would give it. Staging therefore changes which status
    // letters git reports but not the content identity — and the snapshot covers
    // both, so this test pins which half is allowed to move.
    let dir = scratch("stage-move");
    let repo = TestRepo::init(dir.path());
    repo.commit_file("src/a.ts", b"one\n", "base");
    let head_oid = repo.rev_parse("HEAD");

    repo.write("src/a.ts", b"two\n");
    let unstaged = DirtySnapshot::incremental(repo.git(), &head_oid, false).unwrap();
    let unstaged_oid = unstaged.entries["src/a.ts"].worktree_oid.clone();

    repo.add(&["src/a.ts"]);
    let staged = DirtySnapshot::incremental(repo.git(), &head_oid, false).unwrap();

    assert_eq!(
        unstaged_oid, staged.entries["src/a.ts"].worktree_oid,
        "the content identity of the bytes on disk did not change"
    );
    assert_eq!(
        staged.entries["src/a.ts"].staged_oid, unstaged_oid,
        "and staging gives the index the same blob"
    );
}

#[test]
fn a_deleted_file_is_recorded_rather_than_dropped() {
    let dir = scratch("deleted");
    let repo = TestRepo::init(dir.path());
    repo.commit_file("src/a.ts", b"one\n", "base");
    let head_oid = repo.rev_parse("HEAD");
    repo.remove("src/a.ts");

    let snapshot = DirtySnapshot::incremental(repo.git(), &head_oid, false).unwrap();
    let entry = snapshot
        .entries
        .get("src/a.ts")
        .expect("a deletion is a change");
    assert_eq!(
        entry.worktree_oid, None,
        "there are no bytes to hash, and inventing an OID for absent content is worse than none"
    );
}

#[test]
fn the_incremental_snapshot_is_stable_and_moves_only_with_content() {
    let dir = scratch("stability");
    let repo = TestRepo::init(dir.path());
    repo.commit_file("src/a.ts", b"one\n", "base");
    let head_oid = repo.rev_parse("HEAD");
    repo.write("src/a.ts", b"two\n");

    let first = DirtySnapshot::incremental(repo.git(), &head_oid, false).unwrap();
    let second = DirtySnapshot::incremental(repo.git(), &head_oid, false).unwrap();
    assert_eq!(first.digest(), second.digest(), "repeat calls must agree");

    repo.write("src/a.ts", b"three\n");
    let third = DirtySnapshot::incremental(repo.git(), &head_oid, false).unwrap();
    assert_ne!(first.digest(), third.digest());
    assert_eq!(first.mode, SnapshotMode::Incremental);
}

#[test]
fn the_full_rehash_fallback_agrees_about_content_while_keying_separately() {
    // PREMORTEM T6: the fallback exists, and it is not the steady state. It must
    // find the same bytes the incremental path found — otherwise it is not a
    // fallback — while producing a different key, so that a cached value from
    // one path is never served to the other.
    let dir = scratch("fallback");
    let repo = TestRepo::init(dir.path());
    repo.commit_file("src/a.ts", b"one\n", "base");
    repo.commit_file("src/b.ts", b"two\n", "second");
    let head_oid = repo.rev_parse("HEAD");
    repo.write("src/a.ts", b"edited\n");

    let incremental = DirtySnapshot::incremental(repo.git(), &head_oid, false).unwrap();
    let full = DirtySnapshot::full_rehash(repo.git(), &head_oid, false).unwrap();

    assert_eq!(
        incremental.entries["src/a.ts"].worktree_oid, full.entries["src/a.ts"].worktree_oid,
        "both paths must see the same bytes for the dirty file"
    );
    assert_eq!(
        incremental.len(),
        1,
        "the incremental path visits the dirty set"
    );
    assert_eq!(full.len(), 2, "the fallback visits every tracked file");
    assert_ne!(incremental.digest(), full.digest());
    assert_eq!(full.mode, SnapshotMode::FullRehash);
}

// ---------------------------------------------------------------------------
// dirty endpoints are not comparable
// ---------------------------------------------------------------------------

#[test]
fn a_worktree_head_resolves_but_yields_no_wire_tuple() {
    let dir = scratch("worktree-head");
    let repo = TestRepo::init(dir.path());
    repo.commit_file("src/a.ts", b"one\n", "base");
    repo.write("src/a.ts", b"dirty\n");

    let range = ResolvedRange::resolve(
        repo.git(),
        &Revision::Rev("HEAD".into()),
        &Revision::Worktree,
    )
    .expect("a dirty head is measurable");

    assert!(matches!(range.head, Endpoint::Worktree { .. }));
    assert!(!range.is_comparable());
    // The whole point: the verifier must never be handed a tuple describing
    // bytes that were never committed (PLAN B3/R2-4).
    assert!(matches!(
        range.compare_context(),
        Err(ResolveError::NotComparable {
            side: "head",
            kind: "worktree"
        })
    ));
}

#[test]
fn an_index_head_resolves_but_yields_no_wire_tuple_either() {
    let dir = scratch("index-head");
    let repo = TestRepo::init(dir.path());
    repo.commit_file("src/a.ts", b"one\n", "base");
    repo.write("src/a.ts", b"staged\n");
    repo.add_all();

    let range = ResolvedRange::resolve(repo.git(), &Revision::Rev("HEAD".into()), &Revision::Index)
        .expect("a staged head is measurable");
    assert!(matches!(range.head, Endpoint::Index { .. }));
    assert!(range.compare_context().is_err());
}

// ---------------------------------------------------------------------------
// content lane
// ---------------------------------------------------------------------------

#[test]
fn blob_reads_are_checkout_independent_and_worktree_reads_are_not() {
    // The T1 property, stated as a test. The file is committed with LF and then
    // rewritten on disk with CRLF, exactly as a `core.autocrlf=true` checkout
    // would have produced it. The blob still reads LF; the worktree reads CRLF;
    // and only one of them is allowed into a digest.
    let dir = scratch("lane");
    let repo = TestRepo::init(dir.path());
    repo.commit_file("src/a.ts", b"one\ntwo\n", "base");
    let blob_oid = repo.rev_parse("HEAD:src/a.ts");
    repo.write("src/a.ts", b"one\r\ntwo\r\n");

    let mut batch = BlobBatch::open(repo.git()).unwrap();
    let from_blob = batch.read(&blob_oid).expect("blob reads");
    let from_disk = Content::from_worktree(repo.git(), "src/a.ts").expect("worktree reads");

    assert_eq!(from_blob.bytes(), b"one\ntwo\n");
    assert_eq!(from_disk.bytes(), b"one\r\ntwo\r\n");
    assert_eq!(from_blob.lane(), ContentLane::Compared);
    assert_eq!(from_disk.lane(), ContentLane::Advisory);
}

#[test]
fn a_missing_object_is_a_typed_error_and_the_batch_survives_it() {
    let dir = scratch("missing");
    let repo = TestRepo::init(dir.path());
    repo.commit_file("src/a.ts", b"one\n", "base");
    let good = repo.rev_parse("HEAD:src/a.ts");

    let mut batch = BlobBatch::open(repo.git()).unwrap();
    let err = batch.read(&"0".repeat(40)).expect_err("no such object");
    assert!(matches!(err, BlobError::Missing { .. }), "{err}");
    // Desynchronizing the batch on an error would make every later read return
    // the wrong object's bytes — silently.
    assert_eq!(batch.read(&good).unwrap().bytes(), b"one\n");
}

#[test]
fn non_ascii_paths_survive_enumeration_intact() {
    let dir = scratch("nonascii");
    let repo = TestRepo::init(dir.path());
    let base = repo.commit_file("src/a.ts", b"one\n", "base");
    let head = repo.commit_file("src/naïve — ü.ts", b"two\n", "unicode path");

    let range =
        ResolvedRange::resolve(repo.git(), &Revision::Rev(base), &Revision::Rev(head)).unwrap();
    let changed = ChangedSet::enumerate(repo.git(), &range).unwrap();

    let paths: Vec<&str> = changed.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        paths,
        vec!["src/naïve — ü.ts"],
        "core.quotepath must not octal-escape the path"
    );
}

// ---------------------------------------------------------------------------
// renames
// ---------------------------------------------------------------------------

#[test]
fn a_rename_carries_both_paths_and_reads_the_destination_blob() {
    let dir = scratch("rename");
    let repo = TestRepo::init(dir.path());
    let body: Vec<u8> = (0..60)
        .map(|i| format!("export const value{i} = {i};\n"))
        .collect::<String>()
        .into_bytes();
    let base = repo.commit_file("src/old-name.ts", &body, "base");
    repo.run(&["mv", "src/old-name.ts", "src/new-name.ts"]);
    let head = repo.commit("rename");

    let range =
        ResolvedRange::resolve(repo.git(), &Revision::Rev(base), &Revision::Rev(head)).unwrap();
    let changed = ChangedSet::enumerate(repo.git(), &range).unwrap();

    assert_eq!(
        changed.len(),
        1,
        "a pure rename is one entry, not a delete plus an add"
    );
    let entry = &changed.entries[0];
    assert_eq!(entry.status, ChangeStatus::Renamed);
    assert_eq!(entry.old_path.as_deref(), Some("src/old-name.ts"));
    assert_eq!(entry.path, "src/new-name.ts");
    assert_eq!(entry.similarity, Some(100));

    let blobs = changed.read_head_blobs(repo.git()).unwrap();
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].0, "src/new-name.ts");
    assert_eq!(blobs[0].1.bytes(), body.as_slice());
}

#[test]
fn a_rename_with_an_edit_is_still_one_entry() {
    let dir = scratch("rename-edit");
    let repo = TestRepo::init(dir.path());
    let body: Vec<u8> = (0..60)
        .map(|i| format!("export const value{i} = {i};\n"))
        .collect::<String>()
        .into_bytes();
    let base = repo.commit_file("src/old.ts", &body, "base");
    repo.run(&["mv", "src/old.ts", "src/new.ts"]);
    let mut edited = body.clone();
    edited.extend_from_slice(b"export const extra = true;\n");
    repo.write("src/new.ts", &edited);
    repo.add_all();
    let head = repo.commit("rename with edit");

    let range =
        ResolvedRange::resolve(repo.git(), &Revision::Rev(base), &Revision::Rev(head)).unwrap();
    let changed = ChangedSet::enumerate(repo.git(), &range).unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed.entries[0].status, ChangeStatus::Renamed);
    assert!(
        changed.entries[0].similarity.unwrap() < 100,
        "an edited rename scores below identical"
    );
}

// ---------------------------------------------------------------------------
// rebase
// ---------------------------------------------------------------------------

#[test]
fn after_a_rebase_the_merge_base_follows_the_new_parent() {
    let dir = scratch("rebase");
    let (repo, original_base, pre_rebase_head, main_advanced) = forked_repo(dir.path());

    let before = ResolvedRange::resolve(
        repo.git(),
        &Revision::merge_base("main"),
        &Revision::Rev("HEAD".into()),
    )
    .unwrap()
    .compare_context()
    .unwrap();
    assert_eq!(before.base_oid, original_base);
    assert_eq!(before.head_oid, pre_rebase_head);

    repo.run(&["rebase", "--quiet", "main"]);

    let after = ResolvedRange::resolve(
        repo.git(),
        &Revision::merge_base("main"),
        &Revision::Rev("HEAD".into()),
    )
    .unwrap()
    .compare_context()
    .unwrap();

    assert_eq!(
        after.base_oid, main_advanced,
        "the fork point moved to where main was rebased onto"
    );
    assert_ne!(
        after.head_oid, pre_rebase_head,
        "the rebase rewrote the commit, so the head OID is new"
    );
    // This is the shape P1.5 classifies as `unwitnessed-base-mismatch`: a
    // measurement taken before the rebase names a tuple that still exists but no
    // longer describes the branch. P1's job is to make the difference visible.
    assert_ne!(before.base_oid, after.base_oid);
}

#[test]
fn a_half_finished_rebase_is_refused_rather_than_measured() {
    let dir = scratch("rebase-conflict");
    let repo = TestRepo::init(dir.path());
    repo.commit_file("src/a.ts", b"original\n", "base");
    repo.run(&["checkout", "--quiet", "-b", "feature"]);
    repo.commit_file("src/a.ts", b"feature version\n", "feature edit");
    repo.run(&["checkout", "--quiet", "main"]);
    repo.commit_file("src/a.ts", b"main version\n", "main edit");
    repo.run(&["checkout", "--quiet", "feature"]);

    // Conflicts on the only file, leaving the rebase suspended.
    assert!(
        !repo.try_run(&["rebase", "main"]),
        "the fixture depends on this rebase conflicting"
    );

    let err = ResolvedRange::resolve(
        repo.git(),
        &Revision::merge_base("main"),
        &Revision::Rev("HEAD".into()),
    )
    .expect_err("a suspended rebase is not a change");
    assert!(
        matches!(err, ResolveError::OperationInProgress { .. }),
        "{err}"
    );
    repo.try_run(&["rebase", "--abort"]);
}

// ---------------------------------------------------------------------------
// shallow clone
// ---------------------------------------------------------------------------

#[test]
fn a_shallow_clone_is_flagged_and_a_lost_merge_base_says_why() {
    let dir = scratch("shallow");
    let origin_path = dir.path().join("origin");
    let origin = TestRepo::init(&origin_path);
    origin.commit_file("src/a.ts", b"one\n", "first");
    origin.run(&["checkout", "--quiet", "-b", "feature"]);
    origin.commit_file("src/b.ts", b"two\n", "second");
    origin.commit_file("src/c.ts", b"three\n", "third");

    // A depth-limited clone needs the file:// transport; a plain path clone is a
    // hardlink copy and ignores --depth.
    let url = format!(
        "file:///{}",
        origin_path.display().to_string().replace('\\', "/")
    );
    let clone_path = dir.path().join("shallow");
    origin.run(&[
        "clone",
        "--quiet",
        "--depth=1",
        "--branch=feature",
        &url,
        &clone_path.display().to_string(),
    ]);

    let git = Git::open(&clone_path).expect("the clone is a repository");
    assert!(git.facts().shallow, "the clone must report itself shallow");

    let range = ResolvedRange::resolve(
        &git,
        &Revision::Rev("HEAD".into()),
        &Revision::Rev("HEAD".into()),
    )
    .expect("HEAD itself is present even in a shallow clone");
    assert!(range.shallow, "the flag reaches the resolved range");

    // `main` is not in the shallow clone at all, so the merge base cannot be
    // computed. The error has to say that history was truncated rather than that
    // the histories are unrelated, because the two have opposite remedies.
    origin.run(&[
        "-C",
        &clone_path.display().to_string(),
        "fetch",
        "--quiet",
        "--depth=1",
        "origin",
        "main:refs/remotes/origin/main",
    ]);
    let err = ResolvedRange::resolve(
        &git,
        &Revision::merge_base("refs/remotes/origin/main"),
        &Revision::Rev("HEAD".into()),
    )
    .expect_err("no merge base is reachable");
    match err {
        ResolveError::NoMergeBase { shallow, .. } => {
            assert!(shallow, "the diagnosis must name the truncation");
            assert!(
                err_text(&ResolveError::NoMergeBase {
                    head: "x".into(),
                    with: "y".into(),
                    shallow: true
                })
                .contains("shallow"),
                "and say so in the message a user reads"
            );
        }
        other => panic!("expected NoMergeBase, got {other}"),
    }
}

fn err_text(err: &ResolveError) -> String {
    err.to_string()
}

// ---------------------------------------------------------------------------
// submodules
// ---------------------------------------------------------------------------

#[test]
fn a_submodule_bump_is_a_change_and_never_a_blob_read() {
    let dir = scratch("submodule");
    let sub_path = dir.path().join("sub");
    let sub = TestRepo::init(&sub_path);
    sub.commit_file("lib.ts", b"export const lib = 1;\n", "sub first");

    let outer_path = dir.path().join("outer");
    let outer = TestRepo::init(&outer_path);
    outer.commit_file("src/a.ts", b"one\n", "base");

    // git 2.38 refused file:// submodules by default (CVE-2022-39253). The
    // fixture opts in explicitly rather than relying on the host's config.
    let sub_url = format!(
        "file:///{}",
        sub_path.display().to_string().replace('\\', "/")
    );
    outer.run(&[
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "--quiet",
        "add",
        &sub_url,
        "vendor/sub",
    ]);
    outer.add_all();
    let base = outer.commit("add submodule");

    // Advance the submodule and record the new pointer in the outer repository.
    sub.commit_file("lib.ts", b"export const lib = 2;\n", "sub second");
    let nested = outer_path.join("vendor/sub").display().to_string();
    outer.run(&["-C", &nested, "fetch", "--quiet", "origin"]);
    outer.run(&["-C", &nested, "checkout", "--quiet", "origin/main"]);
    outer.add_all();
    let head = outer.commit("bump submodule");

    let range =
        ResolvedRange::resolve(outer.git(), &Revision::Rev(base), &Revision::Rev(head)).unwrap();
    let changed = ChangedSet::enumerate(outer.git(), &range).unwrap();

    let gitlink = changed
        .entries
        .iter()
        .find(|e| e.path == "vendor/sub")
        .expect("the bumped pointer is a change to this tree");
    assert!(gitlink.is_gitlink());
    assert!(
        gitlink.src_oid.is_some() && gitlink.dst_oid.is_some(),
        "both sides name real commits in the submodule"
    );
    // The load-bearing half: those OIDs are commits, and reading one as file
    // content would hash a commit header and call it a measurement.
    assert_eq!(
        gitlink.readable_blob(),
        None,
        "a gitlink must never be offered to the blob reader"
    );

    let blobs = changed.read_head_blobs(outer.git()).unwrap();
    assert!(
        blobs.iter().all(|(path, _)| path != "vendor/sub"),
        "and the batch read skips it rather than failing on it"
    );
}

#[test]
fn asking_the_blob_reader_for_a_commit_is_a_typed_refusal() {
    // The defence behind the skip: even if an entry reached the reader, the
    // reader itself refuses a non-blob rather than returning a commit's bytes.
    let dir = scratch("not-a-blob");
    let repo = TestRepo::init(dir.path());
    let commit = repo.commit_file("a.ts", b"one\n", "base");

    let mut batch = BlobBatch::open(repo.git()).unwrap();
    let err = batch.read(&commit).expect_err("a commit is not a blob");
    assert!(
        matches!(&err, BlobError::NotABlob { kind, .. } if kind == "commit"),
        "{err}"
    );
    // And the stream is still usable, because the body was drained.
    let blob = repo.rev_parse("HEAD:a.ts");
    assert_eq!(batch.read(&blob).unwrap().bytes(), b"one\n");
}

#[test]
fn a_submodules_internal_dirtiness_does_not_churn_the_outer_key() {
    let dir = scratch("submodule-dirty");
    let sub_path = dir.path().join("sub");
    let sub = TestRepo::init(&sub_path);
    sub.commit_file("lib.ts", b"export const lib = 1;\n", "sub first");

    let outer_path = dir.path().join("outer");
    let outer = TestRepo::init(&outer_path);
    outer.commit_file("src/a.ts", b"one\n", "base");
    let sub_url = format!(
        "file:///{}",
        sub_path.display().to_string().replace('\\', "/")
    );
    outer.run(&[
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "--quiet",
        "add",
        &sub_url,
        "vendor/sub",
    ]);
    outer.add_all();
    outer.commit("add submodule");

    let head_oid = outer.rev_parse("HEAD");
    let clean = DirtySnapshot::incremental(outer.git(), &head_oid, false).unwrap();

    // Edit a file *inside* the submodule. That is the submodule's business; the
    // outer tree is unchanged until the pointer moves.
    std::fs::write(outer_path.join("vendor/sub/lib.ts"), b"scratch\n").unwrap();
    let after = DirtySnapshot::incremental(outer.git(), &head_oid, false).unwrap();

    assert_eq!(
        clean.digest(),
        after.digest(),
        "--ignore-submodules=dirty keeps a vendored checkout from churning every key"
    );
}
