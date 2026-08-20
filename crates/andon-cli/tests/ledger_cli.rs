//! `andon ledger` — the P8 machinery at the shipped surface.
//!
//! Every test drives the real binary, because the requirement under test is
//! about what a **user** sees: PLAN P8's fault-injection AC says exhausted
//! push retries produce a red, user-visible failure, and "user-visible" is a
//! property of the process boundary — the exit code and stderr — not of a
//! library error type. The library half lives in
//! `andon-ledger/tests/fault_injection.rs`; this file is the half a person
//! actually meets.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use andon_core::git::Git;
use andon_core::schema::payload::{MeasurementRecord, MetricValue};
use andon_core::testing::{sample_record, sample_result};
use andon_ledger_min::notes::{Notes, MEASURE_REF};

const EXE: &str = env!("CARGO_BIN_EXE_andon");

fn honest_repo() -> common::Built {
    let dir = common::golden_root().join("honest-change");
    let case = common::read_case(&dir);
    common::build(&dir, &case)
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(EXE).args(args).output().expect("andon runs")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn head_of(git: &Git) -> String {
    git.cmd(["rev-parse", "HEAD"])
        .text()
        .expect("rev-parse")
        .trim()
        .to_string()
}

/// Wire a bare origin in its own temporary directory and point `origin` at it.
///
/// Its own directory, not a sibling of the repository: the repositories live
/// directly under the system temp dir, so a shared "../origin.git" would be
/// one path raced by every test in this file at once.
fn add_bare_origin(repo: &Path) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let origin = dir.path().join("origin.git");
    let git = Git::open(repo).expect("repo");
    git.cmd(["init", "--quiet", "--bare"])
        .arg(&origin)
        .output()
        .expect("create origin");
    git.cmd(["remote", "add", "origin"])
        .arg(&origin)
        .output()
        .expect("add origin");
    (dir, origin)
}

fn reject_all_pushes(bare: &Path) {
    let hook = bare.join("hooks").join("pre-receive");
    std::fs::create_dir_all(hook.parent().expect("hooks")).expect("mkdir");
    std::fs::write(&hook, "#!/bin/sh\necho 'rejected by policy' >&2\nexit 1\n")
        .expect("write hook");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
}

/// A sealed record whose one result carries `metric_id` and `value`.
///
/// Sealed properly — the seal is recomputed after the edits — because these
/// records go through the ledger's real read path, and that path refuses a
/// record whose contents no longer hash to its own digests.
fn planted(metric_id: &str, value: MetricValue) -> MeasurementRecord {
    let mut record = sample_record();
    let mut result = sample_result();
    result.metric_id = metric_id.to_string();
    result.value = value;
    result
        .seal(&record.compare_context)
        .expect("the planted result seals");
    record.results = vec![result];
    record
}

fn plant(git: &Git, commit: &str, records: &[MeasurementRecord]) {
    let notes = Notes::new(git, MEASURE_REF);
    for record in records {
        notes.append(commit, record).expect("append");
    }
}

#[test]
fn a_sync_whose_retries_exhaust_is_red_on_stderr_with_a_nonzero_exit() {
    // THE fault-injection acceptance criterion, at the surface it names: the
    // push is rejected by a real pre-receive hook, the retries run out, and
    // what the user gets is exit 1 and a red sentence — not a green exit with
    // a ledger silently missing from the remote.
    let repo = honest_repo();
    let (_origin_dir, origin) = add_bare_origin(repo.path());
    reject_all_pushes(&origin);
    let git = Git::open(repo.path()).expect("repo");
    plant(
        &git,
        &head_of(&git),
        &[planted("sample.metric", MetricValue::Count(3))],
    );

    let output = run(&[
        "ledger",
        "sync",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--attempts",
        "2",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "exhausted retries must exit 1; stdout: {}\nstderr: {}",
        stdout(&output),
        stderr(&output)
    );
    let err = stderr(&output);
    for needle in ["LEDGER PUSH FAILED", MEASURE_REF, "all 2 attempt(s)"] {
        assert!(err.contains(needle), "missing {needle:?} in stderr: {err}");
    }
    assert!(
        stdout(&output).is_empty(),
        "the failure belongs on stderr, not mixed into a report"
    );
}

#[test]
fn a_clean_sync_reports_what_each_ref_did() {
    let repo = honest_repo();
    let (_origin_dir, _origin) = add_bare_origin(repo.path());
    let git = Git::open(repo.path()).expect("repo");
    plant(
        &git,
        &head_of(&git),
        &[planted("sample.metric", MetricValue::Count(3))],
    );

    let output = run(&[
        "ledger",
        "sync",
        "--repo",
        repo.path().to_str().expect("utf-8"),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains("refs/notes/andon-measure: merged and pushed."),
        "{out}"
    );
    assert!(
        out.contains("refs/notes/andon-attest: nothing recorded locally"),
        "{out}"
    );
}

#[test]
fn stats_carries_the_scope_line_and_answers_by_dimension() {
    // End to end on a record the product itself wrote: `measure --record` is
    // the write path, `ledger stats` the read path, and the scope statement —
    // single-repo, not the fleet — must be in the output, not in a doc.
    let repo = honest_repo();
    let path = repo.path().to_str().expect("utf-8");
    let output = run(&[
        "measure",
        "--repo",
        path,
        "--record",
        "--harness",
        "test-rig",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let output = run(&["ledger", "stats", "--repo", path]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    for needle in [
        "Scope:",
        "not a fleet dashboard",
        "invocation-source: human-cli 1",
        "harness: test-rig 1",
        "iteration: 0 1",
    ] {
        assert!(out.contains(needle), "missing {needle:?} in: {out}");
    }

    let output = run(&["ledger", "stats", "--repo", path, "--by", "source"]);
    let out = stdout(&output);
    assert!(out.contains("by invocation-source:"), "{out}");
    assert!(out.contains("human-cli: 1 record(s)"), "{out}");

    // The filter keeps what matches and says what it kept.
    let output = run(&[
        "ledger",
        "stats",
        "--repo",
        path,
        "--filter",
        "harness=nonexistent",
    ]);
    let out = stdout(&output);
    assert!(out.contains("kept 0 of 1 record(s)"), "{out}");
}

#[test]
fn a_planted_cluster_turns_check_into_exit_two_with_a_warning() {
    // The CI cron's contract: `--check` keys the exit code on the clustering
    // finding, so the workflow goes red on the finding rather than on a grep.
    // Six of eight cognitive-complexity values sit at 14, just under the
    // shipped Medium rung at 15 — the shape of shaving a number until it
    // stops firing.
    let repo = honest_repo();
    let path = repo.path().to_str().expect("utf-8");
    let git = Git::open(repo.path()).expect("repo");
    let head = head_of(&git);
    let metric = "static.cognitive-complexity.typescript";
    let records: Vec<MeasurementRecord> = [3u64, 5, 14, 14, 14, 14, 14, 14]
        .iter()
        .map(|v| planted(metric, MetricValue::Count(*v)))
        .collect();
    plant(&git, &head, &records);

    let output = run(&["ledger", "stats", "--repo", path, "--check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a clustering finding must exit 2 under --check; stdout: {}\nstderr: {}",
        stdout(&output),
        stderr(&output)
    );
    let out = stdout(&output);
    assert!(out.contains("WARNING:"), "{out}");
    assert!(out.contains(metric), "{out}");
    assert!(out.contains("rung at 15"), "{out}");

    // Without --check the same warning prints but the exit stays 0: the
    // finding is for a human reading the report, and only the CI mode turns
    // it into a gate.
    let output = run(&["ledger", "stats", "--repo", path, "--distribution"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("WARNING:"), "{}", stdout(&output));
}

#[test]
fn check_with_an_honest_ledger_exits_zero_and_says_so() {
    let repo = honest_repo();
    let path = repo.path().to_str().expect("utf-8");
    let git = Git::open(repo.path()).expect("repo");
    plant(
        &git,
        &head_of(&git),
        &[planted("sample.metric", MetricValue::Count(3))],
    );

    let output = run(&["ledger", "stats", "--repo", path, "--check"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("No value distribution hugs a declared severity rung"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn trailer_emits_one_line_per_record_that_round_trips_through_the_parser() {
    // The producing surface of the trailer digest option: what this prints is
    // what a fork contributor pastes into a commit message, so it must be the
    // bare line — parseable by the same reader P9's verifier uses — with no
    // framing around it.
    let repo = honest_repo();
    let path = repo.path().to_str().expect("utf-8");
    let git = Git::open(repo.path()).expect("repo");
    let record = planted("sample.metric", MetricValue::Count(3));
    plant(&git, &head_of(&git), std::slice::from_ref(&record));

    let output = run(&["ledger", "trailer", "--repo", path]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    let expected = andon_ledger::trailer::trailer_digest(&record).expect("digest");
    assert_eq!(
        andon_ledger::trailer::digests_in(&out),
        vec![expected],
        "the printed line must carry the record's own trailer digest: {out}"
    );
    assert_eq!(
        out.lines().count(),
        1,
        "bare trailer lines only — framing would end up inside a commit message: {out}"
    );

    // And an unrecorded commit says so instead of printing nothing.
    let output = run(&["ledger", "trailer", "--repo", path, "HEAD~1"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("No record is recorded against"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn migrate_carries_the_record_onto_the_landed_commit_and_says_what_it_did() {
    let repo = honest_repo();
    let path = repo.path().to_str().expect("utf-8");
    let git = Git::open(repo.path()).expect("repo");
    let source = head_of(&git);
    plant(
        &git,
        &source,
        &[planted("sample.metric", MetricValue::Count(3))],
    );
    // The squash stand-in: a new commit that no note points at.
    git.cmd([
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "squash: landing",
    ])
    .output()
    .expect("commit");
    let landed = head_of(&git);

    let output = run(&[
        "ledger", "migrate", "--repo", path, "--from", &source, "--to", &landed,
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains("refs/notes/andon-measure: 1 record(s) migrated"),
        "{out}"
    );
    assert!(
        out.contains("refs/notes/andon-attest: no records on the source commit"),
        "{out}"
    );

    let records = Notes::new(&git, MEASURE_REF)
        .read(&landed)
        .expect("read the landed commit");
    assert_eq!(records.len(), 1, "the landed commit carries the record");
}
