//! The async lane, end to end through the binary (PLAN P7, APPROACH graft 4).
//!
//! The contract under test, in one sentence per leg: a measurement that owes
//! slow work returns fast with `completeness: partial` and a job on disk;
//! `andon wait` executes the job in the foreground, merges the results in with
//! `lane: async` freshness, re-verdicts under the measurement's own policy
//! snapshot, and consumes the job; a failed suite blocks through
//! `severity.block_on_test_failure`; a timed-out suite is an unanswered
//! question and never a failure.
//!
//! Commands are shell builtins (`exit 0`, `exit 3`) so the same fixture runs
//! on all three OS legs without a helper binary.

use std::path::{Path, PathBuf};
use std::process::Command;

use andon_core::git::Git;

const EXE: &str = env!("CARGO_BIN_EXE_andon");

fn run_in(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new(EXE)
        .args(args)
        .args(["--repo", repo.to_str().expect("utf-8 path"), "--no-color"])
        .output()
        .expect("the binary runs")
}

/// A repository whose base commit carries `.andon.toml` with the lane on, and
/// whose worktree carries an uncommitted edit — the agent-loop shape, so the
/// sandbox materializes an overlay rather than a plain commit.
fn lane_repo(policy_toml: &str) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("a temporary directory");
    let bootstrap =
        Git::open(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("the workspace is a repository");
    bootstrap
        .cmd(["init", "--quiet", "--initial-branch=main"])
        .arg(temp.path())
        .output()
        .expect("git init");
    let git = Git::open(temp.path()).expect("opens");
    for (key, value) in [
        ("user.name", "Andon Test"),
        ("user.email", "test@andon.invalid"),
        ("core.autocrlf", "false"),
    ] {
        git.cmd(["config", key, value]).output().expect("config");
    }
    std::fs::write(temp.path().join(".andon.toml"), policy_toml).expect("policy");
    std::fs::write(temp.path().join("a.ts"), b"export const a = 1;\n").expect("write");
    // A function, so the static engine has a complexity number for this path
    // and the hotspot metric has its input — every question answerable, which
    // is what lets the record read exactly `partial` while work is deferred
    // rather than sinking to `unwitnessed` under an honest absence.
    std::fs::write(
        temp.path().join("b.ts"),
        b"export function b(x: number): number {\n  if (x > 0) {\n    return 1;\n  }\n  return 0;\n}\n",
    )
    .expect("write");
    // A coverage report, committed and unchanged, so the artifacts engine has
    // something to parse rather than an honest `unwitnessed` marker.
    std::fs::write(
        temp.path().join("lcov.info"),
        b"SF:b.ts\nDA:1,1\nDA:2,1\nDA:3,0\nend_of_record\n",
    )
    .expect("write");
    git.cmd(["add", "--all", "."]).output().expect("add");
    git.cmd(["commit", "--quiet", "-m", "base"])
        .output()
        .expect("commit");
    // A second commit so the default base ladder has a change to measure, then
    // a dirty edit on top: the measured head is the working tree.
    std::fs::write(temp.path().join("a.ts"), b"export const a = 2;\n").expect("write");
    git.cmd(["add", "--all", "."]).output().expect("add");
    git.cmd(["commit", "--quiet", "-m", "second"])
        .output()
        .expect("commit");
    std::fs::write(
        temp.path().join("b.ts"),
        b"export function b(x: number): number {\n  if (x > 1) {\n    return 2;\n  }\n  return 0;\n}\n",
    )
    .expect("write");
    let path = temp.path().to_path_buf();
    (temp, path)
}

fn state_path(repo: &Path, file: &str) -> PathBuf {
    repo.join(".git").join("andon").join(file)
}

fn last_record(repo: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(state_path(repo, "last-measure.json"))
        .expect("the record was saved");
    serde_json::from_str(&text).expect("the record parses")
}

const FAILING: &str = "schema_version = 1\n[sandbox]\nenabled = true\ntest_command = \"exit 3\"\n";
const PASSING: &str = "schema_version = 1\n[sandbox]\nenabled = true\ntest_command = \"exit 0\"\n";

#[test]
fn a_deferred_suite_comes_back_partial_and_wait_completes_it_to_a_block() {
    let (_temp, repo) = lane_repo(FAILING);

    let measured = run_in(&repo, &["measure"]);
    assert!(
        measured.status.success(),
        "the fast lane's verdict on a trivial edit is a pass; the suite has not run yet:\n{}",
        String::from_utf8_lossy(&measured.stderr)
    );
    let record = last_record(&repo);
    assert_eq!(
        record["completeness"], "partial",
        "a measurement owing the suite says so: {record}"
    );
    assert!(
        record["verdict"]["reasons"]
            .as_array()
            .expect("reasons")
            .iter()
            .any(|r| r["code"] == "engine-spilled-async"),
        "the deferral is its own wire-visible reason: {}",
        record["verdict"]["reasons"]
    );
    assert!(
        state_path(&repo, "async-job.json").exists(),
        "the job the wait will execute is on disk"
    );

    let waited = run_in(&repo, &["wait"]);
    assert_eq!(
        waited.status.code(),
        Some(2),
        "the merged verdict blocks on the failed suite:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&waited.stdout),
        String::from_utf8_lossy(&waited.stderr)
    );
    let stdout = String::from_utf8_lossy(&waited.stdout);
    assert!(
        stdout.contains("async lane"),
        "the lane report names the lane:\n{stdout}"
    );

    let merged = last_record(&repo);
    assert_eq!(merged["completeness"], "complete", "{merged}");
    let results = merged["results"].as_array().expect("results");
    let flag = results
        .iter()
        .find(|r| r["metric_id"] == "tests.suite-failure")
        .expect("the suite flag is in the merged record");
    assert_eq!(flag["value"]["value"], true, "the flag fired: {flag}");
    assert_eq!(
        flag["freshness"]["lane"], "async",
        "the suite result rides the async lane: {flag}"
    );
    assert!(
        flag["measurement_regime"]["sandbox"] == "no-net-isolation",
        "the payload carries the isolation disclosure: {flag}"
    );
    assert!(
        merged["verdict"]["reasons"]
            .as_array()
            .expect("reasons")
            .iter()
            .any(|r| r["code"] == "test-failure"),
        "{}",
        merged["verdict"]["reasons"]
    );
    assert!(
        !state_path(&repo, "async-job.json").exists(),
        "the job was consumed by the merge"
    );
    assert!(
        state_path(&repo, "test-suite-output.log").exists(),
        "the suite's output tails were persisted for the operator"
    );

    // A second wait finds nothing pending and re-serves the merged verdict.
    let again = run_in(&repo, &["wait"]);
    assert_eq!(again.status.code(), Some(2));
}

#[test]
fn a_passing_suite_completes_to_a_clean_record() {
    let (_temp, repo) = lane_repo(PASSING);
    assert!(run_in(&repo, &["measure"]).status.success());
    let waited = run_in(&repo, &["wait"]);
    assert_eq!(
        waited.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&waited.stderr)
    );
    let merged = last_record(&repo);
    assert_eq!(merged["completeness"], "complete");
    let flag = merged["results"]
        .as_array()
        .expect("results")
        .iter()
        .find(|r| r["metric_id"] == "tests.suite-failure")
        .cloned()
        .expect("the suite flag is present");
    assert_eq!(flag["value"]["value"], false, "a pass is a measured fact");
    assert_eq!(flag["severity"], "info", "and ranks as nothing");
}

#[test]
fn a_timed_out_suite_stays_an_unanswered_question() {
    let sleeper = if cfg!(windows) {
        // `timeout /t` refuses a null stdin; ping is the portable sleep.
        "ping -n 6 127.0.0.1 >nul"
    } else {
        "sleep 5"
    };
    let policy = format!(
        "schema_version = 1\n[sandbox]\nenabled = true\ntest_command = \"{sleeper}\"\n\
         test_timeout_ms = 400\n"
    );
    let (_temp, repo) = lane_repo(&policy);
    assert!(run_in(&repo, &["measure"]).status.success());

    let waited = run_in(&repo, &["wait"]);
    let merged = last_record(&repo);
    let reasons = merged["verdict"]["reasons"].as_array().expect("reasons");
    assert!(
        reasons.iter().any(|r| r["code"] == "engine-unavailable"
            && r["message"]
                .as_str()
                .expect("a message")
                .contains("never a test failure")),
        "a timeout is an unanswered question, and the refusal states the rule: {reasons:?}"
    );
    assert!(
        !reasons.iter().any(|r| r["code"] == "test-failure"),
        "a timeout must NOT read as a failed suite: {reasons:?}"
    );
    assert_eq!(
        merged["completeness"], "partial",
        "what was not answered is not claimed: {merged}"
    );
    assert_ne!(
        waited.status.code(),
        Some(2),
        "an unanswered question does not stop the line"
    );
    let flags: Vec<_> = merged["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter(|r| r["metric_id"] == "tests.suite-failure")
        .collect();
    assert!(
        flags.is_empty(),
        "no suite result exists for a run that never finished: {flags:?}"
    );
}

#[test]
fn the_cold_cap_spills_content_engines_and_wait_finishes_them() {
    // Graft 4's mechanism, forced deterministically: a zero cold cap means
    // every content engine's start is already past the deadline, so all three
    // spill; the history and artifact engines still answer inline.
    let policy = "schema_version = 1\n[sandbox]\nenabled = true\n\
                  [perf]\nfast_lane_cold_cap_ms = 0\n";
    let (_temp, repo) = lane_repo(policy);

    let measured = run_in(&repo, &["measure"]);
    assert!(measured.status.success());
    let record = last_record(&repo);
    // With the content engines spilled, the process engine's hotspot has no
    // complexity input and honestly reports `unwitnessed` — which outranks
    // `partial` downward in the roll-up. What matters here is that the record
    // does not claim completeness, and that the spill is named.
    assert_ne!(record["completeness"], "complete", "{record}");
    let spilled_reason = record["verdict"]["reasons"]
        .as_array()
        .expect("reasons")
        .iter()
        .find(|r| r["code"] == "engine-spilled-async")
        .cloned()
        .expect("the spill is a wire-visible reason");
    for engine in ["static-metrics", "clones", "tamper"] {
        assert!(
            spilled_reason["message"]
                .as_str()
                .expect("a message")
                .contains(engine),
            "{engine} spilled at the zero cap: {spilled_reason}"
        );
    }
    assert!(
        record["results"]
            .as_array()
            .expect("results")
            .iter()
            .all(|r| r["engine_id"] != "static-metrics"),
        "a spilled engine contributed nothing yet"
    );

    let waited = run_in(&repo, &["wait"]);
    assert!(
        waited.status.code() != Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&waited.stderr)
    );
    let merged = last_record(&repo);
    assert_ne!(
        merged["completeness"], "partial",
        "nothing is deferred any more: {merged}"
    );
    let static_results: Vec<_> = merged["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter(|r| r["engine_id"] == "static-metrics")
        .collect();
    assert!(
        !static_results.is_empty(),
        "the spilled engine's results arrived in the merge"
    );
    assert!(
        static_results
            .iter()
            .all(|r| r["freshness"]["lane"] == "async"),
        "and they carry the lane they actually ran on"
    );
    assert!(
        !merged["verdict"]["reasons"]
            .as_array()
            .expect("reasons")
            .iter()
            .any(|r| r["code"] == "engine-spilled-async"),
        "no deferral outlives its completion: {}",
        merged["verdict"]["reasons"]
    );
    assert!(!state_path(&repo, "async-job.json").exists());
}
