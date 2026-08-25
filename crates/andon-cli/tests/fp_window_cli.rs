//! `andon ledger fp-window`, driven as the P10b entry gate will drive it
//! (PLAN P9b, PREMORTEM S6).
//!
//! The window quantities have unit tests beside their computation
//! (`andon-ledger/src/fp_window.rs`); what this suite holds is the surface the
//! gate actually reads — a real repository, a real measurement recorded through
//! the real binary, and the report read back off stdout. The MED+ change here
//! is the same shape P6's convergence test uses (cognitive complexity across
//! the Medium rung), so the P2 rider split is exercised against a finding the
//! shipped policy really produces, not one a fixture asserted.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use andon_core::git::Git;

const EXE: &str = env!("CARGO_BIN_EXE_andon");

fn run_in(repo: &Path, args: &[&str]) -> Output {
    Command::new(EXE)
        .args(args)
        .arg("--repo")
        .arg(repo)
        .output()
        .expect("andon runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A repository with a root commit, plus one measured-and-recorded change whose
/// cognitive complexity crosses the Medium rung.
fn measured_scratch() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("a temporary directory");
    let bootstrap = Git::open(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("a repository");
    bootstrap
        .cmd([
            "init",
            "--quiet",
            "--initial-branch=main",
            "--object-format=sha1",
        ])
        .arg(temp.path())
        .output()
        .expect("git init");
    let git = Git::open(temp.path()).expect("a repository");
    for (key, value) in [
        ("user.name", common::FIXTURE_NAME),
        ("user.email", common::FIXTURE_EMAIL),
        ("core.autocrlf", "false"),
    ] {
        git.cmd(["config", key, value]).output().expect("config");
    }

    let commit = |message: &str| {
        git.cmd(["add", "--all", "."]).output().expect("add");
        git.cmd(["commit", "--quiet", "-m", message])
            .env("GIT_AUTHOR_NAME", common::FIXTURE_NAME)
            .env("GIT_AUTHOR_EMAIL", common::FIXTURE_EMAIL)
            .env("GIT_AUTHOR_DATE", common::FIXTURE_DATE)
            .env("GIT_COMMITTER_NAME", common::FIXTURE_NAME)
            .env("GIT_COMMITTER_EMAIL", common::FIXTURE_EMAIL)
            .env("GIT_COMMITTER_DATE", common::FIXTURE_DATE)
            .output()
            .expect("commit");
        git.cmd(["rev-parse", "HEAD"])
            .text()
            .expect("rev-parse")
            .trim()
            .to_string()
    };

    std::fs::write(
        temp.path().join("src.ts"),
        "export function a(x: number) {\n  return x;\n}\n",
    )
    .expect("write");
    let base = commit("root");

    std::fs::write(temp.path().join("src.ts"), TANGLED).expect("write");
    let head = commit("a change that crosses the Medium rung");

    let measured = run_in(
        temp.path(),
        &[
            "measure",
            "--base",
            &base,
            "--head",
            &head,
            "--record",
            "--exit-zero",
        ],
    );
    assert!(
        measured.status.success(),
        "measure --record failed: {}",
        String::from_utf8_lossy(&measured.stderr)
    );
    temp
}

/// The P6 convergence shape: cognitive complexity past the Medium rung.
const TANGLED: &str = concat!(
    "export function classify(x: number): number {\n",
    "  let out = 0;\n",
    "  if (x > 0) {\n",
    "    if (x > 1) {\n",
    "      if (x > 2) {\n",
    "        if (x > 3) {\n",
    "          if (x > 4) {\n",
    "            if (x > 5) {\n",
    "              out = 6;\n",
    "            } else {\n",
    "              out = 5;\n",
    "            }\n",
    "          }\n",
    "        }\n",
    "      }\n",
    "    }\n",
    "  }\n",
    "  if (x < 0 && x > -10) {\n",
    "    out = -1;\n",
    "  }\n",
    "  return out;\n",
    "}\n",
);

#[test]
fn the_report_counts_the_recorded_change_and_its_med_plus_rider_split() {
    let repo = measured_scratch();
    let output = run_in(
        repo.path(),
        &["ledger", "fp-window", "--since", "2020-01-01T00:00:00Z"],
    );
    let text = stdout(&output);
    assert!(output.status.success(), "{text}");

    assert!(text.contains("1 self-report(s) in window"), "{text}");
    assert!(text.contains("1 distinct measured change(s)"), "{text}");
    // The change really crosses the rung under the shipped policy, and the
    // rider split attributes it to the cognitive/cyclomatic family.
    assert!(
        text.contains("1 change(s) carried a MED+ finding — 100.0% of changes"),
        "{text}"
    );
    assert!(
        text.contains("1 of those driven by cognitive/cyclomatic complexity"),
        "{text}"
    );
    assert!(
        text.contains("med+ on   static.cognitive-complexity.typescript: 1 change(s)"),
        "{text}"
    );
    // No `.andon.toml` in the scratch repo: the B8 diff names the defaults case
    // in as many words rather than printing an empty section.
    assert!(
        text.contains("no field differs: the policy in force is the conservative defaults."),
        "{text}"
    );
    // The budget is cited, and the judging is explicitly somebody else's.
    assert!(text.contains("Checked at P10b entry"), "{text}");
}

#[test]
fn a_window_holding_nothing_says_so_rather_than_failing() {
    let repo = measured_scratch();
    let output = run_in(
        repo.path(),
        &[
            "ledger",
            "fp-window",
            "--since",
            "2099-01-01T00:00:00Z",
            "--until",
            "2099-01-02T00:00:00Z",
        ],
    );
    let text = stdout(&output);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("0 self-report(s) in window"), "{text}");
    assert!(text.contains("0 distinct measured change(s)"), "{text}");
}

#[test]
fn the_window_start_is_required_because_it_is_the_ledgered_fact() {
    let repo = measured_scratch();
    let output = run_in(repo.path(), &["ledger", "fp-window"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--since"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_malformed_bound_is_refused_with_the_expected_shape() {
    let repo = measured_scratch();
    let output = run_in(
        repo.path(),
        &["ledger", "fp-window", "--since", "2026-08-20"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("YYYY-MM-DDTHH:MM:SSZ"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
