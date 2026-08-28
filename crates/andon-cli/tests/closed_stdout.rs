//! A reader that stops reading is not an Andon failure.
//!
//! `andon <anything> | head -c 100` used to panic: the moment `head` closed the
//! pipe, the next `println!` in the binary crashed with a backtrace on stderr
//! and exit 101. A tool built to be piped into `head`, `grep`, `jq`, and an
//! agent's truncated read cannot do that. Every write to stdout now goes
//! through one fallible writer, and a `BrokenPipe` at the top level is a quiet
//! exit 0 — on Windows as well as Unix, because Windows reports the closed pipe
//! as `ErrorKind::BrokenPipe` on the write rather than as a signal.
//!
//! The probe closes the read end of the child's stdout immediately after
//! spawning it — before the child has finished starting, let alone written —
//! so the child's first write meets a closed pipe. This test went red against
//! the unfixed binary (exit 101, "panicked" on stderr), which is what proves
//! the close wins the race.

use std::process::{Command, Stdio};

const EXE: &str = env!("CARGO_BIN_EXE_andon");

/// Run the binary with its stdout piped to nobody, and return the exit code and
/// stderr.
fn with_closed_stdout(args: &[&str]) -> (Option<i32>, String) {
    let mut child = Command::new(EXE)
        .args(args)
        // Pinned so the red excerpt is stable and the assertion reads the
        // panic message rather than a backtrace.
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("andon spawns");
    // The reader leaves before reading a byte.
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("andon exits");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn assert_quiet_exit(args: &[&str]) {
    let (code, stderr) = with_closed_stdout(args);
    assert!(
        !stderr.contains("panicked"),
        "andon {} panicked on a closed stdout:\n{stderr}",
        args.join(" ")
    );
    assert_eq!(
        code,
        Some(0),
        "andon {} on a closed stdout: expected a quiet exit 0, got {code:?}\nstderr:\n{stderr}",
        args.join(" ")
    );
}

#[test]
fn the_usage_pages_exit_quietly_when_the_reader_is_gone() {
    for args in [
        &["--help"][..],
        &["--version"],
        &["measure", "--help"],
        &["report", "--help"],
        &["explain", "--help"],
        &["wait", "--help"],
        &["ledger"],
        &["attest-stub", "--help"],
        &["init", "--help"],
        &["hook", "--help"],
        &["demo", "--help"],
        &["doctor", "--help"],
    ] {
        assert_quiet_exit(args);
    }
}

#[test]
fn the_demo_exits_quietly_when_the_reader_is_gone() {
    // The largest stdout the binary produces, and the first command a stranger
    // pipes into `head`. The demo's forgery is performed by a separate
    // adversary binary (`tests/demo.rs` says why); it is located the same way
    // and its absence fails loudly rather than skipping the subject.
    let name = format!("andon-spike-forge{}", std::env::consts::EXE_SUFFIX);
    let forge = std::path::Path::new(EXE)
        .parent()
        .expect("the andon binary has a directory")
        .join(&name);
    assert!(
        forge.is_file(),
        "{} is not built; build it first (`cargo build -p andon-ledger-min --bins`) or run \
         the full workspace suite, which builds it.",
        forge.display()
    );
    let mut child = Command::new(EXE)
        .args(["demo", "tamper"])
        .env("ANDON_SPIKE_FORGE_BIN", &forge)
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("andon spawns");
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("andon exits");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "andon demo tamper panicked on a closed stdout:\n{stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "andon demo tamper on a closed stdout: expected a quiet exit 0\nstderr:\n{stderr}"
    );
}

#[test]
fn a_full_explanation_exits_quietly_when_the_reader_is_gone() {
    // The longest stdout the binary produces without a repository, in two
    // shapes: the whole metric list, and one metric's full page. Outside a
    // repository `explain` measures nothing and explains under the default
    // policy, so a plain temporary directory is enough.
    let outside = tempfile::tempdir().expect("a temporary directory");
    let repo = outside.path().to_str().expect("utf-8 path");
    assert_quiet_exit(&["explain", "--list"]);
    assert_quiet_exit(&["explain", "tamper.test-removal", "--repo", repo]);
}
