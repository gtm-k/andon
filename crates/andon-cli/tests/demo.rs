//! `andon demo tamper`, driven as a stranger drives it (PLAN P9b, PREMORTEM A3).
//!
//! The demo's promises are behavioural and each is held by running the real
//! binary and reading what it printed: one command, zero CI, a legit leg that
//! attests `confirmed`, a gamed leg the adversary forged that attests
//! `divergent`, the self-reported→attested distinction stated before any
//! verifier runs, and a theater directory that is gone afterwards unless
//! `--keep` asked for it.
//!
//! # The adversary is a controlled premise
//!
//! The forgery is performed by `andon-spike-forge`, a different binary — the
//! workspace's separation doctrine (`binary_separation.rs`) — so these tests
//! need it built. Under the workspace gate (`cargo test --workspace`) cargo
//! builds every member's binaries before any test runs, so it is always
//! present there. A bare `cargo test -p andon-cli` does not build it, and the
//! locator below FAILS with the one command to run rather than skipping: a
//! suite that silently skips its subject stays green after the subject breaks.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const EXE: &str = env!("CARGO_BIN_EXE_andon");

/// The adversary binary, expected beside `andon` in the target directory.
fn forge() -> PathBuf {
    let name = format!("andon-spike-forge{}", std::env::consts::EXE_SUFFIX);
    let candidate = Path::new(EXE)
        .parent()
        .expect("the andon binary has a directory")
        .join(&name);
    assert!(
        candidate.is_file(),
        "{} is not built. The demo's forgery is deliberately performed by a separate \
         adversary binary; build it first (`cargo build -p andon-ledger-min --bins`) or run \
         the full workspace suite, which builds it.",
        candidate.display()
    );
    candidate
}

fn run_demo(extra: &[&str]) -> Output {
    Command::new(EXE)
        .arg("demo")
        .args(extra)
        // Explicit rather than relying on adjacency, so the premise this suite
        // controls is visible in the invocation.
        .env("ANDON_SPIKE_FORGE_BIN", forge())
        .output()
        .expect("andon runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The theater path the narrative names, from "under <path>; nothing else".
fn theater_path(narrative: &str) -> PathBuf {
    let start = narrative
        .find("under ")
        .expect("the narrative names the theater directory")
        + "under ".len();
    let rest = &narrative[start..];
    let end = rest.find(';').expect("the path ends at a semicolon");
    PathBuf::from(rest[..end].trim())
}

#[test]
fn one_command_tells_the_whole_story_and_cleans_up() {
    let output = run_demo(&["tamper"]);
    let text = stdout(&output);
    assert!(
        output.status.success(),
        "exit {:?}\nstdout:\n{text}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // The self-reported→attested distinction is stated before any verifier
    // output: a fresh self-report is unwitnessed and counts for nothing.
    assert!(text.contains("Trust so far: unwitnessed"), "{text}");
    assert!(
        text.contains("A self-report is a claim; nothing has checked it yet."),
        "{text}"
    );

    // The legit leg confirms, the gamed leg diverges, in that order.
    let confirmed = text
        .find("attestation   confirmed")
        .expect("the legit leg attests confirmed");
    let divergent = text
        .find("attestation   divergent")
        .expect("the gamed leg attests divergent");
    assert!(
        confirmed < divergent,
        "the honest leg comes first so the flip in `counts` reads as a story"
    );
    assert!(
        text.contains("counts        yes — a record with this value counts as evidence downstream"),
        "{text}"
    );
    assert!(
        text.contains(
            "counts        no — this record does not count as attested evidence downstream"
        ),
        "{text}"
    );

    // The divergence names what disagreed rather than only asserting that
    // something did.
    assert!(text.contains("disagreed: static.sloc"), "{text}");

    // The forgery is attributed to the adversary binary, and the stub says
    // what it did not check — the two honesty lines this surface must never
    // lose.
    assert!(text.contains("adversary: forged 1 record(s)"), "{text}");
    assert!(text.contains("THIS IS A STUB."), "{text}");

    // Zero CI, zero litter: the theater it named is gone.
    let theater = theater_path(&text);
    assert!(
        !theater.exists(),
        "{} should have been removed",
        theater.display()
    );
}

#[test]
fn keep_leaves_the_theater_and_says_where() {
    let output = run_demo(&["tamper", "--keep"]);
    let text = stdout(&output);
    assert!(output.status.success(), "{text}");
    let theater = theater_path(&text);
    assert!(
        text.contains("kept at"),
        "--keep must say where the theater is: {text}"
    );
    assert!(theater.exists(), "{} was not kept", theater.display());
    std::fs::remove_dir_all(&theater).expect("test cleanup");
}

#[test]
fn a_missing_adversary_is_a_loud_refusal_that_teaches_the_separation() {
    let output = Command::new(EXE)
        .args(["demo", "tamper"])
        .env(
            "ANDON_SPIKE_FORGE_BIN",
            Path::new(EXE).parent().unwrap().join("no-such-forge"),
        )
        .output()
        .expect("andon runs");
    assert_eq!(output.status.code(), Some(1));
    let err = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(err.contains("ANDON_SPIKE_FORGE_BIN"), "{err}");
    // The refusal happens before the theater is built, so there is nothing to
    // leak; and nothing measured means no story half-told on stdout.
    assert!(stdout(&output).trim().is_empty(), "{}", stdout(&output));
}

#[test]
fn an_unknown_demo_is_refused_with_the_list() {
    let output = Command::new(EXE)
        .args(["demo", "heist"])
        .output()
        .expect("andon runs");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("the demos are: tamper"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
