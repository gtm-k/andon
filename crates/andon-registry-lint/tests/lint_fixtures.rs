//! End-to-end tests for the registry lint, run against the real binary.
//!
//! These invoke the compiled executable rather than calling the library
//! function, because the acceptance criterion in PLAN.md is that *the build
//! fails* — and what fails a build is a process exit code. A test that asserted
//! on a `LintReport` struct would prove the analysis works while leaving the
//! wiring between the analysis and CI untested.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Run the lint over a fixture, using the fixture's own `.andon.toml` if it has
/// one. `--as-of` is always explicit: a lint whose verdict depends on the day it
/// runs turns green builds into a slow decay nobody notices.
fn run_lint(name: &str, as_of: &str) -> Output {
    let dir = fixture(name);
    let mut command = Command::new(env!("CARGO_BIN_EXE_andon-registry-lint"));
    command.arg("--as-of").arg(as_of);
    let policy = dir.join(".andon.toml");
    if policy.is_file() {
        command.arg("--policy").arg(&policy);
    }
    command.arg(dir.join("registry"));
    command.output().expect("registry lint binary must run")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The acceptance criterion of PLAN.md P0, stated directly: a metric with no
/// claim tuple behind it fails the build.
#[test]
fn a_metric_without_a_claim_fails_the_build() {
    let output = run_lint("reject-unmapped-metric", "2026-08-17");
    assert_eq!(
        output.status.code(),
        Some(1),
        "an unmapped metric must fail the lint.\nstderr: {}",
        stderr(&output)
    );
    let errors = stderr(&output);
    assert!(
        errors.contains("registry.unmapped-metric"),
        "expected the unmapped-metric diagnostic, got:\n{errors}"
    );
    assert!(
        errors.contains("static.cognitive-complexity"),
        "the diagnostic must name the offending metric, got:\n{errors}"
    );
}

#[test]
fn a_well_formed_registry_passes() {
    let output = run_lint("ok-minimal", "2026-08-17");
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("registry lint clean"));
}

/// The P0 state of this repository. If a registry with no engine files yet were
/// an error, CI would be red from the first commit and stay red until P2.
#[test]
fn an_empty_registry_passes_and_says_it_is_empty() {
    let output = run_lint("empty-registry", "2026-08-17");
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("no engine registry files yet"),
        "an empty registry must announce itself rather than look like a pass \
         over content that was checked; got:\n{}",
        stdout(&output)
    );
}

/// PREMORTEM S2: expiry demotes, it does not stop the line.
#[test]
fn an_expired_claim_is_a_visible_notice_and_not_a_failure() {
    let output = run_lint("notice-expired-claim", "2026-08-17");
    assert_eq!(
        output.status.code(),
        Some(0),
        "an expired claim must not fail the build.\nstderr: {}",
        stderr(&output)
    );
    let notices = stderr(&output);
    assert!(
        notices.contains("registry.evidence-stale"),
        "the demotion must be visible, got:\n{notices}"
    );
    assert!(
        notices.contains("evidence: stale") && notices.contains("gtm-k"),
        "the notice must name the demotion and the owner who re-reviews, got:\n{notices}"
    );
}

/// The same fixture, evaluated before the expiry date, is silent about staleness
/// — which is what makes `--as-of` load-bearing rather than cosmetic.
#[test]
fn the_same_claim_is_not_stale_before_its_expiry() {
    let output = run_lint("notice-expired-claim", "2025-12-01");
    assert_eq!(output.status.code(), Some(0));
    assert!(!stderr(&output).contains("registry.evidence-stale"));
}

#[test]
fn exceeding_the_claim_budget_fails_the_build() {
    let output = run_lint("reject-over-budget", "2026-08-17");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("registry.claim-budget"));
}

#[test]
fn clustering_expiries_in_one_month_fails_the_build() {
    let output = run_lint("reject-expiry-stagger", "2026-08-17");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let errors = stderr(&output);
    assert!(errors.contains("registry.expiry-stagger"));
    assert!(
        errors.contains("2027-03"),
        "the diagnostic must name the crowded month, got:\n{errors}"
    );
}

#[test]
fn a_claim_id_that_disagrees_with_its_tuple_fails_the_build() {
    let output = run_lint("reject-claim-id-format", "2026-08-17");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("registry.claim-id-format"));
}

/// A claim that never says what it fails to predict is exactly the kind of
/// evidence this registry exists to refuse.
#[test]
fn a_claim_without_does_not_predict_fails_the_build() {
    let output = run_lint("reject-empty-does-not-predict", "2026-08-17");
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("registry.missing-field"));
}

#[test]
fn a_missing_registry_directory_is_a_usage_error_not_a_pass() {
    let output = Command::new(env!("CARGO_BIN_EXE_andon-registry-lint"))
        .arg("--as-of")
        .arg("2026-08-17")
        .arg(fixture("does-not-exist"))
        .output()
        .expect("binary must run");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a typo'd path must not be indistinguishable from a clean registry"
    );
}

#[test]
fn a_malformed_as_of_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_andon-registry-lint"))
        .arg("--as-of")
        .arg("17-08-2026")
        .arg(fixture("ok-minimal").join("registry"))
        .output()
        .expect("binary must run");
    assert_eq!(output.status.code(), Some(2));
}
