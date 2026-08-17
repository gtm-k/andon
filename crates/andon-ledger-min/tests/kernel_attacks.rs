//! Attacks on the kernel that the fixture vocabulary cannot express.
//!
//! The verdict set covers everything that is "build a repository, stage one
//! attack, state the verdict". What lives here needs something a manifest has no
//! word for: several records appended by hand, an attestation written and then
//! undermined, a remote that is unreachable rather than merely empty.
//!
//! Every case is an evasion someone proposed and somebody had to answer.

use std::path::{Path, PathBuf};

use andon_core::git::{Git, Revision};
use andon_core::schema::enums::{Attestation, InvocationSource, RecordKind, Verdict};
use andon_ledger_min::measure::measure;
use andon_ledger_min::notes::Notes;
use andon_ledger_min::scenario::{self, Manifest, PrepareOptions};
use andon_ledger_min::verify::{reason, verify, VerifyOutcome, VerifyRequest};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root is reachable from the crate")
}

fn options() -> PrepareOptions {
    PrepareOptions {
        forge_bin: Some(PathBuf::from(env!("CARGO_BIN_EXE_andon-spike-forge"))),
    }
}

fn dest(name: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("kernel-attacks")
        .join(name)
}

fn manifest(relative: &str) -> Manifest {
    scenario::load(&repo_root().join("fixtures").join(relative))
        .unwrap_or_else(|e| panic!("{relative}: {e}"))
}

/// Build a fixture and hand back the repository and the head under test.
fn staged(relative: &str, name: &str) -> (Git, String, String) {
    let manifest = manifest(relative);
    let prepared = scenario::prepare(&manifest, &dest(name), &options())
        .unwrap_or_else(|e| panic!("{name}: prepare failed: {e}"));
    let git = Git::open(&prepared.repo).expect("the fixture is a repository");
    (git, prepared.head, prepared.trusted_branch)
}

fn run_verify(git: &Git, head: &str, trusted_branch: &str) -> VerifyOutcome {
    verify(
        git,
        &VerifyRequest {
            head: head.to_string(),
            trusted_branch: trusted_branch.to_string(),
            fork_tier: false,
        },
    )
    .expect("verify")
}

fn reason_codes(outcome: &VerifyOutcome) -> Vec<String> {
    outcome
        .attest_record
        .verdict
        .reasons
        .iter()
        .map(|r| r.code.clone())
        .collect()
}

/// Append one more self-report to a head, as a second `andon measure` run would.
fn append_report(git: &Git, head: &str, trusted_branch: &str, engine_version: &str) {
    let (record, _) = measure(
        git,
        &Revision::merge_base(trusted_branch),
        &Revision::Rev(head.to_string()),
        RecordKind::SelfReport,
        InvocationSource::Hook,
        engine_version,
    )
    .expect("measure");
    Notes::measure(git)
        .append(head, &record)
        .expect("append the self-report");
}

fn run_forge(repo: &Path, commit: &str, op: &str) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_andon-spike-forge"))
        .arg("--repo")
        .arg(repo)
        .args(["--commit", commit, "--op", op])
        .output()
        .expect("run the adversary");
    assert!(
        output.status.success(),
        "forge {op} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// P15-R1: the version-skew laundering window
// ---------------------------------------------------------------------------

/// A skew does not hide an E4 flip, even though `classify` never reaches the
/// flag comparison.
///
/// The compound attack: stamp a version the verifier is not running *and* flip
/// every `deterministic` flag *and* forge every number. The regime check fires
/// first and returns before the flag comparison, so `CompareOutcome` is empty in
/// every field — which is why the verifier computes the disagreements itself
/// rather than reading them off the compare it did not get to run.
#[test]
fn a_flip_hidden_behind_a_version_skew_is_still_reported() {
    let (git, head, trusted) = staged("honest/version-skew/manifest.toml", "flip-behind-skew");
    run_forge(git.workdir(), &head, "flip-deterministic");
    let outcome = run_verify(&git, &head, &trusted);

    // The outcome is still the skew — and must be. Calling this `divergent`
    // would accuse every developer running a version behind (PREMORTEM S4).
    assert_eq!(outcome.attestation, Attestation::UnwitnessedVersionSkew);
    let compare = outcome
        .attest_record
        .attestation
        .compare
        .as_ref()
        .expect("a compare outcome is recorded even when it stopped early");
    assert!(
        compare.flag_disagreements.is_empty(),
        "the compare itself cannot have seen the flags: it returned at the regime"
    );

    let codes = reason_codes(&outcome);
    assert!(
        codes.contains(&reason::REGIME_SKEW.to_string()),
        "the withheld compare must be named: {codes:?}"
    );
    assert!(
        codes.contains(&reason::FLAG_DISAGREEMENT.to_string()),
        "the flip must survive the cloak: {codes:?}"
    );
}

/// Repeated skew on one head escalates to a human (PLAN R2-4 precedent).
///
/// One skewed report is a stale binary. Three is a party that has been told
/// twice that its measurements are unusable and has carried on.
#[test]
fn repeated_skewed_reports_on_one_head_escalate() {
    let (git, head, trusted) = staged("honest/version-skew/manifest.toml", "repeated-skew");

    // The fixture leaves one skewed report. Two more, at other old versions,
    // because an agent re-running a stale binary is what this models.
    let before = run_verify(&git, &head, &trusted);
    assert_eq!(before.skewed_reports, 1);
    assert!(!before.escalated, "one skew is not an escalation");
    assert_eq!(before.attest_record.verdict.verdict, Verdict::Advise);

    append_report(&git, &head, &trusted, "0.0.2-also-old");
    let two = run_verify(&git, &head, &trusted);
    assert_eq!(two.skewed_reports, 2);
    assert!(!two.escalated, "two skews is a stale binary run twice");

    append_report(&git, &head, &trusted, "0.0.3-still-old");
    let three = run_verify(&git, &head, &trusted);
    assert_eq!(three.skewed_reports, 3);
    assert!(three.escalated, "the third crosses the threshold");
    assert_eq!(
        three.attest_record.verdict.verdict,
        Verdict::EscalateToHuman,
        "a loop producing unusable records is what escalate_to_human is for"
    );
    assert!(three.attest_record.verdict.iteration.escalated);
    assert!(reason_codes(&three).contains(&reason::REPEATED_REGIME_SKEW.to_string()));
    // Still not an accusation: repetition is a reason to involve a human, not
    // evidence of tampering.
    assert!(three.attest_record.attestation.tamper_signals.is_empty());
    assert_eq!(
        three.attestation,
        Attestation::UnwitnessedVersionSkew,
        "escalation moves the verdict, never the attestation value"
    );
}

/// An honest measurement does not acquire a skew marker.
///
/// The mirror of the two tests above: a reason that fired on everything would be
/// a reason nobody reads.
#[test]
fn an_honest_run_carries_no_skew_or_escalation_marker() {
    let (git, head, trusted) = staged("honest/moving-main/manifest.toml", "honest-no-marker");
    let outcome = run_verify(&git, &head, &trusted);
    assert_eq!(outcome.attestation, Attestation::Confirmed);
    assert_eq!(outcome.skewed_reports, 0);
    assert!(!outcome.escalated);
    assert!(
        reason_codes(&outcome).is_empty(),
        "a clean confirmation explains itself: {:?}",
        reason_codes(&outcome)
    );
}

// ---------------------------------------------------------------------------
// P15-R2: a transport failure is not an empty ledger
// ---------------------------------------------------------------------------

/// A remote that cannot be reached is an error, not an absent ledger.
///
/// The fail-open this closes is quiet and specific: `git fetch` exits nonzero
/// both when a ref is missing and when the remote is unreachable, so mapping
/// every nonzero exit to "no ledger" lets a dead remote, an expired token, or a
/// DNS blip manufacture an absence. The verifier then reads an empty local
/// ledger and reports `unwitnessed` — a neutral notice nobody investigates — on
/// a head that has self-reports sitting on the remote.
#[test]
fn an_unreachable_remote_is_a_typed_error_rather_than_an_empty_ledger() {
    let (git, _head, _trusted) = staged("honest/moving-main/manifest.toml", "dead-remote");
    let nowhere = dest("dead-remote").join("no-such-remote.git");
    assert!(
        !nowhere.exists(),
        "the test needs a remote that is not there"
    );

    let err = Notes::measure(&git)
        .fetch(&nowhere.to_string_lossy())
        .expect_err("an unreachable remote must not report an empty ledger");
    let message = err.to_string();
    assert!(
        message.contains("not an empty ledger"),
        "the refusal must say why it refuses: {message}"
    );
}

/// A reachable remote that simply has no ledger yet is a clean, quiet `false`.
///
/// The other half, and the reason the fix is `ls-remote` rather than "treat
/// every failure as fatal": the first push in any repository's life happens
/// against a remote with no notes refs, and that must not be an error.
#[test]
fn a_reachable_remote_without_the_ref_reports_a_clean_absence() {
    let (git, _head, _trusted) = staged("honest/moving-main/manifest.toml", "empty-remote");
    let remote = dest("empty-remote").join("origin.git");
    git.cmd(["init", "--quiet", "--bare", "--initial-branch", "main"])
        .arg(&remote)
        .output()
        .expect("create an empty remote");

    let found = Notes::measure(&git)
        .fetch(&remote.to_string_lossy())
        .expect("a reachable remote with no ledger is not a failure");
    assert!(!found, "there is genuinely nothing there yet");
}
