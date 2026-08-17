//! The verdict set: every committed fixture, end to end, on real git.
//!
//! This is the phase's headline evidence. Each `fixtures/*/*/manifest.toml`
//! builds a repository, runs the agent-side measurement, stages whatever the
//! scenario stages — a rebase, an engine-version skew, a forging binary — and
//! then runs the same verifier the composite action runs. The observed
//! attestation is checked against the value committed in the manifest.
//!
//! Two things this file deliberately does not contain: the expected verdicts
//! (they are in the manifests, where a change to one is a change a reviewer
//! reads) and any fixture construction (that is in `scenario.rs`, so the action
//! and the tests build fixtures the same way).
//!
//! What it does contain is a coverage assertion. A suite that silently lost the
//! `divergent` cases would still be green, and green is the wrong colour for a
//! trust spike that stopped testing whether tampering is caught.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use andon_core::git::Git;
use andon_core::schema::enums::Attestation;
use andon_ledger_min::scenario::{self, Manifest, PrepareOptions};
use andon_ledger_min::verify::{verify, VerifyRequest};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root is reachable from the crate")
}

/// Every committed manifest, sorted, with its family directory.
fn manifests() -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    for family in ["honest", "gamed"] {
        let dir = repo_root().join("fixtures").join(family);
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("dir entry").path();
            let manifest = path.join("manifest.toml");
            if manifest.is_file() {
                found.push((family.to_string(), manifest));
            }
        }
    }
    found.sort();
    found
}

fn options() -> PrepareOptions {
    PrepareOptions {
        // Cargo knows exactly where it put the adversary; nothing is searched
        // for. The forge is a separate executable on purpose — see
        // `tests/binary_separation.rs`.
        forge_bin: Some(PathBuf::from(env!("CARGO_BIN_EXE_andon-spike-forge"))),
    }
}

fn dest(name: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("verdict-set")
        .join(name)
}

/// Build, verify, and check one scenario. Returns the observed attestation.
fn run(manifest: &Manifest) -> Attestation {
    let prepared = scenario::prepare(manifest, &dest(&manifest.name), &options())
        .unwrap_or_else(|e| panic!("{}: prepare failed: {e}", manifest.name));
    let git = Git::open(&prepared.repo).expect("the fixture is a repository");
    let outcome = verify(
        &git,
        &VerifyRequest {
            head: prepared.head.clone(),
            trusted_branch: prepared.trusted_branch.clone(),
            fork_tier: manifest.verify.fork_tier,
        },
    )
    .unwrap_or_else(|e| panic!("{}: verify failed: {e}", manifest.name));

    let problems = scenario::check(manifest, &outcome.attest_record);
    assert!(
        problems.is_empty(),
        "{} ({}):\n  {}\n  repository left at {} for inspection",
        manifest.name,
        manifest.title,
        problems.join("\n  "),
        prepared.repo.display()
    );
    outcome.attestation
}

#[test]
fn every_committed_scenario_produces_the_verdict_it_declares() {
    let found = manifests();
    assert!(!found.is_empty(), "no fixtures found under fixtures/");
    let mut table = Vec::new();
    for (family, path) in &found {
        let manifest = scenario::load(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let observed = run(&manifest);
        table.push(format!("{family:>6}/{:<22} -> {observed:?}", manifest.name));
    }
    // Printed rather than only asserted: the verdict table is a deliverable of
    // this phase, and `cargo test -- --nocapture` is where it comes from.
    println!("\nP1.5 verdict set\n{}", table.join("\n"));
}

#[test]
fn the_required_fixtures_are_all_present() {
    let names: BTreeSet<String> = manifests()
        .iter()
        .map(|(_, path)| {
            scenario::load(path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
                .name
        })
        .collect();

    // PLAN R2-5's five, plus the E4 flip, the PREMORTEM S4 skew, and the two
    // fixtures repair round 1 added. Named individually so that deleting one is
    // a failure with a reason attached rather than a shorter list nobody counts.
    for required in [
        "determinism",
        "moving-main",
        "rebased-pr",
        "version-skew",
        "inflated-metric",
        "flipped-deterministic",
        "flipped-one-deterministic",
        "fabricated-base",
        "skewed-forge",
    ] {
        assert!(
            names.contains(required),
            "the '{required}' fixture is missing; PLAN R2-5 / E4 / PREMORTEM S4 / \
             P15-R1 require it and a suite without it is green for the wrong reason"
        );
    }
}

/// Every fixture under `fixtures/gamed/` must expect a **non-pass carrying
/// evidence**, and every fixture under `fixtures/honest/` must expect **no
/// accusation**.
///
/// This is the direction binding, and it exists because the name check above is
/// not one. Names bind nothing: defang `gamed/flipped-deterministic` by deleting
/// its `forge` step and flipping its expectation to `confirmed`, and the fixture
/// is still called `flipped-deterministic`, still present, still green — and the
/// suite has quietly stopped testing whether tampering is caught while
/// continuing to report that it does.
///
/// A directory is a claim about direction. `gamed/` says "this must not pass and
/// the verifier must be able to say why"; `honest/` says "this must never be
/// accused". Both halves matter: a suite that only bound the gamed side could be
/// satisfied by a verifier that accused everything.
#[test]
fn each_fixture_family_binds_the_direction_of_its_verdict() {
    for (family, path) in manifests() {
        let manifest = scenario::load(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let expected = &manifest.verify;
        let name = &manifest.name;

        match family.as_str() {
            "gamed" => {
                assert!(
                    !expected.expect.counts_downstream(),
                    "gamed/{name} expects {:?}, which is a pass; a fixture staging an \
                     attack that is expected to succeed is not a fixture",
                    expected.expect
                );
                // A non-pass on its own is not enough. `unwitnessed` is a
                // non-pass and it is also what a verifier that did nothing
                // returns, so an attack fixture has to pin something the
                // verifier actively *produced*.
                let evidence = expected.expect_mismatches
                    || expected.expect_flag_disagreements
                    || !expected.expect_tamper.is_empty()
                    || !expected.expect_reason_codes.is_empty();
                assert!(
                    evidence,
                    "gamed/{name} expects {:?} and pins no evidence — no digest \
                     mismatch, no flag disagreement, no tamper signal, no reason \
                     code. A verifier that silently did nothing would satisfy it.",
                    expected.expect
                );
            }
            "honest" => {
                assert!(
                    expected.expect_tamper.is_empty(),
                    "honest/{name} expects tamper signals {:?}; an honest change \
                     must never be accused (PREMORTEM T1)",
                    expected.expect_tamper
                );
                assert!(
                    !expected.expect_mismatches,
                    "honest/{name} expects a digest mismatch; two honest \
                     measurements of the same change agree, and a fixture that \
                     says otherwise has stopped being honest"
                );
            }
            other => panic!("fixtures/{other}/ has no declared direction; add one to this test"),
        }
    }
}

/// Both directions are actually represented.
///
/// The binding above is vacuous over an empty family: a suite with no `honest/`
/// fixtures satisfies every honest rule.
#[test]
fn the_suite_holds_both_a_should_pass_and_a_should_fail() {
    let expectations: Vec<(String, Attestation)> = manifests()
        .iter()
        .map(|(family, path)| {
            (
                family.clone(),
                scenario::load(path).expect("loads").verify.expect,
            )
        })
        .collect();
    assert!(
        expectations
            .iter()
            .any(|(_, e)| *e == Attestation::Confirmed),
        "no should-pass fixture: a detector that never confirms is not a detector"
    );
    assert!(
        expectations
            .iter()
            .any(|(_, e)| *e == Attestation::Divergent),
        "no should-fail fixture: a suite that never catches tampering is green \
         for the wrong reason"
    );
    assert!(
        expectations.iter().any(|(family, _)| family == "gamed"),
        "the gamed family is empty"
    );
    assert!(
        expectations.iter().any(|(family, _)| family == "honest"),
        "the honest family is empty"
    );
}

#[test]
fn a_verifier_pointed_at_the_wrong_checkout_refuses_rather_than_reporting_a_mismatch() {
    // PLAN B3's guard. GitHub's `pull_request` event checks out a synthetic
    // merge commit unless a workflow says otherwise, and verifying that instead
    // of the PR head would report `unwitnessed-base-mismatch` on every honest
    // PR — a wrong answer that looks like a considered one. So the verifier
    // refuses outright when it is not standing where it was told to stand.
    let manifest = scenario::load(&repo_root().join("fixtures/honest/moving-main/manifest.toml"))
        .expect("the moving-main manifest loads");
    let prepared = scenario::prepare(&manifest, &dest("wrong-checkout"), &options())
        .expect("prepare succeeds");
    let git = Git::open(&prepared.repo).expect("the fixture is a repository");

    // Stand on main — which is what a merge-ref checkout amounts to for this
    // purpose: some commit that is not the PR head.
    git.cmd(["checkout", "--quiet", "main"])
        .output()
        .expect("checkout main");

    let err = verify(
        &git,
        &VerifyRequest {
            head: prepared.head.clone(),
            trusted_branch: prepared.trusted_branch.clone(),
            fork_tier: false,
        },
    )
    .expect_err("verifying from the wrong checkout must refuse");
    let message = err.to_string();
    assert!(
        message.contains("synthetic merge ref"),
        "the refusal must name the mistake it is guarding against: {message}"
    );
}
