//! The registry file and the engine must say the same thing.
//!
//! The lint is a standalone tool that reads TOML and never builds an engine, so
//! the declarative manifest it polices could drift from the code it describes.
//! `Registry::check_engine` closes that gap in both directions, and this is
//! where P4 calls it.
//!
//! The whole `registry/` directory is linted here too, not just this engine's
//! file: duplicate claim ids, a busted claim budget, and an expiry cliff are all
//! cross-file properties, and P4 ships two files into a directory that P2 and P3
//! are shipping into at the same time.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use andon_core::date::Date;
use andon_core::git::ChangedSet;
use andon_core::policy::Policy;
use andon_core::registry::{lint, parse_file, EngineRegistryFile, Registry};
use andon_engine_process::complexity::NoComplexity;
use andon_engine_process::engine::{claim_ids, metric_ids, registry_file, ProcessEngine};
use andon_engine_process::history::{HistoryWindow, WINDOW_VERSION};

/// A date the fixtures are evaluated against, so that a passing lint today does
/// not become a failing one tomorrow. Expiry staleness is a notice rather than
/// an error, but the assertion below is about errors and it should mean the same
/// thing in a year.
const AS_OF: &str = "2026-08-17";

fn workspace_root() -> PathBuf {
    // crates/engines/process -> crates/engines -> crates -> root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("the crate lives three levels below the workspace root")
        .to_path_buf()
}

fn empty_engine() -> ProcessEngine {
    let window = HistoryWindow {
        version: WINDOW_VERSION,
        anchor_oid: "a".repeat(40),
        anchor_committed_at: 0,
        window_days: 365,
        cutoff: 0,
        git_version: "git version 2.39.0".to_string(),
        truncated: false,
        paths: Vec::new(),
        commits: Vec::new(),
    };
    ProcessEngine::from_window(
        &window,
        &ChangedSet {
            entries: Vec::new(),
        },
        &NoComplexity,
    )
}

fn registry_files() -> Vec<(String, EngineRegistryFile)> {
    let dir = workspace_root().join("registry");
    let mut files: Vec<(String, EngineRegistryFile)> = std::fs::read_dir(&dir)
        .expect("registry/ is readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "toml"))
        .map(|path| {
            let name = path
                .file_name()
                .expect("a file name")
                .to_string_lossy()
                .into_owned();
            let text = std::fs::read_to_string(&path).expect("registry file is readable");
            let parsed = parse_file(&name, &text)
                .unwrap_or_else(|err| panic!("{name} does not parse: {err}"));
            (name, parsed)
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

#[test]
fn the_engine_and_its_registry_file_do_not_drift() {
    let engine = empty_engine();
    Registry::check_engine(
        registry_file().expect("the compiled registry parses"),
        &engine,
    )
    .unwrap_or_else(|problems| panic!("registry drift: {problems:#?}"));
}

#[test]
fn every_emitted_metric_is_declared_and_every_declared_metric_is_emitted() {
    // `check_engine` already asserts this, and it is stated separately because
    // the failure messages are what a reader needs when a metric is renamed.
    let declared: Vec<String> = registry_file()
        .expect("parses")
        .metrics
        .iter()
        .map(|m| m.metric_id.clone())
        .collect();
    let mut emitted = metric_ids();
    emitted.sort();
    let mut declared = declared;
    declared.sort();
    assert_eq!(emitted, declared);
}

#[test]
fn the_whole_registry_directory_lints_clean() {
    let as_of: Date = AS_OF.parse().expect("a valid date");
    let (registry, report) = lint(&registry_files(), &Policy::default().registry, as_of);
    let errors: Vec<String> = report
        .errors()
        .map(|d| format!("{} [{}]: {}", d.code, d.location, d.message))
        .collect();
    assert!(
        errors.is_empty(),
        "registry lint failed:\n{}",
        errors.join("\n")
    );
    for claim_id in claim_ids() {
        assert!(
            registry.claims.contains_key(&claim_id),
            "{claim_id} is cited by a metric and declared by nothing"
        );
    }
}

#[test]
fn this_phase_spends_six_claims_of_the_budget_of_twenty_four() {
    // The budget is enforced across the merged registry (PREMORTEM S2), and P2
    // and P3 are filling the same directory in the same wave. Stating P4's share
    // as a test means a later edit that quietly adds a seventh claim has to
    // argue with this line first.
    let files = registry_files();
    let p4: usize = files
        .iter()
        .filter(|(name, _)| name == "process.toml" || name == "artifacts.toml")
        .map(|(_, file)| file.claims.len())
        .sum();
    assert_eq!(p4, 6, "P4 declares six claim tuples");
    assert!(p4 <= Policy::default().registry.claim_budget as usize);
}

#[test]
fn no_two_of_this_phases_claims_expire_in_the_same_month() {
    // The stagger limit is three per month across the whole merged registry, and
    // three phases are landing claims in one wave. One per month from P4 leaves
    // the whole allowance for P2 and P3 in every month P4 touches.
    let mut months: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, file) in registry_files() {
        if name != "process.toml" && name != "artifacts.toml" {
            continue;
        }
        for claim in &file.claims {
            months
                .entry(claim.expiry.year_month())
                .or_default()
                .push(claim.claim_id.clone());
        }
    }
    for (month, claims) in &months {
        assert_eq!(
            claims.len(),
            1,
            "{} of P4's claims expire in {month}: {claims:?}",
            claims.len()
        );
    }
    assert_eq!(months.len(), 6);
}

#[test]
fn every_claim_says_what_it_does_not_predict() {
    // The lint enforces non-emptiness; this asserts the contents are sentences
    // rather than a placeholder that satisfies the check.
    for (name, file) in registry_files() {
        if name != "process.toml" && name != "artifacts.toml" {
            continue;
        }
        for claim in &file.claims {
            assert!(
                claim.does_not_predict.len() >= 3,
                "{} lists only {} things it does not predict",
                claim.claim_id,
                claim.does_not_predict.len()
            );
            for entry in &claim.does_not_predict {
                assert!(
                    entry.split_whitespace().count() >= 3,
                    "{}: {entry:?} is too short to be a claim about anything",
                    claim.claim_id
                );
            }
        }
    }
}
