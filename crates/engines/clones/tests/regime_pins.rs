//! The grammar versions in the regime are the grammar versions in the build.
//!
//! `GRAMMAR_PINS` is a constant a human maintains; `Cargo.lock` is what the
//! resolver picked. When they drift, every clone number changes at an
//! apparently-equal `measurement_regime` — and an equal regime is precisely
//! what tells the verifier a digest disagreement is tampering rather than skew
//! (PREMORTEM S4 feeding Story 1). This test is the only thing making the two
//! equal.
//!
//! It is the same class of hole the ensemble caught in P0 (a self-reported
//! `deterministic` flag) and again in P1.5 (a self-reported `engine_version`):
//! a field that gates the compare and that nothing checks. Here the check is
//! cheap, so there is no reason for the hole to exist.

use std::path::{Path, PathBuf};

use andon_engine_clones::syntax::{normalization_revision, GRAMMAR_PINS};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root is reachable from the crate")
}

/// Package name -> version, from the lock file. Hand-parsed: adding a TOML
/// crate to read a file this test could parse with two `starts_with` calls
/// would put a dependency in the build for the sake of a test about
/// dependencies.
fn locked_versions() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(workspace_root().join("Cargo.lock"))
        .expect("the workspace has a lock file");
    let mut found = Vec::new();
    let mut name: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            name = None;
        } else if let Some(rest) = line.strip_prefix("name = \"") {
            name = rest.strip_suffix('"').map(str::to_string);
        } else if let Some(rest) = line.strip_prefix("version = \"") {
            if let (Some(name), Some(version)) = (name.take(), rest.strip_suffix('"')) {
                found.push((name, version.to_string()));
            }
        }
    }
    found
}

/// The crate each pin names. `tree-sitter` is the runtime; the rest are
/// grammars, and `tsx` is not here because it ships inside
/// `tree-sitter-typescript`.
fn crate_for(pin: &str) -> String {
    match pin {
        "tree-sitter" => "tree-sitter".to_string(),
        other => format!("tree-sitter-{other}"),
    }
}

#[test]
fn every_pin_matches_the_resolved_dependency() {
    let locked = locked_versions();
    for (pin, declared) in GRAMMAR_PINS {
        let package = crate_for(pin);
        let resolved: Vec<&String> = locked
            .iter()
            .filter(|(name, _)| *name == package)
            .map(|(_, version)| version)
            .collect();
        assert_eq!(
            resolved.len(),
            1,
            "expected exactly one {package} in Cargo.lock, found {resolved:?}"
        );
        assert_eq!(
            resolved[0], declared,
            "GRAMMAR_PINS says {package} is {declared}, Cargo.lock resolved {}. \
             Update the pin *and* re-measure: a grammar bump changes every \
             fingerprint, so the old numbers and the new ones are not comparable.",
            resolved[0]
        );
    }
}

#[test]
fn the_pins_are_sorted_so_the_regime_string_is_stable() {
    let names: Vec<&str> = GRAMMAR_PINS.iter().map(|(name, _)| *name).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        names, sorted,
        "normalization_revision() joins GRAMMAR_PINS in order; an unsorted \
         list would make the regime depend on how the constant was edited"
    );
}

#[test]
fn the_regime_string_names_the_runtime_as_well_as_the_grammars() {
    let revision = normalization_revision();
    assert!(
        revision.contains("tree-sitter@"),
        "the tree-sitter runtime version belongs in the regime too: its parser \
         changes can move a token stream without any grammar moving ({revision})"
    );
}
