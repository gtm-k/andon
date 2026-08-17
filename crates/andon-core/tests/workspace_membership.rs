//! Guards the workspace member globs.
//!
//! The root manifest matches crates with `crates/andon-*` and
//! `crates/engines/*`, chosen so that no phase after P0 has to edit it. The
//! failure mode of a glob scheme is silence: a crate whose directory matches
//! neither pattern is simply not a member, so it is never built, never linted,
//! and its tests never run — and nothing says so. This test converts that
//! silence into a red build.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    // crates/andon-core -> crates -> root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("andon-core lives two levels below the workspace root")
        .to_path_buf()
}

fn subdirectories(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .expect("directory has a name")
        .to_string_lossy()
        .into_owned()
}

/// Every top-level crate directory must match `crates/andon-*`.
#[test]
fn every_top_level_crate_matches_the_member_glob() {
    let crates = workspace_root().join("crates");
    for dir in subdirectories(&crates) {
        let name = name_of(&dir);
        if name == "engines" {
            continue;
        }
        assert!(
            dir.join("Cargo.toml").is_file(),
            "crates/{name} is not a crate. Only crates and the `engines` \
             directory belong under crates/, because `crates/andon-*` would \
             try to load a manifest from anything else that matched."
        );
        assert!(
            name.starts_with("andon-"),
            "crates/{name} has a manifest but does not match the `crates/andon-*` \
             member glob, so cargo silently ignores it: it is never built, never \
             linted, and its tests never run. Rename it to `andon-{name}`."
        );
    }
}

/// Every directory under `crates/engines/` must be a crate.
#[test]
fn every_engines_subdirectory_is_a_crate() {
    let engines = workspace_root().join("crates").join("engines");
    for dir in subdirectories(&engines) {
        let name = name_of(&dir);
        assert!(
            dir.join("Cargo.toml").is_file(),
            "crates/engines/{name} has no Cargo.toml. The `crates/engines/*` glob \
             matches every subdirectory here and cargo fails on one that is not a \
             crate — put non-crate material elsewhere."
        );
    }
}

/// `crates/engines/` must never be empty of files.
///
/// A members glob that expands to nothing falls back to the literal path and
/// errors, so the directory needs at least one entry. Cargo skips non-directory
/// matches, which is why a README satisfies this without becoming a member.
#[test]
fn the_engines_directory_is_never_empty() {
    let engines = workspace_root().join("crates").join("engines");
    assert!(engines.is_dir(), "crates/engines must exist");
    let entries: Vec<PathBuf> = std::fs::read_dir(&engines)
        .expect("crates/engines is readable")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    assert!(
        !entries.is_empty(),
        "crates/engines is empty, so the `crates/engines/*` glob expands to \
         nothing and cargo falls back to the literal path, failing the build. \
         Keep crates/engines/README.md committed until a real engine lands."
    );
}

/// The root manifest still carries the globs this test is written against.
///
/// Parsed rather than string-matched, so that the explanatory comments in the
/// manifest — which necessarily mention `exclude` — do not trip the check.
#[test]
fn the_root_manifest_uses_the_expected_globs() {
    let text = std::fs::read_to_string(workspace_root().join("Cargo.toml"))
        .expect("root Cargo.toml is readable");
    let manifest: toml::Value = text.parse().expect("root Cargo.toml is valid TOML");
    let workspace = manifest
        .get("workspace")
        .expect("root manifest declares a workspace");

    let members: Vec<&str> = workspace
        .get("members")
        .and_then(|m| m.as_array())
        .expect("workspace declares members")
        .iter()
        .filter_map(|m| m.as_str())
        .collect();
    assert!(
        members.contains(&"crates/andon-*"),
        "root manifest no longer uses the `crates/andon-*` glob this test guards; \
         members are {members:?}"
    );
    assert!(
        members.contains(&"crates/engines/*"),
        "root manifest no longer uses the `crates/engines/*` glob this test guards; \
         members are {members:?}"
    );

    assert!(
        workspace.get("exclude").is_none(),
        "cargo's workspace `exclude` is path-prefix based: excluding \
         `crates/engines` also excludes every engine crate beneath it, which is \
         why the plan's suggested remedy does not work. Verified empirically at \
         P0; do not reintroduce it."
    );
}
