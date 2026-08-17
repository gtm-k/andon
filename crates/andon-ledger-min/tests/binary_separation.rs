//! The measuring binary cannot forge. Enforced, not asserted in prose.
//!
//! `andon-spike-forge` exists because the threat this phase tests is a
//! deliberately forging agent binary, and the honest way to test that is with a
//! binary that actually forges. The risk of writing one is that its capability
//! leaks back into the tool: a `--lie` flag, a "test-only" helper in the
//! library, a mutation function someone reuses. Any of those would put forging
//! inside the binary whose product is not forging, and would do it in a diff
//! that reads as tidying up.
//!
//! So the invariant is mechanical, in the same spirit as andon-core's
//! `git_spawn_guard`: **every line that alters a sealed record lives in one
//! file, and that file is compiled only into the adversary.**

use std::path::{Path, PathBuf};

/// The mutations that turn an honest record into a forged one.
///
/// Assignment syntax specifically. Building a `MeasurementResult` from scratch
/// uses `field: value` and is what the engine legitimately does; writing over a
/// field of a record that already exists is what a forger does.
const FORGING_MARKERS: &[&str] = &[".seal(", ".deterministic =", ".value =", ".base_oid ="];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn forge_file() -> PathBuf {
    src_dir().join("bin").join("andon-spike-forge.rs")
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current).expect("src is readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Lines of `text` that carry a marker, ignoring comments.
///
/// Comments are skipped because this file, and the module docs that explain the
/// separation, necessarily quote the things they forbid.
fn offending_lines(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && FORGING_MARKERS.iter().any(|m| line.contains(m))
        })
        .map(|(n, line)| (n + 1, line.trim().to_string()))
        .collect()
}

#[test]
fn nothing_the_measuring_binary_links_can_alter_a_sealed_record() {
    let forge = forge_file();
    let mut offenders = Vec::new();
    for file in rust_files(&src_dir()) {
        if file == forge {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("source is UTF-8");
        for (line, content) in offending_lines(&text) {
            offenders.push(format!("{}:{line}: {content}", file.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "a sealed record is altered outside the adversary binary:\n  {}\n\n\
         The forge is a separate executable so that `andon-spike` provably \
         cannot produce a record whose numbers disagree with what it measured. \
         If a legitimate reason to re-seal appears, it needs a design decision \
         and a new home, not a quiet addition here.",
        offenders.join("\n  ")
    );
}

#[test]
fn the_adversary_binary_really_does_forge() {
    // Otherwise the guard above passes because nothing in the crate forges at
    // all, and would keep passing after the forge was gutted — leaving a
    // "gamed" fixture set that stages no attack and a suite that is green
    // because it stopped testing anything.
    let text = std::fs::read_to_string(forge_file()).expect("the adversary exists");
    let found = offending_lines(&text);
    assert!(
        found.len() >= 3,
        "expected the adversary to rewrite and re-seal records; found {found:?}"
    );
    for marker in [".seal(", ".deterministic =", ".base_oid ="] {
        assert!(
            found.iter().any(|(_, line)| line.contains(marker)),
            "the adversary no longer performs `{marker}`, so the fixture that \
             depends on it is staging nothing"
        );
    }
}

#[test]
fn the_library_does_not_name_the_adversarys_operations() {
    // A second angle on the same line. The scenario runner *invokes* the forge
    // binary — which is how a real attack works, a different program writing a
    // different note — but nothing in the library implements one, so the op
    // names appear only as data passed through from a manifest.
    let lib_files: Vec<PathBuf> = rust_files(&src_dir())
        .into_iter()
        .filter(|p| !p.starts_with(src_dir().join("bin")))
        .collect();
    for file in lib_files {
        let text = std::fs::read_to_string(&file).expect("source is UTF-8");
        for (number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            assert!(
                !line.contains("inflate-metric") && !line.contains("flip-deterministic"),
                "{}:{}: the library names an adversary operation; the ops are \
                 the forge binary's vocabulary and reach it as manifest data",
                file.display(),
                number + 1
            );
        }
    }
}
