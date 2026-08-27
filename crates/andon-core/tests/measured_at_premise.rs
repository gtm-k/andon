//! The premise `fp_window` rests on: no shipped engine stamps a wall clock.
//!
//! `andon-ledger/src/fp_window.rs:42-48` justifies its central design decision —
//! dating records by the notes ref's committer timestamps rather than by a field
//! on the record — with this sentence:
//!
//! > Records carry a `freshness.measured_at` field and every shipped engine
//! > leaves it empty … a self-reported wall clock is a value the measuring
//! > machine chooses for itself, and the window is dated on evidence rather than
//! > on a claim.
//!
//! The mechanism is sound and `fp_window` is correct: it genuinely never reads
//! the field, it walks `landing_times`. What was missing (D42) is anything
//! holding the premise true. "Every shipped engine leaves it empty" is a claim
//! about a construction site in every engine crate, written in prose, and no
//! test asserted any of them. An engine that started stamping a clock would make
//! that doc false, and the only thing that would notice is a human reading two
//! files at once.
//!
//! Scope is the claim's own scope: engine producers. Test fixtures deliberately
//! set a real timestamp (`testing.rs`, `payload/tests.rs`) to exercise the field,
//! and they are correct to — so a scan over all of `crates/` would fail on code
//! doing the right thing. This walks only the engine crates plus `andon-sandbox`,
//! the async-lane engine whose comment the `fp_window` doc quotes verbatim.
//!
//! The engine list is read from `crates/engines/` at test time rather than
//! written here. A hardcoded roster would be the same species of unwatched claim
//! this test exists to retire.
//!
//! The value check is textual and deliberately strict: the line must read
//! exactly `measured_at: String::new(),`. A semantically empty but differently
//! spelled form — `{ String::new() }`, `"".to_string()`, `Default::default()`, a
//! helper call — fails loudly with the offending text quoted. That is the
//! intended trade. Parsing expressions to decide emptiness would let a helper
//! that *returns a clock* pass as long as its name looked innocent; a spelling
//! rule cannot be fooled that way, and its false positives cost one edit each.
//! Two facts make the strictness safe rather than brittle: `Freshness` does not
//! derive `Default`, so no construction can omit the field and escape the scan
//! entirely; and rustfmt normalises the whitespace, so the one canonical
//! spelling is the one every site already has.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <root>/crates/andon-core.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the workspace root")
        .to_path_buf()
}

/// Crates that produce engine results: every directory under `crates/engines/`,
/// plus the async-lane engine. Derived, never listed.
fn engine_crate_srcs(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let engines = root.join("crates").join("engines");
    for entry in std::fs::read_dir(&engines)
        .expect("crates/engines exists")
        .filter_map(|e| e.ok())
    {
        if entry.path().is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            out.push((name, entry.path().join("src")));
        }
    }
    out.push((
        "andon-sandbox".to_string(),
        root.join("crates").join("andon-sandbox").join("src"),
    ));
    out.sort();
    out
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    // Loud, not silent. The first version returned quietly on an unreadable
    // directory. A whole unreadable crate would still trip the
    // `crates_with_a_site` assertion below — but an unreadable *nested*
    // subdirectory beside a readable sibling would not: the sibling satisfies
    // `found_here`, and an offending `measured_at:` inside the skipped subtree
    // goes unflagged with neither assertion firing. That is the walk
    // under-covering in exactly the shape it guards (D43, the Codex gate on
    // D42). A directory this test cannot read is a failure of the test's
    // premise, not a thing to step around.
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "cannot read `{}` while checking the measured_at premise: {e}. \
             An unreadable directory here means the scan is incomplete, and an \
             incomplete scan that reports success is the failure this test exists \
             to prevent.",
            dir.display()
        )
    });
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_shipped_engine_stamps_a_wall_clock() {
    let root = workspace_root();
    let crates = engine_crate_srcs(&root);
    assert!(
        crates.len() >= 2,
        "expected the engine crates plus andon-sandbox; found {crates:?}. \
         If crates/engines/ moved, fix this walk rather than deleting the test."
    );

    let mut checked = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    let mut crates_with_a_site: Vec<String> = Vec::new();

    for (crate_name, src) in &crates {
        let mut files = Vec::new();
        rs_files(src, &mut files);
        let mut found_here = false;

        for file in files {
            let text = std::fs::read_to_string(&file).expect("a readable source file");
            for (i, line) in text.lines().enumerate() {
                if !line.trim_start().starts_with("measured_at:") {
                    continue;
                }
                found_here = true;
                checked += 1;
                let value = line.trim().trim_start_matches("measured_at:").trim();
                if value != "String::new()," {
                    offenders.push(format!(
                        "{}:{} sets `{}`",
                        file.strip_prefix(&root).unwrap_or(&file).display(),
                        i + 1,
                        value
                    ));
                }
            }
        }
        if found_here {
            crates_with_a_site.push(crate_name.clone());
        }
    }

    // Vacuity: a scan that finds nothing would pass and prove nothing, which is
    // the precise shape of the problem being fixed.
    assert!(
        checked > 0,
        "found no `measured_at:` assignment in any engine crate — the scan is \
         broken, or the field was renamed. Either way this test is no longer \
         checking what it claims."
    );
    let missing: Vec<&(String, PathBuf)> = crates
        .iter()
        .filter(|(name, _)| !crates_with_a_site.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "these engine crates construct no `measured_at` at all, so the premise is \
         unverified for them: {:?}. Either they do not produce results (in which \
         case narrow this walk deliberately) or the scan missed them.",
        missing.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );

    assert!(
        offenders.is_empty(),
        "`fp_window.rs` states that every shipped engine leaves \
         `freshness.measured_at` empty, and dates the FP window on the notes ref \
         instead BECAUSE of it. These sites break that premise:\n  {}\n\n\
         If stamping a clock here is deliberate, the fp_window doc must change in \
         the same commit — a self-reported wall clock is a value the measuring \
         machine chooses for itself, which is exactly what the window refuses to \
         date on.",
        offenders.join("\n  ")
    );
}
