//! Every record this crate reads arrives through the -min crate's guarded
//! readers. Enforced, not asserted in prose.
//!
//! # Why this is a source scan and not a behavioral test
//!
//! `andon_ledger_min::notes::Notes::read` and `andon_ledger_min::records::read`
//! are where the ledger's integrity checks live — the malformed-line refusal
//! today, and every check those readers gain later (the seal verification
//! landing on `fix/seal-binding` is exactly such a check). The project's
//! dominant defect class is a correct guard that a new path simply does not
//! call. A behavioral test here would pin *today's* checks; what this crate
//! must guarantee is structural — **no read path of its own** — so the test is
//! structural too, in the same spirit as `binary_separation.rs` and
//! `git_spawn_guard`: any way of turning bytes into a `MeasurementRecord`
//! outside the guarded readers is a red test, whatever the bytes.
//!
//! The scan is cfg-blind on purpose (a parse path that creeps in as test-only
//! code inside `src/` is still a parse path a refactor can reach), and it
//! covers both this crate's `src/` and the CLI's ledger surface, which is the
//! other place this phase added record-consuming code.

use std::path::{Path, PathBuf};

/// The ways bytes become a deserialized value in this workspace.
///
/// `from_str` covers `serde_json::from_str` however it is imported;
/// `from_slice` and `from_reader` close the sibling byte routes;
/// `from_value` closes the serde_json::Value staging route (parse to a Value
/// through some other door, then deserialize the Value); `::deserialize(`
/// closes the direct Deserializer invocation. `toml::from_str` would be
/// caught by the same net, which is correct — a record has no business
/// arriving as TOML either.
const PARSE_MARKERS: &[&str] = &[
    "from_str",
    "from_slice",
    "from_reader",
    "from_value",
    "::deserialize(",
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current).expect("directory is readable") {
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

/// Lines carrying a parse marker, ignoring comments (which quote what they
/// forbid, this file's own docs included).
fn offending_lines(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && PARSE_MARKERS.iter().any(|m| line.contains(m))
        })
        .map(|(n, line)| (n + 1, line.trim().to_string()))
        .collect()
}

fn assert_no_parsing_in(files: &[PathBuf]) {
    let mut offenders = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(file).expect("source is UTF-8");
        for (line, content) in offending_lines(&text) {
            offenders.push(format!("{}:{line}: {content}", file.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "a byte-to-value parse exists outside the guarded -min readers:\n  {}\n\n\
         Every record this phase reads must come through andon_ledger_min's readers \
         (`Notes::read`, `records::read`), which is where the ledger's integrity checks \
         live — including checks added after this crate was written. A parallel parse is \
         a read path those checks never see. If the line is not parsing a record at all, \
         it still does not belong here: route it through a helper in a crate whose job \
         that is, so this guard stays a flat refusal rather than an allowlist.",
        offenders.join("\n  ")
    );
}

#[test]
fn the_ledger_crate_parses_no_records_of_its_own() {
    assert_no_parsing_in(&rust_files(&manifest_dir().join("src")));
}

#[test]
fn the_cli_ledger_surface_parses_no_records_of_its_own() {
    // The CLI files this phase touched: the ledger module it owns and the
    // dispatch in main.rs it extended. The rest of the CLI predates P8 and
    // has its own reader discipline (and its own review history); scanning it
    // from here would make this crate's gate red over code it cannot change.
    let cli_src = manifest_dir()
        .parent()
        .expect("crates/")
        .join("andon-cli")
        .join("src");
    let scanned: Vec<_> = [cli_src.join("ledger.rs"), cli_src.join("main.rs")]
        .into_iter()
        .inspect(|file| {
            assert!(
                file.is_file(),
                "{} moved; point this guard at its new home rather than deleting it",
                file.display()
            );
        })
        .collect();
    assert_no_parsing_in(&scanned);
}
