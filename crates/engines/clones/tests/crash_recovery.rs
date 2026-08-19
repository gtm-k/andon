//! A writer killed mid-write leaves the index usable, and the results after
//! recovery are the cold results (PREMORTEM T2).
//!
//! # Why a child process, and why `abort`
//!
//! A crash has to be a real one. Dropping a value or returning early would
//! exercise Rust's cleanup paths, which is the opposite of what a crash does —
//! `Drop` is exactly what a killed process does not run. So the write happens
//! in a child process that calls [`std::process::abort`] while its temporary
//! file is on disk and unpublished: no destructors, no flush, no rename.
//!
//! # Why it is not timing-dependent
//!
//! Killing a child at an arbitrary moment and hoping to catch it inside the
//! write is a flaky test that passes for the wrong reason most runs. The write
//! is instead split at the exact point that matters — [`Index::write_pending`]
//! puts the bytes on disk, [`PendingIndex::publish`] makes them the index — and
//! the child aborts between them. That is the whole crash window, entered
//! deterministically.
//!
//! The child is this same test binary, re-executed. Nothing crash-related
//! therefore exists in any shipped code path.

use std::path::{Path, PathBuf};
use std::process::Command;

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::policy::Policy;
use andon_core::schema::payload::{CompareContext, HeadKind};
use andon_engine_clones::index::{FileInput, Index};
use andon_engine_clones::ClonesEngine;

/// Set on the child; names the index it should crash while writing.
const CRASH_TARGET: &str = "ANDON_CRASH_RECOVERY_TARGET";

fn body(name: &str) -> String {
    format!(
        "export function {name}(items: number[], factor: number): number {{\n\
         \x20 let total = 0;\n\
         \x20 for (const item of items) {{\n\
         \x20   if (item > factor) {{ total += item * factor; }}\n\
         \x20   else {{ total -= item; }}\n\
         \x20 }}\n\
         \x20 return total;\n\
         }}\n"
    )
}

fn input(path: &str, source: &str) -> FileInput {
    FileInput {
        path: path.to_string(),
        blob_oid: format!(
            "{:040x}",
            andon_engine_clones::syntax::fnv1a(source.as_bytes())
        ),
        source: source.as_bytes().to_vec(),
    }
}

fn first_generation() -> Vec<FileInput> {
    vec![input("src/a.ts", &body("alpha"))]
}

fn second_generation() -> Vec<FileInput> {
    vec![
        input("src/a.ts", &body("alpha")),
        input("src/b.ts", &body("beta")),
        input("src/c.ts", "export const version = 3;\n"),
    ]
}

fn context() -> MeasureContext {
    MeasureContext {
        compare_context: CompareContext {
            base_oid: "a".repeat(40),
            head_oid: "b".repeat(40),
            git_version: "git version 2.51.0".to_string(),
            head_kind: HeadKind::Commit,
            base_resolution: "explicit".to_string(),
        },
        policy: Policy::default(),
        changed_paths: Vec::new(),
        sandbox_available: false,
    }
}

fn digests(inputs: Vec<FileInput>, index_path: Option<&Path>) -> Vec<String> {
    let engine = ClonesEngine::for_files(inputs, index_path).expect("engine builds");
    run_engine(&engine, &context())
        .expect("measure")
        .into_iter()
        .map(|r| r.digest)
        .collect()
}

fn temp_siblings(index_path: &Path) -> Vec<PathBuf> {
    let parent = index_path.parent().unwrap();
    let stem = index_path.file_name().unwrap().to_str().unwrap();
    let prefix = format!("{stem}.tmp-");
    let mut found: Vec<PathBuf> = std::fs::read_dir(parent)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .collect();
    found.sort();
    found
}

/// The child half. A no-op unless the environment names a target, which is why
/// it is safe for it to be an ordinary test.
#[test]
fn crash_writer_child() {
    let Ok(target) = std::env::var(CRASH_TARGET) else {
        return;
    };
    let target = PathBuf::from(target);
    let (index, _) = Index::empty().update(&second_generation());
    let pending = index
        .write_pending(&target)
        .expect("the temporary is written");
    assert!(pending.temp_path().exists(), "the crash window is real");
    // No unwinding, no destructors, no publish. Exactly what a kill -9 leaves.
    std::process::abort();
}

#[test]
fn a_crash_between_the_write_and_the_rename_costs_nothing_but_a_rebuild() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("crash-recovery");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let index_path = root.join("clones-index");

    // Generation one, published normally. This is what a reader must still see
    // after the crash.
    let before = digests(first_generation(), Some(&index_path));
    let bytes_before = std::fs::read(&index_path).expect("an index exists");

    // Generation two, written by a process that dies before publishing.
    let status = Command::new(std::env::current_exe().expect("the test binary knows its path"))
        .args(["--exact", "crash_writer_child", "--nocapture"])
        .env(CRASH_TARGET, &index_path)
        .status()
        .expect("the child runs");
    assert!(
        !status.success(),
        "the child must abort, not exit cleanly ({status:?})"
    );

    // 1. The published index is untouched — a torn write never reached it.
    assert_eq!(
        std::fs::read(&index_path).expect("the index is still there"),
        bytes_before,
        "the crash modified the published index"
    );

    // 2. It still loads, and still answers the way it did before the crash.
    assert_eq!(Index::load(&index_path).code(), "loaded");
    assert_eq!(
        digests(first_generation(), Some(&index_path)),
        before,
        "the surviving index gives different answers after the crash"
    );

    // 3. The child left its temporary behind — garbage, which is the intended
    //    failure shape, and evidence that the crash really happened inside the
    //    window rather than before it.
    assert_eq!(
        temp_siblings(&index_path).len(),
        1,
        "the aborted write should have left exactly one unpublished temporary"
    );

    // 4. Recovery: the next real write succeeds, and its results are the cold
    //    results. This is the property the phase is gated on, exercised through
    //    an index that a crash has been through.
    let recovered = digests(second_generation(), Some(&index_path));
    let cold = digests(second_generation(), None);
    assert_eq!(
        recovered, cold,
        "after a crash, an incremental result diverged from a cold one"
    );

    // 5. And the recovered index equals the cold index, so nothing was carried
    //    over from the aborted attempt.
    let loaded = Index::load(&index_path).index().expect("reloads");
    let (cold_index, _) = Index::empty().update(&second_generation());
    assert_eq!(loaded.to_bytes().unwrap(), cold_index.to_bytes().unwrap());
}

/// The lock is what stops two live writers interleaving; the crash test above
/// covers the writer that dies. Both matter, and neither implies the other.
#[test]
fn a_second_writer_is_refused_while_the_first_holds_the_lock() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("crash-recovery-lock");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let index_path = root.join("clones-index");

    let held = andon_engine_clones::IndexLock::acquire(&index_path).expect("first writer");
    let refused = ClonesEngine::for_files(first_generation(), Some(&index_path));
    assert!(
        matches!(
            refused,
            Err(andon_engine_clones::CloneEngineError::Index(
                andon_engine_clones::IndexError::Locked { .. }
            ))
        ),
        "a second writer must be refused, got {refused:?}"
    );
    drop(held);

    // And the refusal is not permanent: with the lock released the same call
    // succeeds. A gate that never reopens is a gate that wedges a repository.
    ClonesEngine::for_files(first_generation(), Some(&index_path)).expect("second writer");
}
