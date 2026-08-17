//! One spawn path, enforced.
//!
//! Subprocess hygiene is a property of the *set* of git invocations, not of any
//! one of them. `PINNED_CONFIG` and the environment sweep can be perfect and
//! still worthless if a later phase adds `Command::new("git")` somewhere
//! convenient — that call inherits the developer's `core.autocrlf`, produces
//! bytes CI cannot reproduce, and the first symptom is a `divergent` verdict on
//! an honest change (PREMORTEM T1).
//!
//! So the invariant is checked mechanically rather than left to review. P0 set
//! the precedent with `workspace_membership`: a cheap structural test that fails
//! loudly on the configuration mistake nobody would catch by reading.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
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

#[test]
fn only_the_command_module_constructs_a_subprocess() {
    let src = src_dir();
    let allowed = src.join("git").join("command.rs");
    let mut offenders = Vec::new();

    for file in rust_files(&src) {
        if file == allowed {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("source is UTF-8");
        for (number, line) in text.lines().enumerate() {
            // The literal spelling is what a new call site would use, whether it
            // imported `std::process::Command` or wrote the path out.
            if line.contains("Command::new") {
                offenders.push(format!("{}:{}", file.display(), number + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a subprocess is constructed outside src/git/command.rs, so it does not \
         carry the pinned config or the swept environment: {offenders:?}\n\
         Route it through `Git::cmd` instead — that is the whole mechanism \
         behind PREMORTEM T1's prevention line."
    );
}

#[test]
fn the_command_module_does_construct_one() {
    // Otherwise the test above would pass by virtue of the workspace having no
    // subprocesses at all, and would keep passing after someone moved the spawn
    // somewhere it should not be.
    let text = std::fs::read_to_string(src_dir().join("git").join("command.rs"))
        .expect("the command module exists");
    assert!(
        text.contains("Command::new"),
        "the guard above is vacuous unless the allowed file is the one spawning"
    );
}

#[test]
fn the_spawn_counter_covers_every_way_a_process_starts() {
    // Three methods reach `Command`: `output`, `succeeds`/`succeeds_with_output`,
    // and `spawn_piped`. Each must increment the counter, or the perf gate's
    // asserted spawn count silently under-reports — and an under-reported count
    // is worse than no count, because it reads as a passing budget.
    let text = std::fs::read_to_string(src_dir().join("git").join("command.rs"))
        .expect("the command module exists");
    let increments = text.matches("spawns.fetch_add(1").count();
    let spawn_sites =
        text.matches("self.command.output()").count() + text.matches("self.command\n").count();
    assert!(
        increments >= spawn_sites,
        "found {spawn_sites} places that start a process and {increments} counter \
         increments; every spawn must be counted"
    );
    assert!(
        increments >= 4,
        "expected at least four counted spawn methods"
    );
}
