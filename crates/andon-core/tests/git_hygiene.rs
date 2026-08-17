//! Subprocess hygiene, proved against a hostile machine.
//!
//! PLAN P1 asks for a test that plants a hostile global gitconfig and shows the
//! output unchanged. This does that and two things more, because the global file
//! is only one of the three surfaces an attacker — or an ordinary developer with
//! opinions — can reach:
//!
//! 1. **A hostile global config** in an isolated `HOME`.
//! 2. **A hostile repository config** in `.git/config`, which no `HOME` setting
//!    can neutralize and which travels with a clone.
//! 3. **A hostile environment**, including `GIT_CONFIG_COUNT` — the variable
//!    that injects arbitrary config without touching a file at all.
//!
//! The settings planted are the ones PREMORTEM Story 1 names: `core.autocrlf`,
//! `core.quotepath`, and an external diff driver. The assertion in every case is
//! byte equality against the same repository read from a clean environment.
//!
//! # Every test carries a positive control
//!
//! "The hostile config changed nothing" is only evidence if the hostile config
//! *could* have changed something. Half the keys planted here turn out to be
//! inert against our call sites whatever the config says — `-z` output is never
//! quoted, so `core.quotepath` cannot bite; `--no-ext-diff` outranks
//! `diff.external` — and a test built only from those would pass forever while
//! proving nothing.
//!
//! So each test first runs a **bare** git, without our pins, and asserts that
//! the planted setting *does* change its answer. Only then does it assert that
//! the same setting changes nothing when the pins are applied. Removing the pins
//! from `PINNED_CONFIG` makes these tests fail, which was verified by doing it.
//!
//! The bare invocations use `std::process::Command` directly. That is the one
//! place in the workspace where doing so is correct, and it is in a test rather
//! than in `src/git/`, which is where the spawn-path guard looks.

mod common;

use std::path::Path;

use andon_core::git::{BlobBatch, ChangedSet, DirtySnapshot, Git, ResolvedRange, Revision};
use common::TestRepo;

/// Everything one pass over a repository produces, as bytes worth comparing.
#[derive(Debug, PartialEq, Eq)]
struct Observation {
    paths: Vec<String>,
    statuses: Vec<String>,
    src_oids: Vec<Option<String>>,
    dst_oids: Vec<Option<String>>,
    blobs: Vec<(String, Vec<u8>)>,
    snapshot_digest: String,
}

fn observe(repo_path: &Path, base: &str, head: &str) -> Observation {
    let git = Git::open(repo_path).expect("repository opens");
    let range = ResolvedRange::resolve(
        &git,
        &Revision::Rev(base.to_string()),
        &Revision::Rev(head.to_string()),
    )
    .expect("resolves");
    let changed = ChangedSet::enumerate(&git, &range).expect("enumerates");

    let mut batch = BlobBatch::open(&git).expect("batch opens");
    let mut blobs = Vec::new();
    for entry in &changed.entries {
        if let Some(oid) = entry.readable_blob() {
            blobs.push((
                entry.path.clone(),
                batch.read(oid).expect("blob").into_bytes(),
            ));
        }
    }

    let snapshot = DirtySnapshot::incremental(&git, head, false).expect("snapshot");

    Observation {
        paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        statuses: changed
            .entries
            .iter()
            .map(|e| format!("{:?}{:?}", e.status, e.similarity))
            .collect(),
        src_oids: changed.entries.iter().map(|e| e.src_oid.clone()).collect(),
        dst_oids: changed.entries.iter().map(|e| e.dst_oid.clone()).collect(),
        blobs,
        snapshot_digest: snapshot.digest(),
    }
}

/// A repository whose content is chosen to be maximally sensitive to the
/// settings being planted: CRLF bytes committed as CRLF, a non-ASCII path, a
/// rename, and an unstaged edit.
fn hostile_bait_repo(root: &Path) -> (TestRepo, String, String) {
    let repo = TestRepo::init(root);
    let long_body: Vec<u8> = (0..80)
        .map(|i| format!("export const value{i} = {i};\r\n"))
        .collect::<String>()
        .into_bytes();
    repo.write("src/crlf.ts", b"alpha\r\nbeta\r\n");
    repo.write("src/renamed-from.ts", &long_body);
    repo.write("src/plain.ts", b"plain\n");
    repo.add_all();
    let base = repo.commit("base");

    repo.run(&["mv", "src/renamed-from.ts", "src/renamed-to.ts"]);
    repo.write("src/naïve — ü.ts", "const uü = 'ü';\r\n".as_bytes());
    repo.write("src/crlf.ts", b"alpha\r\nbeta\r\ngamma\r\n");
    repo.add_all();
    let head = repo.commit("head");

    // Leave the tree dirty so the snapshot path is exercised too.
    repo.write("src/plain.ts", b"plain\r\nedited\r\n");
    (repo, base, head)
}

/// Run `git hash-object` on a working-tree file with **no pins at all**, under a
/// controlled environment.
///
/// The positive control. `hash-object` is the probe because it is the one place
/// a config key demonstrably changes bytes we would hash: with
/// `core.autocrlf=true` a CRLF file hashes to one value and without it to
/// another, and that difference is the whole of PREMORTEM Story 1 in miniature.
fn bare_hash_object(repo: &Path, rel: &str, env: &[(&str, &str)]) -> String {
    let mut command = std::process::Command::new("git");
    command
        .current_dir(repo)
        .arg("hash-object")
        .arg("--")
        .arg(rel)
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for (key, value) in env {
        command.env(key, value);
    }
    let out = command.output().expect("bare git runs");
    assert!(
        out.status.success(),
        "bare git failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Run `git status` with **no pins at all**, under a controlled environment.
///
/// The probe for environment variables that have no config equivalent, so no
/// `-c` pin could ever cover them. `GIT_INDEX_FILE` is the sharpest of them:
/// point it at a file that is not this repository's index and git reports every
/// tracked file as deleted and then re-added as untracked.
fn bare_status(repo: &Path, env: &[(&str, &str)]) -> String {
    let mut command = std::process::Command::new("git");
    command
        .current_dir(repo)
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for (key, value) in env {
        command.env(key, value);
    }
    let out = command.output().expect("bare git runs");
    assert!(
        out.status.success(),
        "bare git failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Write a file and return its path in a form git config will accept.
///
/// Backslashes are escape characters in git config, so a Windows path pasted in
/// raw makes the whole file unparseable (`bad config line`). Git accepts forward
/// slashes on Windows everywhere, including in `core.attributesFile`.
fn write_global_config(dir: &Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path.display().to_string().replace('\\', "/")
}

/// The `[core] attributesFile` stanza, as its own section so it cannot land
/// under whichever section the preceding text happened to end in.
fn attributes_file_stanza(path: &str) -> String {
    format!("\n[core]\n\tattributesFile = {path}\n")
}

/// An empty global config, so the control has a genuinely neutral baseline
/// rather than whatever the developer's machine happens to carry. This one
/// matters: the machine these tests were written on has `core.autocrlf=true`
/// globally, which would have made a hostile `core.autocrlf=true` look inert.
fn empty_global_config(dir: &Path) -> String {
    write_global_config(dir, "empty.gitconfig", "")
}

const HOSTILE_GLOBAL: &str = "\
[core]
    autocrlf = true
    quotepath = on
    eol = crlf
    safecrlf = true
    hooksPath = /tmp/attacker-hooks
[diff]
    external = /bin/false
    algorithm = minimal
    renames = false
    renameLimit = 1
    indentHeuristic = false
    noprefix = true
    mnemonicPrefix = true
[status]
    showUntrackedFiles = no
    renames = true
[i18n]
    logOutputEncoding = latin1
[gc]
    auto = 1
";

const HOSTILE_REPO_LOCAL: &str = "\
[core]
    autocrlf = true
    quotepath = on
[diff]
    external = /bin/false
    renames = false
";

/// The file the bait repository leaves dirty, with CRLF bytes on disk.
const PROBE_FILE: &str = "src/plain.ts";

#[test]
fn a_hostile_global_config_changes_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (repo, base, head) = hostile_bait_repo(&dir.path().join("repo"));

    // Two homes: one empty, one carrying settings that would translate line
    // endings, octal-escape the unicode path, disable rename detection, and
    // route the diff through a program that always fails.
    let clean_home = dir.path().join("clean-home");
    let hostile_home = dir.path().join("hostile-home");
    std::fs::create_dir_all(&clean_home).unwrap();
    std::fs::create_dir_all(&hostile_home).unwrap();
    std::fs::write(clean_home.join(".gitconfig"), "").unwrap();
    let attrs = write_global_config(dir.path(), "hostile.gitattributes", "*.ts text eol=crlf\n");
    std::fs::write(
        hostile_home.join(".gitconfig"),
        format!("{HOSTILE_GLOBAL}{}", attributes_file_stanza(&attrs)),
    )
    .unwrap();

    let home_env = |home: &Path| {
        vec![
            ("HOME", Some(home.display().to_string())),
            ("USERPROFILE", Some(home.display().to_string())),
            ("XDG_CONFIG_HOME", Some(home.display().to_string())),
        ]
    };

    // Positive control. Proves two things at once: that redirecting HOME
    // actually delivers the config on this platform, and that the settings
    // delivered do change what an unpinned git returns.
    let bare_clean = bare_hash_object(
        repo.path(),
        PROBE_FILE,
        &[
            ("HOME", &clean_home.display().to_string()),
            ("USERPROFILE", &clean_home.display().to_string()),
        ],
    );
    let bare_hostile = bare_hash_object(
        repo.path(),
        PROBE_FILE,
        &[
            ("HOME", &hostile_home.display().to_string()),
            ("USERPROFILE", &hostile_home.display().to_string()),
        ],
    );
    assert_ne!(
        bare_clean, bare_hostile,
        "the bait is inert: an unpinned git gave the same answer either way, \
         so proving our git does too would prove nothing"
    );

    let clean = with_env(&home_env(&clean_home), || {
        observe(repo.path(), &base, &head)
    });
    let hostile = with_env(&home_env(&hostile_home), || {
        observe(repo.path(), &base, &head)
    });

    assert_eq!(
        clean, hostile,
        "a hostile global gitconfig must not change one byte of what we read"
    );
    // And the fixture must still contain the things those settings act on.
    assert!(
        clean.paths.iter().any(|p| p.contains('ü')),
        "the fixture must carry a non-ASCII path"
    );
    assert!(
        clean
            .blobs
            .iter()
            .any(|(_, b)| b.windows(2).any(|w| w == b"\r\n")),
        "the fixture must carry CRLF bytes"
    );
    assert!(
        clean.statuses.iter().any(|s| s.starts_with("Renamed")),
        "the fixture must carry a rename"
    );
}

#[test]
fn a_hostile_repository_config_changes_nothing_either() {
    // `.git/config` outranks the global file and travels with a clone, so a
    // measurement that only defended against `~/.gitconfig` would be defeated by
    // the repository it was measuring.
    let dir = tempfile::tempdir().expect("temp dir");
    let (repo, base, head) = hostile_bait_repo(&dir.path().join("repo"));
    let empty_global = empty_global_config(dir.path());
    let neutral: &[(&str, &str)] = &[("GIT_CONFIG_GLOBAL", &empty_global)];

    let bare_before = bare_hash_object(repo.path(), PROBE_FILE, neutral);
    let clean = observe(repo.path(), &base, &head);

    let attrs = write_global_config(dir.path(), "repo.gitattributes", "*.ts text eol=crlf\n");
    let config_path = repo.path().join(".git").join("config");
    let existing = std::fs::read_to_string(&config_path).unwrap();
    std::fs::write(
        &config_path,
        format!(
            "{existing}\n{HOSTILE_REPO_LOCAL}{}",
            attributes_file_stanza(&attrs)
        ),
    )
    .unwrap();

    let bare_after = bare_hash_object(repo.path(), PROBE_FILE, neutral);
    assert_ne!(
        bare_before, bare_after,
        "the repository-local bait is inert; the test below would prove nothing"
    );

    assert_eq!(
        clean,
        observe(repo.path(), &base, &head),
        "a hostile .git/config must not change one byte of what we read"
    );
}

#[test]
fn a_hostile_environment_changes_nothing_either() {
    // `GIT_CONFIG_COUNT` injects config with no file involved, and
    // `GIT_EXTERNAL_DIFF` names a program to run. Both are why the wrapper
    // sweeps every GIT_* variable rather than listing the dangerous ones.
    let dir = tempfile::tempdir().expect("temp dir");
    let (repo, base, head) = hostile_bait_repo(&dir.path().join("repo"));
    let empty_global = empty_global_config(dir.path());

    // Control 1: config injected through the environment rather than a file.
    let bare_clean = bare_hash_object(
        repo.path(),
        PROBE_FILE,
        &[("GIT_CONFIG_GLOBAL", &empty_global)],
    );
    let bare_hostile = bare_hash_object(
        repo.path(),
        PROBE_FILE,
        &[
            ("GIT_CONFIG_GLOBAL", &empty_global),
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.autocrlf"),
            ("GIT_CONFIG_VALUE_0", "true"),
        ],
    );
    assert_ne!(
        bare_clean, bare_hostile,
        "GIT_CONFIG_COUNT injection is inert here; the test below would prove nothing"
    );

    // Control 2, and the one that makes the *sweep* load-bearing rather than the
    // pins. `GIT_INDEX_FILE` has no config equivalent, so no `-c` could cover
    // it: point it elsewhere and git reports every tracked file as deleted and
    // re-added. Removing the environment sweep makes this test fail; removing
    // only the `-c` pins does too, and the two failures are for different
    // reasons, which is the point of having both controls.
    let stray_index = dir.path().join("stray.index").display().to_string();
    assert_ne!(
        bare_status(repo.path(), &[("GIT_CONFIG_GLOBAL", &empty_global)]),
        bare_status(
            repo.path(),
            &[
                ("GIT_CONFIG_GLOBAL", &empty_global),
                ("GIT_INDEX_FILE", &stray_index),
            ],
        ),
        "GIT_INDEX_FILE is inert here; the sweep would be untested"
    );

    let clean = observe(repo.path(), &base, &head);
    let hostile = with_env(
        &[
            ("GIT_CONFIG_COUNT", Some("3".to_string())),
            ("GIT_CONFIG_KEY_0", Some("core.autocrlf".to_string())),
            ("GIT_CONFIG_VALUE_0", Some("true".to_string())),
            ("GIT_CONFIG_KEY_1", Some("core.quotepath".to_string())),
            ("GIT_CONFIG_VALUE_1", Some("true".to_string())),
            ("GIT_CONFIG_KEY_2", Some("diff.renames".to_string())),
            ("GIT_CONFIG_VALUE_2", Some("false".to_string())),
            ("GIT_INDEX_FILE", Some(stray_index.clone())),
            ("GIT_EXTERNAL_DIFF", Some("/bin/false".to_string())),
            ("GIT_DIFF_OPTS", Some("--unified=99".to_string())),
            ("GIT_ICASE_PATHSPECS", Some("1".to_string())),
            ("GIT_LITERAL_PATHSPECS", Some("1".to_string())),
            ("GIT_NO_REPLACE_OBJECTS", None),
            ("LC_ALL", Some("tr_TR.UTF-8".to_string())),
            ("LANG", Some("tr_TR.UTF-8".to_string())),
        ],
        || observe(repo.path(), &base, &head),
    );

    assert_eq!(clean, hostile, "a hostile environment must not reach git");
}

#[test]
fn the_git_version_is_captured_for_the_payload() {
    // `CompareContext::git_version` and the process `measurement_regime` both
    // carry it, because git's rename-detection defaults move across releases and
    // two gits are two regimes (PREMORTEM S4).
    let dir = tempfile::tempdir().expect("temp dir");
    let repo = TestRepo::init(dir.path());
    let base = repo.commit_file("a.ts", b"one\n", "base");
    let head = repo.commit_file("b.ts", b"two\n", "head");

    let range =
        ResolvedRange::resolve(repo.git(), &Revision::Rev(base), &Revision::Rev(head)).unwrap();
    let ctx = range.compare_context().unwrap();

    assert!(
        ctx.git_version.starts_with("git version "),
        "{}",
        ctx.git_version
    );
    assert_eq!(ctx.git_version, repo.git().version());
    assert!(
        !ctx.git_version.contains('\n'),
        "the version is one trimmed line"
    );
}

#[test]
fn opening_a_repository_and_reading_a_change_stays_inside_the_spawn_budget() {
    // The asserted count, not merely the observed one (PREMORTEM T6). Counted
    // from `Git::open` so the number is what one `andon measure` actually costs.
    let dir = tempfile::tempdir().expect("temp dir");
    let (repo, base, head) = hostile_bait_repo(&dir.path().join("repo"));

    let git = Git::open(repo.path()).unwrap();
    let range = ResolvedRange::resolve(&git, &Revision::Rev(base), &Revision::Rev(head)).unwrap();
    let changed = ChangedSet::enumerate(&git, &range).unwrap();
    let blobs = changed.read_head_blobs(&git).unwrap();

    assert!(blobs.len() >= 3, "the fixture reads several blobs");
    let spawns = git.spawn_count();
    // 2 to open, 2 to resolve, 1 to enumerate, 1 for the whole batch of blobs.
    assert_eq!(
        spawns, 6,
        "a committed-range pass costs a fixed number of spawns regardless of file count"
    );
}

/// Run `body` with environment variables set, then restore them.
///
/// Rust 2024 marks `set_var` unsafe because it races with other threads reading
/// the environment. These tests are `#[test]` functions in a binary that runs
/// them in parallel, so the restoration is not enough on its own — a lock keeps
/// the mutating tests off each other, and no other test in this file reads the
/// environment concurrently.
fn with_env<T>(vars: &[(&str, Option<String>)], body: impl FnOnce() -> T) -> T {
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let saved: Vec<(String, Option<String>)> = vars
        .iter()
        .map(|(key, _)| ((*key).to_string(), std::env::var(key).ok()))
        .collect();
    for (key, value) in vars {
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
    let result = body();
    for (key, value) in saved {
        match value {
            Some(value) => std::env::set_var(&key, value),
            None => std::env::remove_var(&key),
        }
    }
    result
}
