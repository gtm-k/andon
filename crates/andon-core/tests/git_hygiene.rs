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
    // And leave one file untracked, which `status.showUntrackedFiles = no` acts
    // on. Our own status call passes `--untracked-files=all` explicitly, so the
    // planted setting cannot reach it — which is exactly the immunity this test
    // asserts, and is also what makes the untracked probe below a usable
    // positive control.
    repo.write("src/untracked.ts", b"export const stray = 1;\r\n");
    (repo, base, head)
}

/// `git --version`, for failure messages that have to name the git that failed.
fn git_version() -> String {
    let out = std::process::Command::new("git")
        .arg("--version")
        .output()
        .expect("bare git runs");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Run an arbitrary bare `git` invocation — **no pins at all** — under a
/// controlled `HOME`.
///
/// # Why the two `env_remove` calls, which are the whole bugfix
///
/// This control assumes that writing `$HOME/.gitconfig` and redirecting `HOME`
/// puts that file in front of git. That assumption is false whenever
/// `GIT_CONFIG_GLOBAL` is set in the ambient environment: git then reads *that*
/// path as the global config and never looks at `$HOME/.gitconfig` at all. The
/// planted bait is not weakened, it is not delivered — both homes read the same
/// leaked file, both answers match, and the control reports "the bait is inert"
/// on a build where nothing about this crate changed. Reproduced exactly:
///
/// ```text
/// HOME=clean   git hash-object plain.ts -> a636bef...   LIVE
/// HOME=hostile git hash-object plain.ts -> f171456...
///
/// GIT_CONFIG_GLOBAL=leak.gitconfig HOME=clean   -> a636bef...   INERT
/// GIT_CONFIG_GLOBAL=leak.gitconfig HOME=hostile -> a636bef...
/// ```
///
/// `GIT_CONFIG_COUNT` is removed for the same reason: it injects config that
/// outranks the file, so a leaked one could equally decide the answer.
///
/// This is *not* a general un-pinning of the environment. Only the two variables
/// that decide **whether the planted file is read at all** are cleared. Anything
/// that merely changes git's behaviour is left exactly as the runner set it,
/// because an unpinned git is what this control is supposed to be.
///
/// `XDG_CONFIG_HOME` is redirected alongside `HOME` so the other standard global
/// location (`$XDG_CONFIG_HOME/git/config`) cannot come from the real user
/// either.
fn bare_git_under_home(repo: &Path, args: &[&str], home: &Path) -> String {
    let home = home.display().to_string();
    let out = std::process::Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", &home)
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_CONFIG_COUNT")
        .output()
        .expect("bare git runs");
    // Not asserting success: a hostile setting is allowed to make an unpinned
    // git *fail*, and a failure that a clean run does not produce is itself a
    // demonstration that the setting bites. Status and stderr are folded into
    // the compared string so that difference is visible rather than swallowed.
    format!(
        "status={:?}\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// One way of showing that the planted config actually changes what an unpinned
/// git says.
struct Bait {
    /// What is being read, for the failure message.
    setting: &'static str,
    /// The bare invocation that reads it.
    args: &'static [&'static str],
}

/// The positive-control candidates, in the order they are tried.
///
/// # Why this is a list rather than one probe
///
/// It used to be one: `hash-object` on the CRLF-dirty file, reading
/// `core.autocrlf`. That is a good probe and it is still first. But it went
/// inert on a GitHub runner — the clean and hostile homes hashed identically —
/// and the test went red saying "the bait is inert" on a build where nothing
/// about *this* crate had changed. A newer git had moved a default out from
/// under the control.
///
/// That failure was correct in the narrow sense and useless in the wide one: the
/// thing being controlled for is "does a hostile global config change unpinned
/// git's answer", and the answer was still yes — through several other settings
/// the same planted file sets. One probe made a property of git the sole
/// evidence for a property of the planted config.
///
/// So the control now tries several independent readings of the same planted
/// config and needs **one** to bite. It never skips: if every candidate is
/// inert the test fails, loudly, naming the git version and each probe that
/// produced no difference — because at that point the main assertion below
/// really would be proving that our git agrees with itself about nothing.
///
/// Each entry reads a *different* key, so no single upstream default change can
/// silence the set:
const BAITS: &[Bait] = &[
    // `core.autocrlf` + `core.eol` + the planted `attributesFile`. The original,
    // and the one that is PREMORTEM Story 1 in miniature: a CRLF file hashes to
    // one value with end-of-line translation on and another with it off.
    Bait {
        setting: "core.autocrlf / core.eol / core.attributesFile",
        args: &["hash-object", "--", PROBE_FILE],
    },
    // `status.showUntrackedFiles = no`, which hides `src/untracked.ts`. Stable
    // across every git that has had the setting, and it needs no filter, no
    // attributes file and no content translation to bite.
    Bait {
        setting: "status.showUntrackedFiles",
        args: &["status", "--porcelain=v1"],
    },
    // `diff.renames = false` + `diff.renameLimit = 1`. The bait repo renames a
    // file, so the clean run reports `R` and the hostile one reports a delete
    // and an add. `--name-status` produces no textual diff, so the planted
    // `diff.external` cannot interfere with this reading.
    Bait {
        setting: "diff.renames / diff.renameLimit",
        args: &["diff", "--name-status", "-M", "HEAD~1", "HEAD"],
    },
];

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
    //
    // Tried across several independent readings of the same planted config
    // (see `BAITS`) because a single probe makes one upstream default the sole
    // evidence for both. One live bait is enough; none is a failure, never a
    // skip.
    let mut live = Vec::new();
    let mut inert = Vec::new();
    for bait in BAITS {
        let bare_clean = bare_git_under_home(repo.path(), bait.args, &clean_home);
        let bare_hostile = bare_git_under_home(repo.path(), bait.args, &hostile_home);
        if bare_clean == bare_hostile {
            inert.push(format!(
                "  INERT  {} (`git {}`)\n           both homes said: {}",
                bait.setting,
                bait.args.join(" "),
                bare_clean.replace('\n', " | ")
            ));
        } else {
            live.push(format!("  live   {}", bait.setting));
        }
    }
    for line in live.iter().chain(inert.iter()) {
        println!("{line}");
    }
    assert!(
        !live.is_empty(),
        "the bait is inert on every probe: an unpinned git gave the same answer \
         either way for all {} of them, so proving our git does too would prove \
         nothing.\n\n\
         This is a statement about the git running this test, not about \
         andon-core. Either the HOME redirection is not delivering the config on \
         this platform, or every setting the bait plants has become a default. \
         Add a probe that reads a key this git still honours — do not delete the \
         control.\n\n\
         git version: {}\n{}",
        BAITS.len(),
        git_version(),
        inert.join("\n")
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
    let clean = serialized(|| observe(repo.path(), &base, &head));

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
        serialized(|| observe(repo.path(), &base, &head)),
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

    let clean = serialized(|| observe(repo.path(), &base, &head));
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

// ---------------------------------------------------------------------------
// the one place the pins must not reach
// ---------------------------------------------------------------------------

/// Run a bare `git` — no pins of ours — with extra `-c` settings and an
/// explicitly supplied config environment.
///
/// The controls below need a git that answers as the machine would, which is
/// what every other helper in this file is built to prevent. The environment is
/// swept and then set from `env` rather than inherited, so "as the machine
/// would" means "as the arm under test says", and not "as whichever test
/// happened to be running in parallel had left it".
fn bare_git(cwd: &Path, config: &[&str], args: &[&str], env: &[(&str, String)]) -> String {
    let mut command = std::process::Command::new("git");
    // Swept for the same reason the production path sweeps, and for one more:
    // the environment tests in this file set `GIT_INDEX_FILE` process-wide while
    // they run, and `cargo test` runs test functions in parallel. An inherited
    // one turns this clone into a failure that depends on scheduling.
    for (key, _) in std::env::vars_os() {
        if let Some(key) = key.to_str() {
            if key.starts_with("GIT_") && key != "GIT_EXEC_PATH" {
                command.env_remove(key);
            }
        }
    }
    command.current_dir(cwd);
    for (key, value) in env {
        command.env(key, value);
    }
    for setting in config {
        command.arg("-c").arg(setting);
    }
    let out = command.args(args).output().expect("bare git runs");
    assert!(
        out.status.success(),
        "bare git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Which config scope carries `core.autocrlf=true` in one arm of the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// `etc/gitconfig`. What a fresh Git-for-Windows install actually ships.
    System,
    /// `~/.gitconfig`. What a developer who ran `git config --global` has.
    Global,
    /// The clone's own `.git/config`, written by `clone -c`.
    Local,
}

impl Scope {
    fn label(self) -> &'static str {
        match self {
            Scope::System => "system",
            Scope::Global => "global",
            Scope::Local => "local",
        }
    }
}

#[test]
fn a_conversion_produced_checkout_is_not_reported_dirty_in_any_config_scope() {
    // PREMORTEM Story 1 from the other end. Pinning `core.autocrlf=false` fixes
    // the bytes we hash, which is right when the question is what the bytes are
    // and wrong when the question is whether a file was edited: on a clone made
    // with `core.autocrlf=true` — the Git-for-Windows default — every text file
    // on disk carries CRLF that the checkout itself put there.
    //
    // Three arms, because git resolves that setting from three files and the
    // first repair only reached two of them. The system arm is not the exotic
    // one: `core.autocrlf=true` is what Git for Windows writes into
    // `etc/gitconfig`, so on a fresh install it is the *only* scope carrying it,
    // and a repair blind to it leaves the whole failure standing for the most
    // common Windows setup there is.
    //
    // Each arm redirects both `GIT_CONFIG_SYSTEM` and `GIT_CONFIG_GLOBAL` — one
    // at a fixture carrying the setting, the other at an empty file — so an arm
    // proves its own scope and cannot be carried by the machine's real config.
    for scope in [Scope::System, Scope::Global, Scope::Local] {
        one_conversion_scope(scope);
    }
}

/// One arm of the scope matrix: build, clone, and assert the whole property.
fn one_conversion_scope(scope: Scope) {
    let label = scope.label();
    let dir = tempfile::tempdir().expect("temp dir");

    let carrying = write_global_config(
        dir.path(),
        &format!("{label}-carries.gitconfig"),
        "[core]\n\tautocrlf = true\n",
    );
    let empty = write_global_config(dir.path(), &format!("{label}-empty.gitconfig"), "");
    // The two file-scope variables are always both set, so whichever scope is
    // not under test is empty rather than whatever this machine happens to hold.
    let scope_env: Vec<(&str, String)> = vec![
        (
            "GIT_CONFIG_SYSTEM",
            if scope == Scope::System {
                carrying.clone()
            } else {
                empty.clone()
            },
        ),
        (
            "GIT_CONFIG_GLOBAL",
            if scope == Scope::Global {
                carrying.clone()
            } else {
                empty.clone()
            },
        ),
    ];

    let origin_path = dir.path().join("origin");
    let origin = TestRepo::init(&origin_path);
    for i in 0..200 {
        origin.write(
            &format!("src/f{i}.ts"),
            format!("export const v{i} = {i};\nexport const w{i} = {i};\n").as_bytes(),
        );
    }
    origin.add_all();
    let head = origin.commit("two hundred files, committed with LF");

    // Two clones, made identically, because the first `status` any git runs
    // against a fresh conversion checkout **rewrites the index stat cache** —
    // git records size 0 for a converted entry so that it must compare content,
    // and a successful comparison replaces that with trustworthy stat data.
    // Every later reader then trusts the stat and answers "clean" whatever its
    // own conversion says. That is the flip-flop this fix exists to remove, and
    // it also means a control and the property under test cannot share a
    // checkout: whichever ran second would be reading the other's leftovers.
    // (It is timing-sensitive too — git distrusts stat data written in the same
    // instant as the index — so sharing one clone fails on a different arm each
    // run.)
    //
    // For the system and global arms the setting is already in force through the
    // environment, so a plain clone converts. For the local arm `clone -c`
    // writes it into the new repository's own config — which is the form that
    // persists. (`-c … clone`, with the flag before the subcommand, would apply
    // to the clone and then vanish, leaving a checkout that disagrees with its
    // own git — a different situation, and one where calling the files modified
    // is the correct answer.)
    let origin_arg = origin_path.display().to_string();
    let clone = |name: &str| -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut args = vec!["clone", "--quiet"];
        if scope == Scope::Local {
            args.extend(["-c", "core.autocrlf=true"]);
        }
        let dest = path.display().to_string();
        args.extend([origin_arg.as_str(), dest.as_str()]);
        bare_git(dir.path(), &[], &args, &scope_env);
        assert!(
            std::fs::read(path.join("src/f0.ts"))
                .expect("the clone has the file")
                .windows(2)
                .any(|w| w == b"\r\n"),
            "[{label}] {name} must actually carry CRLF, or there is no conversion \
             to be consistent with"
        );
        // Every file rewritten with the bytes it already holds — what an editor
        // does when you save without typing. Content is untouched; the mtime
        // moves, so git cannot take the stat-cache shortcut and has to compare
        // content, which is the comparison this test is about.
        //
        // Without it the counts below are a coin toss. Git distrusts stat data
        // written in the same instant as the index and trusts anything older, so
        // on a fresh clone whether a file is re-hashed depends on which side of a
        // timestamp tick its checkout landed: observed 200, 72, and 0 for the
        // same arm across three runs.
        for i in 0..200 {
            let file = path.join(format!("src/f{i}.ts"));
            let bytes = std::fs::read(&file).expect("read back");
            std::fs::write(&file, bytes).expect("rewrite unchanged");
        }
        path
    };
    let control_path = clone("control-clone");
    let clone_path = clone("crlf-clone");

    let status_args = ["status", "--porcelain=v1", "--untracked-files=all"];
    let clean_lines = |out: &str| out.lines().filter(|l| !l.is_empty()).count();

    // Control 1, and the one that makes everything below mean something: asked
    // under our conversion pins and nothing else, a fresh checkout has all 200
    // files modified. That is the answer the snapshot carried before the fix.
    // It runs first, on an untouched index, because it is the reading the stat
    // cache destroys.
    assert_eq!(
        clean_lines(&bare_git(
            &control_path,
            &["core.autocrlf=false", "core.eol=lf"],
            &status_args,
            &scope_env,
        )),
        200,
        "[{label}] the bait is inert: pinning the conversion off changed nothing \
         here, so the assertions below would prove nothing"
    );
    // Control 2: the clone's own git considers the same tree clean.
    assert_eq!(
        clean_lines(&bare_git(&control_path, &[], &status_args, &scope_env)),
        0,
        "[{label}] the clone's own git must call this tree clean"
    );

    // The production path reads the environment of *this* process, so the arm's
    // redirection has to be process-wide for the rest of the test.
    let env: Vec<(&str, Option<String>)> = scope_env
        .iter()
        .map(|(k, v)| (*k, Some(v.clone())))
        .collect();
    with_env(&env, || {
        let git = Git::open(&clone_path).expect("the clone is a repository");
        let snapshot = || DirtySnapshot::incremental(&git, &head, false).expect("snapshot");

        let first = snapshot();
        assert!(
            first.is_empty(),
            "[{label}] an untouched clone has no dirty state; got {} entries, e.g. {:?}",
            first.len(),
            first.entries.keys().take(3).collect::<Vec<_>>()
        );
        assert_eq!(
            first.digest(),
            snapshot().digest(),
            "[{label}] two reads of one untouched tree must agree"
        );

        // The flip-flop, which is the sharper half. Our `status` refreshes the
        // index stat cache as it goes, and so does the clone's; before this fix
        // the snapshot's answer depended on which had written it last.
        bare_git(&clone_path, &[], &status_args, &scope_env);
        let after_refresh = snapshot();
        assert!(
            after_refresh.is_empty(),
            "[{label}] still untouched, still clean"
        );
        assert_eq!(
            first.digest(),
            after_refresh.digest(),
            "[{label}] an index refresh by the clone's own git must not move the digest"
        );

        // And the property that makes the fix a fix rather than a mute: a real
        // edit is still a real edit, and it is the only entry.
        std::fs::write(
            clone_path.join("src/f7.ts"),
            b"export const genuinely = 'edited';\r\n",
        )
        .expect("write the edit");
        let edited = snapshot();
        assert_eq!(
            edited.entries.keys().collect::<Vec<_>>(),
            vec!["src/f7.ts"],
            "[{label}] exactly the edited file, and nothing the conversion produced"
        );
        assert_ne!(
            first.digest(),
            edited.digest(),
            "[{label}] and the key has to move when the content does"
        );
    });
}

#[test]
fn a_staged_change_on_a_converting_checkout_keeps_its_staged_half() {
    // The other half of the correction. A file staged through the clone's own
    // git has LF in the index and CRLF on disk, so our pins read it as modified
    // on *both* sides — `MM`. Only the worktree half is phantom: the staged
    // change is real and must survive, which is why the repair corrects the
    // status letter rather than dropping the entry.
    let dir = tempfile::tempdir().expect("temp dir");
    // Both file scopes emptied, so the local `clone -c` below is the only place
    // the setting lives and this machine's own config cannot carry the arm.
    let empty = write_global_config(dir.path(), "staged-empty.gitconfig", "");
    let scope_env: Vec<(&str, String)> = vec![
        ("GIT_CONFIG_SYSTEM", empty.clone()),
        ("GIT_CONFIG_GLOBAL", empty.clone()),
    ];

    let origin_path = dir.path().join("origin");
    let origin = TestRepo::init(&origin_path);
    origin.write("src/a.ts", b"export const a = 1;\n");
    origin.write("src/b.ts", b"export const b = 2;\n");
    origin.add_all();
    let head = origin.commit("base");

    let clone_path = dir.path().join("crlf-clone");
    bare_git(
        dir.path(),
        &[],
        &[
            "clone",
            "--quiet",
            "-c",
            "core.autocrlf=true",
            &origin_path.display().to_string(),
            &clone_path.display().to_string(),
        ],
        &scope_env,
    );

    std::fs::write(
        clone_path.join("src/a.ts"),
        b"export const a = 1;\r\nexport const staged = true;\r\n",
    )
    .expect("write");
    bare_git(&clone_path, &[], &["add", "src/a.ts"], &scope_env);

    let git = Git::open(&clone_path).expect("repository");
    let snapshot = serialized(|| DirtySnapshot::incremental(&git, &head, false).expect("snapshot"));

    assert_eq!(
        snapshot.entries.keys().collect::<Vec<_>>(),
        vec!["src/a.ts"],
        "the untouched file must not be dragged in by conversion"
    );
    let entry = &snapshot.entries["src/a.ts"];
    assert_eq!(
        entry.status, "M.",
        "the staged half is real and the worktree half is not"
    );
    assert!(entry.is_staged(), "and the entry still reads as staged");
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

/// Take the environment lock without changing anything.
///
/// For tests that only *read* the environment through a git spawn. That used to
/// be nobody: the pinned path sweeps every `GIT_*` variable, so what the process
/// carried could not reach git. The checkout-conversion spawn deliberately lets
/// `GIT_CONFIG_SYSTEM` and `GIT_CONFIG_GLOBAL` through, so any test whose
/// production call reaches a dirty snapshot is now a reader — and a reader
/// running in parallel with the scope matrix would see that arm's fixture config
/// instead of its own neutral one.
fn serialized<T>(body: impl FnOnce() -> T) -> T {
    with_env(&[], body)
}

/// Run `body` with environment variables set, then restore them.
///
/// Rust 2024 marks `set_var` unsafe because it races with other threads reading
/// the environment. These tests are `#[test]` functions in a binary that runs
/// them in parallel, so the restoration is not enough on its own — a lock keeps
/// the mutating tests off each other, and [`serialized`] keeps the readers off
/// them too.
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
