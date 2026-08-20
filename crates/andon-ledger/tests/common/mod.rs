//! Fixture plumbing shared by the full-machinery tests.
//!
//! The same shape as `andon-ledger-min/tests/concurrency_and_squash.rs`'s
//! helpers, for the same reasons — most importantly, the fixture repositories
//! deliberately carry **no** configured identity, because a CI runner has none
//! and the notes machinery must work there; identity is attached only at the
//! fixture's own commit-writing spawns.

use std::path::{Path, PathBuf};

use andon_core::git::{Git, GitCommand, Revision};
use andon_core::schema::enums::{InvocationSource, RecordKind};
use andon_ledger_min::measure::measure;
use andon_ledger_min::notes::Notes;
use andon_ledger_min::spike;

const WHO: &[(&str, &str)] = &[
    ("GIT_AUTHOR_NAME", "Andon Fixture"),
    ("GIT_AUTHOR_EMAIL", "fixture@andon.invalid"),
    ("GIT_COMMITTER_NAME", "Andon Fixture"),
    ("GIT_COMMITTER_EMAIL", "fixture@andon.invalid"),
];

/// A scratch root under the target dir, cleared per test.
pub fn root(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("clear the fixture root");
    }
    std::fs::create_dir_all(&root).expect("create the fixture root");
    root
}

/// A git handle for spawning outside any fixture repository.
pub fn bootstrap() -> Git {
    Git::open(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("the crate lives in a repository")
}

/// Attach a committer identity to a fixture's own commit-writing spawn.
pub fn identified(mut cmd: GitCommand) -> GitCommand {
    for (key, value) in WHO {
        cmd = cmd.env(key, value);
    }
    cmd
}

pub fn commit(git: &Git, message: &str) {
    identified(git.cmd(["commit", "--quiet", "--allow-empty", "-m", message]))
        .output()
        .unwrap_or_else(|e| panic!("commit {message}: {e}"));
}

pub fn write_and_commit(git: &Git, path: &str, text: &str, message: &str) -> String {
    let full = git.workdir().join(path);
    std::fs::create_dir_all(full.parent().expect("a parent")).expect("mkdir");
    std::fs::write(&full, text).expect("write");
    git.cmd(["add", "--all", "."]).output().expect("add");
    commit(git, message);
    head(git)
}

pub fn head(git: &Git) -> String {
    git.cmd(["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"])
        .text()
        .expect("rev-parse HEAD")
        .trim()
        .to_string()
}

/// Create a bare central repository at `path`.
pub fn bare_origin(path: &Path) {
    bootstrap()
        .cmd(["init", "--quiet", "--bare", "--initial-branch", "main"])
        .arg(path)
        .output()
        .expect("create the central repository");
}

pub fn clone_from(origin: &Path, dest: &Path, extra: &[&str]) -> Git {
    if dest.exists() {
        std::fs::remove_dir_all(dest).expect("clear clone dir");
    }
    bootstrap()
        .cmd(["clone", "--quiet"])
        .args(extra)
        .arg(origin)
        .arg(dest)
        .output()
        .unwrap_or_else(|e| panic!("clone into {}: {e}", dest.display()));
    Git::open(dest).expect("the clone is a repository")
}

/// Measure a branch head and write the self-report, as an agent would.
pub fn self_report(git: &Git, head_oid: &str) {
    let (record, _) = measure(
        git,
        &Revision::merge_base("origin/main"),
        &Revision::Rev(head_oid.to_string()),
        RecordKind::SelfReport,
        InvocationSource::Hook,
        &spike::engine_version(),
    )
    .expect("measure");
    Notes::measure(git)
        .append(head_oid, &record)
        .expect("write the self-report");
}

/// Install a pre-receive hook in a bare repository.
///
/// The hook is the honest way to make a remote refuse: a real `git push`, a
/// real rejection, git's own "pre-receive hook declined" — not a mock of the
/// transport. Runs relative to the bare repository's own directory, so the
/// reject-once variant can keep its state file there.
pub fn install_pre_receive(bare: &Path, script: &str) {
    let hook = bare.join("hooks").join("pre-receive");
    std::fs::create_dir_all(hook.parent().expect("hooks dir")).expect("mkdir hooks");
    std::fs::write(&hook, script).expect("write the hook");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))
            .expect("mark the hook executable");
    }
}
