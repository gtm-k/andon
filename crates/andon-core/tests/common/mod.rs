//! Building real git repositories for the git tests.
//!
//! Everything here goes through [`Git::cmd`], so the fixtures are built by the
//! same hygienic spawn path the code under test uses. That matters for more than
//! tidiness: a fixture built with the ambient environment would inherit whatever
//! `core.autocrlf` the developer's machine carries, and the tests that exist to
//! prove config cannot reach us would be quietly proving it about a repository
//! that config had already reached.
//!
//! Author and committer identity, and both dates, are fixed, so every commit OID
//! is reproducible on every machine.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use andon_core::git::Git;

/// Fixed identity for every fixture commit.
pub const FIXTURE_NAME: &str = "Andon Fixture";
/// Fixed email for every fixture commit.
pub const FIXTURE_EMAIL: &str = "fixture@andon.invalid";
/// Fixed timestamp: 2026-01-01T00:00:00Z, in git's `<epoch> <offset>` form.
pub const FIXTURE_DATE: &str = "1767225600 +0000";

/// A repository on disk, with a handle onto it.
pub struct TestRepo {
    path: PathBuf,
    git: Git,
}

impl TestRepo {
    /// Create an empty repository at `path` with `main` as its initial branch.
    pub fn init(path: &Path) -> Self {
        std::fs::create_dir_all(path).expect("fixture directory");
        // `Git::open` needs a repository, so the first invocation cannot come
        // from a handle. A bare `Git` on the parent path would not resolve
        // either, so `git init` is run through a temporary handle that only
        // needs `cmd` and never `open`.
        let bootstrap = Git::open(Path::new(".")).expect("the workspace is a git repository");
        bootstrap
            .cmd(["init", "--quiet", "--initial-branch=main"])
            .arg(path)
            .output()
            .expect("git init");

        let git = Git::open(path).expect("the fixture is a git repository");
        // Identity in repository config so that operations which do not go
        // through `commit` — `rebase`, `cherry-pick` — also produce fixed OIDs.
        git.cmd(["config", "user.name", FIXTURE_NAME])
            .output()
            .expect("config user.name");
        git.cmd(["config", "user.email", FIXTURE_EMAIL])
            .output()
            .expect("config user.email");

        TestRepo {
            path: git.workdir().to_path_buf(),
            git,
        }
    }

    /// The handle.
    pub fn git(&self) -> &Git {
        &self.git
    }

    /// The working tree root.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write a file, creating parent directories. Bytes go down exactly as
    /// given — no newline translation, so a test can put CRLF on disk and mean it.
    pub fn write(&self, rel: &str, bytes: &[u8]) {
        let full = self.path.join(rel);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("parent directory");
        }
        std::fs::write(&full, bytes).expect("write fixture file");
    }

    /// Delete a working-tree file.
    pub fn remove(&self, rel: &str) {
        std::fs::remove_file(self.path.join(rel)).expect("remove fixture file");
    }

    /// Stage everything, including deletions.
    pub fn add_all(&self) {
        self.git
            .cmd(["add", "--all", "."])
            .output()
            .expect("git add");
    }

    /// Stage specific paths.
    pub fn add(&self, paths: &[&str]) {
        self.git
            .cmd(["add", "--"])
            .args(paths)
            .output()
            .expect("git add paths");
    }

    /// Commit whatever is staged, at the fixed timestamp. Returns the new OID.
    pub fn commit(&self, message: &str) -> String {
        self.git
            .cmd(["commit", "--quiet", "--allow-empty", "-m", message])
            .env("GIT_AUTHOR_NAME", FIXTURE_NAME)
            .env("GIT_AUTHOR_EMAIL", FIXTURE_EMAIL)
            .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
            .env("GIT_COMMITTER_NAME", FIXTURE_NAME)
            .env("GIT_COMMITTER_EMAIL", FIXTURE_EMAIL)
            .env("GIT_COMMITTER_DATE", FIXTURE_DATE)
            .output()
            .expect("git commit");
        self.rev_parse("HEAD")
    }

    /// Write, stage, and commit in one step.
    pub fn commit_file(&self, rel: &str, bytes: &[u8], message: &str) -> String {
        self.write(rel, bytes);
        self.add_all();
        self.commit(message)
    }

    /// Resolve a revision to a full OID.
    pub fn rev_parse(&self, rev: &str) -> String {
        self.git
            .cmd(["rev-parse", rev])
            .text()
            .expect("git rev-parse")
            .trim()
            .to_string()
    }

    /// Run a git command, panicking on failure. For fixture setup only.
    pub fn run(&self, args: &[&str]) -> String {
        self.git
            .cmd(args)
            .env("GIT_AUTHOR_NAME", FIXTURE_NAME)
            .env("GIT_AUTHOR_EMAIL", FIXTURE_EMAIL)
            .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
            .env("GIT_COMMITTER_NAME", FIXTURE_NAME)
            .env("GIT_COMMITTER_EMAIL", FIXTURE_EMAIL)
            .env("GIT_COMMITTER_DATE", FIXTURE_DATE)
            .text()
            .unwrap_or_else(|err| panic!("git {args:?} failed: {err}"))
    }

    /// Run a git command and report whether it succeeded, without panicking.
    pub fn try_run(&self, args: &[&str]) -> bool {
        self.git
            .cmd(args)
            .env("GIT_AUTHOR_NAME", FIXTURE_NAME)
            .env("GIT_AUTHOR_EMAIL", FIXTURE_EMAIL)
            .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
            .env("GIT_COMMITTER_NAME", FIXTURE_NAME)
            .env("GIT_COMMITTER_EMAIL", FIXTURE_EMAIL)
            .env("GIT_COMMITTER_DATE", FIXTURE_DATE)
            .succeeds()
            .expect("git ran")
    }
}
