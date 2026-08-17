//! Building a real repository, for tests that need one.
//!
//! Everything goes through [`andon_core::git::Git`], so the repositories these
//! tests build carry the same pinned config the product does — `core.autocrlf`
//! off, a swept environment, no system gitconfig. A test repository built with a
//! bare `Command::new("git")` would inherit the developer's config and pass or
//! fail depending on whose machine it ran on, which is the failure PREMORTEM T1
//! is about.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use andon_core::git::Git;

/// Fixed identity and clock, so a repository built twice is the same repository.
const NAME: &str = "Andon Test";
const EMAIL: &str = "test@andon.invalid";
const EPOCH: i64 = 1_767_225_600;

/// A throwaway repository.
pub struct Repo {
    /// Kept so the directory outlives the handle.
    _dir: tempfile::TempDir,
    /// The git handle.
    pub git: Git,
    /// The working tree.
    pub path: PathBuf,
    commits: i64,
}

impl Repo {
    /// Initialize an empty repository on `main`.
    pub fn init() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let bootstrap =
            Git::open(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("this crate is in a repo");
        bootstrap
            .cmd(["init", "--quiet", "--initial-branch", "main"])
            .arg(dir.path())
            .output()
            .expect("git init");
        let git = Git::open(dir.path()).expect("the new repository opens");
        let path = git.workdir().to_path_buf();
        Repo {
            _dir: dir,
            git,
            path,
            commits: 0,
        }
    }

    /// Write a file, creating parents.
    pub fn write(&self, relative: &str, bytes: &[u8]) {
        let path = self.path.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(path, bytes).expect("write");
    }

    /// Remove a file.
    pub fn remove(&self, relative: &str) {
        std::fs::remove_file(self.path.join(relative)).expect("remove");
    }

    /// Stage everything.
    pub fn add_all(&self) {
        self.git.cmd(["add", "--all", "."]).output().expect("add");
    }

    /// Stage everything and commit, returning the new commit's OID.
    pub fn commit(&mut self, message: &str) -> String {
        self.add_all();
        let stamp = format!("{} +0000", EPOCH + self.commits * 60);
        self.commits += 1;
        self.git
            .cmd(["commit", "--quiet", "--allow-empty", "-m", message])
            .env("GIT_AUTHOR_NAME", NAME)
            .env("GIT_AUTHOR_EMAIL", EMAIL)
            .env("GIT_COMMITTER_NAME", NAME)
            .env("GIT_COMMITTER_EMAIL", EMAIL)
            .env("GIT_AUTHOR_DATE", &stamp)
            .env("GIT_COMMITTER_DATE", &stamp)
            .output()
            .expect("commit");
        self.head()
    }

    /// The current `HEAD` commit.
    pub fn head(&self) -> String {
        self.git
            .cmd(["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"])
            .text()
            .expect("rev-parse")
            .trim()
            .to_string()
    }

    /// Create and check out a branch.
    pub fn branch(&self, name: &str) {
        self.git
            .cmd(["checkout", "--quiet", "-b", name])
            .output()
            .expect("checkout -b");
    }
}
