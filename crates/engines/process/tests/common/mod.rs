//! Real git repositories for the process-engine tests.
//!
//! Every command goes through [`Git::cmd`], so fixtures are built by the same
//! hygienic spawn path the code under test uses — a fixture built with the
//! ambient environment would inherit the developer's `core.autocrlf` and the
//! tests would be proving something about a repository that config had already
//! reached.
//!
//! Unlike `andon-core`'s equivalent, the author and the timestamp are per-commit
//! arguments. This engine measures *who* changed a file and *when*, so a helper
//! that fixed both would leave every ownership and age assertion vacuous.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use andon_core::git::Git;

/// 2025-01-01T00:00:00Z. Every fixture timestamp is an offset from here, and it
/// is far enough in the past that a wall-clock window would exclude the whole
/// history — which is what makes
/// `history_semantics::the_window_is_anchored_to_the_commit_and_not_to_the_clock`
/// a real test rather than a coincidence.
pub const EPOCH_2025: i64 = 1_735_689_600;

/// Seconds in a day.
pub const DAY: i64 = 86_400;

/// A repository on disk, with a handle onto it.
pub struct TestRepo {
    path: PathBuf,
    git: Git,
}

impl TestRepo {
    /// Create an empty repository under the system temp directory.
    ///
    /// The name is caller-supplied and the process id is appended, so two tests
    /// running in parallel — which cargo does by default — never share a tree.
    pub fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "andon-p4-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("fixture directory");

        // `Git::open` needs a repository, so the first invocation comes from a
        // handle onto this workspace and only ever uses `cmd`.
        let bootstrap = Git::open(Path::new(".")).expect("the workspace is a git repository");
        bootstrap
            .cmd(["init", "--quiet", "--initial-branch=main"])
            .arg(&path)
            .output()
            .expect("git init");

        let git = Git::open(&path).expect("the fixture is a git repository");
        git.cmd(["config", "user.name", "Fixture"])
            .output()
            .expect("config user.name");
        git.cmd(["config", "user.email", "fixture@andon.invalid"])
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

    /// Write a file, creating parent directories. Bytes go down exactly as given.
    pub fn write(&self, rel: &str, bytes: &[u8]) {
        let full = self.path.join(rel);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("parent directory");
        }
        std::fs::write(&full, bytes).expect("write fixture file");
    }

    /// Stage everything and commit as `author` at `EPOCH_2025 + day × DAY`.
    ///
    /// Both the author and the committer identity are set, and both dates: git
    /// filters on the committer date and this engine attributes to the author,
    /// so a fixture that set only one would test half of what it looks like.
    pub fn commit_as(&self, author: &str, day: i64, message: &str) -> String {
        let when = format!("{} +0000", EPOCH_2025 + day * DAY);
        let email = format!("{author}@andon.invalid");
        self.git
            .cmd(["add", "--all", "."])
            .output()
            .expect("git add");
        self.git
            .cmd(["commit", "--quiet", "--allow-empty", "-m", message])
            .env("GIT_AUTHOR_NAME", author)
            .env("GIT_AUTHOR_EMAIL", &email)
            .env("GIT_AUTHOR_DATE", &when)
            .env("GIT_COMMITTER_NAME", author)
            .env("GIT_COMMITTER_EMAIL", &email)
            .env("GIT_COMMITTER_DATE", &when)
            .output()
            .expect("git commit");
        self.rev_parse("HEAD")
    }

    /// Write one file and commit it.
    pub fn commit_file(&self, rel: &str, bytes: &[u8], author: &str, day: i64) -> String {
        self.write(rel, bytes);
        self.commit_as(author, day, rel)
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

    /// A `file://` URL for this repository, which is what `git clone --depth`
    /// needs: git refuses to make a shallow clone over the local transport and
    /// says so rather than silently producing a complete one.
    pub fn file_url(&self) -> String {
        let text = self.path.display().to_string().replace('\\', "/");
        if text.starts_with('/') {
            format!("file://{text}")
        } else {
            format!("file:///{text}")
        }
    }
}
