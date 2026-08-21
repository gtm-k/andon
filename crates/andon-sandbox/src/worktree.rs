//! The temporary worktree: the measured snapshot, on disk, disposable.
//!
//! # Why `git worktree add` and not an archive extraction
//!
//! A test suite is repository code, and repository code asks git questions —
//! `cargo` reads `.git` for build metadata, suites shell out for a version
//! string. An extracted tarball has no `.git` and those suites fail for a
//! reason that has nothing to do with the change under measurement. A linked
//! worktree gives the suite a real repository view, at the cost of a
//! registration in the parent repository's `.git/worktrees` — which
//! [`TempWorktree::close`] removes and a startup `git worktree prune` clears
//! when a crash leaves one behind.
//!
//! # Why the overlay reads blobs and not the operator's tree
//!
//! An uncommitted head's bytes were measured from git objects
//! (`measure::read_without_staging` writes them), and the suite must run
//! against those same bytes: the operator's tree can have moved since the
//! measurement, and a verdict stitched from one snapshot's numbers and another
//! snapshot's test run would be about no change at all. The overlay entries
//! carry the changed set's blob OIDs — content the object database already
//! holds — and deletions carry `None`.
//!
//! # What a crash leaves behind
//!
//! A process killed between `materialize` and `close` leaves the directory
//! under the system temp dir and a stale registration. The registration is
//! cleared by the `git worktree prune` the next `materialize` runs; the
//! directory waits for the OS's temp cleanup. Disclosed here rather than
//! solved, because the alternative — a cross-process registry of directories
//! to delete — is a mechanism this phase does not need.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use andon_core::git::{BlobBatch, Git};

/// One changed path to lay over the anchor commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayEntry {
    /// Repository-relative path, forward slashes, as git spells it.
    pub path: String,
    /// The blob to write there, or `None` when the change deletes the path.
    pub blob_oid: Option<String>,
    /// Whether the file mode carries the executable bit (`100755`).
    pub executable: bool,
}

/// Distinguishes two sandboxes materialized in one process.
static NONCE: AtomicU64 = AtomicU64::new(0);

/// A registered, materialized, self-cleaning worktree.
#[derive(Debug)]
pub struct TempWorktree {
    /// The parent repository, re-opened here so cleanup does not borrow the
    /// caller's handle.
    repo_workdir: PathBuf,
    path: PathBuf,
    closed: bool,
}

impl TempWorktree {
    /// Register and populate the worktree.
    pub fn materialize(
        git: &Git,
        anchor_oid: &str,
        overlay: &[OverlayEntry],
    ) -> Result<Self, String> {
        // Clear registrations whose directories a crashed run left dangling.
        // Quiet on success and non-fatal on failure: pruning is hygiene for
        // *previous* runs, and this run's worktree does not depend on it.
        let _ = git.cmd(["worktree", "prune"]).output();

        let dir = std::env::temp_dir().join(format!(
            "andon-sandbox-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        let dir_str = dir
            .to_str()
            .ok_or_else(|| format!("temp dir {} is not valid UTF-8", dir.display()))?
            .to_string();

        git.cmd(["worktree", "add", "--detach", "--quiet"])
            .args([dir_str.as_str(), anchor_oid])
            .output()
            .map_err(|e| format!("worktree add at {dir_str}: {e}"))?;

        let worktree = TempWorktree {
            repo_workdir: git.workdir().to_path_buf(),
            path: dir,
            closed: false,
        };

        // The overlay: the measured change, from the object database. Any
        // failure tears the half-built worktree down before reporting — a
        // sandbox that runs the anchor commit while claiming to run the
        // snapshot would test the wrong bytes and say nothing.
        if let Err(e) = worktree.apply_overlay(git, overlay) {
            let notices = worktree.close();
            let suffix = if notices.is_empty() {
                String::new()
            } else {
                format!(" (and cleanup said: {})", notices.join("; "))
            };
            return Err(format!("{e}{suffix}"));
        }
        Ok(worktree)
    }

    fn apply_overlay(&self, git: &Git, overlay: &[OverlayEntry]) -> Result<(), String> {
        if overlay.is_empty() {
            return Ok(());
        }
        let mut batch = BlobBatch::open(git).map_err(|e| e.to_string())?;
        for entry in overlay {
            let target = self.path.join(&entry.path);
            match &entry.blob_oid {
                Some(oid) => {
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| format!("{}: {e}", parent.display()))?;
                    }
                    let content = batch
                        .read(oid)
                        .map_err(|e| format!("{}: blob {oid}: {e}", entry.path))?;
                    std::fs::write(&target, content.into_bytes())
                        .map_err(|e| format!("{}: {e}", target.display()))?;
                    #[cfg(unix)]
                    if entry.executable {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
                            .map_err(|e| format!("{}: {e}", target.display()))?;
                    }
                }
                None => match std::fs::remove_file(&target) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(format!("{}: {e}", target.display())),
                },
            }
        }
        Ok(())
    }

    /// Where the worktree lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the worktree and its registration, loudly on failure.
    pub fn close(mut self) -> Vec<String> {
        self.closed = true;
        self.remove()
    }

    /// The removal itself, shared by [`Self::close`] and the drop backstop.
    ///
    /// `worktree remove --force`, retried, because on Windows a just-killed
    /// process can hold the directory for a beat after its handle dies. The
    /// manual fallback covers a removal git refuses for its own reasons; the
    /// prune afterwards clears the registration the fallback orphans.
    fn remove(&mut self) -> Vec<String> {
        let mut notices = Vec::new();
        let git = match Git::open(&self.repo_workdir) {
            Ok(git) => git,
            Err(e) => {
                notices.push(format!(
                    "the sandbox worktree at {} was NOT removed: the parent repository would \
                     not open ({e}). Remove the directory by hand.",
                    self.path.display()
                ));
                return notices;
            }
        };
        let path_str = self.path.to_string_lossy().to_string();
        for attempt in 0..3 {
            if git
                .cmd(["worktree", "remove", "--force"])
                .arg(&path_str)
                .output()
                .is_ok()
            {
                return notices;
            }
            if attempt < 2 {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        // git would not remove it; take the directory down directly and let
        // prune collect the registration.
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => {
                let _ = git.cmd(["worktree", "prune"]).output();
                notices.push(format!(
                    "the sandbox worktree at {} needed a manual removal after `git worktree \
                     remove` refused three times; its registration was pruned.",
                    self.path.display()
                ));
            }
            Err(e) => notices.push(format!(
                "the sandbox worktree at {} was NOT removed: `git worktree remove` refused and \
                 deleting the directory failed ({e}). Remove it by hand; `git worktree prune` \
                 clears the registration.",
                self.path.display()
            )),
        }
        notices
    }
}

impl Drop for TempWorktree {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        // The backstop, not the path: `close` returns notices a caller can
        // surface, and a drop cannot. Anything it has to say goes to stderr,
        // because a silent failure to clean up is a directory the operator
        // finds weeks later with no explanation.
        for notice in self.remove() {
            eprintln!("andon-sandbox: {notice}");
        }
    }
}
