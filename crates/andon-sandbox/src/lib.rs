//! The code-exec lane's sandbox (PLAN P7, Codex #19).
//!
//! Running a repository's own test command means executing repository-controlled
//! code, and Codex #19 rated shipping that without a boundary a blocker. This
//! crate is the v1 boundary, and this page states exactly what it is — because a
//! sandbox whose documentation claims more than its mechanism is the same
//! defect as a measurement that does.
//!
//! # What this sandbox provides
//!
//! - **A temporary worktree.** The command runs in a throwaway checkout of the
//!   measured snapshot, materialized from git objects ([`Sandbox::enter`]) —
//!   never in the operator's working tree, which it cannot dirty, and never
//!   against bytes other than the ones that were measured.
//! - **A default-deny environment.** The child process receives the base
//!   allowlist ([`BASE_ENV_ALLOW`]), any names `[sandbox] env_allow` adds, and
//!   `ANDON_SANDBOX=1`. Everything else in the invoking environment — tokens,
//!   keys, cloud credentials — never reaches repository code.
//! - **A wall-clock timeout with a process-tree kill.** At
//!   `[sandbox] test_timeout_ms` the whole tree dies: a Windows job object with
//!   kill-on-close, a process group on Unix. The tree is also swept when the
//!   command exits on its own, so a daemon a test spawned does not outlive the
//!   measurement.
//! - **Best-effort resource limits.** `[sandbox] memory_limit_mb` maps to a
//!   job-object memory limit on Windows and an address-space rlimit on Unix.
//!
//! # What this sandbox deliberately does not provide
//!
//! Stated here in the artifact, not only in review notes, per the E45 rule that
//! prose citing a mechanism must not outrun it:
//!
//! - **No network isolation.** The suite can reach anything the invoking user
//!   can. Every tests-family result carries `sandbox: no-net-isolation` in its
//!   `measurement_regime` so the payload says so too (VISION §5's disclosed
//!   limitation).
//! - **No filesystem isolation beyond the working directory.** The suite runs
//!   as the invoking user and can write anywhere that user can. The temp
//!   worktree is where it is *pointed*, not where it is *confined*.
//! - **Not a security boundary against a hostile repository.** The environment
//!   deny-list keeps secrets out of the child's environment; it does not stop
//!   code that reads them from disk. The limits are best-effort. An operator
//!   who does not trust a repository should not declare a `test_command` for
//!   it — the command is policy precisely so that declaring one is a visible,
//!   ledgerable act.
//! - **On Unix, the group kill has a named gap:** a grandchild that calls
//!   `setsid` leaves the process group and survives the sweep. The Windows job
//!   object has no equivalent escape short of breakaway rights, which the
//!   sandbox does not grant.
//!
//! # Where this crate sits
//!
//! [`andon_core::engine::SandboxExec`] is the capability engines consume;
//! [`Sandbox`] implements it. The only shipped consumer is [`TestCommandEngine`],
//! the user test-command occupant — APPROACH names it the only v1 code-exec
//! engine, and the trait boundary (`run_engine`) refuses any `code-exec` engine
//! whose context carries no sandbox.

#![warn(clippy::all)]
#![deny(missing_docs)]

pub mod engine;
mod exec;
mod worktree;

use std::path::Path;

use andon_core::engine::{ExecOutcome, ExecSpec, SandboxExec};
use andon_core::git::Git;

pub use engine::TestCommandEngine;
pub use worktree::OverlayEntry;

/// The isolation class this sandbox provides, spelled exactly as the payload
/// discloses it. One constant, so the regime stamp, the docs, and the tests
/// cannot drift apart.
pub const SANDBOX_ISOLATION: &str = "no-net-isolation";

/// Environment variable names that cross into the sandbox by default.
///
/// The list is the minimum for a child process to start and find its
/// toolchain, per platform. Everything else is denied; `[sandbox] env_allow`
/// is the operator's extension point, and adding to it is a ledgerable policy
/// edit with its own direction (`GrowRelaxes`).
#[cfg(windows)]
pub const BASE_ENV_ALLOW: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "COMSPEC",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "OS",
];
/// Environment variable names that cross into the sandbox by default.
///
/// The list is the minimum for a child process to start and find its
/// toolchain, per platform. Everything else is denied; `[sandbox] env_allow`
/// is the operator's extension point, and adding to it is a ledgerable policy
/// edit with its own direction (`GrowRelaxes`).
#[cfg(not(windows))]
pub const BASE_ENV_ALLOW: &[&str] = &[
    "PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "SHELL", "LANG", "TERM",
];

/// Something the sandbox could not do.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// git refused an operation the worktree needed.
    #[error("sandbox worktree: {0}")]
    Worktree(String),
    /// The command could not be spawned at all.
    #[error("sandbox spawn: {0}")]
    Spawn(String),
}

/// A live sandbox: a materialized temporary worktree, ready to run commands.
///
/// Dropping it cleans up best-effort and says so on stderr when it cannot;
/// [`Sandbox::close`] is the loud path and returns anything a caller should
/// surface.
#[derive(Debug)]
pub struct Sandbox {
    worktree: worktree::TempWorktree,
}

impl Sandbox {
    /// Materialize the measured snapshot into a temporary worktree.
    ///
    /// `anchor_oid` is the commit the snapshot sits on; `overlay` carries the
    /// measured change's entries on top of it — blob OIDs for content, `None`
    /// for deletions — so an uncommitted head is reproduced from the object
    /// database, the same objects the engines read (PREMORTEM T1's blob rule,
    /// applied to execution). For a committed head the overlay is empty and
    /// the worktree is exactly that commit.
    pub fn enter(
        git: &Git,
        anchor_oid: &str,
        overlay: &[OverlayEntry],
    ) -> Result<Self, SandboxError> {
        Ok(Sandbox {
            worktree: worktree::TempWorktree::materialize(git, anchor_oid, overlay)
                .map_err(SandboxError::Worktree)?,
        })
    }

    /// The directory the command runs in.
    pub fn workdir(&self) -> &Path {
        self.worktree.path()
    }

    /// Tear the worktree down, returning notices for anything that did not go
    /// cleanly. An empty vec means nothing of the sandbox remains on disk or in
    /// the repository's worktree registrations.
    pub fn close(self) -> Vec<String> {
        self.worktree.close()
    }
}

impl SandboxExec for Sandbox {
    fn run(&self, spec: &ExecSpec) -> Result<ExecOutcome, String> {
        exec::run(self.workdir(), spec).map_err(|e| e.to_string())
    }
}
