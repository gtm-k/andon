//! The per-branch iteration counter, held in tool state.
//!
//! # What it is for
//!
//! PREMORTEM A4 and S6: an agent handed a finding it cannot resolve will keep
//! trying, and every pass costs tokens and produces a slightly worse change than
//! the one before. The cap is the point at which the tool stops asking and says
//! `escalate_to_human`. The number is a policy field
//! (`loop.iteration_cap`) and never a constant here, because a cap nobody can
//! ledger a change to is a cap that gets worked around in a wrapper script.
//!
//! # Why on disk, and why per branch
//!
//! Per branch, because the loop being counted is "attempts at *this* change" —
//! a counter shared across branches would escalate a fresh piece of work on its
//! first pass because an unrelated branch had a bad afternoon.
//!
//! On disk, because an agent session restarts and the loop does not. A counter
//! in process memory resets every time the harness reconnects, which is both the
//! common case and the one an agent could reach for on purpose. This is *tool
//! state*, not a security boundary: the file is local and writable by whoever
//! runs the tool, so deleting it resets the count. That is acceptable and
//! deliberate — the cap exists to stop honest grinding, and the mechanism that
//! stops dishonest work is the verifier, not this file. What the design does owe
//! is that a reset never happens *silently*: see [`Advance::recovered`].
//!
//! # Concurrency
//!
//! Read-modify-write with an atomic rename, the same shape as
//! [`crate::cache::CacheStore`]. Two measurements racing on one branch can lose
//! an increment — last writer wins. That is the right trade here: the loss is
//! one count on a counter whose purpose is a rough "how many times have we been
//! round this", and the alternative is a lock file in the hot path of a
//! sub-second measurement.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::schema::payload::IterationState;

/// Layout version of the state file. A mismatch is treated as no state at all,
/// visibly — see [`Advance::recovered`].
pub const ITERATION_STATE_VERSION: u32 = 1;

/// File name inside the store root.
pub const ITERATION_STATE_FILE: &str = "iteration-state.json";

/// The counter state could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum IterationError {
    /// A filesystem operation failed.
    #[error("iteration state I/O failed at {path}: {source}")]
    Io {
        /// What was being touched.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The state could not be serialized.
    #[error("iteration state could not be written: {0}")]
    Encode(#[from] serde_json::Error),
}

/// The on-disk shape. `BTreeMap` so the file is byte-stable across runs and a
/// diff of it is readable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StateFile {
    layout_version: u32,
    branches: BTreeMap<String, u32>,
}

/// The outcome of advancing the counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advance {
    /// Where this run sits against the cap, ready for the payload.
    pub state: IterationState,
    /// True when prior state existed but could not be used — unreadable,
    /// unparseable, or written by a different layout version — so the count
    /// restarted from zero.
    ///
    /// Surfaced rather than swallowed. A counter that silently restarts is a cap
    /// that silently stops applying, and the actor who needs to know (whoever
    /// reads the verdict) cannot see this file.
    pub recovered: bool,
}

/// A directory holding the iteration counter.
///
/// The root is the caller's to choose — P5b's CLI puts it under the repository's
/// git directory. Nothing here resolves a path on its own, because a module that
/// picks its own state location is one that writes somewhere surprising in
/// somebody else's repository.
#[derive(Debug, Clone)]
pub struct IterationStore {
    path: PathBuf,
}

impl IterationStore {
    /// Open (or create) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, IterationError> {
        let root: PathBuf = root.into();
        std::fs::create_dir_all(&root).map_err(|source| IterationError::Io {
            path: root.display().to_string(),
            source,
        })?;
        Ok(IterationStore {
            path: root.join(ITERATION_STATE_FILE),
        })
    }

    /// The file this store reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record a pass on `branch` and return where it now sits against `cap`.
    ///
    /// `has_countable_finding` is what makes this a loop counter rather than a
    /// call counter. A measurement that found nothing an agent can act on means
    /// the loop is over, so the count resets: the next unrelated finding on this
    /// branch starts from one rather than inheriting a history that was already
    /// resolved.
    pub fn advance(
        &self,
        branch: &str,
        cap: u32,
        has_countable_finding: bool,
    ) -> Result<Advance, IterationError> {
        let (mut file, recovered) = self.read();

        let count = if has_countable_finding {
            let entry = file.branches.entry(branch.to_string()).or_insert(0);
            // Saturating: a counter that wrapped to zero would hand an agent an
            // unlimited budget at exactly the moment the evidence says it should
            // have stopped long ago.
            *entry = entry.saturating_add(1);
            *entry
        } else {
            file.branches.remove(branch);
            0
        };
        self.write(&file)?;

        Ok(Advance {
            state: state(count, cap),
            recovered,
        })
    }

    /// Where `branch` sits, without advancing it.
    pub fn peek(&self, branch: &str, cap: u32) -> IterationState {
        let (file, _) = self.read();
        state(file.branches.get(branch).copied().unwrap_or(0), cap)
    }

    /// Clear the counter for one branch.
    ///
    /// The exit from `escalate_to_human`. Without it a branch that once passed
    /// the cap escalates for ever, because escalation has no other way out and
    /// the human whose decision it is has no way to record having made it. P5b
    /// wires this to that acknowledgement.
    pub fn reset(&self, branch: &str) -> Result<(), IterationError> {
        let (mut file, _) = self.read();
        file.branches.remove(branch);
        self.write(&file)
    }

    /// Read the state, treating anything unusable as empty.
    ///
    /// Never an error. A corrupt counter must not stop a measurement — the
    /// number it holds is a loop heuristic, not a measurement input — but the
    /// caller is told, via the returned flag, that it restarted.
    fn read(&self) -> (StateFile, bool) {
        let fresh = || StateFile {
            layout_version: ITERATION_STATE_VERSION,
            branches: BTreeMap::new(),
        };
        let Ok(bytes) = std::fs::read(&self.path) else {
            // Absent is the ordinary first run, and not a recovery.
            return (fresh(), false);
        };
        match serde_json::from_slice::<StateFile>(&bytes) {
            Ok(file) if file.layout_version == ITERATION_STATE_VERSION => (file, false),
            // Parsed but from another layout, or did not parse at all. Both are
            // "there was state and we are not using it", which is the thing
            // worth reporting.
            _ => (fresh(), true),
        }
    }

    /// Write atomically: a temporary beside the destination, then a rename.
    fn write(&self, file: &StateFile) -> Result<(), IterationError> {
        let io = |path: &Path, source: std::io::Error| IterationError::Io {
            path: path.display().to_string(),
            source,
        };
        let bytes = serde_json::to_vec_pretty(file)?;
        let temp = self.path.with_extension("json.tmp");

        let mut handle = std::fs::File::create(&temp).map_err(|e| io(&temp, e))?;
        handle.write_all(&bytes).map_err(|e| io(&temp, e))?;
        // Flushed before the rename, so a crash cannot publish a truncated file
        // under the real name.
        handle.sync_all().map_err(|e| io(&temp, e))?;
        drop(handle);

        std::fs::rename(&temp, &self.path).map_err(|e| io(&self.path, e))
    }
}

/// Assemble the payload's view of the counter.
///
/// Escalation is `count > cap`, not `>=`: a cap of three means three passes are
/// allowed and the fourth is the one that has gone too far, which is what
/// `DEFAULT_ITERATION_CAP`'s "past that it is grinding" says.
fn state(count: u32, cap: u32) -> IterationState {
    IterationState {
        count,
        cap,
        escalated: count > cap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DEFAULT_ITERATION_CAP;

    fn store() -> (tempfile::TempDir, IterationStore) {
        let dir = tempfile::tempdir().expect("a temp dir");
        let store = IterationStore::open(dir.path()).expect("opens");
        (dir, store)
    }

    #[test]
    fn a_branch_counts_its_own_passes() {
        let (_dir, store) = store();
        for expected in 1..=3 {
            let advance = store.advance("feat/a", 3, true).unwrap();
            assert_eq!(advance.state.count, expected);
            assert!(!advance.state.escalated);
            assert!(!advance.recovered);
        }
    }

    #[test]
    fn branches_do_not_share_a_counter() {
        let (_dir, store) = store();
        store.advance("feat/a", 3, true).unwrap();
        store.advance("feat/a", 3, true).unwrap();
        let other = store.advance("fix/b", 3, true).unwrap();
        assert_eq!(other.state.count, 1, "a fresh branch starts fresh");
        assert_eq!(store.peek("feat/a", 3).count, 2);
    }

    #[test]
    fn the_pass_after_the_cap_escalates() {
        let (_dir, store) = store();
        let cap = DEFAULT_ITERATION_CAP;
        for _ in 0..cap {
            assert!(!store.advance("feat/a", cap, true).unwrap().state.escalated);
        }
        let over = store.advance("feat/a", cap, true).unwrap();
        assert_eq!(over.state.count, cap + 1);
        assert!(over.state.escalated);
    }

    #[test]
    fn a_run_with_nothing_to_act_on_ends_the_loop() {
        let (_dir, store) = store();
        store.advance("feat/a", 3, true).unwrap();
        store.advance("feat/a", 3, true).unwrap();
        let clean = store.advance("feat/a", 3, false).unwrap();
        assert_eq!(clean.state.count, 0);
        assert!(!clean.state.escalated);
        assert_eq!(
            store.advance("feat/a", 3, true).unwrap().state.count,
            1,
            "the next finding starts a new loop, not the old one"
        );
    }

    #[test]
    fn the_count_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        IterationStore::open(dir.path())
            .unwrap()
            .advance("feat/a", 3, true)
            .unwrap();
        // A different store over the same root: a fresh process, same repository.
        let reopened = IterationStore::open(dir.path()).unwrap();
        assert_eq!(reopened.advance("feat/a", 3, true).unwrap().state.count, 2);
    }

    #[test]
    fn reset_is_the_way_out_of_escalation() {
        let (_dir, store) = store();
        for _ in 0..5 {
            store.advance("feat/a", 3, true).unwrap();
        }
        assert!(store.peek("feat/a", 3).escalated);
        store.reset("feat/a").unwrap();
        assert_eq!(store.peek("feat/a", 3).count, 0);
        assert!(!store.advance("feat/a", 3, true).unwrap().state.escalated);
    }

    #[test]
    fn a_corrupt_state_file_restarts_the_count_and_says_so() {
        let (_dir, store) = store();
        store.advance("feat/a", 3, true).unwrap();
        std::fs::write(store.path(), b"{ this is not json").unwrap();

        let advance = store.advance("feat/a", 3, true).unwrap();
        assert_eq!(advance.state.count, 1);
        assert!(
            advance.recovered,
            "a silent restart is a cap that silently stopped applying"
        );
        // And the store is usable again afterwards.
        assert!(!store.advance("feat/a", 3, true).unwrap().recovered);
    }

    #[test]
    fn a_state_file_from_another_layout_is_not_reinterpreted() {
        let (_dir, store) = store();
        std::fs::write(
            store.path(),
            br#"{"layout_version": 99, "branches": {"feat/a": 40}}"#,
        )
        .unwrap();
        let advance = store.advance("feat/a", 3, true).unwrap();
        assert_eq!(advance.state.count, 1, "not 41");
        assert!(advance.recovered);
    }

    #[test]
    fn a_first_run_is_not_a_recovery() {
        let (_dir, store) = store();
        assert!(!store.advance("feat/a", 3, true).unwrap().recovered);
    }

    #[test]
    fn a_branch_name_with_slashes_is_stored_as_written() {
        // Keys in one file rather than a file per branch: `feat/a/b` needs no
        // escaping and cannot collide with a directory that already exists.
        let (_dir, store) = store();
        store.advance("feat/a/b/c", 3, true).unwrap();
        assert_eq!(store.peek("feat/a/b/c", 3).count, 1);
        assert_eq!(store.peek("feat/a", 3).count, 0);
    }

    #[test]
    fn the_counter_saturates_rather_than_wrapping() {
        let (_dir, store) = store();
        std::fs::write(
            store.path(),
            format!(
                r#"{{"layout_version": {ITERATION_STATE_VERSION}, "branches": {{"feat/a": {}}}}}"#,
                u32::MAX
            ),
        )
        .unwrap();
        let advance = store.advance("feat/a", 3, true).unwrap();
        assert_eq!(advance.state.count, u32::MAX);
        assert!(
            advance.state.escalated,
            "still escalated, never wrapped to 0"
        );
    }
}
