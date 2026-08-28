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
//! stops dishonest work is the verifier, not this file.
//!
//! # Which resets are visible, stated exactly
//!
//! An earlier version of this paragraph said a reset "never happens silently",
//! and that was wider than the mechanism. Precisely:
//!
//! | Reset | Visible? | How |
//! |---|---|---|
//! | state present but unusable — corrupt, or another layout version | yes | [`Advance::recovered`], surfaced as a verdict reason |
//! | the run found nothing to act on over a complete measurement | yes | it is the ordinary end of a loop, and the verdict says `pass` |
//! | the state file was deleted | **no** | absent state is indistinguishable from a first run, here and by construction |
//!
//! The third row is the honest gap, and it is bounded rather than closed: a
//! deleted counter is a local file a local actor removed, and nothing in this
//! module can tell that from a first pass without a durable record kept
//! somewhere the actor does not control. That record is the ledger, and it is
//! P8's. What this module does close is the neighbouring hole that did *not*
//! need durable state — a measurement resetting the count because it could not
//! see, rather than because there was nothing to see. See [`LoopOutcome`].
//!
//! # Concurrency
//!
//! An earlier version of this paragraph argued for an unlocked
//! read-modify-write: two measurements racing on one branch could lose an
//! increment, last writer wins, and losing one count on a rough counter was
//! worth more than a lock file in a sub-second path.
//!
//! The direction of the error was assumed and it was wrong. Twenty-four
//! measurements of **one unchanged snapshot** run at once produced three
//! correct verdicts and twenty-one premature `escalate_to_human` — the signal
//! reserved for "an agent has tried enough times, stop trying" — plus one run
//! that failed outright when two writers picked the same temporary filename and
//! the second `rename` found nothing there. A lost increment would have been
//! harmless. What actually happened was the cap firing on a change nobody had
//! attempted twice, and a hook keyed on exit 3 stopping a line for it.
//!
//! The dedupe that already existed made this worse rather than better: it asked
//! the *last written record* whether the change had been seen, and under
//! concurrency none of the racers had written one yet, so every one of them
//! believed it was first.
//!
//! So change identity is part of the transaction. [`IterationStore::advance`]
//! takes the change it is counting, and inside a lock it advances only when
//! that change differs from the one the branch last counted. Everything the
//! decision needs is read and written under the same lock, which is the only
//! arrangement in which "have we counted this already" can be answered
//! correctly by two processes at once.
//!
//! The lock waits rather than failing — a contended counter is the ordinary
//! case P6's gate-shaped hooks deliberately create, and 24 waiters at a
//! sub-millisecond critical section cost nothing. If the wait is exhausted, the
//! measurement still happens: this is a loop heuristic and not a measurement
//! input, so the run reads the counter without advancing it and says that it
//! did ([`Advance::contended`]). A measurement lost to a busy counter would be
//! the tail wagging the dog.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::schema::payload::IterationState;

/// Layout version of the state file. A mismatch is treated as no state at all,
/// visibly — see [`Advance::recovered`].
///
/// 2 because a branch now records the change its count is about, not just the
/// count. A version 1 file read by this build restarts the counter and says so,
/// which is the documented behaviour for a layout it cannot use.
pub const ITERATION_STATE_VERSION: u32 = 2;

/// File name inside the store root.
pub const ITERATION_STATE_FILE: &str = "iteration-state.json";

/// How long to wait for another writer to finish before giving up on advancing.
///
/// Generous against a critical section that is one small read and one small
/// write: 24 concurrent measurements serialize through it in well under a
/// millisecond each. It is a bound rather than an expectation.
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// How long a lock file must sit untouched before it is treated as abandoned.
///
/// A modification time and not a PID, for the reason the clone index gives for
/// the same choice: a PID from a crashed process can belong to a live one by
/// the time anybody looks.
const LOCK_STALE: Duration = Duration::from_secs(60);

/// Distinguishes two writers inside one process, which the process id does not.
///
/// The tests run measurements on threads, and a fixed temporary name is what
/// made 24 concurrent runs produce a hard I/O failure: both writers opened the
/// same path, the first renamed it away, and the second's rename found nothing
/// there.
static WRITER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    branches: BTreeMap<String, BranchState>,
}

/// What one branch's counter knows.
///
/// The change is stored beside the count because the two are one fact: a count
/// of attempts is meaningless without saying attempts *at what*. Keeping the
/// pair in the file is what lets two processes agree on whether a change has
/// already been counted — which the previous arrangement could not do, because
/// it asked a separate file that neither of them had written yet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BranchState {
    /// Passes counted at [`Self::change`].
    count: u32,
    /// The change the count is about. `None` for a branch counted by an older
    /// build of this layout, which is treated as "not this change".
    #[serde(default)]
    change: Option<String>,
}

/// What a measurement said about the loop it is part of.
///
/// The counter needs three answers, not two, and the missing third is a way for
/// a change to reset its own budget. `advance` used to take a boolean: something
/// to act on, or nothing. "Nothing" reset the count — correctly, when the loop
/// really did end — but a measurement that found nothing *because it could not
/// see* answers "nothing" in exactly the same words. Break the engine that keeps
/// finding the problem, or delete the coverage report it reads, and the run is
/// clean, the count resets, and the cap starts again from one.
///
/// So the third answer is [`LoopOutcome::Inconclusive`], and the count holds
/// rather than resetting. Holding is the conservative direction: the worst case
/// is an agent reaching `escalate_to_human` one pass earlier than it strictly
/// had to, which asks a human to look at a measurement that could not complete —
/// which is the right thing to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopOutcome {
    /// Something the agent can act on. The count advances.
    Countable,
    /// Nothing to act on, over a measurement that saw everything it set out to.
    /// The loop is over and the count resets.
    Finished,
    /// Nothing to act on, over a measurement that did not see everything. The
    /// count holds: this run is not evidence that the loop ended.
    Inconclusive,
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
    /// True when the lock could not be taken inside `LOCK_WAIT`, so the
    /// counter was read and not advanced.
    ///
    /// The measurement is unaffected — the counter is a loop heuristic and not
    /// a measurement input — but a pass that did not count is a pass the cap
    /// will not see, and an actor can only act on what they can observe.
    pub contended: bool,
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

    /// Record a pass on `branch` at `change`, and return where it now sits
    /// against `cap`.
    ///
    /// [`LoopOutcome`] is what makes this a loop counter rather than a call
    /// counter, and what stops a blinded measurement from clearing the budget —
    /// see the enum.
    ///
    /// # Why `change` is a parameter and not the caller's business
    ///
    /// What makes an attempt is a change to what is being measured, not a call
    /// to the tool, so re-reading one unchanged snapshot must count once however
    /// many times it is read. The caller used to decide that by comparing
    /// against the last record it had written, and under concurrency that is
    /// unanswerable: none of the racers has written one yet, so all of them
    /// believe they are first, and twenty-four readings of one snapshot escalate
    /// a human twenty-one times.
    ///
    /// The question is only answerable where the answer is stored. So the change
    /// arrives here and the comparison happens under the lock, beside the write
    /// it guards.
    pub fn advance(
        &self,
        branch: &str,
        cap: u32,
        outcome: LoopOutcome,
        change: &str,
    ) -> Result<Advance, IterationError> {
        let Some(_lock) = StateLock::acquire(&self.path)? else {
            // Waited out. Read the counter and say the pass was not counted,
            // rather than losing a measurement to a busy file.
            let (file, recovered) = self.read();
            return Ok(Advance {
                state: state(file.count(branch), cap),
                recovered,
                contended: true,
            });
        };
        let (mut file, recovered) = self.read();

        let count = match outcome {
            LoopOutcome::Countable => {
                let entry = file.branches.entry(branch.to_string()).or_default();
                if entry.change.as_deref() == Some(change) {
                    // Already counted. This is another reading of the same
                    // change, and reading is not attempting.
                    entry.count
                } else {
                    // Saturating: a counter that wrapped to zero would hand an
                    // agent an unlimited budget at exactly the moment the
                    // evidence says it should have stopped long ago.
                    entry.count = entry.count.saturating_add(1);
                    entry.change = Some(change.to_string());
                    entry.count
                }
            }
            LoopOutcome::Finished => {
                file.branches.remove(branch);
                0
            }
            // Held, not advanced and not cleared: this run says nothing about
            // whether the loop ended.
            LoopOutcome::Inconclusive => file.count(branch),
        };
        self.write(&file)?;

        Ok(Advance {
            state: state(count, cap),
            recovered,
            contended: false,
        })
    }

    /// Where `branch` sits, without advancing it.
    pub fn peek(&self, branch: &str, cap: u32) -> IterationState {
        let (file, _) = self.read();
        state(file.count(branch), cap)
    }

    /// Clear the counter for one branch.
    ///
    /// The exit from `escalate_to_human`. Without it a branch that once passed
    /// the cap escalates for ever, because escalation has no other way out and
    /// the human whose decision it is has no way to record having made it. P5b
    /// wires this to that acknowledgement.
    pub fn reset(&self, branch: &str) -> Result<(), IterationError> {
        // Under the same lock as `advance`, because it is the same
        // read-modify-write. An acknowledgement that lost its race with a
        // measurement would leave the branch escalating, which is the state the
        // human just said they had dealt with. A lock this cannot take is worth
        // failing on: unlike a measurement, the whole of this operation *is* the
        // counter write, so proceeding without the lock would be doing the one
        // thing unsafely rather than doing something else safely.
        let _lock = StateLock::acquire(&self.path)?.ok_or_else(|| IterationError::Io {
            path: self.path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "another measurement held the loop counter for longer than the wait; the \
                 acknowledgement was not recorded, so re-run `andon ledger ack`",
            ),
        })?;
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
    ///
    /// The temporary carries the writer's identity, the way the clone index's
    /// and the last-record store's do. A fixed name made two concurrent writers
    /// destructive rather than merely racy — both open the same path, the first
    /// renames it away, and the second's rename fails with "the system cannot
    /// find the file specified", which is a measurement lost to a temporary
    /// file. The process id is not enough on its own: this crate's own tests run
    /// measurements on threads.
    fn write(&self, file: &StateFile) -> Result<(), IterationError> {
        let io = |path: &Path, source: std::io::Error| IterationError::Io {
            path: path.display().to_string(),
            source,
        };
        let bytes = serde_json::to_vec_pretty(file)?;
        let temp = self.path.with_extension(format!(
            "json.tmp-{}-{}",
            std::process::id(),
            WRITER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));

        let mut handle = std::fs::File::create(&temp).map_err(|e| io(&temp, e))?;
        handle.write_all(&bytes).map_err(|e| io(&temp, e))?;
        // Flushed before the rename, so a crash cannot publish a truncated file
        // under the real name.
        handle.sync_all().map_err(|e| io(&temp, e))?;
        drop(handle);

        std::fs::rename(&temp, &self.path).map_err(|e| io(&self.path, e))
    }
}

impl StateFile {
    /// The count for `branch`, zero when it has none.
    fn count(&self, branch: &str) -> u32 {
        self.branches.get(branch).map_or(0, |state| state.count)
    }
}

/// Exclusive access to one counter file, for the length of a read-modify-write.
///
/// The shape the clone index already uses — `create_new` as the primitive,
/// modification time as the staleness test — with one difference that matters
/// here: this one **waits**. A busy clone index means a cache is contended and
/// the caller can do without it; a busy counter means another measurement of the
/// same repository is deciding the same thing, and the right answer is to let it
/// finish and then read what it decided.
#[derive(Debug)]
struct StateLock {
    path: PathBuf,
}

impl StateLock {
    /// Take the lock, waiting up to [`LOCK_WAIT`]. `Ok(None)` means the wait ran
    /// out, which is the caller's cue to read without advancing.
    fn acquire(state_path: &Path) -> Result<Option<StateLock>, IterationError> {
        let path = state_path.with_extension("json.lock");
        let io = |source: std::io::Error| IterationError::Io {
            path: path.display().to_string(),
            source,
        };
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        // Kept so the deadline can report *why* it never got the lock, rather
        // than inventing a reason.
        let mut last;
        loop {
            match create_lock(&path) {
                Ok(()) => return Ok(Some(StateLock { path })),
                // ACCESS DENIED IS A CONTENTION SIGNAL ON WINDOWS.
                //
                // `CreateFile` with `CREATE_NEW` answers `ERROR_ACCESS_DENIED`
                // rather than `ERROR_FILE_EXISTS` while a delete is pending on
                // the name — which is exactly the window between one holder's
                // `remove_file` and the close of a transient handle another
                // waiter opened for the staleness check. Treating it as fatal
                // failed roughly half the runs of this module's own concurrency
                // test with "Access is denied", which is contention wearing a
                // permissions error's clothes.
                //
                // The two are indistinguishable by error code, so both wait. A
                // directory that really is unwritable is still reported, at the
                // deadline, by the check below: it says whether anybody is
                // actually holding the lock.
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    last = err;
                }
                Err(err) => return Err(io(err)),
            }
            // Abandoned by a process that died holding it. Stealing is safe in
            // the direction that matters: the worst case is the same lost
            // increment the unlocked version had, a minute after anything was
            // still running.
            let stale = std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .map(|modified| {
                    SystemTime::now()
                        .duration_since(modified)
                        .map(|age| age > LOCK_STALE)
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if stale {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            if std::time::Instant::now() >= deadline {
                // Waited out. If the lock file is there, somebody holds it and
                // the honest answer is "not counted this time". If it is not,
                // then every attempt failed for a reason that has nothing to do
                // with contention — an unwritable directory — and reporting that
                // as a busy counter would hide it for ever.
                if path.exists() {
                    return Ok(None);
                }
                return Err(io(last));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn create_lock(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    // For a human reading a wedged repository. Never parsed.
    writeln!(file, "pid={}", std::process::id())
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // Best effort: a failure here leaves a lock the staleness timeout
        // clears. Panicking in a destructor would be worse.
        let _ = std::fs::remove_file(&self.path);
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

    #[test]
    fn the_write_is_atomic_and_leaves_nothing_behind() {
        // The rename is what makes a crash mid-write leave the old counter
        // rather than half a new one, and nothing exercised it. What is
        // checkable without crashing a process is the shape the argument rests
        // on: the temporary is gone when the write returns, the destination
        // parses, and a stale temporary left by an earlier crash is overwritten
        // rather than read.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = IterationStore::open(dir.path()).expect("opens");

        // A stale temporary from a crash that never got as far as the rename.
        // Under a writer-unique name, because that is what a crashed writer
        // leaves now — the fixed name it used to leave was itself the defect:
        // two live writers shared it, the first renamed it away, and the
        // second's rename failed with "the system cannot find the file
        // specified", losing a whole measurement to a temporary file.
        let stale = store.path().with_extension("json.tmp-999999-0");
        std::fs::write(&stale, b"{ this is not json").expect("plant a stale temporary");

        store
            .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
            .expect("advances");

        // This writer's own temporary is gone: it was renamed onto the
        // destination, which is what makes a crash mid-write leave the old
        // counter rather than half a new one.
        let mine = format!("iteration-state.json.tmp-{}-", std::process::id());
        let left: Vec<String> = std::fs::read_dir(dir.path())
            .expect("the store directory reads")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(&mine))
            .collect();
        assert!(left.is_empty(), "a temporary outlived the write: {left:?}");
        let bytes = std::fs::read(store.path()).expect("the destination exists");
        let parsed: StateFile = serde_json::from_slice(&bytes).expect("and it parses");
        assert_eq!(parsed.layout_version, ITERATION_STATE_VERSION);
        assert_eq!(parsed.branches.get("feat/a").map(|b| b.count), Some(1));

        // And the count survived the stale temporary, which is the point: a
        // half-written file under any temporary name is not state, and is never
        // read as state.
        assert_eq!(store.peek("feat/a", 3).count, 1);
    }

    // `the_test_failure_knob_is_declared_and_unread` lived here for six
    // phases, pinning the claim that `severity.block_on_test_failure` gated
    // nothing. P7 built the reader — `severity::stops_the_line`'s suite-flag
    // route — so the pin was retired exactly as its own comment planned:
    // "the day something does read it, the claim above fails rather than
    // quietly becoming false." The reader's own tests live beside the rule
    // in `severity::tests`.

    /// A change nothing else in this file uses.
    ///
    /// The counter counts attempts at a change, so a test that means "another
    /// pass" has to hand it another change — three calls with one change are
    /// one attempt by construction, which is the property `advance` exists to
    /// hold. Tests that mean "the same change again" pass a literal on purpose.
    fn unique_change() -> String {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "base..head{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    fn store() -> (tempfile::TempDir, IterationStore) {
        let dir = tempfile::tempdir().expect("a temp dir");
        let store = IterationStore::open(dir.path()).expect("opens");
        (dir, store)
    }

    #[test]
    fn re_reading_one_change_is_one_attempt_however_many_readers() {
        // THE DEFECT, in the shape it was found in. Twenty-four measurements of
        // one unchanged snapshot, run at once, produced three correct verdicts
        // and twenty-one premature `escalate_to_human` — the one signal reserved
        // for "an agent has tried enough times, stop trying", fired at a change
        // nobody had attempted twice.
        //
        // The dedupe was correct and lived in the wrong place: it asked the last
        // written record whether the change had been seen, and under concurrency
        // none of the racers had written one yet, so all of them were first.
        let (_dir, store) = store();
        let store = std::sync::Arc::new(store);
        let change = "base..one-unchanged-snapshot";
        let readers: Vec<_> = (0..24)
            .map(|_| {
                let store = std::sync::Arc::clone(&store);
                std::thread::spawn(move || {
                    store.advance("feat/a", 3, LoopOutcome::Countable, change)
                })
            })
            .collect();

        for reader in readers {
            let advance = reader
                .join()
                .expect("no reader panicked")
                .expect("no reader lost its write to another writer's temporary file");
            assert_eq!(
                advance.state.count, 1,
                "a reading of an already-counted change was counted as another attempt"
            );
            assert!(
                !advance.state.escalated,
                "concurrent readings of one snapshot escalated a human"
            );
            assert!(
                !advance.contended,
                "the lock was not taken inside its wait, which 24 sub-millisecond writers                  should never manage"
            );
        }
        assert_eq!(store.peek("feat/a", 3).count, 1);

        // The other half, without which this would pass over a cap that had
        // stopped counting altogether: an actual edit still counts.
        let edited = store
            .advance("feat/a", 3, LoopOutcome::Countable, "base..an-actual-edit")
            .expect("advances");
        assert_eq!(edited.state.count, 2);
    }

    #[test]
    fn a_branch_counts_its_own_passes() {
        let (_dir, store) = store();
        for expected in 1..=3 {
            let advance = store
                .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
                .unwrap();
            assert_eq!(advance.state.count, expected);
            assert!(!advance.state.escalated);
            assert!(!advance.recovered);
        }
    }

    #[test]
    fn branches_do_not_share_a_counter() {
        let (_dir, store) = store();
        store
            .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        store
            .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        let other = store
            .advance("fix/b", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        assert_eq!(other.state.count, 1, "a fresh branch starts fresh");
        assert_eq!(store.peek("feat/a", 3).count, 2);
    }

    #[test]
    fn the_pass_after_the_cap_escalates() {
        let (_dir, store) = store();
        let cap = DEFAULT_ITERATION_CAP;
        for _ in 0..cap {
            assert!(
                !store
                    .advance("feat/a", cap, LoopOutcome::Countable, &unique_change())
                    .unwrap()
                    .state
                    .escalated
            );
        }
        let over = store
            .advance("feat/a", cap, LoopOutcome::Countable, &unique_change())
            .unwrap();
        assert_eq!(over.state.count, cap + 1);
        assert!(over.state.escalated);
    }

    #[test]
    fn a_run_with_nothing_to_act_on_ends_the_loop() {
        let (_dir, store) = store();
        store
            .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        store
            .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        let clean = store
            .advance("feat/a", 3, LoopOutcome::Finished, &unique_change())
            .unwrap();
        assert_eq!(clean.state.count, 0);
        assert!(!clean.state.escalated);
        assert_eq!(
            store
                .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
                .unwrap()
                .state
                .count,
            1,
            "the next finding starts a new loop, not the old one"
        );
    }

    #[test]
    fn the_count_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        IterationStore::open(dir.path())
            .unwrap()
            .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        // A different store over the same root: a fresh process, same repository.
        let reopened = IterationStore::open(dir.path()).unwrap();
        assert_eq!(
            reopened
                .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
                .unwrap()
                .state
                .count,
            2
        );
    }

    #[test]
    fn reset_is_the_way_out_of_escalation() {
        let (_dir, store) = store();
        for _ in 0..5 {
            store
                .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
                .unwrap();
        }
        assert!(store.peek("feat/a", 3).escalated);
        store.reset("feat/a").unwrap();
        assert_eq!(store.peek("feat/a", 3).count, 0);
        assert!(
            !store
                .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
                .unwrap()
                .state
                .escalated
        );
    }

    #[test]
    fn a_corrupt_state_file_restarts_the_count_and_says_so() {
        let (_dir, store) = store();
        store
            .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        std::fs::write(store.path(), b"{ this is not json").unwrap();

        let advance = store
            .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        assert_eq!(advance.state.count, 1);
        assert!(
            advance.recovered,
            "a silent restart is a cap that silently stopped applying"
        );
        // And the store is usable again afterwards.
        assert!(
            !store
                .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
                .unwrap()
                .recovered
        );
    }

    #[test]
    fn a_state_file_from_another_layout_is_not_reinterpreted() {
        let (_dir, store) = store();
        std::fs::write(
            store.path(),
            br#"{"layout_version": 99, "branches": {"feat/a": 40}}"#,
        )
        .unwrap();
        let advance = store
            .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        assert_eq!(advance.state.count, 1, "not 41");
        assert!(advance.recovered);
    }

    #[test]
    fn a_first_run_is_not_a_recovery() {
        let (_dir, store) = store();
        assert!(
            !store
                .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
                .unwrap()
                .recovered
        );
    }

    #[test]
    fn a_branch_name_with_slashes_is_stored_as_written() {
        // Keys in one file rather than a file per branch: `feat/a/b` needs no
        // escaping and cannot collide with a directory that already exists.
        let (_dir, store) = store();
        store
            .advance("feat/a/b/c", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        assert_eq!(store.peek("feat/a/b/c", 3).count, 1);
        assert_eq!(store.peek("feat/a", 3).count, 0);
    }

    #[test]
    fn the_counter_saturates_rather_than_wrapping() {
        let (_dir, store) = store();
        std::fs::write(
            store.path(),
            format!(
                r#"{{"layout_version": {ITERATION_STATE_VERSION}, "branches": {{"feat/a": {{"count": {}, "change": "base..old"}}}}}}"#,
                u32::MAX
            ),
        )
        .unwrap();
        let advance = store
            .advance("feat/a", 3, LoopOutcome::Countable, &unique_change())
            .unwrap();
        assert_eq!(advance.state.count, u32::MAX);
        assert!(
            advance.state.escalated,
            "still escalated, never wrapped to 0"
        );
    }
}
