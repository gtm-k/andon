//! The notes transport: fetch, merge, push — retried with backoff, loud on
//! defeat.
//!
//! # The loudness rule (PLAN P8, round-1 fix)
//!
//! The disqualifying shape here is a quiet give-up: a push loop that runs out
//! of retries, logs something at debug level, and exits 0. The ledger would
//! then be missing from the remote while every signal said it was written —
//! and a verifier fetching from that remote would call the head `unwitnessed`,
//! manufacturing absence-of-evidence out of a transport failure. So exhausted
//! retries are an **error**, the error's message states the consequence and the
//! recovery, and the CLI turns it into a nonzero exit. The fault-injection test
//! (`tests/fault_injection.rs`) pins all three.
//!
//! # What the loop actually does
//!
//! Per ref: fetch the remote's copy into the tracking ref, merge it into the
//! working ref with `cat_sort_uniq` (the strategy the whole note format is
//! built around — see `andon_ledger_min::notes`), then push. A rejected push
//! means the remote moved after the merge, so the recovery inside
//! [`Notes::push_with_retry`] fetches and merges again; this module adds the
//! part the spike deliberately left out — more than one go, with a backoff
//! sleep between goes, and a typed loud failure when the goes run out.

use std::time::{Duration, Instant};

use andon_core::git::Git;
use andon_ledger_min::notes::{Notes, NotesError, ATTEST_REF, MEASURE_REF};

/// How long to wait before each retry after a rejected push.
///
/// Deterministic doubling from `base_ms` up to `cap_ms`, no jitter: jitter
/// exists to de-synchronize fleets, and this is one repository's CI job racing
/// at most a handful of concurrent writers. A dependency for randomness would
/// buy nothing but lockfile surface.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// The first delay.
    pub base_ms: u64,
    /// The largest delay, however many failures have accumulated.
    pub cap_ms: u64,
}

impl Backoff {
    /// No waiting at all. For tests, where the retries themselves are the
    /// subject and wall-clock sleeps would only slow the suite.
    pub const fn none() -> Self {
        Backoff {
            base_ms: 0,
            cap_ms: 0,
        }
    }

    /// The delay after `failures` consecutive rejected pushes (1-based).
    pub fn delay(&self, failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(16);
        Duration::from_millis(self.base_ms.saturating_mul(1 << doublings).min(self.cap_ms))
    }
}

impl Default for Backoff {
    /// 500ms, 1s, 2s, 4s, then 8s flat — enough that a busy remote's writers
    /// interleave, small enough that a hook or a CI step never hangs for long.
    fn default() -> Self {
        Backoff {
            base_ms: 500,
            cap_ms: 8_000,
        }
    }
}

/// How hard to try.
#[derive(Debug, Clone, Copy)]
pub struct SyncOptions {
    /// Total push attempts per ref before giving up loudly.
    pub attempts: u32,
    /// The wait between attempts.
    pub backoff: Backoff,
}

impl Default for SyncOptions {
    fn default() -> Self {
        SyncOptions {
            attempts: 3,
            backoff: Backoff::default(),
        }
    }
}

/// What happened to one ref during a sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefSync {
    /// The ref in question.
    pub notes_ref: String,
    /// Whether the remote had the ref to fetch.
    pub fetched: bool,
    /// Whether a tracking ref existed to merge.
    pub merged: bool,
    /// How the push went.
    pub pushed: Pushed,
}

/// The push half of a ref's sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    /// There is no local ref, so there was nothing to push. Not a failure:
    /// a repository that has never recorded a measurement has an empty ledger,
    /// and syncing an empty ledger is a no-op, not an error.
    NothingToPush,
    /// The push landed, on this (1-based) attempt.
    OnAttempt(u32),
}

/// A sync failed.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The underlying notes machinery refused — transport failure, recovery
    /// failure, an unreadable note. Already loud and typed; passed through.
    #[error(transparent)]
    Notes(#[from] NotesError),
    /// Every attempt to push was rejected. The red, user-visible failure PLAN
    /// P8 requires: it states the consequence (the remote does not have the
    /// records) and the recovery (fix the remote, sync again) rather than
    /// dumping a struct.
    #[error(
        "LEDGER PUSH FAILED: {notes_ref} was rejected by {remote} on all {attempts} attempt(s), \
         with fetch+merge recovery and backoff between attempts ({waited_ms}ms total).\n\
         Every record is still safe in this repository's local ref — nothing was lost — but \
         {remote} does not have them: anyone reading the remote ledger will not see these \
         measurements, and a verifier fetching from it would read this head as unwitnessed.\n\
         Last rejection: {last}\n\
         Fix what the remote is enforcing (permissions, a pre-receive hook, protected refs), \
         then run `andon ledger sync` again — nothing needs re-measuring."
    )]
    PushExhausted {
        /// The ref that could not be pushed.
        notes_ref: String,
        /// The remote that kept refusing.
        remote: String,
        /// How many pushes were attempted.
        attempts: u32,
        /// Total time spent waiting between attempts.
        waited_ms: u128,
        /// What the last rejection said, git's own words included.
        last: String,
    },
}

/// Fetch, merge, and push one notes ref.
pub fn sync_ref(
    git: &Git,
    notes_ref: &str,
    remote: &str,
    options: &SyncOptions,
) -> Result<RefSync, SyncError> {
    let notes = Notes::new(git, notes_ref);
    let fetched = notes.fetch(remote)?;
    let merged = notes.merge_tracking()?;

    if !ref_exists(git, notes_ref)? {
        // No local ref even after the merge: nothing was ever recorded here and
        // the remote had nothing either (a fetched ref would have been merged
        // into existence above). `git push` of a nonexistent src would fail
        // with a refspec error, which would dress an empty ledger up as a
        // transport problem.
        return Ok(RefSync {
            notes_ref: notes_ref.to_string(),
            fetched,
            merged,
            pushed: Pushed::NothingToPush,
        });
    }

    let started = Instant::now();
    let mut waited = Duration::ZERO;
    let mut last: Option<String> = None;
    let attempts = options.attempts.max(1);
    for attempt in 1..=attempts {
        if attempt > 1 {
            let delay = options.backoff.delay(attempt - 1);
            waited += delay;
            std::thread::sleep(delay);
        }
        // One attempt per call: the spike's own retry loop already contains the
        // recovery (fetch, then cat_sort_uniq merge) that makes the next push
        // meaningful, so this loop adds only what the spike left out — the
        // backoff, and the loud exhaustion below.
        match notes.push_with_retry(remote, 1) {
            Ok(_) => {
                return Ok(RefSync {
                    notes_ref: notes_ref.to_string(),
                    fetched,
                    merged,
                    pushed: Pushed::OnAttempt(attempt),
                })
            }
            Err(NotesError::PushRejected { source, .. }) => {
                last = Some(source.to_string());
            }
            // Anything else — transport gone, recovery broken, a note that
            // cannot be read — is not a race to retry out of. It is already a
            // typed, attributed failure; retrying would only bury it.
            Err(other) => return Err(SyncError::Notes(other)),
        }
    }
    let _ = started;
    Err(SyncError::PushExhausted {
        notes_ref: notes_ref.to_string(),
        remote: remote.to_string(),
        attempts,
        waited_ms: waited.as_millis(),
        last: last.expect("at least one attempt was made"),
    })
}

/// Sync both ledger refs, measure first.
///
/// Fail-fast on the first ref that cannot be synced: the error names its ref,
/// and carrying on to the second ref after the first failed loudly would only
/// let the success sentence of one drown the failure sentence of the other.
pub fn sync_all(git: &Git, remote: &str, options: &SyncOptions) -> Result<Vec<RefSync>, SyncError> {
    let mut out = Vec::with_capacity(2);
    for notes_ref in [MEASURE_REF, ATTEST_REF] {
        out.push(sync_ref(git, notes_ref, remote, options)?);
    }
    Ok(out)
}

/// Whether `name` resolves to anything in this repository.
fn ref_exists(git: &Git, name: &str) -> Result<bool, SyncError> {
    Ok(git
        .cmd(["rev-parse", "--verify", "--quiet", "--end-of-options", name])
        .succeeds_with_output()
        .map_err(NotesError::from)?
        .is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_base_and_stops_at_the_cap() {
        let backoff = Backoff {
            base_ms: 500,
            cap_ms: 8_000,
        };
        assert_eq!(backoff.delay(1), Duration::from_millis(500));
        assert_eq!(backoff.delay(2), Duration::from_millis(1_000));
        assert_eq!(backoff.delay(3), Duration::from_millis(2_000));
        assert_eq!(backoff.delay(4), Duration::from_millis(4_000));
        assert_eq!(backoff.delay(5), Duration::from_millis(8_000));
        assert_eq!(backoff.delay(50), Duration::from_millis(8_000));
    }

    #[test]
    fn no_backoff_never_waits() {
        for failures in 1..10 {
            assert_eq!(Backoff::none().delay(failures), Duration::ZERO);
        }
    }

    #[test]
    fn the_exhaustion_message_names_the_consequence_and_the_recovery() {
        // The loudness rule as a property of the TEXT, not just the type: the
        // reader of this failure is a person staring at a red CI step, and the
        // message must tell them what is true (records safe locally, absent
        // remotely), what it means (a verifier would read unwitnessed), and
        // what to do (fix the remote, sync again).
        let err = SyncError::PushExhausted {
            notes_ref: MEASURE_REF.to_string(),
            remote: "origin".to_string(),
            attempts: 3,
            waited_ms: 1_500,
            last: "pre-receive hook declined".to_string(),
        };
        let text = err.to_string();
        for needle in [
            "LEDGER PUSH FAILED",
            MEASURE_REF,
            "origin",
            "all 3 attempt(s)",
            "nothing was lost",
            "unwitnessed",
            "pre-receive hook declined",
            "andon ledger sync",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in: {text}");
        }
    }
}
