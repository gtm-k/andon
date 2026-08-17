//! The ledger: measurement records carried on git notes.
//!
//! Two refs, flat, and the flatness is empirical rather than aesthetic. PLAN
//! round-1 B2 renamed them from a `refs/notes/andon/{measure,attest}` hierarchy
//! after verifying that git cannot hold `refs/notes/andon` and
//! `refs/notes/andon/measure` at once — a directory/file conflict in the loose
//! ref store, which is the sort of thing that only shows up when someone tries
//! it.
//!
//! - [`MEASURE_REF`] — what the agent-side binary claims it measured.
//! - [`ATTEST_REF`] — what the verifier found when it recomputed.
//!
//! # Why the note body is JSON Lines
//!
//! `git notes merge -s cat_sort_uniq` is the only merge strategy that never
//! conflicts and never asks a human: it concatenates both note bodies, sorts the
//! lines, and drops duplicates. That strategy is **line-oriented**, so a record
//! spanning several lines would be interleaved with another record's lines by a
//! concurrent merge and both would be destroyed.
//!
//! [`andon_core::canonical::to_canonical_string`] emits no insignificant
//! whitespace and escapes every control character, so a record is a single line
//! by construction. One record per line therefore makes the PREMORTEM T4
//! property — two concurrent attestations survive a merge with neither lost —
//! true by construction rather than by retry logic. The retry logic exists too;
//! it handles the push race, not the content merge.
//!
//! # Identity
//!
//! [`andon_core::git::Git`] sweeps every inherited `GIT_*` variable, and a CI
//! runner has no `user.email` configured, so `git notes add` would fail with
//! "please tell me who you are" on the first run anywhere. The identity below is
//! set explicitly on the spawns that write objects, through the documented
//! [`andon_core::git::GitCommand::env`] hole.
//!
//! This is a **bot identity on a note object**, not a commit-authorship
//! override: nothing here writes a commit to the repository's history. The rule
//! about never overriding a configured git author is about authorship of work; a
//! ledger record is machine output and says so in the name.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use andon_core::canonical::{self, CanonicalError};
use andon_core::git::{Git, GitCommand, GitError};
use andon_core::schema::payload::MeasurementRecord;

/// Where a self-report goes (PLAN B2).
pub const MEASURE_REF: &str = "refs/notes/andon-measure";

/// Where the verifier's attestation goes (PLAN B2).
pub const ATTEST_REF: &str = "refs/notes/andon-attest";

/// The merge strategy. Line-oriented, conflict-free, and the reason records are
/// one line each.
pub const MERGE_STRATEGY: &str = "cat_sort_uniq";

/// Identity stamped on note objects. See the module docs.
const NOTE_IDENTITY: &[(&str, &str)] = &[
    ("GIT_AUTHOR_NAME", "andon-ledger"),
    ("GIT_AUTHOR_EMAIL", "ledger@andon.invalid"),
    ("GIT_COMMITTER_NAME", "andon-ledger"),
    ("GIT_COMMITTER_EMAIL", "ledger@andon.invalid"),
];

/// A ledger operation failed.
#[derive(Debug, thiserror::Error)]
pub enum NotesError {
    /// A git command failed.
    #[error(transparent)]
    Git(#[from] GitError),
    /// A record could not be canonically serialized.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// A note body held a line that is not a measurement record.
    ///
    /// Refused rather than skipped. A note is the ledger; a line in it that
    /// cannot be read is either corruption or a record from a schema version
    /// this binary does not implement, and quietly dropping either would make
    /// the ledger report over a subset it never announced.
    #[error("{notes_ref} on {commit}: line {line} is not a measurement record: {source}")]
    Malformed {
        /// Which ref the note came from.
        notes_ref: String,
        /// Which commit it was attached to.
        commit: String,
        /// 1-based line number within the note body.
        line: usize,
        /// The parse failure.
        #[source]
        source: serde_json::Error,
    },
    /// The remote could not answer, which is not the same as having no ledger.
    ///
    /// Kept apart from every other error because the whole point is that it must
    /// not be mistaken for `Ok(false)`. See [`Notes::fetch`].
    #[error(
        "could not reach {remote} for {notes_ref}: {source}\n\
         a transport failure is not an empty ledger — treating it as one would let \
         a network error report `unwitnessed` on a head that has self-reports"
    )]
    Transport {
        /// The remote that was asked.
        remote: String,
        /// The ref that was being fetched.
        notes_ref: String,
        /// What git said.
        ///
        /// Boxed: `GitError` carries three owned strings on its widest variant,
        /// and inlining it here made every `Result` in this module pay for the
        /// rarest failure it has. `clippy::result_large_err` is the thing that
        /// noticed.
        #[source]
        source: Box<GitError>,
    },
    /// The temporary file holding a note body could not be written.
    #[error("could not stage a note body at {path}: {source}")]
    Staging {
        /// Where the write was attempted.
        path: String,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

/// The local tracking ref a notes ref is fetched into.
///
/// Under `refs/andon-remote/` rather than `refs/notes/`: a tracking copy is not
/// a ledger, and putting it under `refs/notes` would make `git notes` tooling
/// list it as if it were one.
pub fn tracking_ref_for(notes_ref: &str) -> String {
    format!(
        "refs/andon-remote/{}",
        notes_ref.trim_start_matches("refs/notes/")
    )
}

/// A handle to one notes ref in one repository.
#[derive(Debug, Clone)]
pub struct Notes<'a> {
    git: &'a Git,
    notes_ref: String,
}

impl<'a> Notes<'a> {
    /// Open a handle to `notes_ref`.
    pub fn new(git: &'a Git, notes_ref: impl Into<String>) -> Self {
        Self {
            git,
            notes_ref: notes_ref.into(),
        }
    }

    /// The self-report ledger.
    pub fn measure(git: &'a Git) -> Self {
        Self::new(git, MEASURE_REF)
    }

    /// The attestation ledger.
    pub fn attest(git: &'a Git) -> Self {
        Self::new(git, ATTEST_REF)
    }

    /// Which ref this handle writes.
    pub fn notes_ref(&self) -> &str {
        &self.notes_ref
    }

    /// The local tracking ref this handle fetches into.
    pub fn tracking_ref(&self) -> String {
        tracking_ref_for(&self.notes_ref)
    }

    /// Every record attached to `commit`, in note-body order.
    ///
    /// An absent note is `Ok(vec![])`, not an error: "nobody measured this" is
    /// an answer the verifier acts on — it becomes `unwitnessed` — and turning
    /// it into a failure would make a missing self-report louder than a forged
    /// one.
    pub fn read(&self, commit: &str) -> Result<Vec<MeasurementRecord>, NotesError> {
        let Some(body) = self.read_raw(commit)? else {
            return Ok(Vec::new());
        };
        let mut records = Vec::new();
        for (index, line) in body.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let record = serde_json::from_str(line).map_err(|source| NotesError::Malformed {
                notes_ref: self.notes_ref.clone(),
                commit: commit.to_string(),
                line: index + 1,
                source,
            })?;
            records.push(record);
        }
        Ok(records)
    }

    /// The raw note body, or `None` when there is no note.
    pub fn read_raw(&self, commit: &str) -> Result<Option<String>, NotesError> {
        // `git notes show` exits 1 with "no note found"; `succeeds_with_output`
        // maps exactly that code to `None` and lets 128 — an unknown object, a
        // broken repository — surface as the error it is.
        Ok(self
            .git
            .cmd(["notes", &self.ref_flag(), "show", commit])
            .succeeds_with_output()?)
    }

    /// Replace whatever note is on `commit` with exactly these records.
    pub fn write(&self, commit: &str, records: &[MeasurementRecord]) -> Result<(), NotesError> {
        let body = render(records)?;
        self.run_with_body("add", &["-f"], &body, commit)
    }

    /// Add one record to whatever is already on `commit`.
    ///
    /// `append` rather than `add -f` so that a second engine, a second agent, or
    /// a retry does not silently delete the first one's record.
    pub fn append(&self, commit: &str, record: &MeasurementRecord) -> Result<(), NotesError> {
        let body = render(std::slice::from_ref(record))?;
        self.run_with_body("append", &[], &body, commit)
    }

    /// Carry the note from one commit to another.
    ///
    /// Two callers with the same shape and different stories. A **squash merge**
    /// lands a branch's content on a new commit that no note points at, so
    /// PREMORTEM T4 needs the record migrated onto what actually landed. A
    /// **rebase** produces a new head for the same work, and an agent that
    /// reuses its pre-rebase measurement rather than re-measuring is exactly the
    /// R2-4 `unwitnessed-base-mismatch` case — which the tool must be able to
    /// represent, and then refuse to confirm.
    pub fn copy(&self, from: &str, to: &str) -> Result<(), NotesError> {
        self.identified(
            self.git
                .cmd(["notes", &self.ref_flag(), "copy", "-f", from, to]),
        )
        .output()?;
        Ok(())
    }

    /// Commits carrying a note on this ref.
    pub fn annotated_commits(&self) -> Result<Vec<String>, NotesError> {
        let text = self.git.cmd(["notes", &self.ref_flag(), "list"]).text()?;
        Ok(text
            .lines()
            .filter_map(|line| line.split_whitespace().nth(1).map(str::to_string))
            .collect())
    }

    /// Fetch the remote's copy of this ref into a local tracking ref.
    ///
    /// The refspec is explicit and the destination is a *tracking* ref rather
    /// than the working ref, because fetching straight onto `refs/notes/...`
    /// would discard local records that have not been pushed yet — losing
    /// exactly the concurrent write PREMORTEM T4 is about. [`Notes::merge_tracking`]
    /// is what combines the two.
    ///
    /// `false` means the remote has no such ref yet, which is the first-push
    /// case and not a failure.
    ///
    /// # Why this asks twice
    ///
    /// `git fetch` collapses two entirely different answers into one nonzero
    /// exit: *the remote has no such ref* and *the remote could not be reached*.
    /// Mapping both to "no ledger here" is a fail-open, and the failure it opens
    /// is specific and bad: a dead remote, an expired token, or a DNS blip makes
    /// the verifier read an empty local ledger and report `unwitnessed` on a
    /// head that **does** have self-reports. Absence of evidence would have been
    /// manufactured by a network error, and `unwitnessed` is a neutral notice
    /// nobody investigates.
    ///
    /// So `ls-remote` is asked first, where the two cases are distinguishable:
    /// exit 0 with empty output means the ref genuinely is not there, and a
    /// nonzero exit means the remote could not answer. The second becomes
    /// [`NotesError::Transport`] — loud, typed, and fatal to the caller — so a
    /// workflow's fetch step goes red rather than a verification quietly
    /// proceeding over a ledger it never managed to read.
    pub fn fetch(&self, remote: &str) -> Result<bool, NotesError> {
        let transport = |source: GitError| NotesError::Transport {
            remote: remote.to_string(),
            notes_ref: self.notes_ref.clone(),
            source: Box::new(source),
        };
        let listing = self
            .git
            .cmd(["ls-remote", remote, &self.notes_ref])
            .text()
            .map_err(transport)?;
        if listing.trim().is_empty() {
            return Ok(false);
        }

        // The ref exists on the remote, so from here a failure is a real one and
        // is not swallowed.
        let refspec = format!("+{}:{}", self.notes_ref, self.tracking_ref());
        self.git
            .cmd([
                "fetch",
                "--no-tags",
                // A notes tree references no commit in history, so a shallow
                // clone does not truncate the ledger. Said explicitly because
                // PREMORTEM T4's third leg is "shallow checkouts" and a reader
                // should not have to infer it.
                "--no-recurse-submodules",
                remote,
                &refspec,
            ])
            .output()
            .map_err(transport)?;
        Ok(true)
    }

    /// Merge the tracking ref into the working ref with `cat_sort_uniq`.
    ///
    /// `false` when there is no tracking ref to merge, which is the first-push
    /// case.
    pub fn merge_tracking(&self) -> Result<bool, NotesError> {
        let tracking = self.tracking_ref();
        if !self.ref_exists(&tracking)? {
            return Ok(false);
        }
        self.identified(self.git.cmd([
            "notes",
            &self.ref_flag(),
            "merge",
            "-s",
            MERGE_STRATEGY,
            &tracking,
        ]))
        .output()?;
        Ok(true)
    }

    /// Push this ref, merging and retrying when the remote has moved.
    ///
    /// Returns which attempt succeeded. A rejected push is not swallowed: the
    /// loop re-fetches, merges with `cat_sort_uniq`, and tries again, and when
    /// the attempts are exhausted the caller gets git's own stderr inside a
    /// [`GitError::Failed`]. PLAN P8 turns that into a red, user-visible failure
    /// with a fault-injection test; this is the mechanism it will extend.
    pub fn push_with_retry(&self, remote: &str, attempts: u32) -> Result<u32, NotesError> {
        let refspec = format!("{}:{}", self.notes_ref, self.notes_ref);
        let mut last: Option<GitError> = None;
        for attempt in 1..=attempts.max(1) {
            match self.git.cmd(["push", remote, &refspec]).output() {
                Ok(_) => return Ok(attempt),
                Err(err) => {
                    last = Some(err);
                    self.fetch(remote)?;
                    self.merge_tracking()?;
                }
            }
        }
        Err(NotesError::Git(
            last.expect("at least one attempt was made"),
        ))
    }

    fn ref_flag(&self) -> String {
        format!("--ref={}", self.notes_ref)
    }

    fn ref_exists(&self, name: &str) -> Result<bool, NotesError> {
        Ok(self
            .git
            .cmd(["rev-parse", "--verify", "--quiet", "--end-of-options", name])
            .succeeds_with_output()?
            .is_some())
    }

    fn identified(&self, command: GitCommand) -> GitCommand {
        NOTE_IDENTITY
            .iter()
            .fold(command, |cmd, (key, value)| cmd.env(key, value))
    }

    /// Run a `git notes` subcommand whose message comes from a file.
    ///
    /// A staged file rather than stdin. Writing a note body down a pipe while
    /// the same process waits to read the child's output deadlocks whenever the
    /// body outgrows the pipe buffer, and a record covering a few hundred
    /// changed files does. A file has no such coupling and costs one write.
    fn run_with_body(
        &self,
        subcommand: &str,
        flags: &[&str],
        body: &str,
        commit: &str,
    ) -> Result<(), NotesError> {
        let staged = StagedBody::write(body)?;
        self.identified(
            self.git
                .cmd(["notes", &self.ref_flag()])
                .arg(subcommand)
                .args(flags)
                .arg("-F")
                .arg(&staged.path)
                .arg(commit),
        )
        .output()?;
        Ok(())
    }
}

/// Render records as the note body: one canonical JSON line each.
pub fn render(records: &[MeasurementRecord]) -> Result<String, CanonicalError> {
    let mut body = String::new();
    for record in records {
        body.push_str(&canonical::to_canonical_string(record)?);
        body.push('\n');
    }
    Ok(body)
}

/// A note body on disk, removed when it goes out of scope.
struct StagedBody {
    path: PathBuf,
}

impl StagedBody {
    fn write(body: &str) -> Result<Self, NotesError> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "andon-note-{}-{}.jsonl",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let staged = StagedBody { path };
        let stage = |source| NotesError::Staging {
            path: staged.path.display().to_string(),
            source,
        };
        let mut file = std::fs::File::create(&staged.path).map_err(stage)?;
        file.write_all(body.as_bytes())
            .and_then(|()| file.flush())
            .map_err(stage)?;
        Ok(staged)
    }
}

impl Drop for StagedBody {
    fn drop(&mut self) {
        // Best effort: a leaked temp file is untidy, and failing a measurement
        // because a cleanup failed would be worse.
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andon_core::testing::sample_record;

    #[test]
    fn a_rendered_record_occupies_exactly_one_line() {
        // The property `cat_sort_uniq` depends on. If a record ever spans two
        // lines, a concurrent merge interleaves it with another record's lines
        // and both are destroyed — silently, because the result is still a note.
        let body = render(&[sample_record(), sample_record()]).expect("records render");
        assert_eq!(body.lines().count(), 2);
        for line in body.lines() {
            assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
            serde_json::from_str::<MeasurementRecord>(line).expect("each line round-trips");
        }
    }

    #[test]
    fn a_record_carrying_newlines_in_its_strings_still_occupies_one_line() {
        // The canonical serializer escapes control characters, so a message with
        // an embedded newline cannot break the line discipline. Asserted because
        // a serializer change that emitted raw control bytes would break
        // `cat_sort_uniq` in a way no schema test would notice.
        let mut record = sample_record();
        record.verdict.reasons[0].message = "line one\nline two\r\n".to_string();
        let body = render(&[record]).expect("records render");
        assert_eq!(body.lines().count(), 1, "body was {body:?}");
    }

    #[test]
    fn the_tracking_ref_is_not_itself_a_notes_ref() {
        // A tracking copy that lived under `refs/notes/` would be listed by
        // `git notes` tooling as a second ledger.
        assert_eq!(
            tracking_ref_for(MEASURE_REF),
            "refs/andon-remote/andon-measure"
        );
        assert_eq!(
            tracking_ref_for(ATTEST_REF),
            "refs/andon-remote/andon-attest"
        );
        assert!(!tracking_ref_for(MEASURE_REF).starts_with("refs/notes/"));
    }
}
