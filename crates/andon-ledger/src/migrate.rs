//! Squash-merge note migration as a supported operation.
//!
//! # The T4 story this closes
//!
//! A squash merge lands a branch's content on a brand-new commit that no note
//! points at. Every squash-merging repository — which is most of them — would
//! silently orphan its ledger at the exact moment the work becomes permanent
//! (PREMORTEM T4). The P1.5 fixture proved the mechanism works; what was
//! missing is an operation someone can actually run: `andon ledger migrate`
//! carries both refs' records from the pre-squash head onto the landed commit.
//!
//! The mechanics live in [`Notes::migrate`] — union, deduplicated, source left
//! in place — and this module is a caller over both refs, not a second
//! implementation. See that method's documentation for why migration merges
//! rather than overwrites (the target frequently already has a record, and
//! `git notes copy -f` would delete it).

use andon_core::git::Git;
use andon_ledger_min::notes::{Notes, NotesError, ATTEST_REF, MEASURE_REF};

/// What one ref's migration moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefMigration {
    /// The ref migrated.
    pub notes_ref: String,
    /// Records found on the source commit.
    pub source_records: usize,
    /// Records the target carries after the union. Zero when the source had
    /// nothing — the migration is then a no-op and writes nothing.
    pub target_records: usize,
}

/// Carry both refs' records from `from` onto `to`.
///
/// `from` is the pre-squash branch head; `to` is the commit the squash landed.
/// Records already on `to` survive: the operation is a union, so running it
/// twice — or migrating two branches onto one batch commit — loses nothing.
pub fn migrate_squash(git: &Git, from: &str, to: &str) -> Result<Vec<RefMigration>, NotesError> {
    let mut out = Vec::with_capacity(2);
    for notes_ref in [MEASURE_REF, ATTEST_REF] {
        let notes = Notes::new(git, notes_ref);
        // Through the guarded reader, like every read in this crate: a source
        // note that cannot be believed must refuse the migration, not ride it
        // onto the landed commit.
        let source_records = notes.read(from)?.len();
        let target_records = if source_records == 0 {
            0
        } else {
            notes.migrate(from, to)?
        };
        out.push(RefMigration {
            notes_ref: notes_ref.to_string(),
            source_records,
            target_records,
        });
    }
    Ok(out)
}
