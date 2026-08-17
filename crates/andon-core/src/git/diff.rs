//! What changed between two endpoints, with the blob OIDs to read it from.
//!
//! Everything here uses git's `--raw -z` form, which hands back the source and
//! destination modes and OIDs alongside each path. That is the difference
//! between an enumeration that feeds the compared lane and one that does not:
//! the OIDs come from git's own tree walk, so the bytes behind them are fixed
//! regardless of what is checked out (PREMORTEM T1).
//!
//! # Sorting
//!
//! [`ChangedSet::entries`] is sorted by path here, in Rust, rather than trusted
//! from git. `diff.orderFile` reorders raw output and cannot be neutralized by
//! pinning — git rejects an empty value — so the order is taken out of git's
//! hands entirely. Downstream digests cover per-result values rather than the
//! list, but an engine that iterates in a config-dependent order will eventually
//! find a way to let that leak into one.

use super::blob::{BlobBatch, BlobError, Content};
use super::command::{Git, GitError};
use super::resolve::{Endpoint, ResolvedRange};
use super::status::split_nul;

/// The gitlink mode. A tree entry with this mode holds a *commit* OID belonging
/// to a submodule, not a blob OID, and asking `cat-file` for it returns a commit
/// object (PLAN P1 submodule test).
pub const GITLINK_MODE: &str = "160000";

/// What happened to one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeStatus {
    /// Added.
    Added,
    /// Content or mode modified.
    Modified,
    /// Deleted.
    Deleted,
    /// Renamed, possibly with an edit. `similarity` carries git's score.
    Renamed,
    /// Copied from another path.
    Copied,
    /// Type changed, e.g. a file became a symlink or a gitlink.
    TypeChanged,
    /// Unmerged. Only reachable mid-conflict, which resolution refuses first.
    Unmerged,
    /// git reported a letter this version does not know.
    Unknown,
}

impl ChangeStatus {
    fn from_letter(letter: u8) -> Self {
        match letter {
            b'A' => ChangeStatus::Added,
            b'M' => ChangeStatus::Modified,
            b'D' => ChangeStatus::Deleted,
            b'R' => ChangeStatus::Renamed,
            b'C' => ChangeStatus::Copied,
            b'T' => ChangeStatus::TypeChanged,
            b'U' => ChangeStatus::Unmerged,
            _ => ChangeStatus::Unknown,
        }
    }
}

/// One changed path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedEntry {
    /// Destination path, repository-relative with forward slashes. For a
    /// deletion, the path that was deleted.
    pub path: String,
    /// Source path, for a rename or copy.
    pub old_path: Option<String>,
    /// What happened.
    pub status: ChangeStatus,
    /// Rename or copy similarity score, 0–100.
    pub similarity: Option<u32>,
    /// Mode on the base side, e.g. `100644`. `None` when the path is new.
    pub src_mode: Option<String>,
    /// Mode on the head side. `None` when the path was deleted.
    pub dst_mode: Option<String>,
    /// Blob OID on the base side. `None` when new or unavailable.
    pub src_oid: Option<String>,
    /// Blob OID on the head side. `None` when deleted, and — for a diff against
    /// the working tree — when git has not hashed the file, in which case it
    /// reports all zeroes.
    pub dst_oid: Option<String>,
}

impl ChangedEntry {
    /// True when this entry is a submodule pointer rather than a file.
    ///
    /// The OIDs on a gitlink entry name commits in another repository. They are
    /// legitimate change information — a bumped submodule *is* a change to this
    /// tree — and they are not readable as content here.
    pub fn is_gitlink(&self) -> bool {
        self.src_mode.as_deref() == Some(GITLINK_MODE)
            || self.dst_mode.as_deref() == Some(GITLINK_MODE)
    }

    /// The head-side blob OID, if there is one worth reading.
    ///
    /// `None` for a deletion, for a gitlink, and for the all-zero OID git emits
    /// when diffing against an unhashed working-tree file.
    pub fn readable_blob(&self) -> Option<&str> {
        if self.is_gitlink() {
            return None;
        }
        self.dst_oid.as_deref().filter(|oid| !is_null_oid(oid))
    }
}

/// Every changed path between two endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedSet {
    /// Sorted by path. See the module docs on why the order is ours.
    pub entries: Vec<ChangedEntry>,
}

impl ChangedSet {
    /// Enumerate the change described by a resolved range. One spawn.
    ///
    /// Which plumbing command runs depends on what the head is, and the choice
    /// is the lane boundary in miniature: a commit head is diffed tree-to-tree
    /// and every OID is real; a working-tree head is diffed index-to-worktree
    /// and the head-side OIDs are absent by construction, which is what stops
    /// dirty bytes from acquiring compared-lane identities.
    pub fn enumerate(git: &Git, range: &ResolvedRange) -> Result<Self, GitError> {
        let mut entries = match &range.head {
            Endpoint::Commit { oid: head, .. } => {
                let raw = git
                    .cmd(["diff-tree"])
                    .args(RAW_FLAGS)
                    .args(["-M", range.base.anchor_oid(), head])
                    .output()?;
                parse_raw(&raw)
            }
            // A dirty head already scanned the working tree once, and the
            // snapshot it produced holds every path with its HEAD, index, and
            // working-tree blob OIDs. Running `diff-index` here would pay a
            // second 100k-entry scan (PREMORTEM T6) to learn what is already
            // known — and, worse, could disagree with it: a file edited between
            // the two scans appears in one and not the other, leaving a changed
            // set that contradicts the cache key naming it.
            Endpoint::Index { snapshot, .. } | Endpoint::Worktree { snapshot, .. } => {
                from_snapshot(snapshot)
            }
        };
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(ChangedSet { entries })
    }

    /// Read the head-side blob of every entry that has one, through a single
    /// `cat-file --batch`.
    ///
    /// Deletions, gitlinks, and unhashed working-tree files are skipped rather
    /// than errored: they are ordinary parts of a change, and none of them names
    /// a blob.
    pub fn read_head_blobs(&self, git: &Git) -> Result<Vec<(String, Content)>, BlobError> {
        let readable: Vec<(&str, &str)> = self
            .entries
            .iter()
            .filter_map(|e| e.readable_blob().map(|oid| (e.path.as_str(), oid)))
            .collect();
        // Starting `cat-file --batch` to read nothing costs a process — around
        // ninety milliseconds on Windows, a tenth of the warm budget — and a
        // working-tree head reads no blobs at all, because its bytes are not in
        // the object database.
        if readable.is_empty() {
            return Ok(Vec::new());
        }
        let mut batch = BlobBatch::open(git)?;
        let mut out = Vec::with_capacity(readable.len());
        for (path, oid) in readable {
            out.push((path.to_string(), batch.read(oid)?));
        }
        Ok(out)
    }

    /// How many entries there are.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing changed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Flags applied to every raw diff.
///
/// `--no-ext-diff` and `--no-textconv` are the flag forms of two config keys
/// that would otherwise route our diff through a program of the repository's
/// choosing; they are belt to the `-c` braces in
/// [`super::command::PINNED_CONFIG`], and unlike config they cannot be
/// overridden by anything.
const RAW_FLAGS: &[&str] = &[
    "-r",
    "--raw",
    "-z",
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    "--find-renames",
];

fn is_null_oid(oid: &str) -> bool {
    oid.bytes().all(|b| b == b'0')
}

/// Turn a dirty-tree snapshot into changed entries.
///
/// The head-side OID is the staged blob **only when the path is actually
/// staged**, and `None` otherwise. The distinction is not pedantry: for an
/// unstaged edit the index still holds `HEAD`'s content, so copying the index
/// OID across would hand the blob reader the *pre-edit* bytes and label them as
/// what the working tree contains. Unstaged bytes live only on disk, have no
/// blob to read, and belong to the advisory lane by construction (PREMORTEM T1).
///
/// The snapshot's `worktree_oid` is likewise absent here: it is a content hash
/// computed for keying, not an object in the database, and offering it to the
/// blob reader would name something `cat-file` cannot resolve.
fn from_snapshot(snapshot: &super::status::DirtySnapshot) -> Vec<ChangedEntry> {
    snapshot
        .entries
        .iter()
        .map(|(path, entry)| {
            let status = match (entry.head_mode.is_some(), entry.worktree_mode.is_some()) {
                (false, _) => ChangeStatus::Added,
                (true, false) => ChangeStatus::Deleted,
                (true, true) => ChangeStatus::Modified,
            };
            ChangedEntry {
                path: path.clone(),
                old_path: None,
                status,
                similarity: None,
                src_mode: entry.head_mode.clone(),
                dst_mode: entry.worktree_mode.clone(),
                src_oid: entry.head_oid.clone(),
                dst_oid: entry
                    .is_staged()
                    .then(|| entry.staged_oid.clone())
                    .flatten(),
            }
        })
        .collect()
}

/// Parse git's `--raw -z` output.
///
/// The record is `:<srcmode> <dstmode> <srcoid> <dstoid> <status>` followed by
/// NUL, then the path, then — for a rename or copy — NUL and the destination
/// path. Fields are space-separated; the status may carry a similarity score.
pub(crate) fn parse_raw(raw: &[u8]) -> Vec<ChangedEntry> {
    let mut records = split_nul(raw).peekable();
    let mut entries = Vec::new();

    while let Some(record) = records.next() {
        // `diff-tree` given a single commit prefixes its output with the commit
        // id. Every meta record starts with a colon, so anything else is that
        // header or noise, and skipping it is safer than positional trimming.
        if record.first() != Some(&b':') {
            continue;
        }
        let text = String::from_utf8_lossy(&record[1..]);
        let fields: Vec<&str> = text.split(' ').filter(|f| !f.is_empty()).collect();
        let [src_mode, dst_mode, src_oid, dst_oid, status] = fields.as_slice() else {
            continue;
        };
        let status_bytes = status.as_bytes();
        let Some(&letter) = status_bytes.first() else {
            continue;
        };
        let change = ChangeStatus::from_letter(letter);
        let similarity = status[1..].parse::<u32>().ok();

        let Some(first_path) = records.next() else {
            break;
        };
        let first_path = String::from_utf8_lossy(first_path).into_owned();

        let (old_path, path) = if matches!(change, ChangeStatus::Renamed | ChangeStatus::Copied) {
            // A rename record carries both paths: source first, destination
            // second. Taking only the first would name the file that no longer
            // exists.
            match records.next() {
                Some(second) => (
                    Some(first_path),
                    String::from_utf8_lossy(second).into_owned(),
                ),
                None => (None, first_path),
            }
        } else {
            (None, first_path)
        };

        entries.push(ChangedEntry {
            path,
            old_path,
            status: change,
            similarity,
            src_mode: none_if_empty_mode(src_mode),
            dst_mode: none_if_empty_mode(dst_mode),
            src_oid: none_if_null(src_oid),
            dst_oid: none_if_null(dst_oid),
        });
    }
    entries
}

/// Mode `000000` means "absent on this side", not "mode zero".
fn none_if_empty_mode(mode: &str) -> Option<String> {
    (mode != "000000").then(|| mode.to_string())
}

fn none_if_null(oid: &str) -> Option<String> {
    (!is_null_oid(oid)).then(|| oid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_modification_parses_into_both_sides() {
        let raw = b":100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb M\0src/a.ts\0";
        let entries = parse_raw(raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "src/a.ts");
        assert_eq!(entries[0].status, ChangeStatus::Modified);
        assert_eq!(entries[0].src_oid.as_deref(), Some(&"a".repeat(40)[..]));
        assert_eq!(entries[0].readable_blob(), Some(&"b".repeat(40)[..]));
    }

    #[test]
    fn a_rename_carries_both_paths_in_the_right_order() {
        let raw = b":100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb R096\0old/a.ts\0new/a.ts\0";
        let entries = parse_raw(raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, ChangeStatus::Renamed);
        assert_eq!(entries[0].old_path.as_deref(), Some("old/a.ts"));
        assert_eq!(entries[0].path, "new/a.ts");
        assert_eq!(entries[0].similarity, Some(96));
    }

    #[test]
    fn an_addition_has_no_base_side() {
        let raw = b":000000 100644 0000000000000000000000000000000000000000 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb A\0src/new.ts\0";
        let entries = parse_raw(raw);
        assert_eq!(entries[0].status, ChangeStatus::Added);
        assert_eq!(entries[0].src_mode, None);
        assert_eq!(entries[0].src_oid, None);
    }

    #[test]
    fn a_gitlink_is_never_offered_as_a_blob() {
        // The submodule case. Both OIDs are real and both name commits in
        // another repository; reading either as file content would hash a
        // commit header and call it a measurement.
        let raw = b":160000 160000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb M\0vendor/sub\0";
        let entries = parse_raw(raw);
        assert!(entries[0].is_gitlink());
        assert_eq!(entries[0].readable_blob(), None);
    }

    #[test]
    fn an_unhashed_worktree_file_offers_no_blob() {
        let raw = b":100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000000000000000000000000000000000000000 M\0src/dirty.ts\0";
        let entries = parse_raw(raw);
        assert_eq!(entries[0].readable_blob(), None);
    }

    #[test]
    fn a_leading_commit_id_record_is_skipped() {
        let raw = b"cccccccccccccccccccccccccccccccccccccccc\0:100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb M\0src/a.ts\0";
        assert_eq!(parse_raw(raw).len(), 1);
    }
}
