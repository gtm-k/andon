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

use std::collections::BTreeMap;

use super::blob::{BlobBatch, BlobError, Content};
use super::command::{decode_record, Git, GitError};
use super::resolve::{Endpoint, ResolveError, ResolvedRange};
use super::status::split_nul;

/// The raw-diff invocation, for error messages.
const RAW_DIFF_ARGV: &str = "diff-tree --raw";

/// The gitlink mode. A tree entry with this mode holds a *commit* OID belonging
/// to a submodule, not a blob OID, and asking `cat-file` for it returns a commit
/// object (PLAN P1 submodule test).
pub const GITLINK_MODE: &str = "160000";

/// What happened to one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// Unmerged. Reachable from a raw diff over a conflicted index; the
    /// snapshot path refuses such a tree outright
    /// ([`super::command::GitError::ConflictedTree`]) because a path with
    /// competing stages has no single content to key on.
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
///
/// Serde-derived so the async lane's job file (P7) can carry the enumerated
/// change across processes: a spilled engine at `andon wait` time must measure
/// exactly the set the fast lane enumerated, and an uncommitted head cannot be
/// re-enumerated later — the operator's tree has moved on. Not a wire schema:
/// nothing here is a published contract, and no `JsonSchema` is derived.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChangedSet {
    /// Sorted by path. See the module docs on why the order is ours.
    pub entries: Vec<ChangedEntry>,
}

impl ChangedSet {
    /// Enumerate the change described by a resolved range. One spawn.
    ///
    /// Which plumbing runs depends on what the head is, and the split is the
    /// lane boundary in miniature. Committed endpoints are diffed tree-to-tree
    /// and every OID is real. The dirty segment carries no head-side OID for
    /// anything the working tree has moved off, by construction, which is what
    /// stops uncommitted bytes from acquiring compared-lane identities — see
    /// [`from_snapshot`] for the three conditions.
    ///
    /// A range can contain both, and then it contains both kinds of entry: the
    /// committed ones are readable blobs and the dirty ones are not. That is not
    /// a leak, it is the boundary drawn per path rather than per range.
    ///
    /// # A dirty head against a base that is not `HEAD`
    ///
    /// A dirty snapshot is anchored at `HEAD` — it is what `status` reports, and
    /// `status` has one thing to compare against. That is the whole change only
    /// when the base *is* `HEAD`. Ask for the default `andon measure` — merge
    /// base against the trusted branch, working tree as head — from a feature
    /// branch that has commits on it, and `HEAD` is not the merge base: the
    /// committed work sits between them, and enumerating the snapshot alone
    /// silently omits every file the branch has already committed.
    ///
    /// That is the flagship flow, not an edge: an agent measuring its own change
    /// mid-loop has commits behind it and edits in front of it. So the changed
    /// set is the **union** of the two segments — `diff-tree` from the base to
    /// the snapshot's anchor, and the snapshot itself — keyed by path. See
    /// [`compose`] for what happens to a path that appears in both.
    ///
    /// The `diff-tree` is skipped entirely when the base already *is* the
    /// snapshot's anchor, so the common `HEAD`-to-worktree case costs exactly
    /// what it did before.
    ///
    /// # Why a dirty base is refused
    ///
    /// A `WORKTREE` base against a commit head has no tree for git to diff, and
    /// the selection below would take the commit branch and diff against
    /// `Endpoint::anchor_oid` — the commit the dirty base *sits on top of*,
    /// rather than what it holds. Unlike the case above there is no honest
    /// enumeration to substitute: the caller asked for a comparison against
    /// uncommitted content, and nothing can stand in for it. So this mirrors
    /// [`ResolvedRange::compare_context`], down to the error — an endpoint with
    /// no commit id cannot stand where one is required.
    pub fn enumerate(git: &Git, range: &ResolvedRange) -> Result<Self, ResolveError> {
        if !range.base.is_commit() {
            return Err(ResolveError::NotComparable {
                side: "base",
                kind: range.base.kind(),
            });
        }
        let base_oid = range.base.anchor_oid();
        let mut entries = match &range.head {
            Endpoint::Commit { oid: head, .. } => committed_segment(git, base_oid, head)?,
            // A dirty head already scanned the working tree once, and the
            // snapshot it produced holds every path with its HEAD, index, and
            // working-tree blob OIDs. Running `diff-index` here would pay a
            // second 100k-entry scan (PREMORTEM T6) to learn what is already
            // known — and, worse, could disagree with it: a file edited between
            // the two scans appears in one and not the other, leaving a changed
            // set that contradicts the cache key naming it.
            Endpoint::Index { snapshot, .. } | Endpoint::Worktree { snapshot, .. } => {
                let dirty = from_snapshot(snapshot);
                if base_oid == snapshot.head_oid {
                    dirty
                } else {
                    union(committed_segment(git, base_oid, &snapshot.head_oid)?, dirty)
                }
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

/// One `diff-tree` between two commits. The committed half of a union, and the
/// whole of a commit-to-commit enumeration.
fn committed_segment(git: &Git, base: &str, head: &str) -> Result<Vec<ChangedEntry>, ResolveError> {
    let raw = git
        .cmd(["diff-tree"])
        .args(RAW_FLAGS)
        .args(["-M", base, head])
        .output()?;
    Ok(parse_raw(&raw)?)
}

/// Merge the committed segment with the dirty one, keyed by path.
///
/// # The approximation, stated
///
/// The key is the destination path, which is the identity every consumer uses.
/// One case it gets wrong: a file renamed `old` → `new` in the committed segment
/// whose `old` name is then recreated in the working tree. `old` appears only in
/// the dirty segment, so it is reported `Added` although the base has it. Fixing
/// it would mean a second index keyed on source paths and a rule for which
/// entry wins when both match — machinery for a case nobody has hit, in a
/// function whose value is that it is obvious. Written down rather than built.
fn union(committed: Vec<ChangedEntry>, dirty: Vec<ChangedEntry>) -> Vec<ChangedEntry> {
    let mut by_path: BTreeMap<String, ChangedEntry> = committed
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    for entry in dirty {
        match by_path.remove(&entry.path) {
            // Touched only since the last commit: the snapshot describes it
            // whole.
            None => {
                by_path.insert(entry.path.clone(), entry);
            }
            Some(committed) => {
                if let Some(composed) = compose(committed, entry) {
                    by_path.insert(composed.path.clone(), composed);
                }
            }
        }
    }
    by_path.into_values().collect()
}

/// One path that both segments describe.
///
/// Neither entry is right on its own, and taking either whole is a specific
/// wrong answer. The committed entry's destination side is the state at `HEAD`,
/// which the working tree has since moved off. The dirty entry's *source* side
/// is `HEAD` too — that is what `status` compares against — so taking it whole
/// would report the file as having changed from its `HEAD` content when the
/// caller asked what changed since the base.
///
/// So each side comes from the segment that knows it: the base side from the
/// committed entry, the working-tree side from the snapshot.
///
/// `similarity` is dropped. Git scored a rename between two commits; nothing has
/// scored base against working tree, and carrying the old number would attach a
/// measurement to a comparison it was not taken on. `old_path` survives, because
/// it is a fact about where the file came from rather than a score.
///
/// Returns `None` when neither side has the file: added on the branch and then
/// deleted from the working tree is, against the base, no change at all.
fn compose(committed: ChangedEntry, dirty: ChangedEntry) -> Option<ChangedEntry> {
    let ChangedEntry {
        old_path,
        src_mode,
        src_oid,
        ..
    } = committed;
    let ChangedEntry {
        path,
        dst_mode,
        dst_oid,
        ..
    } = dirty;

    if src_mode.is_none() && dst_mode.is_none() {
        return None;
    }
    let status = match (src_mode.is_some(), dst_mode.is_some()) {
        (false, _) => ChangeStatus::Added,
        (true, false) => ChangeStatus::Deleted,
        (true, true) if old_path.is_some() => ChangeStatus::Renamed,
        (true, true) => ChangeStatus::Modified,
    };
    Some(ChangedEntry {
        path,
        old_path,
        status,
        similarity: None,
        src_mode,
        dst_mode,
        src_oid,
        dst_oid,
    })
}

/// Turn a dirty-tree snapshot into changed entries.
///
/// # When the index blob is the head side, and when it only looks like it
///
/// The head-side OID is the staged blob **only when that blob describes the
/// state being measured**, and `None` otherwise. Three conditions, and each one
/// closes a way of handing an engine bytes that are not what it asked for.
///
/// - **The path must be staged at all.** For an unstaged edit the index still
///   holds `HEAD`'s content, so copying the index OID across would offer the
///   *pre-edit* bytes as what the working tree contains.
/// - **For the `WORKTREE` sentinel, the working tree must match the index.** A
///   path edited on top of a staged change (`MM`) has a perfectly readable index
///   blob describing content that is one revision behind what is being measured,
///   and a path staged and then deleted (`MD`) has one describing a file that is
///   not there at all. Both are the same mistake as the unstaged case wearing
///   better clothes: a blob the reader can resolve, holding bytes the
///   measurement is not about.
/// - **For the `INDEX` sentinel, that second condition does not apply.** The
///   index *is* the measured state there, so a later worktree edit is simply out
///   of scope and the staged blob is exactly right.
///
/// The snapshot's `worktree_oid` is absent here in every case: it is a content
/// hash computed for keying, not an object in the database, and offering it to
/// the blob reader would name something `cat-file` cannot resolve. Unstaged
/// bytes live only on disk and belong to the advisory lane by construction
/// (PREMORTEM T1).
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
            let index_blob_is_the_measured_state =
                entry.is_staged() && (snapshot.staged_only || entry.is_worktree_unmodified());
            ChangedEntry {
                path: path.clone(),
                old_path: None,
                status,
                similarity: None,
                src_mode: entry.head_mode.clone(),
                dst_mode: entry.worktree_mode.clone(),
                src_oid: entry.head_oid.clone(),
                dst_oid: index_blob_is_the_measured_state
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
pub(crate) fn parse_raw(raw: &[u8]) -> Result<Vec<ChangedEntry>, GitError> {
    let mut records = split_nul(raw).peekable();
    let mut entries = Vec::new();

    while let Some(record) = records.next() {
        // `diff-tree` given a single commit prefixes its output with the commit
        // id. Every meta record starts with a colon, so anything else is that
        // header or noise, and skipping it is safer than positional trimming.
        if record.first() != Some(&b':') {
            continue;
        }
        let text = decode_record(&record[1..], RAW_DIFF_ARGV)?;
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
        // Both paths become identities — `ChangedEntry::path` reaches
        // `ResultScope::path` on the wire, and `old_path` names the file a
        // rename came from — so both are decoded strictly. Lossy decoding would
        // let two distinct files collapse onto one string
        // (`GitError::UnrepresentablePath`).
        let first_path = decode_record(first_path, RAW_DIFF_ARGV)?.to_string();

        let (old_path, path) = if matches!(change, ChangeStatus::Renamed | ChangeStatus::Copied) {
            // A rename record carries both paths: source first, destination
            // second. Taking only the first would name the file that no longer
            // exists.
            match records.next() {
                Some(second) => (
                    Some(first_path),
                    decode_record(second, RAW_DIFF_ARGV)?.to_string(),
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
    Ok(entries)
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
    use std::collections::BTreeMap;

    use super::super::status::{DirtyEntry, DirtySnapshot, SnapshotMode, SNAPSHOT_VERSION};
    use super::*;

    /// A one-entry snapshot with the given porcelain status letters.
    fn snapshot_of(status: &str, staged_only: bool) -> DirtySnapshot {
        let deleted = status.as_bytes()[1] == b'D';
        let mut entries = BTreeMap::new();
        entries.insert(
            "src/a.ts".to_string(),
            DirtyEntry {
                status: status.to_string(),
                head_mode: Some("100644".to_string()),
                worktree_mode: (!deleted).then(|| "100644".to_string()),
                head_oid: Some("1".repeat(40)),
                staged_oid: Some("2".repeat(40)),
                // Computed for keying and never an object anyone can read.
                worktree_oid: Some("3".repeat(40)),
            },
        );
        DirtySnapshot {
            version: SNAPSHOT_VERSION,
            head_oid: "9".repeat(40),
            staged_only,
            mode: SnapshotMode::Incremental,
            entries,
        }
    }

    fn only_entry(snapshot: &DirtySnapshot) -> ChangedEntry {
        let entries = from_snapshot(snapshot);
        assert_eq!(entries.len(), 1);
        entries.into_iter().next().expect("one entry")
    }

    #[test]
    fn a_staged_path_the_worktree_has_not_touched_offers_its_blob() {
        // The case the offer exists for: staged, and the index still describes
        // what is on disk.
        let entry = only_entry(&snapshot_of("M.", false));
        assert_eq!(entry.readable_blob(), Some(&"2".repeat(40)[..]));
    }

    #[test]
    fn an_edit_on_top_of_a_staged_change_offers_nothing() {
        // `MM`. The index blob resolves and reads cleanly, and it holds the
        // content from *before* the working-tree edit — which is precisely the
        // state not being measured. A readable wrong answer is worse than none.
        let entry = only_entry(&snapshot_of("MM", false));
        assert_eq!(entry.readable_blob(), None);
        assert_eq!(entry.dst_oid, None);
    }

    #[test]
    fn a_staged_change_then_deleted_from_disk_offers_nothing() {
        // `MD`. The blob describes a file that is not in the measured tree at
        // all, which is the same mistake with the volume turned up.
        let entry = only_entry(&snapshot_of("MD", false));
        assert_eq!(entry.status, ChangeStatus::Deleted);
        assert_eq!(entry.readable_blob(), None);
    }

    #[test]
    fn an_unstaged_edit_still_offers_nothing() {
        // The case that was already right, asserted so the new condition cannot
        // be written in a way that accidentally loosens it.
        let entry = only_entry(&snapshot_of(".M", false));
        assert_eq!(entry.readable_blob(), None);
    }

    #[test]
    fn the_index_sentinel_is_unaffected_by_what_the_worktree_did_next() {
        // For `INDEX` the index *is* the measured state, so a later worktree
        // edit is out of scope rather than a reason to withhold the blob.
        for status in ["M.", "MM", "MD"] {
            let entry = only_entry(&snapshot_of(status, true));
            assert_eq!(
                entry.readable_blob(),
                Some(&"2".repeat(40)[..]),
                "the INDEX sentinel must still offer the staged blob for {status}"
            );
        }
    }

    #[test]
    fn a_modification_parses_into_both_sides() {
        let raw = b":100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb M\0src/a.ts\0";
        let entries = parse_raw(raw).expect("every path is UTF-8");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "src/a.ts");
        assert_eq!(entries[0].status, ChangeStatus::Modified);
        assert_eq!(entries[0].src_oid.as_deref(), Some(&"a".repeat(40)[..]));
        assert_eq!(entries[0].readable_blob(), Some(&"b".repeat(40)[..]));
    }

    #[test]
    fn a_rename_carries_both_paths_in_the_right_order() {
        let raw = b":100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb R096\0old/a.ts\0new/a.ts\0";
        let entries = parse_raw(raw).expect("every path is UTF-8");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, ChangeStatus::Renamed);
        assert_eq!(entries[0].old_path.as_deref(), Some("old/a.ts"));
        assert_eq!(entries[0].path, "new/a.ts");
        assert_eq!(entries[0].similarity, Some(96));
    }

    #[test]
    fn an_addition_has_no_base_side() {
        let raw = b":000000 100644 0000000000000000000000000000000000000000 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb A\0src/new.ts\0";
        let entries = parse_raw(raw).expect("every path is UTF-8");
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
        let entries = parse_raw(raw).expect("every path is UTF-8");
        assert!(entries[0].is_gitlink());
        assert_eq!(entries[0].readable_blob(), None);
    }

    #[test]
    fn an_unhashed_worktree_file_offers_no_blob() {
        let raw = b":100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000000000000000000000000000000000000000 M\0src/dirty.ts\0";
        let entries = parse_raw(raw).expect("every path is UTF-8");
        assert_eq!(entries[0].readable_blob(), None);
    }

    #[test]
    fn two_paths_that_would_collapse_into_one_are_refused_instead() {
        // `0xFF` and `0xFE` are both invalid UTF-8 and both render as U+FFFD, so
        // a lossy decode turns two distinct files into one string — one entry
        // overwriting the other in a map, one digest describing two files. The
        // collision is asserted first, because refusing bytes that were never
        // ambiguous would prove nothing.
        let meta = b":100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb M\0";
        let one = [&meta[..], b"src/\xff.ts\0"].concat();
        let two = [&meta[..], b"src/\xfe.ts\0"].concat();
        assert_eq!(
            String::from_utf8_lossy(b"src/\xff.ts"),
            String::from_utf8_lossy(b"src/\xfe.ts"),
            "the bait is inert: these two paths do not collide lossily"
        );

        for raw in [one, two] {
            match parse_raw(&raw) {
                Err(GitError::UnrepresentablePath { detail, .. }) => {
                    assert!(detail.contains("UTF-8"), "{detail}")
                }
                other => panic!("expected a typed refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_rename_refuses_on_either_side_of_the_pair() {
        // `old_path` is an identity too — it names the file a rename came from —
        // so a source path that only survives approximately is refused as
        // readily as a destination one.
        let meta = b":100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb R100\0";
        let bad_source = [&meta[..], b"old/\xff.ts\0", b"new/a.ts\0"].concat();
        let bad_dest = [&meta[..], b"old/a.ts\0", b"new/\xff.ts\0"].concat();
        for raw in [bad_source, bad_dest] {
            assert!(matches!(
                parse_raw(&raw),
                Err(GitError::UnrepresentablePath { .. })
            ));
        }
    }

    #[test]
    fn a_leading_commit_id_record_is_skipped() {
        let raw = b"cccccccccccccccccccccccccccccccccccccccc\0:100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb M\0src/a.ts\0";
        assert_eq!(parse_raw(raw).expect("every path is UTF-8").len(), 1);
    }
}
