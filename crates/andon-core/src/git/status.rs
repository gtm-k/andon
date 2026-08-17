//! Dirty-tree snapshots: what the working tree holds that `HEAD` does not.
//!
//! # Why this exists (PREMORTEM T6)
//!
//! The fast lane is keyed on content, and the working tree has no content hash
//! of its own. The obvious way to get one — walk the checkout and hash every
//! file — makes the cost of *every* measurement proportional to repository size
//! rather than to diff size. On a 100k-file repository that is the latency
//! collapse T6 describes: the tool is fast on the repositories nobody needed it
//! for and unusable on the ones they did.
//!
//! So the snapshot is incremental. `git status --porcelain=v2 -z` names the
//! handful of paths that differ from `HEAD`, one batched `hash-object` turns the
//! modified ones into the blob OIDs they would have if staged, and the snapshot
//! digest covers `HEAD` plus that handful.
//!
//! # Why porcelain v2, and why it is the only scan
//!
//! Each full scan of a 100,000-entry index costs a fifth of a second before any
//! measurement happens, so the number of scans is the budget. Porcelain **v2**
//! reports, per changed path, the HEAD blob OID and the index blob OID alongside
//! the status letters — everything a `diff-index --cached` would have been run to
//! find out. One scan answers what v1 needed three to answer.
//!
//! That is also why [`super::ChangedSet`] is derived from this snapshot rather
//! than from its own `diff-index`. Two scans of a moving working tree can
//! disagree — a file edited between them appears in one and not the other — and
//! a changed set that disagrees with the cache key describing it is a bug that
//! only shows up under exactly the conditions nobody can reproduce.
//!
//! # The fallback, and why it is a different key
//!
//! [`DirtySnapshot::full_rehash`] walks every tracked file instead. It exists
//! because `status` can be unusable — a corrupt index, an fsmonitor answering
//! nonsense — and the honest response to "I cannot tell you cheaply" is to pay
//! rather than to guess. It is a **cache-miss fallback and never steady state**:
//! [`SnapshotMode`] is part of the cache key, so a fallback snapshot and an
//! incremental one over the same tree are different keys. That is deliberate.
//! Making them agree would mean deriving the full effective tree on the
//! incremental path too, which is the O(repository) walk the incremental path
//! exists to avoid. Two keys costs a cache miss; one wrong key costs a wrong
//! answer.
//!
//! # Lane
//!
//! Everything here describes uncommitted state, so everything here is advisory
//! (PREMORTEM T1). The snapshot is a *cache key input*, not a measurement: it
//! never enters a per-result digest, and
//! [`super::resolve::ResolvedRange::compare_context`] refuses to build a wire
//! tuple from an endpoint that has one.

use std::collections::BTreeMap;
use std::io::Write;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::command::{decode_record, Git, GitError};
use crate::canonical;

/// The `status` invocation, for error messages.
const STATUS_ARGV: &str = "status --porcelain=v2";
/// The `ls-files` invocation, for error messages.
const LS_FILES_ARGV: &str = "ls-files -s";
/// The `hash-object` invocation, for error messages.
const HASH_OBJECT_ARGV: &str = "hash-object --stdin-paths";

/// How a snapshot was computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotMode {
    /// `status` named the dirty set and only those files were hashed. The
    /// steady state.
    Incremental,
    /// Every tracked file was re-hashed. The fallback.
    FullRehash,
}

/// The mode git uses for an absent side.
const ABSENT_MODE: &str = "000000";
/// The gitlink mode: a submodule pointer, not a file.
const GITLINK_MODE: &str = "160000";

/// One path that differs from `HEAD`.
///
/// Serialized into the snapshot digest, so the field set is the definition of
/// "the same dirty state" and adding one changes every key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirtyEntry {
    /// The two status letters git reported, index-side then worktree-side.
    /// `??` for an untracked file.
    pub status: String,
    /// Mode in `HEAD`, or `None` when the path is new.
    pub head_mode: Option<String>,
    /// Mode in the working tree, or `None` when the path was deleted.
    pub worktree_mode: Option<String>,
    /// Blob OID in `HEAD`. `None` for a path `HEAD` does not have.
    pub head_oid: Option<String>,
    /// Blob OID of the staged content, when the path is staged.
    pub staged_oid: Option<String>,
    /// Blob OID the working-tree bytes would have if staged. `None` for a path
    /// that has been deleted, or that git could not hash.
    pub worktree_oid: Option<String>,
}

impl DirtyEntry {
    /// True when this entry is a submodule pointer rather than a file.
    pub fn is_gitlink(&self) -> bool {
        self.head_mode.as_deref() == Some(GITLINK_MODE)
            || self.worktree_mode.as_deref() == Some(GITLINK_MODE)
    }

    /// True when the path is gone from the working tree.
    pub fn is_deleted(&self) -> bool {
        self.worktree_mode.is_none()
    }

    /// True when the index holds content that `HEAD` does not.
    ///
    /// Porcelain v2 writes `.` in the index column for "unmodified there", so a
    /// staged path is any whose first status character is neither that nor the
    /// `?` of an untracked file. The distinction decides whether this entry has
    /// a blob anyone can read: staged bytes are in the object database, unstaged
    /// bytes are only on disk.
    pub fn is_staged(&self) -> bool {
        !matches!(
            self.status.as_bytes().first().copied(),
            Some(b'.') | Some(b'?') | Some(b' ') | None
        )
    }

    /// True when git reported the working-tree side as content-modified
    /// relative to the index.
    ///
    /// Porcelain v2's second status character. `.` means "unmodified there",
    /// which is the case [`super::diff`] needs so that it knows whether the
    /// index blob still describes what is on disk.
    pub fn is_worktree_modified(&self) -> bool {
        self.status.as_bytes().get(1).copied() == Some(b'M')
    }

    /// True when git reported the working-tree side as matching the index
    /// exactly.
    ///
    /// Not the negation of [`DirtyEntry::is_worktree_modified`], and the gap is
    /// the point: the worktree side can also be `D` for a path deleted from
    /// disk while its staged content remains. That is neither "modified" — there
    /// is nothing there to have been modified — nor "unmodified". Only `.` means
    /// the index blob still describes what the working tree holds.
    pub fn is_worktree_unmodified(&self) -> bool {
        self.status.as_bytes().get(1).copied() == Some(b'.')
    }

    /// Record that the working-tree side turned out to match the index after
    /// all, leaving the index side of the status untouched.
    fn clear_worktree_modification(&mut self) {
        let index_side = self.status.chars().next().unwrap_or('.');
        self.status = format!("{index_side}.");
    }

    /// True when the entry now describes no difference from `HEAD` at all.
    fn is_no_change(&self) -> bool {
        self.status == ".."
    }
}

/// The uncommitted state of a working tree, as a hashable value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirtySnapshot {
    /// Snapshot schema version. Bumping it invalidates every cache entry keyed
    /// on a snapshot, which is the intended effect of changing what a snapshot
    /// covers.
    pub version: u32,
    /// The commit the working tree sits on top of.
    pub head_oid: String,
    /// Whether only staged changes were considered (the `INDEX` sentinel) or
    /// staged and unstaged together (the `WORKTREE` sentinel).
    pub staged_only: bool,
    /// How this was computed.
    pub mode: SnapshotMode,
    /// Path to entry. `BTreeMap` and not `HashMap`: this reaches
    /// [`crate::canonical`], and randomized iteration order is one of the three
    /// independent byte-nondeterminism sources of PREMORTEM Story 1.
    pub entries: BTreeMap<String, DirtyEntry>,
}

/// The snapshot format version. See [`DirtySnapshot::version`].
pub const SNAPSHOT_VERSION: u32 = 1;

impl DirtySnapshot {
    /// Snapshot the dirty set incrementally.
    ///
    /// Two spawns: one `status --porcelain=v2`, one batched `hash-object`. The
    /// second is skipped when nothing needs hashing.
    ///
    /// `staged_only` distinguishes the `INDEX` sentinel from `WORKTREE`.
    pub fn incremental(git: &Git, head_oid: &str, staged_only: bool) -> Result<Self, GitError> {
        let raw = git
            .cmd([
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=all",
                "--no-renames",
                // Submodule *internal* dirtiness is the submodule's business.
                // A change to the gitlink itself still shows, because that is a
                // change to this repository's tree; a modified file inside the
                // submodule is not. Without this a monorepo with vendored
                // submodules reports itself permanently dirty and every cache
                // key churns.
                "--ignore-submodules=dirty",
            ])
            .output()?;

        let mut entries: BTreeMap<String, DirtyEntry> = BTreeMap::new();

        for record in parse_porcelain_v2(&raw)? {
            let PorcelainEntry {
                path,
                status,
                head_mode,
                worktree_mode,
                head_oid: entry_head_oid,
                index_oid,
                untracked,
            } = record;

            if staged_only {
                // The `INDEX` sentinel means staged content. An unstaged edit
                // (` M`) is not staged, and neither is an untracked file — git
                // spells "nothing is staged here" more than one way, and only
                // one of them is a space.
                let index_state = status.as_bytes().first().copied().unwrap_or(b' ');
                if untracked || matches!(index_state, b' ' | b'.' | b'?' | b'!') {
                    continue;
                }
            }

            entries.insert(
                path,
                DirtyEntry {
                    status,
                    head_mode,
                    worktree_mode,
                    head_oid: entry_head_oid,
                    staged_oid: index_oid,
                    worktree_oid: None,
                },
            );
        }

        if !staged_only {
            drop_conversion_phantoms(git, &mut entries)?;
        }

        // Only what survived detection gets hashed, and it gets hashed under the
        // full pins. A deleted path has no bytes to hash, and a gitlink's
        // "content" is another repository's commit.
        let to_hash: Vec<String> = if staged_only {
            Vec::new()
        } else {
            entries
                .iter()
                .filter(|(_, e)| !e.is_deleted() && !e.is_gitlink())
                .map(|(path, _)| path.clone())
                .collect()
        };
        if !to_hash.is_empty() {
            for (path, oid) in hash_paths(git, &to_hash)? {
                if let Some(entry) = entries.get_mut(&path) {
                    entry.worktree_oid = Some(oid);
                }
            }
        }

        Ok(DirtySnapshot {
            version: SNAPSHOT_VERSION,
            head_oid: head_oid.to_string(),
            staged_only,
            mode: SnapshotMode::Incremental,
            entries,
        })
    }

    /// Snapshot by re-hashing every tracked file. The cache-miss fallback.
    ///
    /// Cost is proportional to repository size, which is the reason it is not
    /// the steady state. Callers reach for it when `status` could not be
    /// trusted, and [`SnapshotMode`] records that they did.
    pub fn full_rehash(git: &Git, head_oid: &str, staged_only: bool) -> Result<Self, GitError> {
        let index = index_entries(git)?;

        let mut entries = BTreeMap::new();
        if staged_only {
            for (path, mode, oid) in index {
                entries.insert(
                    path,
                    DirtyEntry {
                        status: "..".to_string(),
                        head_mode: Some(mode.clone()),
                        worktree_mode: Some(mode),
                        head_oid: None,
                        staged_oid: Some(oid),
                        worktree_oid: None,
                    },
                );
            }
        } else {
            let present: Vec<String> = index
                .iter()
                .filter(|(path, mode, _)| {
                    mode != GITLINK_MODE && git.workdir().join(path).is_file()
                })
                .map(|(path, _, _)| path.clone())
                .collect();
            let hashed: BTreeMap<String, String> = hash_paths(git, &present)?.into_iter().collect();
            for (path, mode, oid) in index {
                // Files deleted from disk cannot be hashed; the absence is the
                // fact worth recording, so they get an entry with no worktree
                // OID rather than being dropped.
                let worktree_oid = hashed.get(&path).cloned();
                entries.insert(
                    path,
                    DirtyEntry {
                        status: "..".to_string(),
                        head_mode: Some(mode.clone()),
                        worktree_mode: worktree_oid.is_some().then_some(mode),
                        head_oid: None,
                        staged_oid: Some(oid),
                        worktree_oid,
                    },
                );
            }
        }

        Ok(DirtySnapshot {
            version: SNAPSHOT_VERSION,
            head_oid: head_oid.to_string(),
            staged_only,
            mode: SnapshotMode::FullRehash,
            entries,
        })
    }

    /// The snapshot's content hash.
    ///
    /// Infallible by construction: every field is a string, a bool, or a
    /// `BTreeMap` of them, so there is no float to be non-finite and no map to
    /// iterate in a random order. The `expect` documents that rather than hiding
    /// a possibility.
    pub fn digest(&self) -> String {
        canonical::digest(self).expect("a snapshot contains no floats and no unordered maps")
    }

    /// How many paths differ from `HEAD`.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the working tree matches `HEAD`.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One parsed porcelain-v2 record.
struct PorcelainEntry {
    path: String,
    status: String,
    head_mode: Option<String>,
    worktree_mode: Option<String>,
    head_oid: Option<String>,
    index_oid: Option<String>,
    untracked: bool,
}

/// Parse `git status --porcelain=v2 -z`.
///
/// Ordinary changes are `1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>`; untracked
/// files are `? <path>`; ignored are `! <path>`. Rename records (`2 …`) carry a
/// second path in the following NUL field and cannot appear under
/// `--no-renames`, but the parser skips their extra field anyway rather than
/// desynchronizing if a future call site drops the flag.
///
/// Unmerged records (`u …`) are a **typed refusal**, not a skip. See
/// [`GitError::ConflictedTree`]: a path with competing stages has no single
/// content, and a snapshot that quietly omitted it would key the rest of the
/// tree under a digest claiming to cover all of it. Resolution refuses
/// in-progress operations before this runs, but it does so from git's marker
/// files, and an index can hold conflicts after those are gone.
fn parse_porcelain_v2(raw: &[u8]) -> Result<Vec<PorcelainEntry>, GitError> {
    let mut records = split_nul(raw);
    let mut out = Vec::new();

    while let Some(record) = records.next() {
        // Decoded strictly, not lossily: the tail of every record is a path, and
        // a path that only survives approximately is a path that has lost its
        // identity (`GitError::UnrepresentablePath`).
        let text = decode_record(record, STATUS_ARGV)?;
        let mut fields = text.splitn(9, ' ');
        let Some(kind) = fields.next() else { continue };

        match kind {
            // `u <XY> <sub> <m1> <m2> <m3> <mW> <h1> <h2> <h3> <path>` — ten
            // fields before the path, so the path is recovered with its own
            // split rather than from the eight-field one above.
            "u" => {
                return Err(GitError::ConflictedTree {
                    path: text.splitn(11, ' ').nth(10).unwrap_or(text).to_string(),
                })
            }
            "?" | "!" => {
                let path = text[2.min(text.len())..].to_string();
                if path.is_empty() {
                    continue;
                }
                out.push(PorcelainEntry {
                    path,
                    status: "??".to_string(),
                    head_mode: None,
                    // An untracked file exists on disk by definition; git does
                    // not report its mode, and the ordinary one is right.
                    worktree_mode: Some("100644".to_string()),
                    head_oid: None,
                    index_oid: None,
                    untracked: true,
                });
            }
            "1" | "2" => {
                let parsed: Vec<&str> = fields.collect();
                let [xy, _sub, m_head, _m_index, m_worktree, h_head, h_index, rest] =
                    parsed.as_slice()
                else {
                    continue;
                };
                // A `2` record's rename score precedes the path, and its source
                // path is the next NUL field. That source is consumed as raw
                // bytes and discarded — it never becomes a key or a digest
                // input here, so it is the one path in this parser that does not
                // need decoding.
                let path = if kind == "2" {
                    let path = rest.split_once(' ').map_or(*rest, |(_score, p)| p);
                    let _source = records.next();
                    path.to_string()
                } else {
                    (*rest).to_string()
                };
                out.push(PorcelainEntry {
                    path,
                    status: (*xy).to_string(),
                    head_mode: keep_present(m_head),
                    worktree_mode: keep_present(m_worktree),
                    head_oid: keep_nonnull(h_head),
                    index_oid: keep_nonnull(h_index),
                    untracked: false,
                });
            }
            // The header lines (`#`), and anything a future git adds. Neither
            // is dirty state, and an unknown kind carries no path we would key
            // on — unlike `u`, which is refused above.
            _ => continue,
        }
    }
    Ok(out)
}

fn keep_present(mode: &str) -> Option<String> {
    (mode != ABSENT_MODE).then(|| mode.to_string())
}

fn keep_nonnull(oid: &str) -> Option<String> {
    (!oid.bytes().all(|b| b == b'0')).then(|| oid.to_string())
}

/// Remove the dirt that only our pins can see.
///
/// # The failure this exists to stop
///
/// A clone made with `core.autocrlf=true` — the Git-for-Windows default — has
/// CRLF on disk for every text file, put there by that conversion. Its own
/// `git status` is clean. Ours, asking with `core.autocrlf=false` pinned, called
/// all 200 files of a probe repository modified: the on-disk bytes were produced
/// by a conversion the question refused to acknowledge.
///
/// Two consequences, and the second is worse than the first. The dirty set is
/// nonsense, so `WORKTREE` measurements on such a checkout enumerate the whole
/// repository. And the answer is *unstable*: our `status` refreshes the index
/// stat cache on the way past, so the second run agrees with the clone and the
/// first does not. One untouched tree, two cache keys.
///
/// # What it does
///
/// Every entry git reports as worktree-modified against an index blob is a
/// suspect. One batched `hash-object` — the only invocation in the workspace
/// that lets the checkout's own conversion speak, see
/// [`Git::cmd_in_checkout_conversion`] — asks what those files hash to *in the
/// terms that produced them*. Where that equals the index blob **and the mode
/// has not moved**, the working-tree side was never modified, and the status
/// letter is corrected: a `.M` becomes `..` and the entry is dropped entirely,
/// an `MM` becomes `M.` and keeps its staged change.
///
/// The mode condition is not belt and braces. `chmod +x` on a file whose content
/// is untouched produces the same `.M` with the same blob OID on both sides, and
/// it is a real change that has to reach the cache key — which is the stated
/// reason [`super::command::PINNED_CONFIG`] leaves `core.fileMode` alone.
///
/// # What it does not do
///
/// It never records an OID. Membership of the dirty set is decided here;
/// everything that survives is hashed under the full pins by the caller, so
/// PREMORTEM T1 is untouched — no byte reaching a digest was hashed under a
/// configuration the machine chose.
///
/// # Cost
///
/// One extra spawn on a dirty `WORKTREE` pass that has suspects, and none on a
/// clean tree, a commit range, or the `INDEX` sentinel. Batched, so it is one
/// process whether there is one suspect or a thousand.
fn drop_conversion_phantoms(
    git: &Git,
    entries: &mut BTreeMap<String, DirtyEntry>,
) -> Result<(), GitError> {
    let suspects: Vec<String> = entries
        .iter()
        .filter(|(_, entry)| {
            entry.is_worktree_modified()
                && entry.staged_oid.is_some()
                && !entry.is_deleted()
                && !entry.is_gitlink()
        })
        .map(|(path, _)| path.clone())
        .collect();
    if suspects.is_empty() {
        return Ok(());
    }

    for (path, effective_oid) in hash_paths_as(git, &suspects, Conversion::Checkout)? {
        let Some(entry) = entries.get_mut(&path) else {
            continue;
        };
        // Content agreement is not enough. `chmod +x` on an unchanged file is
        // reported `.M` with both blob OIDs identical and only the mode moved,
        // which is the exact shape of a conversion phantom — and it is a real
        // change to the tree. This module's own docs say `core.fileMode` is left
        // unpinned *because* a mode change has to reach the cache key, so
        // clearing on the OID alone would contradict the invariant one file
        // over. A conversion never changes a mode, so every genuine phantom
        // still clears.
        //
        // The mode compared is `HEAD`'s rather than the index's, which the
        // parser discards. For an unstaged edit the two are the same. For a
        // staged mode change followed by a conversion-only worktree difference
        // they are not, and the entry stays `MM` where `M.` would have been
        // exact — a path that is genuinely dirty being reported as slightly
        // more dirty, which is the direction to be wrong in.
        let mode_unchanged = entry.head_mode.is_none() || entry.worktree_mode == entry.head_mode;
        if mode_unchanged && entry.staged_oid.as_deref() == Some(effective_oid.as_str()) {
            entry.clear_worktree_modification();
        }
    }
    entries.retain(|_, entry| !entry.is_no_change());
    Ok(())
}

/// Every path in the index with its mode and blob OID.
fn index_entries(git: &Git) -> Result<Vec<(String, String, String)>, GitError> {
    let raw = git.cmd(["ls-files", "-s", "-z"]).output()?;
    let mut out = Vec::new();
    for record in split_nul(&raw) {
        // `<mode> SP <oid> SP <stage> TAB <path>`
        let text = decode_record(record, LS_FILES_ARGV)?;
        let Some((meta, path)) = text.split_once('\t') else {
            continue;
        };
        let fields: Vec<&str> = meta.split(' ').collect();
        if let [mode, oid, _stage] = fields.as_slice() {
            out.push((path.to_string(), (*mode).to_string(), (*oid).to_string()));
        }
    }
    Ok(out)
}

/// Blob OIDs the given working-tree files would have if staged.
///
/// One spawn for any number of paths (`--stdin-paths`), which is what keeps the
/// asserted spawn count flat as the dirty set grows. `-w` is deliberately absent:
/// measuring must not write objects into the repository it is measuring.
///
/// Check-in filters are left on. Under this crate's pinned config that means no
/// CRLF translation, but repository `.gitattributes` still apply — so the OID a
/// path gets here is the OID `git add` would give it, and staging a file does not
/// move the cache key.
///
/// # Why some paths are refused
///
/// `--stdin-paths` is a line-oriented protocol with no NUL variant: git reads one
/// path per line, strips a trailing carriage return, and treats a leading `"` as
/// the start of a C-quoted path. All three are legal bytes in a POSIX filename,
/// and each desynchronizes the exchange in the same silent way — the count of
/// OIDs coming back stops matching the count of paths going out, or worse
/// happens to match while every OID after the offending path belongs to the
/// wrong file. The arity check below would catch the first; nothing would catch
/// the second. So they are refused up front, with the same
/// [`GitError::UnrepresentablePath`] that covers a path we cannot carry for the
/// other reason.
fn hash_paths(git: &Git, paths: &[String]) -> Result<Vec<(String, String)>, GitError> {
    hash_paths_as(git, paths, Conversion::Pinned)
}

/// Whose line-ending rules a hash is taken under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Conversion {
    /// This crate's pins. Every OID that is recorded anywhere.
    Pinned,
    /// The checkout's own. Detection only — see [`drop_conversion_phantoms`].
    Checkout,
}

fn hash_paths_as(
    git: &Git,
    paths: &[String],
    conversion: Conversion,
) -> Result<Vec<(String, String)>, GitError> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    for path in paths {
        check_stdin_path(path)?;
    }
    let command = match conversion {
        Conversion::Pinned => git.cmd(["hash-object", "--stdin-paths"]),
        Conversion::Checkout => git.cmd_in_checkout_conversion(["hash-object", "--stdin-paths"]),
    };
    let mut child = command.spawn_piped()?;
    let mut stdin = child.stdin.take().expect("stdin was piped");

    // Paths go out on one thread while OIDs come back on another. Writing the
    // whole list first deadlocks once it exceeds the pipe buffer: git blocks
    // writing OIDs nobody is reading, and we block writing paths nobody is
    // reading. At 100k dirty files that is not a hypothetical.
    let written: Vec<String> = paths.to_vec();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        for path in &written {
            writeln!(stdin, "{path}")?;
        }
        stdin.flush()?;
        drop(stdin);
        Ok(())
    });

    let output = child.wait_with_output().map_err(|source| GitError::Spawn {
        argv: HASH_OBJECT_ARGV.to_string(),
        source,
    })?;
    let write_result = writer.join();

    if !output.status.success() {
        return Err(GitError::Failed {
            argv: HASH_OBJECT_ARGV.to_string(),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    match write_result {
        Ok(Ok(())) => {}
        Ok(Err(source)) => {
            return Err(GitError::Spawn {
                argv: HASH_OBJECT_ARGV.to_string(),
                source,
            })
        }
        Err(_) => {
            return Err(GitError::Protocol {
                argv: HASH_OBJECT_ARGV.to_string(),
                detail: "the path-writing thread panicked".to_string(),
            })
        }
    }

    let text = String::from_utf8(output.stdout).map_err(|_| GitError::NotUtf8 {
        argv: HASH_OBJECT_ARGV.to_string(),
    })?;
    let oids: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if oids.len() != paths.len() {
        return Err(GitError::Protocol {
            argv: HASH_OBJECT_ARGV.to_string(),
            detail: format!("asked for {} hashes, got {}", paths.len(), oids.len()),
        });
    }
    Ok(paths
        .iter()
        .cloned()
        .zip(oids.into_iter().map(str::to_string))
        .collect())
}

/// Refuse a path `hash-object --stdin-paths` would misread.
///
/// See [`hash_paths`] for why each of these breaks the protocol. Every one is a
/// legal filename on a POSIX filesystem, so this is a refusal rather than an
/// assertion.
fn check_stdin_path(path: &str) -> Result<(), GitError> {
    let detail = if path.contains('\n') {
        "contains a newline, and `hash-object --stdin-paths` reads one path per \
         line with no NUL-delimited form"
    } else if path.contains('\r') {
        "contains a carriage return, which `hash-object --stdin-paths` strips \
         from the end of a line"
    } else if path.starts_with('"') {
        "starts with a double quote, which `hash-object --stdin-paths` reads as \
         the opening of a C-quoted path"
    } else {
        return Ok(());
    };
    Err(GitError::UnrepresentablePath {
        argv: HASH_OBJECT_ARGV.to_string(),
        detail: detail.to_string(),
        lossy: path.escape_debug().to_string(),
    })
}

/// Split NUL-delimited output, dropping the empty tail.
///
/// `-z` is used everywhere a path can appear, because the alternative is git's
/// quoted form — and that form is exactly what `core.quotepath` changes.
pub(crate) fn split_nul(raw: &[u8]) -> impl Iterator<Item = &[u8]> {
    raw.split(|b| *b == 0).filter(|r| !r.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(mode: SnapshotMode, entries: BTreeMap<String, DirtyEntry>) -> DirtySnapshot {
        DirtySnapshot {
            version: SNAPSHOT_VERSION,
            head_oid: "1".repeat(40),
            staged_only: false,
            mode,
            entries,
        }
    }

    fn entry(oid: &str) -> DirtyEntry {
        DirtyEntry {
            status: ".M".to_string(),
            head_mode: Some("100644".to_string()),
            worktree_mode: Some("100644".to_string()),
            head_oid: Some("9".repeat(40)),
            staged_oid: None,
            worktree_oid: Some(oid.to_string()),
        }
    }

    #[test]
    fn the_digest_tracks_content_and_not_insertion_order() {
        let mut a = BTreeMap::new();
        a.insert("z.ts".to_string(), entry(&"a".repeat(40)));
        a.insert("a.ts".to_string(), entry(&"b".repeat(40)));
        let mut b = BTreeMap::new();
        b.insert("a.ts".to_string(), entry(&"b".repeat(40)));
        b.insert("z.ts".to_string(), entry(&"a".repeat(40)));
        assert_eq!(
            snapshot(SnapshotMode::Incremental, a).digest(),
            snapshot(SnapshotMode::Incremental, b).digest()
        );
    }

    #[test]
    fn a_changed_file_changes_the_digest() {
        let mut a = BTreeMap::new();
        a.insert("a.ts".to_string(), entry(&"a".repeat(40)));
        let mut b = BTreeMap::new();
        b.insert("a.ts".to_string(), entry(&"c".repeat(40)));
        assert_ne!(
            snapshot(SnapshotMode::Incremental, a).digest(),
            snapshot(SnapshotMode::Incremental, b).digest()
        );
    }

    #[test]
    fn the_mode_is_part_of_the_digest() {
        // The fallback and the steady-state path describe the tree differently,
        // so their snapshots must never collide into one cache entry.
        let entries = BTreeMap::new();
        assert_ne!(
            snapshot(SnapshotMode::Incremental, entries.clone()).digest(),
            snapshot(SnapshotMode::FullRehash, entries).digest()
        );
    }

    #[test]
    fn nul_splitting_drops_the_trailing_empty_record() {
        let records: Vec<&[u8]> = split_nul(b" M a.ts\0?? b.ts\0").collect();
        assert_eq!(records, vec![&b" M a.ts"[..], &b"?? b.ts"[..]]);
    }

    #[test]
    fn porcelain_v2_yields_both_the_head_and_index_blob_oids() {
        // The whole reason for v2 over v1: these two OIDs arrive free, where v1
        // would need a second full scan of the index to learn them.
        let raw = b"1 .M N... 100644 100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb src/a.ts\0";
        let parsed = parse_porcelain_v2(raw).expect("no unmerged record");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].path, "src/a.ts");
        assert_eq!(parsed[0].status, ".M");
        assert_eq!(parsed[0].head_oid.as_deref(), Some(&"a".repeat(40)[..]));
        assert_eq!(parsed[0].index_oid.as_deref(), Some(&"b".repeat(40)[..]));
        assert!(!parsed[0].untracked);
    }

    #[test]
    fn a_deleted_path_has_no_worktree_mode() {
        let raw = b"1 .D N... 100644 100644 000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa src/gone.ts\0";
        let parsed = parse_porcelain_v2(raw).expect("no unmerged record");
        assert_eq!(parsed[0].worktree_mode, None);
        assert_eq!(parsed[0].head_mode.as_deref(), Some("100644"));
    }

    #[test]
    fn an_untracked_file_is_reported_with_its_path_intact() {
        let raw = b"? src/new file.ts\0";
        let parsed = parse_porcelain_v2(raw).expect("no unmerged record");
        assert_eq!(parsed[0].path, "src/new file.ts");
        assert!(parsed[0].untracked);
        assert_eq!(parsed[0].head_oid, None);
    }

    #[test]
    fn a_path_the_stdin_protocol_would_misread_is_refused() {
        // Every one of these is a legal POSIX filename, and every one of them
        // desynchronizes `--stdin-paths`. The newline is the sharp case: git
        // reads two paths where one was sent, and every OID after it is
        // attributed to the wrong file.
        for path in ["src/two\nlines.ts", "src/trailing\r.ts", "\"quoted.ts"] {
            match check_stdin_path(path) {
                Err(GitError::UnrepresentablePath { detail, .. }) => {
                    assert!(detail.contains("hash-object"), "{detail}")
                }
                other => panic!("expected a refusal for {path:?}, got {other:?}"),
            }
        }
        // And the ordinary awkward ones still go through: a space, a quote that
        // is not leading, and non-ASCII are all fine on this protocol.
        for path in ["src/a file.ts", "src/says\"hello\".ts", "src/naïve.ts"] {
            assert!(check_stdin_path(path).is_ok(), "{path} should be fine");
        }
    }

    #[test]
    fn a_status_path_that_is_not_utf8_is_refused_rather_than_approximated() {
        // The snapshot's `entries` is keyed by path, so a lossy decode is a
        // silent collision: two files, one key, one of them gone from a digest
        // that claims to cover the tree.
        let raw = b"1 .M N... 100644 100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb src/\xff.ts\0";
        match parse_porcelain_v2(raw) {
            Err(GitError::UnrepresentablePath { lossy, .. }) => {
                assert!(lossy.contains("src/"), "the operator needs a signpost")
            }
            Err(other) => panic!("expected UnrepresentablePath, got {other}"),
            Ok(entries) => panic!("expected a refusal, got {} entries", entries.len()),
        }
    }

    #[test]
    fn an_untracked_path_that_is_not_utf8_is_refused_too() {
        // Untracked files reach the advisory lane rather than the compared one,
        // and they are still map keys.
        let raw = b"? src/\xff.ts\0";
        assert!(matches!(
            parse_porcelain_v2(raw),
            Err(GitError::UnrepresentablePath { .. })
        ));
    }

    #[test]
    fn an_unmerged_record_is_refused_and_names_the_path() {
        // Ten fields precede the path on a `u` record, which is why it gets its
        // own split. A parser that reused the eight-field one would report a
        // stage OID as the conflicted path.
        let raw = b"u UU N... 100644 100644 100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccccccccccc src/conflicted.ts\0";
        match parse_porcelain_v2(raw) {
            Err(GitError::ConflictedTree { path }) => assert_eq!(path, "src/conflicted.ts"),
            Err(other) => panic!("expected a ConflictedTree refusal, got {other}"),
            Ok(entries) => panic!(
                "expected a ConflictedTree refusal, got {} parsed entries",
                entries.len()
            ),
        }
    }

    #[test]
    fn one_unmerged_path_refuses_the_whole_snapshot() {
        // Not "the conflicted entry is dropped and the rest is keyed": the rest
        // would then be hashed under a digest claiming to describe the whole
        // tree.
        let raw = b"1 .M N... 100644 100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb src/clean-edit.ts\0u UU N... 100644 100644 100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccccccccccc src/conflicted.ts\0";
        assert!(matches!(
            parse_porcelain_v2(raw),
            Err(GitError::ConflictedTree { .. })
        ));
    }

    #[test]
    fn a_rename_record_does_not_desynchronize_the_parser() {
        // `--no-renames` means these should not arrive, but a parser that
        // consumed the wrong number of NUL fields would attribute every later
        // record to the wrong path — silently.
        let raw = b"2 R. N... 100644 100644 100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb R100 new.ts\0old.ts\0? after.ts\0";
        let parsed = parse_porcelain_v2(raw).expect("no unmerged record");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, "new.ts");
        assert_eq!(parsed[1].path, "after.ts");
    }
}

/// Snapshot constructors for tests in this crate and its integration tests.
///
/// Compiled into the library for the reason [`crate::testing`] is: fixtures
/// built from one shape stop diverging, and a schema change breaks them all in
/// one place rather than in five.
pub mod testing {
    use super::*;

    /// A snapshot with no dirty entries, for keying tests that care only about
    /// identity.
    pub fn empty_snapshot(head_oid: &str, staged_only: bool, mode: SnapshotMode) -> DirtySnapshot {
        DirtySnapshot {
            version: SNAPSHOT_VERSION,
            head_oid: head_oid.to_string(),
            staged_only,
            mode,
            entries: BTreeMap::new(),
        }
    }
}
