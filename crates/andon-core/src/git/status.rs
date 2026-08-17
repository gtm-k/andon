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
//! So the snapshot is incremental. `git status --porcelain -z` names the handful
//! of paths that differ from `HEAD`, one batched `hash-object` turns them into
//! the blob OIDs they would have if staged, and the snapshot digest covers
//! `HEAD` plus that handful. Work is proportional to the dirty set, and git's
//! own stat cache — accelerated by fsmonitor where the platform has it — is what
//! keeps finding the dirty set cheap.
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
//! never enters a per-result digest, and [`super::resolve::ResolvedRange::compare_context`]
//! refuses to build a wire tuple from an endpoint that has one.

use std::collections::BTreeMap;
use std::io::Write;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::command::{Git, GitError};
use crate::canonical;

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

/// One path that differs from `HEAD`.
///
/// Serialized into the snapshot digest, so the field set is the definition of
/// "the same dirty state" and adding one changes every key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirtyEntry {
    /// The two status letters git reported, index-side then worktree-side.
    pub status: String,
    /// Blob OID of the staged content, when the path is staged.
    pub staged_oid: Option<String>,
    /// Blob OID the working-tree bytes would have if staged. `None` for a path
    /// that has been deleted, or that git could not hash.
    pub worktree_oid: Option<String>,
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
    /// Snapshot the dirty set incrementally. Two spawns: `status`, then one
    /// batched `hash-object`.
    ///
    /// `staged_only` distinguishes the `INDEX` sentinel from `WORKTREE`.
    pub fn incremental(git: &Git, head_oid: &str, staged_only: bool) -> Result<Self, GitError> {
        let raw = git
            .cmd([
                "status",
                "--porcelain=v1",
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
        let mut to_hash: Vec<String> = Vec::new();

        for record in split_nul(&raw) {
            // `XY<space><path>`, with `--no-renames` guaranteeing one path per
            // record. Anything shorter is not a status record.
            if record.len() < 4 {
                continue;
            }
            let status = String::from_utf8_lossy(&record[..2]).into_owned();
            let path = String::from_utf8_lossy(&record[3..]).into_owned();
            let index_state = record[0];
            let worktree_state = record[1];

            // The `INDEX` sentinel means staged content. An unstaged edit (` M`)
            // is not staged, and neither is an untracked file (`??`) or an
            // ignored one (`!!`) — git spells "nothing is staged here" three
            // different ways, and only the first is a space.
            if staged_only && matches!(index_state, b' ' | b'?' | b'!') {
                continue;
            }
            // A deleted path has no bytes to hash. `D` on the worktree side
            // means gone from disk; `D` on the index side with a clean worktree
            // means staged for deletion.
            let deleted = worktree_state == b'D' || (staged_only && index_state == b'D');
            if !deleted {
                to_hash.push(path.clone());
            }
            entries.insert(
                path,
                DirtyEntry {
                    status,
                    staged_oid: None,
                    worktree_oid: None,
                },
            );
        }

        // Staged blob OIDs come from the index directly — they are already
        // objects, so hashing the worktree copy would be both slower and wrong
        // for a path staged at one content and edited to another.
        if !entries.is_empty() {
            let staged = staged_blob_oids(git, head_oid)?;
            for (path, oid) in staged {
                if let Some(entry) = entries.get_mut(&path) {
                    entry.staged_oid = Some(oid);
                }
            }
        }

        if !staged_only && !to_hash.is_empty() {
            let hashed = hash_paths(git, &to_hash)?;
            for (path, oid) in hashed {
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
        let raw = git.cmd(["ls-files", "-z", "--cached"]).output()?;
        let paths: Vec<String> = split_nul(&raw)
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();

        let mut entries = BTreeMap::new();
        if staged_only {
            for (path, oid) in index_blob_oids(git)? {
                entries.insert(
                    path,
                    DirtyEntry {
                        status: "??".to_string(),
                        staged_oid: Some(oid),
                        worktree_oid: None,
                    },
                );
            }
        } else {
            // Files deleted from disk cannot be hashed; the absence is the fact
            // worth recording, so they get an entry with no worktree OID rather
            // than being dropped.
            let present: Vec<String> = paths
                .iter()
                .filter(|p| git.workdir().join(p).is_file())
                .cloned()
                .collect();
            let hashed: BTreeMap<String, String> = hash_paths(git, &present)?.into_iter().collect();
            for path in paths {
                let worktree_oid = hashed.get(&path).cloned();
                entries.insert(
                    path,
                    DirtyEntry {
                        status: "??".to_string(),
                        staged_oid: None,
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

/// Staged blob OIDs for paths that differ from `head_oid`.
fn staged_blob_oids(git: &Git, head_oid: &str) -> Result<Vec<(String, String)>, GitError> {
    let raw = git
        .cmd([
            "diff-index",
            "--cached",
            "-r",
            "--raw",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            head_oid,
        ])
        .output()?;
    Ok(super::diff::parse_raw(&raw)
        .into_iter()
        .filter_map(|entry| {
            entry
                .dst_oid
                .filter(|_| entry.dst_mode.as_deref() != Some("160000"))
                .map(|oid| (entry.path, oid))
        })
        .collect())
}

/// Every path in the index with its blob OID.
fn index_blob_oids(git: &Git) -> Result<Vec<(String, String)>, GitError> {
    let raw = git.cmd(["ls-files", "-s", "-z"]).output()?;
    let mut out = Vec::new();
    for record in split_nul(&raw) {
        // `<mode> SP <oid> SP <stage> TAB <path>`
        let text = String::from_utf8_lossy(record);
        let Some((meta, path)) = text.split_once('\t') else {
            continue;
        };
        let fields: Vec<&str> = meta.split(' ').collect();
        if let [mode, oid, _stage] = fields.as_slice() {
            if *mode != "160000" {
                out.push((path.to_string(), (*oid).to_string()));
            }
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
fn hash_paths(git: &Git, paths: &[String]) -> Result<Vec<(String, String)>, GitError> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut child = git.cmd(["hash-object", "--stdin-paths"]).spawn_piped()?;
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
        argv: "hash-object --stdin-paths".to_string(),
        source,
    })?;
    let write_result = writer.join();

    if !output.status.success() {
        return Err(GitError::Failed {
            argv: "hash-object --stdin-paths".to_string(),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    match write_result {
        Ok(Ok(())) => {}
        Ok(Err(source)) => {
            return Err(GitError::Spawn {
                argv: "hash-object --stdin-paths".to_string(),
                source,
            })
        }
        Err(_) => {
            return Err(GitError::Protocol {
                argv: "hash-object --stdin-paths".to_string(),
                detail: "the path-writing thread panicked".to_string(),
            })
        }
    }

    let text = String::from_utf8(output.stdout).map_err(|_| GitError::NotUtf8 {
        argv: "hash-object --stdin-paths".to_string(),
    })?;
    let oids: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if oids.len() != paths.len() {
        return Err(GitError::Protocol {
            argv: "hash-object --stdin-paths".to_string(),
            detail: format!("asked for {} hashes, got {}", paths.len(), oids.len()),
        });
    }
    Ok(paths
        .iter()
        .cloned()
        .zip(oids.into_iter().map(str::to_string))
        .collect())
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
            status: " M".to_string(),
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
}
