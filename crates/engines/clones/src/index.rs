//! The incremental clone index: what it holds, how it is written, and why an
//! incremental update is the same artefact as a cold rebuild.
//!
//! PREMORTEM T2 rates this crippling and names three ways it fails: an
//! incremental index that disagrees with a cold rebuild, corruption from
//! concurrent writers, and a torn write from a crash. Each has a mechanism here
//! rather than a convention.
//!
//! # Equality with a cold rebuild is structural, not hoped for
//!
//! An entry is keyed by the git blob OID of the file it describes, which *is*
//! the content — so a reused entry and a recomputed one are equal by
//! construction. What is left to get wrong is the set of entries: a stale
//! posting for a path that was deleted or renamed away is the classic
//! incremental-index bug, and it is invisible until a clone is reported against
//! a file that no longer exists. [`Index::update`] therefore rebuilds the map
//! from the input set rather than mutating in place — entries are *carried
//! over*, never left behind. `tests/incremental_equivalence.rs` drives edit,
//! rename, and delete sequences through proptest and asserts the serialized
//! index and the sealed results are byte-identical to a cold build.
//!
//! # Reading is checked, and a failed check rebuilds in silence
//!
//! The file carries a format version and a SHA-256 over its payload. A version
//! this build does not know, a checksum that does not match, or a regime key
//! from different grammars all resolve the same way: [`Index::load`] returns
//! `None` and the caller rebuilds. Silent rebuild is the *correct* loudness
//! here — the index is derived state, recomputing it is slower and no less
//! correct, and an error surfaced to an agent mid-loop about a cache would be
//! noise it cannot act on. What must never happen is reinterpreting bytes
//! written under other rules, and the version and checksum are what stop that.
//!
//! # Writing is atomic, and writers are serialized by an advisory lock
//!
//! Bytes go to a temporary file in the destination directory and are renamed
//! over the target, so a reader sees the whole index or the previous one, never
//! half. [`IndexLock`] is a `create_new` lock file with a staleness timeout: it
//! keeps two Andon processes in one repository from interleaving, and it is
//! advisory by construction — a writer that ignores it is not prevented, which
//! is why the checksum exists underneath.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fingerprint;
use crate::syntax;

/// On-disk format version. A file written under a different one is not read.
pub const INDEX_FORMAT_VERSION: u32 = 1;

/// Magic prefix, so a stray file is rejected before it is parsed.
const MAGIC: &str = "andon-clone-index";

/// How long a lock file may go untouched before a later writer treats it as
/// abandoned. Long enough that a slow index build on a large repository is not
/// stolen from, short enough that a crashed process does not wedge a repository
/// until someone deletes a file by hand.
pub const LOCK_STALE: Duration = Duration::from_secs(600);

/// Anything that stopped the index from being read or written.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    /// A filesystem operation failed.
    #[error("clone index I/O failed at {path}: {source}")]
    Io {
        /// What was being touched.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The index could not be serialized.
    #[error("clone index could not be serialized: {0}")]
    Serialize(#[from] serde_json::Error),
    /// Another process holds the lock and has not gone stale.
    #[error("another Andon process holds the clone index lock at {path}")]
    Locked {
        /// The lock file.
        path: String,
    },
}

fn io(path: &Path, source: std::io::Error) -> IndexError {
    IndexError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// One file's fingerprints.
///
/// `symbols` is kept alongside `windows` so a window-hash match can be
/// confirmed against the real token sequence. Storing only the hashes would
/// make a collision indistinguishable from a clone, and the compare set has no
/// room for a probabilistic answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Git blob OID of the bytes this entry describes. The content identity
    /// that makes reuse equal to recomputation.
    pub blob_oid: String,
    /// Normalized symbol hashes, in source order.
    pub symbols: Vec<u64>,
    /// Byte span of each token, parallel to `symbols`, for line reporting.
    pub spans: Vec<(u32, u32)>,
    /// Zero-based start row of each token, parallel to `symbols`.
    pub rows: Vec<u32>,
    /// Rolling window hashes. Empty when the file is shorter than one window.
    pub windows: Vec<u64>,
}

impl FileEntry {
    /// Tokenize and fingerprint one file.
    ///
    /// `None` when no grammar reads the path — an unmeasured file is left out
    /// of the index entirely rather than entered as an empty one, so the index
    /// never implies it looked at something it cannot read.
    pub fn build(path: &str, blob_oid: &str, source: &[u8]) -> Option<FileEntry> {
        let tokens = syntax::tokenize(path, source)?;
        let symbols: Vec<u64> = tokens.iter().map(|t| t.symbol).collect();
        let windows = fingerprint::windows(&symbols);
        Some(FileEntry {
            blob_oid: blob_oid.to_string(),
            spans: tokens.iter().map(|t| (t.start_byte, t.end_byte)).collect(),
            rows: tokens.iter().map(|t| t.start_row).collect(),
            symbols,
            windows,
        })
    }

    /// Token count.
    pub fn token_count(&self) -> usize {
        self.symbols.len()
    }
}

/// One file offered to the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInput {
    /// Repository-relative path with forward slashes, as git spells it.
    pub path: String,
    /// Git blob OID of `source`.
    pub blob_oid: String,
    /// The bytes. Read from the blob, never from the working tree, so the
    /// fingerprint is checkout-independent (PREMORTEM T1).
    pub source: Vec<u8>,
}

/// The index itself.
///
/// `BTreeMap`, never `HashMap`: iteration order reaches the serializer and the
/// detection order, and a randomized order is one of the three independent
/// byte-nondeterminism sources of PREMORTEM Story 1.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    /// Format version of the in-memory shape, mirrored on disk.
    pub version: u32,
    /// Tokenizer and parameter identity. An index built under other grammars or
    /// window sizes describes different numbers and is discarded, not merged.
    pub regime_key: String,
    /// Entries by repository-relative path.
    pub files: BTreeMap<String, FileEntry>,
}

/// The tokenizer-and-parameter identity an index is only valid under.
pub fn regime_key() -> String {
    format!(
        "{}|{}|w{}|m{}",
        fingerprint::ALGORITHM,
        syntax::normalization_revision(),
        fingerprint::WINDOW_TOKENS,
        fingerprint::MIN_CLONE_TOKENS,
    )
}

impl Index {
    /// An empty index for the current regime.
    pub fn empty() -> Index {
        Index {
            version: INDEX_FORMAT_VERSION,
            regime_key: regime_key(),
            files: BTreeMap::new(),
        }
    }

    /// Produce the index describing exactly `inputs`, reusing what is already
    /// known.
    ///
    /// The result is a function of `inputs` alone. Nothing survives that is not
    /// named in the input set — which is what makes an incremental update and a
    /// cold rebuild the same artefact, and what stops a rename from leaving its
    /// old path behind. `reused` counts the entries carried over; it is
    /// diagnostic and deliberately never becomes a measured value, because it
    /// depends on cache state rather than on the change (PLAN P3: only
    /// cold-reproducible values enter the compare set).
    pub fn update(&self, inputs: &[FileInput]) -> (Index, usize) {
        let mut next = Index::empty();
        let mut reused = 0usize;
        for input in inputs {
            let carried = self
                .files
                .get(&input.path)
                .filter(|entry| entry.blob_oid == input.blob_oid)
                .filter(|_| self.regime_key == next.regime_key)
                .cloned();
            let entry = match carried {
                Some(entry) => {
                    reused += 1;
                    Some(entry)
                }
                None => FileEntry::build(&input.path, &input.blob_oid, &input.source),
            };
            if let Some(entry) = entry {
                next.files.insert(input.path.clone(), entry);
            }
        }
        (next, reused)
    }

    /// The bytes this index serializes to. Stable, and the unit the property
    /// test compares.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IndexError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Read an index, or `None` when there is nothing usable to read.
    ///
    /// Every rejection is silent by design — see the module docs. The reasons
    /// are returned to the caller through [`LoadOutcome`] so a diagnostic
    /// surface can say which one fired without the caller having to guess.
    pub fn load(path: &Path) -> LoadOutcome {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return LoadOutcome::Absent;
            }
            Err(_) => return LoadOutcome::Unreadable,
        };
        let Some(newline) = bytes.iter().position(|b| *b == b'\n') else {
            return LoadOutcome::Unreadable;
        };
        let (header, rest) = bytes.split_at(newline);
        let payload = &rest[1..];
        let Ok(header) = std::str::from_utf8(header) else {
            return LoadOutcome::Unreadable;
        };
        let mut fields = header.split(' ');
        if fields.next() != Some(MAGIC) {
            return LoadOutcome::Unreadable;
        }
        let version = fields.next().and_then(|v| v.strip_prefix('v'));
        if version != Some(&INDEX_FORMAT_VERSION.to_string()) {
            return LoadOutcome::VersionMismatch;
        }
        let Some(expected) = fields.next() else {
            return LoadOutcome::Unreadable;
        };
        if hex(&Sha256::digest(payload)) != expected {
            return LoadOutcome::ChecksumMismatch;
        }
        let Ok(index) = serde_json::from_slice::<Index>(payload) else {
            return LoadOutcome::Unreadable;
        };
        if index.version != INDEX_FORMAT_VERSION {
            return LoadOutcome::VersionMismatch;
        }
        if index.regime_key != regime_key() {
            return LoadOutcome::RegimeMismatch;
        }
        LoadOutcome::Loaded(Box::new(index))
    }

    /// Write the index, atomically.
    ///
    /// The two halves are separable ([`Index::write_pending`] then
    /// [`PendingIndex::publish`]) and this is their composition. Splitting them
    /// is not a test hook bolted on: it is what lets a caller prepare an index
    /// and decide later whether to publish it, and it is what makes the crash
    /// window addressable — `tests/crash_recovery.rs` runs the first half in a
    /// child process that then aborts, which is a crash mid-write with no
    /// timing race to make the test flaky.
    pub fn store(&self, path: &Path) -> Result<(), IndexError> {
        self.write_pending(path)?.publish()
    }

    /// Write the bytes to a temporary beside `path`, without publishing them.
    ///
    /// The temporary lives in the destination directory so the eventual rename
    /// stays on one filesystem: a cross-device rename is a copy, and a copy is
    /// not atomic.
    pub fn write_pending(&self, path: &Path) -> Result<PendingIndex, IndexError> {
        let payload = self.to_bytes()?;
        let header = format!(
            "{MAGIC} v{INDEX_FORMAT_VERSION} {}\n",
            hex(&Sha256::digest(&payload))
        );

        let parent = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        sweep_abandoned_temps(path);
        let temp = temp_path(path);
        {
            let mut file = std::fs::File::create(&temp).map_err(|e| io(&temp, e))?;
            file.write_all(header.as_bytes())
                .map_err(|e| io(&temp, e))?;
            file.write_all(&payload).map_err(|e| io(&temp, e))?;
            // Durability before visibility: a rename that lands before the data
            // does would publish a file whose checksum fails after a power
            // loss. The checksum would catch it — this keeps it from happening.
            file.sync_all().map_err(|e| io(&temp, e))?;
        }
        Ok(PendingIndex {
            temp,
            target: path.to_path_buf(),
        })
    }
}

/// An index written to disk and not yet visible.
///
/// Dropping one without publishing leaves the temporary behind. That is the
/// intended failure shape — garbage rather than corruption, in the cache
/// store's phrase — and the next writer sweeps it (see
/// [`Index::write_pending`]).
#[derive(Debug)]
pub struct PendingIndex {
    temp: PathBuf,
    target: PathBuf,
}

impl PendingIndex {
    /// Make the written bytes the index, atomically.
    ///
    /// `fs::rename` replaces an existing destination on Windows as well as on
    /// Unix, so there is no unlink-then-rename window in which the index does
    /// not exist.
    pub fn publish(self) -> Result<(), IndexError> {
        std::fs::rename(&self.temp, &self.target).map_err(|e| io(&self.target, e))
    }

    /// The temporary file holding the unpublished bytes.
    pub fn temp_path(&self) -> &Path {
        &self.temp
    }
}

/// Remove temporaries abandoned by a writer that died before publishing.
///
/// Best effort and deliberately silent: a temp that cannot be removed is
/// wasted disk, not a wrong answer, and the caller is in the middle of writing
/// an index. Only files older than [`LOCK_STALE`] are touched, so a concurrent
/// writer's live temporary is never taken out from under it.
fn sweep_abandoned_temps(index_path: &Path) {
    let Some(parent) = index_path.parent() else {
        return;
    };
    let Some(stem) = index_path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let prefix = format!("{stem}.tmp-");
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(&prefix) {
            continue;
        }
        let abandoned = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .map(|modified| {
                SystemTime::now()
                    .duration_since(modified)
                    .map(|age| age > LOCK_STALE)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if abandoned {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Why [`Index::load`] returned what it did.
#[derive(Debug)]
pub enum LoadOutcome {
    /// A usable index.
    Loaded(Box<Index>),
    /// No index file. The ordinary first run.
    Absent,
    /// Present but written under a different format version.
    VersionMismatch,
    /// Present, this version, and the payload does not match its checksum.
    ChecksumMismatch,
    /// Present and valid, for different grammars or window parameters.
    RegimeMismatch,
    /// Present and not parseable as an index at all.
    Unreadable,
}

impl LoadOutcome {
    /// The index, if there is one.
    pub fn index(self) -> Option<Index> {
        match self {
            LoadOutcome::Loaded(index) => Some(*index),
            _ => None,
        }
    }

    /// A stable code for diagnostics.
    pub fn code(&self) -> &'static str {
        match self {
            LoadOutcome::Loaded(_) => "loaded",
            LoadOutcome::Absent => "absent",
            LoadOutcome::VersionMismatch => "version-mismatch",
            LoadOutcome::ChecksumMismatch => "checksum-mismatch",
            LoadOutcome::RegimeMismatch => "regime-mismatch",
            LoadOutcome::Unreadable => "unreadable",
        }
    }
}

/// A held single-writer advisory lock.
///
/// Advisory, and the word is doing work: it stops two cooperating Andon
/// processes from interleaving writes, and it cannot stop anything else. The
/// checksum in the index file is what covers the case this does not.
#[derive(Debug)]
pub struct IndexLock {
    path: PathBuf,
}

impl IndexLock {
    /// Take the lock for `index_path`, stealing it if the holder has gone
    /// stale.
    pub fn acquire(index_path: &Path) -> Result<IndexLock, IndexError> {
        let path = lock_path(index_path);
        let parent = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;

        match create_lock(&path) {
            Ok(()) => return Ok(IndexLock { path }),
            Err(err) if err.kind() != std::io::ErrorKind::AlreadyExists => {
                return Err(io(&path, err));
            }
            Err(_) => {}
        }

        // Someone holds it. Steal only when the file itself has gone
        // untouched for `LOCK_STALE` — a modification time, not a PID, because
        // a PID from a crashed process can be alive again on another program.
        let stale = std::fs::metadata(&path)
            .and_then(|meta| meta.modified())
            .map(|modified| {
                SystemTime::now()
                    .duration_since(modified)
                    .map(|age| age > LOCK_STALE)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if !stale {
            return Err(IndexError::Locked {
                path: path.display().to_string(),
            });
        }
        std::fs::remove_file(&path).map_err(|e| io(&path, e))?;
        create_lock(&path).map_err(|e| io(&path, e))?;
        Ok(IndexLock { path })
    }

    /// Where the lock file is.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn create_lock(path: &Path) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    // Contents are for a human reading a wedged repository, never parsed.
    writeln!(
        file,
        "pid={} since={}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()
    )
}

impl Drop for IndexLock {
    fn drop(&mut self) {
        // Best effort: a failure here leaves a stale lock, which the staleness
        // timeout clears. Panicking in a destructor would be worse.
        let _ = std::fs::remove_file(&self.path);
    }
}

fn lock_path(index_path: &Path) -> PathBuf {
    let mut name = index_path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    index_path.with_file_name(name)
}

fn temp_path(index_path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    let mut name = index_path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp-{}-{nonce}", std::process::id()));
    index_path.with_file_name(name)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "andon-clone-index-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn input(path: &str, oid: &str, source: &str) -> FileInput {
        FileInput {
            path: path.to_string(),
            blob_oid: oid.to_string(),
            source: source.as_bytes().to_vec(),
        }
    }

    fn body(seed: &str) -> String {
        format!("function {seed}(a: number, b: number) {{ let t = a + b; if (t > 2) {{ t = t * 3; }} return t; }}")
    }

    #[test]
    fn a_round_trip_survives_the_disk() {
        let root = dir("roundtrip");
        let path = root.join("clones.idx");
        let (index, _) = Index::empty().update(&[input("a.ts", "oid-a", &body("f"))]);
        index.store(&path).unwrap();
        let loaded = Index::load(&path).index().expect("loads");
        assert_eq!(loaded, index);
    }

    #[test]
    fn a_flipped_byte_is_a_rebuild_not_a_wrong_answer() {
        let root = dir("checksum");
        let path = root.join("clones.idx");
        let (index, _) = Index::empty().update(&[input("a.ts", "oid-a", &body("f"))]);
        index.store(&path).unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 2;
        bytes[last] ^= 0x20;
        std::fs::write(&path, &bytes).unwrap();

        let outcome = Index::load(&path);
        assert_eq!(outcome.code(), "checksum-mismatch");
        assert!(outcome.index().is_none());
    }

    #[test]
    fn an_index_from_other_grammars_is_discarded() {
        let root = dir("regime");
        let path = root.join("clones.idx");
        let mut index = Index::empty();
        index.regime_key = "rabin-karp|rules0+typescript@0.0.1|w25|m50".to_string();
        index.store(&path).unwrap();
        assert_eq!(Index::load(&path).code(), "regime-mismatch");
    }

    #[test]
    fn a_file_from_another_format_version_is_discarded() {
        let root = dir("version");
        let path = root.join("clones.idx");
        std::fs::write(&path, format!("{MAGIC} v99 deadbeef\n{{}}")).unwrap();
        assert_eq!(Index::load(&path).code(), "version-mismatch");
    }

    #[test]
    fn a_stray_file_is_not_an_index() {
        let root = dir("stray");
        let path = root.join("clones.idx");
        std::fs::write(&path, "not an index at all\n").unwrap();
        assert_eq!(Index::load(&path).code(), "unreadable");
        assert_eq!(Index::load(&root.join("missing.idx")).code(), "absent");
    }

    #[test]
    fn the_lock_admits_one_writer_at_a_time() {
        let root = dir("lock");
        let path = root.join("clones.idx");
        let held = IndexLock::acquire(&path).unwrap();
        assert!(matches!(
            IndexLock::acquire(&path),
            Err(IndexError::Locked { .. })
        ));
        drop(held);
        // Released on drop, so the next writer gets in.
        let _second = IndexLock::acquire(&path).unwrap();
    }

    #[test]
    fn an_abandoned_lock_is_stolen_rather_than_wedging_the_repository() {
        let root = dir("stale-lock");
        let path = root.join("clones.idx");
        let held = IndexLock::acquire(&path).unwrap();
        let lock_file = held.path().to_path_buf();
        std::mem::forget(held); // a crashed holder: never released

        // Backdate the lock past the staleness horizon.
        let old = SystemTime::now() - LOCK_STALE - Duration::from_secs(60);
        set_mtime(&lock_file, old);
        let _stolen = IndexLock::acquire(&path).expect("a stale lock is stealable");
    }

    fn set_mtime(path: &Path, when: SystemTime) {
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_modified(when).unwrap();
    }

    #[test]
    fn reuse_is_keyed_on_content_not_on_the_path() {
        let first = Index::empty()
            .update(&[input("a.ts", "oid-1", &body("f"))])
            .0;
        // Same path, new content: not reused.
        let (_, reused) = first.update(&[input("a.ts", "oid-2", &body("g"))]);
        assert_eq!(reused, 0);
        // Same path, same content: reused.
        let (_, reused) = first.update(&[input("a.ts", "oid-1", &body("f"))]);
        assert_eq!(reused, 1);
    }

    #[test]
    fn a_path_no_longer_offered_leaves_no_posting_behind() {
        let first = Index::empty()
            .update(&[
                input("a.ts", "oid-a", &body("f")),
                input("b.ts", "oid-b", &body("g")),
            ])
            .0;
        let (second, _) = first.update(&[input("b.ts", "oid-b", &body("g"))]);
        assert!(!second.files.contains_key("a.ts"));
        assert_eq!(
            second,
            Index::empty()
                .update(&[input("b.ts", "oid-b", &body("g"))])
                .0
        );
    }

    #[test]
    fn a_file_no_grammar_reads_is_absent_rather_than_empty() {
        let (index, _) = Index::empty().update(&[input("a.rs", "oid", "fn main() {}")]);
        assert!(index.files.is_empty());
    }
}
