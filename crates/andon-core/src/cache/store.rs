//! A content-addressed store for fast-lane results.
//!
//! Deliberately small. Entries are derived values — recomputing one is slower
//! than reading it and no less correct — so the store's only real obligation is
//! never to return bytes that are not what was written under that key.
//!
//! Two mechanisms cover it:
//!
//! - **Atomic publication.** Bytes go to a temporary file in the same directory
//!   and are renamed into place. A reader sees the whole entry or no entry;
//!   there is no window in which it sees half. A crash mid-write leaves a temp
//!   file, which is garbage rather than corruption.
//! - **A versioned layout.** Entries live under a version directory, so changing
//!   the format abandons the old entries rather than reinterpreting them.
//!
//! What is *not* here — a single-writer lock, a checksummed index, crash
//! recovery — belongs to P3's clone index, where the artefact is expensive to
//! rebuild and a torn write is a real loss (PREMORTEM T2).

use std::io::Write;
use std::path::{Path, PathBuf};

use super::key::CacheKey;

/// Layout version. Entries live under `<root>/v<N>/`.
pub const STORE_LAYOUT_VERSION: u32 = 1;

/// The store could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// A filesystem operation failed.
    #[error("cache I/O failed at {path}: {source}")]
    Io {
        /// What was being touched.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The key could not be canonically serialized.
    #[error(transparent)]
    Canonical(#[from] crate::canonical::CanonicalError),
}

/// A directory of cached fast-lane results.
#[derive(Debug, Clone)]
pub struct CacheStore {
    root: PathBuf,
}

impl CacheStore {
    /// Open (or create) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CacheError> {
        let root = root.into().join(format!("v{STORE_LAYOUT_VERSION}"));
        std::fs::create_dir_all(&root).map_err(|source| CacheError::Io {
            path: root.display().to_string(),
            source,
        })?;
        Ok(CacheStore { root })
    }

    /// The versioned root this store writes under.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Look up an entry. `None` is a miss, never an error.
    pub fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>, CacheError> {
        let path = self.path_for(&key.digest()?);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(CacheError::Io {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Store an entry, replacing any previous one atomically.
    pub fn put(&self, key: &CacheKey, bytes: &[u8]) -> Result<(), CacheError> {
        let digest = key.digest()?;
        let path = self.path_for(&digest);
        let parent = path.parent().expect("shard path always has a parent");
        std::fs::create_dir_all(parent).map_err(|source| CacheError::Io {
            path: parent.display().to_string(),
            source,
        })?;

        // The temporary lives beside its destination so the rename stays within
        // one filesystem: a cross-device rename is a copy, and a copy is not
        // atomic. The name carries the process id so two concurrent writers of
        // the same key do not truncate each other's temp file — they race on the
        // rename instead, where the loser's bytes are simply replaced by the
        // winner's identical ones.
        let temp = parent.join(format!("{digest}.{}.tmp", std::process::id()));
        let write = (|| -> std::io::Result<()> {
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(bytes)?;
            file.sync_all()
        })();
        if let Err(source) = write {
            let _ = std::fs::remove_file(&temp);
            return Err(CacheError::Io {
                path: temp.display().to_string(),
                source,
            });
        }

        // Windows `rename` fails when the destination exists, where POSIX
        // replaces it. `std::fs::rename` documents that it replaces on both, so
        // the remove-then-rename dance other code needs is not required here —
        // and would reintroduce the window this whole approach exists to close.
        if let Err(source) = std::fs::rename(&temp, &path) {
            let _ = std::fs::remove_file(&temp);
            return Err(CacheError::Io {
                path: path.display().to_string(),
                source,
            });
        }
        Ok(())
    }

    /// Whether an entry exists, without reading it.
    pub fn contains(&self, key: &CacheKey) -> Result<bool, CacheError> {
        Ok(self.path_for(&key.digest()?).is_file())
    }

    /// Two hex characters of shard prefix. Flat directories with a hundred
    /// thousand entries are slow to enumerate on every filesystem this runs on.
    fn path_for(&self, digest: &str) -> PathBuf {
        let (shard, rest) = digest.split_at(2);
        self.root.join(shard).join(rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::{Endpoint, ResolvedRange};
    use crate::policy::Policy;

    fn key(head: &str) -> CacheKey {
        let range = ResolvedRange {
            base: Endpoint::Commit {
                oid: "1".repeat(40),
                resolution: "merge-base".to_string(),
            },
            head: Endpoint::Commit {
                oid: head.to_string(),
                resolution: "explicit".to_string(),
            },
            git_version: "git version 2.39.0".to_string(),
            shallow: false,
        };
        CacheKey::new(&range, &Policy::default(), "static-metrics", "0.1.0").unwrap()
    }

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("andon-cache-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn a_miss_is_none_and_not_an_error() {
        let store = CacheStore::open(temp_root("miss")).unwrap();
        assert_eq!(store.get(&key(&"2".repeat(40))).unwrap(), None);
        assert!(!store.contains(&key(&"2".repeat(40))).unwrap());
    }

    #[test]
    fn what_goes_in_comes_back_out() {
        let store = CacheStore::open(temp_root("roundtrip")).unwrap();
        let key = key(&"2".repeat(40));
        store.put(&key, b"measured").unwrap();
        assert_eq!(store.get(&key).unwrap().as_deref(), Some(&b"measured"[..]));
        assert!(store.contains(&key).unwrap());
    }

    #[test]
    fn a_different_key_does_not_hit() {
        let store = CacheStore::open(temp_root("distinct")).unwrap();
        store.put(&key(&"2".repeat(40)), b"one").unwrap();
        assert_eq!(store.get(&key(&"3".repeat(40))).unwrap(), None);
    }

    #[test]
    fn rewriting_a_key_replaces_it_and_leaves_no_temp_file() {
        let store = CacheStore::open(temp_root("replace")).unwrap();
        let key = key(&"2".repeat(40));
        store.put(&key, b"first").unwrap();
        store.put(&key, b"second").unwrap();
        assert_eq!(store.get(&key).unwrap().as_deref(), Some(&b"second"[..]));

        let shard = store.root().join(&key.digest().unwrap()[..2]);
        let leftovers: Vec<_> = std::fs::read_dir(shard)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "a completed put left a temp file");
    }
}
