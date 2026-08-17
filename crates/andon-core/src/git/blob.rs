//! Content reads, and the lane boundary that makes digests reproducible.
//!
//! # The rule
//!
//! **Compared-lane content comes from git blob objects and nothing else.**
//!
//! A blob's bytes are fixed by its OID: `cat-file` on `de98044…` returns the
//! same bytes on Windows with `core.autocrlf=true` as on a Linux CI runner,
//! because checkout filters run on the way *out* of the object database and
//! `cat-file` does not use them. Worktree bytes have no such property — they are
//! whatever the checkout produced — so they are confined to an advisory lane
//! whose numbers are never digest-compared (PREMORTEM T1, PLAN pre-round
//! "compared lane reads git blob OIDs only").
//!
//! The boundary is a type, not a convention. [`Content`] carries its
//! [`ContentOrigin`], every read returns one, and [`Content::lane`] answers from
//! the origin. There is no constructor that produces compared-lane bytes from a
//! path.
//!
//! # Batching
//!
//! [`BlobBatch`] runs one `git cat-file --batch` process and streams every read
//! through it, so reading a thousand changed files costs one spawn instead of a
//! thousand (PREMORTEM T6). The child is killed on drop, so a panicking test
//! cannot leave the harness waiting on a pipe.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout};

use super::command::{Git, GitError};

/// Which trust lane some bytes may be used in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentLane {
    /// Checkout-independent. Eligible for per-result digests and the CI compare.
    Compared,
    /// Checkout-dependent. Advisory only, and never digest-compared: the same
    /// file can differ byte-for-byte between two honest machines.
    Advisory,
}

/// Where some bytes came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentOrigin {
    /// A git blob object, named by its OID.
    Blob {
        /// The blob OID the bytes are the content of.
        oid: String,
    },
    /// A file in the working tree, named by its repository-relative path.
    Worktree {
        /// Repository-relative path, forward slashes.
        path: String,
    },
}

/// Bytes, plus where they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    bytes: Vec<u8>,
    origin: ContentOrigin,
}

impl Content {
    /// The bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Take ownership of the bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Where they came from.
    pub fn origin(&self) -> &ContentOrigin {
        &self.origin
    }

    /// Which lane these bytes may be used in.
    pub fn lane(&self) -> ContentLane {
        match self.origin {
            ContentOrigin::Blob { .. } => ContentLane::Compared,
            ContentOrigin::Worktree { .. } => ContentLane::Advisory,
        }
    }

    /// Read a working-tree file. Advisory lane by construction.
    ///
    /// Nothing derived from these bytes may enter a per-result digest. The type
    /// says so and [`Content::lane`] proves it at runtime, but the reason is
    /// worth restating at the call site: an engine that hashes a worktree read
    /// has reintroduced the false-divergence epidemic.
    pub fn from_worktree(git: &Git, path: &str) -> Result<Self, GitError> {
        let full = git.workdir().join(path);
        let bytes = std::fs::read(&full).map_err(|source| GitError::Spawn {
            argv: format!("<read worktree file {path}>"),
            source,
        })?;
        Ok(Content {
            bytes,
            origin: ContentOrigin::Worktree {
                path: path.to_string(),
            },
        })
    }
}

/// A long-running `git cat-file --batch`.
///
/// One spawn, many reads. The protocol is git's: write `<oid>\n`, read back
/// `<oid> SP <type> SP <size> LF`, then exactly `size` bytes and a trailing LF.
/// A missing object answers `<name> SP missing LF` with no body.
#[derive(Debug)]
pub struct BlobBatch {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// A `cat-file --batch` read did not produce a blob.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// The batch process itself failed.
    #[error(transparent)]
    Git(#[from] GitError),
    /// The object is not in the database.
    #[error("object {oid} is missing from the object database")]
    Missing {
        /// The OID that was asked for.
        oid: String,
    },
    /// The object exists but is not a blob.
    ///
    /// The case that matters is a gitlink: a submodule's tree entry holds the
    /// submodule's *commit* OID, and asking `cat-file` for it returns a commit
    /// object whose bytes are a tree pointer and a log message. Hashing those as
    /// if they were file content would be a measurement of nothing.
    #[error("object {oid} is a {kind}, not a blob")]
    NotABlob {
        /// The OID that was asked for.
        oid: String,
        /// What git said it was.
        kind: String,
    },
    /// git's answer did not match the documented batch format.
    #[error("cat-file --batch protocol error: {0}")]
    Protocol(String),
    /// The pipe to or from the batch process broke.
    #[error("cat-file --batch I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl BlobBatch {
    /// Start the batch process. One spawn, however many reads follow.
    pub fn open(git: &Git) -> Result<Self, GitError> {
        let mut child = git.cmd(["cat-file", "--batch"]).spawn_piped()?;
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        Ok(BlobBatch {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    /// Read one blob by OID.
    ///
    /// Only accepts OIDs that came out of a tree or the index, which is what
    /// makes the compared lane compared: there is no path argument, so there is
    /// no way to reach the working tree through this type.
    pub fn read(&mut self, oid: &str) -> Result<Content, BlobError> {
        if oid.is_empty() || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(BlobError::Protocol(format!(
                "{oid:?} is not a hexadecimal object id"
            )));
        }
        writeln!(self.stdin, "{oid}")?;
        self.stdin.flush()?;

        let mut header = String::new();
        if self.stdout.read_line(&mut header)? == 0 {
            return Err(BlobError::Protocol(
                "cat-file --batch closed its output".to_string(),
            ));
        }
        let header = header.trim_end_matches('\n');
        let fields: Vec<&str> = header.split(' ').collect();
        match fields.as_slice() {
            [_, "missing"] => Err(BlobError::Missing {
                oid: oid.to_string(),
            }),
            [_, kind, size] => {
                let size: usize = size.parse().map_err(|_| {
                    BlobError::Protocol(format!("{header:?} does not end in a byte count"))
                })?;
                // The body is read whatever the type is: leaving an unread
                // object in the pipe would desynchronize every later read, so a
                // wrong type has to be drained before it can be reported.
                let mut bytes = vec![0u8; size];
                self.stdout.read_exact(&mut bytes)?;
                let mut terminator = [0u8; 1];
                self.stdout.read_exact(&mut terminator)?;
                if terminator[0] != b'\n' {
                    return Err(BlobError::Protocol(
                        "object body was not terminated by a newline".to_string(),
                    ));
                }
                if *kind != "blob" {
                    return Err(BlobError::NotABlob {
                        oid: oid.to_string(),
                        kind: (*kind).to_string(),
                    });
                }
                Ok(Content {
                    bytes,
                    origin: ContentOrigin::Blob {
                        oid: oid.to_string(),
                    },
                })
            }
            _ => Err(BlobError::Protocol(format!(
                "{header:?} is not a cat-file --batch header"
            ))),
        }
    }
}

impl Drop for BlobBatch {
    fn drop(&mut self) {
        // Closing stdin is the documented way to ask the batch process to stop.
        // The kill is the fallback for a child that is wedged: a perf harness
        // that hangs on a pipe reports nothing at all, which is worse than a
        // failure it can print.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_origin_is_the_compared_lane_and_worktree_origin_is_not() {
        let blob = Content {
            bytes: b"x".to_vec(),
            origin: ContentOrigin::Blob {
                oid: "a".repeat(40),
            },
        };
        let worktree = Content {
            bytes: b"x".to_vec(),
            origin: ContentOrigin::Worktree {
                path: "src/a.ts".to_string(),
            },
        };
        assert_eq!(blob.lane(), ContentLane::Compared);
        assert_eq!(worktree.lane(), ContentLane::Advisory);
        // Identical bytes, different lanes: the lane is a fact about provenance,
        // never about content.
        assert_eq!(blob.bytes(), worktree.bytes());
    }
}
