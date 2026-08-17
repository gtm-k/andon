//! Base and head resolution.
//!
//! `measure_change(base, head)` has to say what it measured before it can say
//! anything else. Four things can be asked for — an explicit commit-ish, the
//! merge base against a trusted branch, the index, or the working tree — and
//! only the first two produce something the CI verifier can recompute.
//!
//! # Why a dirty endpoint cannot become a `CompareContext`
//!
//! [`crate::schema::payload::CompareContext`] requires a `base_oid` and a
//! `head_oid`, and P0 made them non-optional deliberately: a record that cannot
//! say what it measured is exactly the shape a fabricated base hides in
//! (PLAN B3/R2-4). The working tree has no commit OID. The tempting move —
//! writing `HEAD`'s OID into `head_oid` and calling it near enough — produces a
//! record that passes the verifier's tuple-equality check while describing bytes
//! that were never committed, which is the laundering path R2-4 exists to close.
//!
//! So [`ResolvedRange::compare_context`] returns an error for a dirty endpoint,
//! and there is no other way to build one from a resolution. A working-tree
//! measurement is advisory in the same sense its content is: real, useful to the
//! author, and never a thing CI is asked to witness.
//!
//! **Forward contract for P5a:** assembling a record from a dirty endpoint must
//! not synthesize a tuple. Either the record is not emitted, or the schema grows
//! a representation for "measured against an uncommitted tree" — a plan change,
//! not a phase decision.

use serde::Serialize;

use super::command::{Git, GitError};
use super::status::{DirtySnapshot, SnapshotMode};
use crate::schema::payload::CompareContext;

/// What the caller asked to measure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revision {
    /// An explicit commit-ish: a full or abbreviated SHA, a ref name, `HEAD~2`,
    /// a tag. Resolved with `rev-parse` to a full OID.
    Rev(String),
    /// The merge base of `head` and a trusted branch. The default for `base`,
    /// because "what did this change add" is a question about the fork point and
    /// not about wherever the trusted branch has since advanced to.
    MergeBase {
        /// The trusted branch, e.g. `origin/main`.
        with: String,
    },
    /// The index: staged content. Has real blob OIDs, but no commit.
    Index,
    /// The working tree: staged and unstaged content together.
    Worktree,
}

impl Revision {
    /// The default base: the merge base against `with`.
    pub fn merge_base(with: impl Into<String>) -> Self {
        Revision::MergeBase { with: with.into() }
    }
}

/// A resolved endpoint of a comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A real commit, named by its full OID.
    Commit {
        /// Full commit OID.
        oid: String,
        /// How it was arrived at — `explicit`, `merge-base`, `head`. Carried
        /// into [`CompareContext::base_resolution`] so a reader can tell a
        /// pinned base from a computed one.
        resolution: String,
    },
    /// The index. Content is blob-addressable, but there is no commit to pin to.
    Index {
        /// The staged state. Carried whole rather than as a digest so that
        /// [`super::ChangedSet`] can be derived from it instead of costing a
        /// second scan — see [`DirtySnapshot`]'s note on why one scan is both
        /// faster and the only self-consistent answer.
        snapshot: Box<DirtySnapshot>,
        /// Digest of `snapshot`, computed once.
        digest: String,
    },
    /// The working tree.
    Worktree {
        /// The dirty state, carried whole. See [`Endpoint::Index`].
        snapshot: Box<DirtySnapshot>,
        /// Digest of `snapshot`, computed once.
        digest: String,
    },
}

impl Endpoint {
    /// True when this endpoint is a commit and can therefore be witnessed.
    pub fn is_commit(&self) -> bool {
        matches!(self, Endpoint::Commit { .. })
    }

    /// The commit OID this endpoint is anchored to.
    ///
    /// For a dirty endpoint this is the commit it sits *on top of*, which is not
    /// the same thing as what was measured — see the module docs before putting
    /// it anywhere a verifier will read it.
    pub fn anchor_oid(&self) -> &str {
        match self {
            Endpoint::Commit { oid, .. } => oid,
            Endpoint::Index { snapshot, .. } | Endpoint::Worktree { snapshot, .. } => {
                &snapshot.head_oid
            }
        }
    }

    /// The stable identity of this endpoint for cache keying.
    ///
    /// A commit OID *is* a content hash; a dirty endpoint's is computed. Both
    /// change when and only when the content they name changes, which is the
    /// whole requirement (PLAN P1 "content-hash(base, head)").
    pub fn content_hash(&self) -> &str {
        match self {
            Endpoint::Commit { oid, .. } => oid,
            Endpoint::Index { digest, .. } | Endpoint::Worktree { digest, .. } => digest,
        }
    }

    /// Build a dirty endpoint from a snapshot, computing its digest once.
    ///
    /// `staged_only` on the snapshot decides which sentinel this is, so the two
    /// cannot disagree — an `INDEX` endpoint holding a worktree snapshot would
    /// key one question under another's name.
    pub fn from_snapshot(snapshot: DirtySnapshot) -> Self {
        let snapshot = Box::new(snapshot);
        let digest = snapshot.digest();
        if snapshot.staged_only {
            Endpoint::Index { snapshot, digest }
        } else {
            Endpoint::Worktree { snapshot, digest }
        }
    }

    /// The dirty state behind this endpoint, when it has one.
    pub fn snapshot(&self) -> Option<&DirtySnapshot> {
        match self {
            Endpoint::Commit { .. } => None,
            Endpoint::Index { snapshot, .. } | Endpoint::Worktree { snapshot, .. } => {
                Some(snapshot)
            }
        }
    }

    /// A short label for the endpoint kind, used in keys and messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Endpoint::Commit { .. } => "commit",
            Endpoint::Index { .. } => "index",
            Endpoint::Worktree { .. } => "worktree",
        }
    }
}

/// Both endpoints, resolved, with the facts a record needs to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRange {
    /// What the change is measured against.
    pub base: Endpoint,
    /// What is being measured.
    pub head: Endpoint,
    /// `git --version` of the git that resolved this.
    pub git_version: String,
    /// True when history is truncated. Callers that need full history report
    /// `completeness: unwitnessed` rather than a number computed over a window
    /// that silently ends at the shallow boundary.
    pub shallow: bool,
}

/// Resolution could not produce an honest answer.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// A git command failed.
    #[error(transparent)]
    Git(#[from] GitError),
    /// The revision does not name anything in this repository.
    #[error("{rev} does not resolve to a commit in this repository")]
    UnknownRevision {
        /// What was asked for.
        rev: String,
    },
    /// No merge base exists — unrelated histories, or a truncated clone.
    #[error("no merge base between {head} and {with}{}", if *.shallow {
        " (the repository is shallow; fetch more history or pass an explicit base)"
    } else {
        " (the histories are unrelated)"
    })]
    NoMergeBase {
        /// The head side.
        head: String,
        /// The trusted branch.
        with: String,
        /// Whether the repository is shallow, which is nearly always the cause.
        shallow: bool,
    },
    /// A working-tree or index endpoint was asked for in a bare repository.
    #[error("a {kind} endpoint needs a working tree, and this repository is bare")]
    NoWorkingTree {
        /// Which sentinel was asked for.
        kind: &'static str,
    },
    /// A commit tuple was requested for a range with a dirty endpoint.
    #[error(
        "the {side} endpoint is a {kind}, which has no commit id; \
         a working-tree or index measurement is advisory and cannot be attested"
    )]
    NotComparable {
        /// `base` or `head`.
        side: &'static str,
        /// The endpoint kind.
        kind: &'static str,
    },
    /// A rebase, merge, bisect, or cherry-pick is half-finished.
    #[error(
        "a {operation} is in progress; the working tree is a partial result, \
         not a change worth measuring"
    )]
    OperationInProgress {
        /// Which operation git reports as unfinished.
        operation: &'static str,
    },
}

impl ResolvedRange {
    /// Resolve a base and a head.
    ///
    /// Costs at most: one `rev-parse` for each explicit revision, one
    /// `merge-base`, and — for a dirty endpoint — whatever [`DirtySnapshot`]
    /// needs (a `status` and one batched `hash-object`).
    pub fn resolve(git: &Git, base: &Revision, head: &Revision) -> Result<Self, ResolveError> {
        // Order matters: refuse a half-finished operation before spending
        // anything on resolving it. A tree mid-rebase is neither the old change
        // nor the new one, and measuring it produces a number about a state that
        // will not exist in a minute.
        if let Some(operation) = in_progress_operation(git)? {
            return Err(ResolveError::OperationInProgress { operation });
        }

        let head_endpoint = resolve_endpoint(git, head, "head", None)?;
        let base_endpoint = resolve_endpoint(git, base, "base", Some(&head_endpoint))?;

        Ok(ResolvedRange {
            base: base_endpoint,
            head: head_endpoint,
            git_version: git.version().to_string(),
            shallow: git.facts().shallow,
        })
    }

    /// The wire tuple for this range, if both endpoints are commits.
    ///
    /// Errors on a dirty endpoint rather than approximating one. See the module
    /// docs: the approximation is the vulnerability.
    pub fn compare_context(&self) -> Result<CompareContext, ResolveError> {
        let Endpoint::Commit {
            oid: base_oid,
            resolution,
        } = &self.base
        else {
            return Err(ResolveError::NotComparable {
                side: "base",
                kind: self.base.kind(),
            });
        };
        let Endpoint::Commit { oid: head_oid, .. } = &self.head else {
            return Err(ResolveError::NotComparable {
                side: "head",
                kind: self.head.kind(),
            });
        };
        Ok(CompareContext {
            base_oid: base_oid.clone(),
            head_oid: head_oid.clone(),
            git_version: self.git_version.clone(),
            base_resolution: resolution.clone(),
        })
    }

    /// True when this range can be witnessed by the verifier at all.
    pub fn is_comparable(&self) -> bool {
        self.base.is_commit() && self.head.is_commit()
    }
}

fn resolve_endpoint(
    git: &Git,
    revision: &Revision,
    side: &'static str,
    head: Option<&Endpoint>,
) -> Result<Endpoint, ResolveError> {
    match revision {
        Revision::Rev(rev) => Ok(Endpoint::Commit {
            oid: rev_parse_commit(git, rev)?,
            resolution: if rev == "HEAD" { "head" } else { "explicit" }.to_string(),
        }),
        Revision::MergeBase { with } => {
            let head_oid = match head {
                Some(endpoint) => endpoint.anchor_oid().to_string(),
                // A merge base on the head side has nothing to be the base of.
                None => rev_parse_commit(git, "HEAD")?,
            };
            let with_oid = rev_parse_commit(git, with)?;
            let output = git
                .cmd(["merge-base", &head_oid, &with_oid])
                .succeeds_with_output()?;
            match output {
                Some(text) => Ok(Endpoint::Commit {
                    oid: expect_oid(text.trim(), with)?,
                    resolution: "merge-base".to_string(),
                }),
                // `merge-base` exits 1 when there is none. On a shallow clone
                // that is an artefact of the truncation, not a fact about the
                // histories, and the error says which.
                None => Err(ResolveError::NoMergeBase {
                    head: head_oid,
                    with: with.clone(),
                    shallow: git.facts().shallow,
                }),
            }
        }
        Revision::Index | Revision::Worktree => {
            if git.facts().bare {
                return Err(ResolveError::NoWorkingTree {
                    kind: if matches!(revision, Revision::Index) {
                        "index"
                    } else {
                        "worktree"
                    },
                });
            }
            // `side` is unused, and deliberately: a dirty snapshot is anchored
            // at `HEAD` whichever side it is on, because `status` compares
            // against `HEAD` and nothing else. Anchoring a *base* snapshot
            // somewhere else would not help — [`super::ChangedSet::enumerate`]
            // refuses a dirty base outright — and for a dirty *head* the gap
            // between the base and `HEAD` is closed there too, by the union with
            // a `diff-tree` over the committed segment.
            let _ = side;
            let head_oid = rev_parse_commit(git, "HEAD")?;
            let staged_only = matches!(revision, Revision::Index);
            Ok(Endpoint::from_snapshot(DirtySnapshot::incremental(
                git,
                &head_oid,
                staged_only,
            )?))
        }
    }
}

/// Resolve a commit-ish to a full commit OID.
///
/// `^{commit}` is not decoration: without it a tag resolves to the tag object's
/// own OID, and an annotated tag would produce a `base_oid` that is not a commit
/// at all.
fn rev_parse_commit(git: &Git, rev: &str) -> Result<String, ResolveError> {
    let spec = format!("{rev}^{{commit}}");
    let output = git
        .cmd([
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &spec,
        ])
        .succeeds_with_output()?;
    match output {
        Some(text) => expect_oid(text.trim(), rev),
        None => Err(ResolveError::UnknownRevision {
            rev: rev.to_string(),
        }),
    }
}

fn expect_oid(text: &str, rev: &str) -> Result<String, ResolveError> {
    let looks_like_oid = !text.is_empty()
        && text.len() >= 40
        && text.bytes().all(|b| b.is_ascii_hexdigit())
        && text.bytes().all(|b| !b.is_ascii_uppercase());
    if looks_like_oid {
        Ok(text.to_string())
    } else {
        Err(ResolveError::UnknownRevision {
            rev: rev.to_string(),
        })
    }
}

/// Which multi-step git operation, if any, is half-finished.
///
/// Detected by the marker directories and files git itself uses, so the answer
/// does not depend on parsing a localized message — and `LC_ALL=C` notwithstanding,
/// a state machine read from prose is a state machine read wrong.
fn in_progress_operation(git: &Git) -> Result<Option<&'static str>, ResolveError> {
    let git_dir = &git.facts().git_dir;
    for (marker, operation) in [
        ("rebase-merge", "rebase"),
        ("rebase-apply", "rebase or am"),
        ("CHERRY_PICK_HEAD", "cherry-pick"),
        ("REVERT_HEAD", "revert"),
        ("MERGE_HEAD", "merge"),
        ("BISECT_LOG", "bisect"),
    ] {
        if git_dir.join(marker).exists() {
            return Ok(Some(operation));
        }
    }
    Ok(None)
}

/// The cache-key view of an endpoint: identity without the incidental detail.
///
/// `BTreeMap` is not needed here because there is no map, but the same rule
/// applies for the same reason — this is a digest path, so field order and
/// representation are fixed by the type and never by iteration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EndpointKey {
    /// A commit, identified by its OID.
    Commit {
        /// Full commit OID.
        oid: String,
    },
    /// The index, identified by its snapshot digest.
    Index {
        /// Snapshot digest.
        snapshot: String,
        /// How the snapshot was computed. Part of the key so that a fallback
        /// re-hash can never be served a value the incremental path produced.
        mode: SnapshotMode,
    },
    /// The working tree, identified by its snapshot digest.
    Worktree {
        /// Snapshot digest.
        snapshot: String,
        /// How the snapshot was computed.
        mode: SnapshotMode,
    },
}

impl From<&Endpoint> for EndpointKey {
    fn from(endpoint: &Endpoint) -> Self {
        match endpoint {
            Endpoint::Commit { oid, .. } => EndpointKey::Commit { oid: oid.clone() },
            Endpoint::Index { snapshot, digest } => EndpointKey::Index {
                snapshot: digest.clone(),
                mode: snapshot.mode,
            },
            Endpoint::Worktree { snapshot, digest } => EndpointKey::Worktree {
                snapshot: digest.clone(),
                mode: snapshot.mode,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(oid: &str) -> Endpoint {
        Endpoint::Commit {
            oid: oid.to_string(),
            resolution: "explicit".to_string(),
        }
    }

    fn dirty() -> Endpoint {
        Endpoint::from_snapshot(crate::git::testing::empty_snapshot(
            &"1".repeat(40),
            false,
            SnapshotMode::Incremental,
        ))
    }

    fn range(base: Endpoint, head: Endpoint) -> ResolvedRange {
        ResolvedRange {
            base,
            head,
            git_version: "git version 2.39.0".to_string(),
            shallow: false,
        }
    }

    #[test]
    fn a_commit_range_yields_the_wire_tuple() {
        let range = range(commit(&"1".repeat(40)), commit(&"2".repeat(40)));
        let ctx = range.compare_context().expect("both endpoints are commits");
        assert_eq!(ctx.base_oid, "1".repeat(40));
        assert_eq!(ctx.head_oid, "2".repeat(40));
        assert_eq!(ctx.base_resolution, "explicit");
        assert!(range.is_comparable());
    }

    #[test]
    fn a_dirty_head_refuses_to_produce_a_tuple() {
        // The load-bearing assertion of this module. If this ever returns Ok,
        // an uncommitted measurement can be handed to the verifier wearing
        // HEAD's commit id, and tuple equality stops meaning what R2-4 needs it
        // to mean.
        let range = range(commit(&"1".repeat(40)), dirty());
        assert!(matches!(
            range.compare_context(),
            Err(ResolveError::NotComparable {
                side: "head",
                kind: "worktree"
            })
        ));
        assert!(!range.is_comparable());
    }

    #[test]
    fn a_dirty_base_refuses_too() {
        let range = range(dirty(), commit(&"2".repeat(40)));
        assert!(matches!(
            range.compare_context(),
            Err(ResolveError::NotComparable { side: "base", .. })
        ));
    }

    #[test]
    fn the_anchor_of_a_dirty_endpoint_is_not_its_content_hash() {
        // Stated as a test because conflating the two is precisely how a
        // worktree measurement would acquire a commit identity.
        let endpoint = dirty();
        assert_ne!(endpoint.anchor_oid(), endpoint.content_hash());
    }
}
