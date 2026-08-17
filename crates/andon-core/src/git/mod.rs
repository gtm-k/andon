//! Git plumbing: what a change is, where its bytes come from, and what it costs
//! to find out.
//!
//! Three properties this module exists to hold, each one a pre-mortem row:
//!
//! 1. **Compared-lane bytes come from blob objects.** [`BlobBatch`] reads by
//!    OID and takes no path; [`Content::from_worktree`] reads by path and stamps
//!    its output advisory. A digest taken over blob bytes reproduces on any
//!    checkout, which is the whole of PREMORTEM T1's prevention line.
//! 2. **Every spawn is hygienic.** [`Git`] is the only thing in the workspace
//!    that constructs a `git` command, and it applies [`PINNED_CONFIG`] and a
//!    swept environment to all of them. A guard test fails the build if a second
//!    spawn path appears.
//! 3. **Cost scales with the diff, not the repository.** Enumeration is one
//!    spawn — two when the range spans committed work *and* uncommitted work,
//!    which needs both a `diff-tree` and a `status` — content is one more
//!    however many files, and dirty state is keyed from `status` rather than a
//!    full walk (PREMORTEM T6). [`Git::spawn_count`] is asserted by the perf
//!    gate so a regression is caught as a count before it is felt as a timeout.
//!
//! The lane boundary in (1) is drawn per path, not per range. A branch with
//! commits behind it and edits in front of it produces a changed set holding
//! both kinds of entry: the committed paths carry readable blob OIDs, the dirty
//! ones carry none.
//!
//! # A measurement's git work, end to end
//!
//! ```no_run
//! use andon_core::git::{ChangedSet, Git, ResolvedRange, Revision};
//!
//! let git = Git::open(std::path::Path::new("."))?;
//! let range = ResolvedRange::resolve(
//!     &git,
//!     &Revision::merge_base("origin/main"),
//!     &Revision::Rev("HEAD".into()),
//! )?;
//! let changed = ChangedSet::enumerate(&git, &range)?;
//! let blobs = changed.read_head_blobs(&git)?;
//! // Only now is there a wire tuple, and only because both endpoints are commits.
//! let context = range.compare_context()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod blob;
mod command;
mod diff;
mod resolve;
mod status;

pub use blob::{BlobBatch, BlobError, Content, ContentLane, ContentOrigin};
pub use command::{Git, GitCommand, GitError, RepoFacts, PINNED_CONFIG};
pub use diff::{ChangeStatus, ChangedEntry, ChangedSet, GITLINK_MODE};
pub use resolve::{Endpoint, EndpointKey, ResolveError, ResolvedRange, Revision};
pub use status::{testing, DirtyEntry, DirtySnapshot, SnapshotMode, SNAPSHOT_VERSION};
