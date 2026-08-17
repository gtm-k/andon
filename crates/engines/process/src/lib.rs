//! # andon-engine-process
//!
//! Churn, code age, ownership entropy, hotspots, and change coupling, computed
//! over a windowed git history (PLAN P4).
//!
//! This is the family `docs/metric-families.csv` rates highest and the reason is
//! worth restating: process metrics are the ones that **outperform product
//! metrics for defect prediction** (Rahman & Devanbu, ICSE 2013; Majumder et
//! al., EMSE 2021 replication) and the ones an agent editing a single file
//! cannot game. A model can lower a file's cyclomatic complexity by splitting a
//! function. It cannot lower the number of times that file has been changed by
//! four different people in the last year.
//!
//! ## The three properties this crate is built around
//!
//! 1. **The window is anchored to a commit, never to the clock.** Two honest
//!    runs of the same `(base_oid, head_oid)` forty minutes apart must produce
//!    the same numbers, or the verifier reports `divergent` on clean work.
//!    [`history`] derives the cutoff from the anchor commit's own committer
//!    timestamp.
//! 2. **Absence is reported, never filled in.** A shallow clone, a path the
//!    window never saw, a binary-only file, a hotspot with no complexity input:
//!    each produces `completeness: unwitnessed` and no number. PLAN P4 puts it
//!    as "never fabricated zeros".
//! 3. **What the *checkout* can change must not be allowed to pair.** The
//!    subtlest of the three, and the one with a test named after it: a truncated
//!    window emits change-scoped markers instead of per-file results, so a
//!    shallow verifier meeting a complete agent produces `unwitnessed` rather
//!    than an accusation. [`engine`]'s module documentation carries the full
//!    argument, and `tests/compare_asymmetry.rs` proves it against the real
//!    `andon_core::compare::classify`.
//!
//! ## Cost
//!
//! Two git spawns cold, none warm. The history cache is keyed by anchor commit —
//! an immutable object, so an entry can never name two answers — and stores the
//! commit list rather than per-path totals, because change coupling is a
//! question about which paths move together and an aggregate has already thrown
//! that away.
//!
//! ## What is deliberately not here
//!
//! No libgit2, no git bindings: PLAN P4 says plain git subprocess only, through
//! P1's hygiene-pinned [`andon_core::git::Git`], which is the only thing in the
//! workspace allowed to construct one.

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod cache;
pub mod complexity;
pub mod engine;
pub mod entropy;
pub mod history;
pub mod metrics;
pub mod probe;

pub use complexity::{ComplexitySource, NoComplexity};
pub use engine::{ProcessEngine, ProcessError, ENGINE_ID, SPEC_REVISION};
pub use history::HistoryWindow;
