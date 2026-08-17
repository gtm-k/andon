//! # andon-ledger-min
//!
//! The P1.5 trust spike: the whole kernel of Andon's trust model, end to end,
//! on real git, with nothing else in the way.
//!
//! An agent measures a change and writes what it found to
//! `refs/notes/andon-measure`. CI checks out **the PR head SHA** — never the
//! synthetic merge ref — recomputes the same numbers independently, compares
//! per-result digests conditioned on `(base_oid, head_oid)` tuple equality, and
//! writes the result to `refs/notes/andon-attest`. That paragraph is the whole
//! product. This crate exists to find out whether it actually holds before ten
//! more phases are built on top of it (PLAN B1: P1.5 hard-gates P2/P3/P4).
//!
//! ## The modules, and what each one is answerable for
//!
//! - [`spike`] — three byte counts read from git blobs. Small on purpose: if the
//!   matrix goes red, nobody should have to ask whether the engine or the kernel
//!   is at fault.
//! - [`notes`] — the ledger. One canonical-JSON record per line, so
//!   `cat_sort_uniq` merges concurrent writes without losing either (PREMORTEM
//!   T4).
//! - [`measure`] — one implementation of "measure", used by both sides. Two
//!   would be two chances to disagree for reasons that are not tampering.
//! - [`verify`] — the verifier: pinned checkout, self-resolved base, R2-4
//!   classification, attestation.
//! - [`records`] — cross-leg digest comparison, which is what the matrix asserts.
//! - [`scenario`] — fixtures as committed data, including their expected
//!   verdicts.
//!
//! ## Two binaries
//!
//! `andon-spike` measures and verifies. `andon-spike-forge` is the adversary,
//! and it is a **separate executable holding all of its own logic** — nothing in
//! this library can alter a sealed record. That is not tidiness: the threat
//! model this phase exists to test is a deliberately forging agent binary, and
//! the honest way to test it is with a binary that actually forges rather than
//! a flag on the one that does not. `tests/binary_separation.rs` holds the line.
//!
//! ## What this crate is not
//!
//! Not the ledger. P8 builds that — dimensions, `ledger stats`, fault-injected
//! push failures, squash migration as a supported operation rather than a
//! fixture step. What is here is the minimum that makes the trust claim
//! falsifiable, and it is written as production lineage because P8 and P9 extend
//! it rather than replace it.

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod measure;
pub mod notes;
pub mod records;
pub mod scenario;
pub mod spike;
pub mod verify;
