//! # andon-core
//!
//! The measurement contract. Every other crate in the workspace depends on this
//! one and none of it depends on them, because the contract is the thing that
//! has to stay still while engines, surfaces, and the verifier move.
//!
//! What lives here, and why it is all one crate:
//!
//! - [`schema`] — payload schema v1: the versioned JSON contract shared by the
//!   CLI, the MCP server, the report, and the CI verifier (VISION §3.4).
//! - [`canonical`] — the one way bytes are produced for hashing. Digest equality
//!   is the trust mechanism, so there is exactly one serializer.
//! - [`compare`] — how a self-report and a recompute become an attestation
//!   value, in the order that keeps honest changes out of the tamper bucket.
//! - [`git`] — the plumbing: base/head resolution, blob-only content reads for
//!   the compared lane, and one hygienic path to every `git` subprocess.
//! - [`cache`] — the fast-lane cache key and store, keyed so that cost scales
//!   with the diff rather than the repository (PREMORTEM T6).
//! - [`engine`] — the `MeasureEngine` trait every measurement enters through.
//! - [`parse_health`] — what a half-understood file does to a number, shared by
//!   every engine that holds a grammar (PREMORTEM T3).
//! - [`registry`] — evidence claims, and the lint that fails the build when a
//!   metric has none.
//! - [`policy`] — `.andon.toml`, where every threshold lives so that changing
//!   one is a reviewable edit.
//! - [`selfmeasure`] — the rules for Andon measuring Andon.
//!
//! ## The property the whole design rests on
//!
//! Two runs of the same measurement, on different operating systems, in
//! different checkouts, must produce byte-identical digests. Everything else is
//! downstream of that: without it the verifier reports `divergent` on honest
//! work and the tool is finished (PREMORTEM Story 1). The rules are in
//! [`canonical`], the compare-set boundary is documented on
//! [`schema::payload::ResultDigestInput`], and P1.5 wires the cross-OS matrix
//! that proves it.

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod cache;
pub mod canonical;
pub mod compare;
pub mod date;
pub mod engine;
pub mod git;
pub mod parse_health;
pub mod policy;
pub mod registry;
pub mod schema;
pub mod selfmeasure;
pub mod testing;
