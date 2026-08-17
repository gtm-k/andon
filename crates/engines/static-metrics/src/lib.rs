//! # andon-static-metrics
//!
//! The static family: source size, cyclomatic complexity, and cognitive
//! complexity over tree-sitter for TypeScript, TSX, JavaScript and Python; a
//! tokenization tier for Rust that measures size alone; and parse health as a
//! first-class payload state rather than an error path.
//!
//! ## The two properties this crate has to hold
//!
//! **Numbers reproduce byte for byte, everywhere.** Every input is a git blob,
//! every counting rule is defined on bytes, and every version that could change
//! an answer — the tree-sitter runtime, each grammar, and this crate's own
//! [`lang::SPEC_REVISION`] — is stamped into the `measurement_regime` and
//! therefore into every per-result digest. Two binaries at different versions
//! produce `unwitnessed-version-skew`, never `divergent` (PREMORTEM S4). The
//! cross-OS matrix in `.github/workflows/spike-matrix.yml` is where the claim is
//! tested rather than asserted.
//!
//! **A parse the engine did not fully understand says so.** tree-sitter recovers
//! from anything, so a half-understood file yields numbers that look like any
//! other numbers. [`parse::ParseHealth`] counts what was not understood,
//! [`health`] demotes what was computed from it in the three places three
//! different actors read, and `fixtures/parse-corpus` holds pinned real-world
//! repositories against an ERROR-node budget so a grammar bump cannot quietly
//! degrade the whole corpus (PREMORTEM T3).
//!
//! ## Layout
//!
//! - [`lang`] — languages, pinned grammar versions, the spec revision.
//! - [`parse`] — parsing and parse health.
//! - [`sloc`], [`rustlex`] — source-line counting for both tiers.
//! - [`functions`] — which nodes get their own result, and what they are called.
//! - [`cyclomatic`], [`cognitive`] — the two complexity metrics.
//! - [`health`] — what a degraded parse does to a number.
//! - [`metrics`] — the metric set and the claims it cites.
//! - [`engine`] — the [`andon_core::engine::MeasureEngine`] implementation.
//! - [`record`] — the P2 measurement harness, until P5b's CLI replaces it.
//! - [`fixture`] — the cross-OS matrix fixture, built from committed bytes.
//! - [`corpus`] — the parse-corpus manifest, run, and baseline.

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod cognitive;
pub mod corpus;
pub mod cyclomatic;
pub mod engine;
pub mod fixture;
pub mod functions;
pub mod health;
pub mod lang;
pub mod metrics;
pub mod parse;
pub mod record;
pub mod rustlex;
pub mod sloc;

pub use engine::{measure_blob, FileFacts, FunctionFacts, StaticMetricsEngine};
pub use lang::Language;
pub use parse::ParseHealth;

/// The engine version this build reports.
///
/// Read once at a binary's entry point and passed down explicitly, never
/// consulted deep in the call graph — the same discipline the spike adopted
/// after a process-global override leaked between parallel fixture threads.
pub fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
