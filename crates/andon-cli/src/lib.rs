//! # andon-cli
//!
//! The product's first surface: measurement that carries its evidence, rendered
//! for a person.
//!
//! Everything the `andon` binary does lives in this library and the binary is a
//! dispatcher over it. That split is not tidiness — it is what lets the golden
//! set, the first-run acceptance suite, and the dogfood gate ask questions about
//! the same roster and the same pipeline the binary uses, rather than about a
//! copy of it. An integration test cannot import a binary crate, and the
//! workaround is always the same: a second list of the shipped engines,
//! hand-written beside the first. This phase inherited exactly that defect as an
//! entry note ([`shipped`]), so it does not create another instance of it.
//!
//! ## The modules
//!
//! - [`resolve`] — what to measure, and saying so when it is not what was asked
//!   for. PREMORTEM A1 lives here.
//! - [`measure`] — five engines over one change, assembled into one record.
//! - [`shipped`] — the one roster of engines this build carries.
//! - [`render`] — the terminal render and the self-contained HTML report.
//! - [`explain`] — the claim behind a number, and what it does not predict.
//! - [`lanes`] — what the async lane still owes a measurement.
//! - [`init`] — gate-shaped hooks installed, said aloud, and removable.
//! - [`ledger`] — records in the commit.
//! - [`attest`] — the verifier's shape, and nothing hardened.
//! - [`store`] — where the tool keeps its own state, which is never the working
//!   tree.
//! - [`args`] — a flag parser small enough not to be a dependency.

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod args;
pub mod attest;
pub mod explain;
pub mod init;
pub mod lanes;
pub mod ledger;
pub mod measure;
pub mod render;
pub mod resolve;
pub mod shipped;
pub mod store;
