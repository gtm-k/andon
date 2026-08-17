//! The tamper suite: seven static detectors for a change that improved a number
//! rather than the code.
//!
//! PLAN.md P3: six detectors from the metric catalogue plus the parse-error
//! delta of PREMORTEM T3, with per-detector precision and recall floors set
//! ex ante at 0.80 and 0.70 against a frozen adversarial corpus and a
//! should-pass corpus beside it. The floors are enforced by
//! `tests/corpus_floors.rs`; a report below floor fails the phase, which is what
//! makes them floors rather than a table in a README.
//!
//! # The shape of the thing
//!
//! - [`change`] — the input: a change as `(path, base bytes, head bytes)`
//!   triples, with no repository behind it. That is what lets the corpus be
//!   plain directories a reviewer can read.
//! - [`syntax`] — the tree-sitter facade: node shapes, call names, parse faults.
//! - [`config`] — one scanner for the five syntaxes tool configuration is written in.
//! - [`detectors`] — the seven, each a pure function of a [`change::ChangeView`].
//! - [`corpus`] — the frozen corpus, and the precision/recall arithmetic over it.
//! - [`engine`] — fourteen sealed results, always, so the compare set never
//!   depends on the answer.
//!
//! # What this crate deliberately cannot do
//!
//! Execute anything, resolve an import, or follow a symbol. Every answer is a
//! function of the bytes it was handed, which is what keeps the engine
//! `static-safe` and what puts its results in the digest compare set.

#![deny(missing_docs)]

pub mod change;
pub mod config;
pub mod corpus;
pub mod detectors;
pub mod engine;
pub mod syntax;

pub use change::{ChangeKind, ChangeView, FileChange};
pub use detectors::{Detector, Finding, Outcome};
pub use engine::{TamperEngine, TamperEngineError, ENGINE_ID};
