//! # andon-engine-artifacts
//!
//! Coverage reports that some other tool produced, read for one purpose: which
//! lines this change touched that no test executed (PLAN P4).
//!
//! ## The shape of the claim
//!
//! Coverage is tier C in `docs/metric-families.csv` — "weak as a target, useful
//! as a gap-finder" — because Inozemtseva & Holmes (ICSE 2014) found suite
//! effectiveness only weakly correlated with coverage once suite size is
//! controlled, and because the assertion-free test that scores 100% is a known
//! agent failure mode rather than a hypothetical. So this engine emits a
//! **negative signal only**: uncovered changed lines, never a percentage, never
//! a delta, never a score to raise.
//!
//! ## Three properties
//!
//! 1. **Parse only.** Reports are read and parsed. No test runner, coverage
//!    tool, or build is ever invoked — that is `code-exec` work behind P7's
//!    sandbox, and the engine class says so at the trait boundary.
//! 2. **Never digest-compared.** A report is an untracked build output that no
//!    verifier can reproduce, so the metric is `deterministic: false` in the
//!    registry and the compare set excludes it by the verifier's own reading of
//!    that flag.
//! 3. **Absence is reported.** No report found, or a file the report does not
//!    cover, produces `completeness: unwitnessed` and no number — never a zero
//!    that reads as "fully covered".
//!
//! ## Hostile input is assumed
//!
//! A coverage report is a file the pull request under measurement controls.
//! [`report`] caps the size before parsing, [`cobertura`] uses a parser that
//! bounds entity expansion, and nothing in a document is ever resolved, fetched,
//! or opened.

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod cobertura;
pub mod engine;
pub mod hunks;
pub mod lcov;
pub mod report;

pub use engine::{ArtifactsEngine, ArtifactsError, ENGINE_ID, SPEC_REVISION};
pub use report::{CoverageReport, ReportError, ReportFormat};
