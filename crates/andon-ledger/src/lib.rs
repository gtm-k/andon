//! # andon-ledger
//!
//! The full ledger machinery (PLAN P8): the repository as a longitudinal
//! dataset, and the operations that keep it one.
//!
//! ## Scope: single-repo local analytics, and deliberately nothing more
//!
//! Everything in this crate reads **one repository's** ledger for **that
//! repository's maintainer** — the dogfood loop of measuring a project inside
//! the project. It is not fleet analytics: no cross-repo aggregation, no
//! central collection, no org dashboard. The Gatekeeper fleet product is an
//! explicit non-goal (VISION; PLAN round-1 3.4), and the `stats` output says so
//! in its own header, because a scope that lives only in a doc nobody reads is
//! not a scope.
//!
//! ## The modules, and what each one is answerable for
//!
//! - [`sync`] — the notes transport: fetch → `notes merge` (`cat_sort_uniq`) →
//!   push, retried with backoff, and **loud** when the retries run out. A
//!   rejected push that exits green is a ledger silently missing from the
//!   remote (PLAN P8, round-1 loudness fix).
//! - [`migrate`] — squash-merge note migration as a supported operation rather
//!   than a fixture step (PREMORTEM T4).
//! - [`trailer`] — the commit-trailer digest option: a few dozen bytes in a
//!   commit message that survive transports git notes do not (fork PRs — PLAN
//!   P9 consumes this).
//! - [`stats`] — dimensions (author / harness / model / iteration /
//!   invocation-source) and per-metric value distributions, with the
//!   threshold-clustering warning (PREMORTEM S1) and the cross-regime
//!   aggregation refusal (PREMORTEM S4).
//! - [`worst`] — the durable worst-of consumption rule: several records on one
//!   head are read worst-first, never latest-wins (decision log, P1.5 (a)).
//! - [`fp_window`] — the S6 false-positive budget window, measured: changes,
//!   MED+ rate with the P2 cognitive/cyclomatic split, escalation rate. It
//!   reports quantities; the budget comparison belongs to the P10b entry gate.
//!
//! ## Every record read goes through the guarded readers
//!
//! Nothing in this crate parses a [`andon_core::schema::payload::MeasurementRecord`]
//! out of bytes itself. Every load goes through `andon_ledger_min`'s readers
//! ([`andon_ledger_min::notes::Notes::read`], [`andon_ledger_min::records::read`]),
//! which are where the ledger's integrity checks live — refusing malformed
//! lines today, and every check those readers gain later, without this crate
//! having to know. A parallel parser here would be a read path the checks never
//! see; `tests/no_parallel_parser.rs` makes adding one a red test rather than a
//! review finding.

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod fp_window;
pub mod migrate;
pub mod stats;
pub mod sync;
pub mod trailer;
pub mod worst;
