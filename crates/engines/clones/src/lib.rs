//! Token-level clone detection over an incremental, crash-safe index.
//!
//! PLAN.md P3, first acceptance criterion: a Rabin-Karp token clone detector
//! whose incremental index produces byte-identical results to a cold rebuild,
//! with a versioned checksummed file, atomic writes, a single-writer lock, and
//! a crash-recovery test. PREMORTEM T2 rates the alternative crippling, and
//! names why: an index that disagrees with a rebuild reports clones in code
//! that no longer exists, and a torn write loses an artefact expensive enough
//! that someone will be tempted to trust it anyway.
//!
//! # The four properties, and where each is enforced
//!
//! | Property | Enforced in | Proved by |
//! |---|---|---|
//! | incremental == cold | [`index::Index::update`] rebuilds from the input set | `tests/incremental_equivalence.rs` (proptest over edit/rename/delete sequences) |
//! | versioned + checksummed | [`index::Index::load`] | `index` unit tests; a flipped byte rebuilds |
//! | atomic writes | [`index::Index::store`] — temp file, `sync_all`, rename | `tests/crash_recovery.rs` (a child process aborts mid-write) |
//! | single writer | [`index::IndexLock`] — `create_new` with a staleness timeout | `index` unit tests |
//!
//! # Reading order
//!
//! [`syntax`] turns bytes into normalized symbols, [`fingerprint`] turns symbols
//! into rolling window hashes, [`index`] stores them per file and keys them on
//! the git blob OID, [`detect`] finds and confirms the matches, and [`engine`]
//! turns the answer into sealed [`andon_core::schema::payload::MeasurementResult`]s.

#![deny(missing_docs)]

pub mod detect;
pub mod engine;
pub mod fingerprint;
pub mod index;
pub mod syntax;

pub use engine::{CloneEngineError, ClonesEngine, ENGINE_ID};
pub use index::{FileInput, Index, IndexError, IndexLock};
