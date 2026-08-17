//! The fast-lane cache: what a measurement is keyed on, and where it is kept.
//!
//! # The key (PLAN P1)
//!
//! `content-hash(base, head) × policy_hash × engine_version × history_window`.
//!
//! Every factor is there because changing it changes the answer:
//!
//! - **Content.** A commit OID *is* a content hash; a dirty endpoint gets one
//!   computed incrementally ([`crate::git::DirtySnapshot`]).
//! - **Policy hash.** Severity and thresholds come from `.andon.toml`, so a
//!   policy edit must not be served yesterday's severities.
//! - **Engine version.** A new grammar or a fixed detector produces different
//!   numbers on identical input. Serving the old ones is how a fix appears not
//!   to have worked.
//! - **History window.** Process metrics are defined over it; it is part of
//!   their `measurement_regime` for the same reason it is part of this key.
//!
//! Missing any of them yields a *wrong hit* — the failure mode where the cache
//! silently answers a question nobody asked. Including something incidental
//! yields a miss, which costs time and nothing else. The key is built to fail in
//! the second direction.
//!
//! # Scope
//!
//! A versioned key-to-bytes store with atomic writes, which is what the fast
//! lane and the perf gate need. Single-writer locking, index checksumming, and
//! crash recovery belong to the clone index in P3 (PREMORTEM T2) and are
//! deliberately not built here: this store holds derived values that are free to
//! recompute, so the worst outcome of a torn write is a miss.

mod key;
mod store;

pub use key::{CacheKey, CACHE_KEY_VERSION};
pub use store::{CacheError, CacheStore, STORE_LAYOUT_VERSION};
