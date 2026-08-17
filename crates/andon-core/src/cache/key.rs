//! The fast-lane cache key.

use serde::Serialize;

use crate::canonical::{self, CanonicalError};
use crate::git::{EndpointKey, ResolvedRange};
use crate::policy::Policy;

/// Key format version.
///
/// Bumping it invalidates every existing entry, which is the correct and only
/// response to changing what a key covers: an old entry under a new key
/// definition is a wrong hit waiting to happen.
pub const CACHE_KEY_VERSION: u32 = 1;

/// Everything a fast-lane result depends on.
///
/// Field order is fixed by the struct and every value is a string or an integer,
/// so canonical serialization has nothing to sort and nothing to round. A map
/// here would have to be a `BTreeMap` for the reason given in
/// [`crate::schema::regime`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheKey {
    /// See [`CACHE_KEY_VERSION`].
    pub version: u32,
    /// Content identity of the base endpoint.
    pub base: EndpointKey,
    /// Content identity of the head endpoint.
    pub head: EndpointKey,
    /// Digest of the policy in force, from [`Policy::policy_hash`].
    pub policy_hash: String,
    /// The engine whose result this is, and its version. Two engines at the
    /// same version on the same content still produce different results, so the
    /// id is as load-bearing as the version.
    pub engine_id: String,
    /// Engine version.
    pub engine_version: String,
    /// History window in days, from policy.
    pub history_window_days: u32,
    /// `git --version`. Rename detection and diff defaults have moved across
    /// git releases, so two gits are two regimes (PREMORTEM S4) — and a cache
    /// that ignored the difference would hand the new binary the old binary's
    /// numbers.
    pub git_version: String,
}

impl CacheKey {
    /// Build a key for one engine's result over one resolved range.
    pub fn new(
        range: &ResolvedRange,
        policy: &Policy,
        engine_id: &str,
        engine_version: &str,
    ) -> Result<Self, CanonicalError> {
        Ok(CacheKey {
            version: CACHE_KEY_VERSION,
            base: EndpointKey::from(&range.base),
            head: EndpointKey::from(&range.head),
            policy_hash: policy.policy_hash().map_err(|err| match err {
                crate::policy::PolicyError::Canonical(inner) => inner,
                // `policy_hash` only ever fails through canonicalization; the
                // parse and version variants cannot arise from an in-memory
                // value. Rendering keeps the compiler honest without inventing
                // an error variant nobody can trigger.
                other => CanonicalError::NotSerializable(serde::ser::Error::custom(
                    other.to_string(),
                )),
            })?,
            engine_id: engine_id.to_string(),
            engine_version: engine_version.to_string(),
            history_window_days: policy.history.window_days,
            git_version: range.git_version.clone(),
        })
    }

    /// The key's digest — the name an entry is stored under.
    pub fn digest(&self) -> Result<String, CanonicalError> {
        canonical::digest(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::{Endpoint, SnapshotMode};

    fn range() -> ResolvedRange {
        ResolvedRange {
            base: Endpoint::Commit {
                oid: "1".repeat(40),
                resolution: "merge-base".to_string(),
            },
            head: Endpoint::Commit {
                oid: "2".repeat(40),
                resolution: "explicit".to_string(),
            },
            git_version: "git version 2.39.0".to_string(),
            shallow: false,
        }
    }

    fn key_for(range: &ResolvedRange, policy: &Policy) -> String {
        CacheKey::new(range, policy, "static-metrics", "0.1.0")
            .unwrap()
            .digest()
            .unwrap()
    }

    #[test]
    fn the_same_inputs_give_the_same_key() {
        let policy = Policy::default();
        assert_eq!(key_for(&range(), &policy), key_for(&range(), &policy));
    }

    #[test]
    fn every_factor_the_plan_names_moves_the_key() {
        let policy = Policy::default();
        let baseline = key_for(&range(), &policy);

        // Content: head.
        let mut moved = range();
        moved.head = Endpoint::Commit {
            oid: "3".repeat(40),
            resolution: "explicit".to_string(),
        };
        assert_ne!(baseline, key_for(&moved, &policy), "head content");

        // Content: base.
        let mut moved = range();
        moved.base = Endpoint::Commit {
            oid: "9".repeat(40),
            resolution: "merge-base".to_string(),
        };
        assert_ne!(baseline, key_for(&moved, &policy), "base content");

        // Policy.
        let mut edited = Policy::default();
        edited.loop_policy.iteration_cap = 9;
        assert_ne!(baseline, key_for(&range(), &edited), "policy hash");

        // History window.
        let mut edited = Policy::default();
        edited.history.window_days = 30;
        assert_ne!(baseline, key_for(&range(), &edited), "history window");

        // Engine version, and engine identity.
        let engine_bumped = CacheKey::new(&range(), &policy, "static-metrics", "0.2.0")
            .unwrap()
            .digest()
            .unwrap();
        assert_ne!(baseline, engine_bumped, "engine version");
        let other_engine = CacheKey::new(&range(), &policy, "clones", "0.1.0")
            .unwrap()
            .digest()
            .unwrap();
        assert_ne!(baseline, other_engine, "engine id");

        // Git version.
        let mut moved = range();
        moved.git_version = "git version 2.51.0".to_string();
        assert_ne!(baseline, key_for(&moved, &policy), "git version");
    }

    #[test]
    fn how_the_base_was_resolved_does_not_move_the_key() {
        // `merge-base` and `explicit` naming the same commit are the same
        // measurement. Keying on the label would halve the hit rate for nothing.
        let policy = Policy::default();
        let mut relabelled = range();
        relabelled.base = Endpoint::Commit {
            oid: "1".repeat(40),
            resolution: "explicit".to_string(),
        };
        assert_eq!(key_for(&range(), &policy), key_for(&relabelled, &policy));
    }

    #[test]
    fn a_dirty_endpoint_keys_on_its_snapshot_and_its_mode() {
        let policy = Policy::default();
        let mut incremental = range();
        incremental.head = Endpoint::Worktree {
            snapshot: "a".repeat(64),
            head_oid: "2".repeat(40),
            mode: SnapshotMode::Incremental,
        };
        let mut fallback = incremental.clone();
        fallback.head = Endpoint::Worktree {
            snapshot: "a".repeat(64),
            head_oid: "2".repeat(40),
            mode: SnapshotMode::FullRehash,
        };
        // Same tree, different derivation: a miss, never a shared entry.
        assert_ne!(
            key_for(&incremental, &policy),
            key_for(&fallback, &policy),
            "snapshot mode must be part of the key"
        );
    }

    #[test]
    fn an_index_endpoint_and_a_worktree_endpoint_do_not_collide() {
        // Staged-only and staged-plus-unstaged can hash to the same snapshot
        // when nothing is unstaged. They are still different questions.
        let policy = Policy::default();
        let mut index = range();
        index.head = Endpoint::Index {
            snapshot: "a".repeat(64),
            head_oid: "2".repeat(40),
            mode: SnapshotMode::Incremental,
        };
        let mut worktree = range();
        worktree.head = Endpoint::Worktree {
            snapshot: "a".repeat(64),
            head_oid: "2".repeat(40),
            mode: SnapshotMode::Incremental,
        };
        assert_ne!(key_for(&index, &policy), key_for(&worktree, &policy));
    }
}
