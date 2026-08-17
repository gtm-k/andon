//! The windowed history cache.
//!
//! # What makes this cache safe to have
//!
//! An entry is keyed by the **anchor commit OID**, and a commit is immutable.
//! The history reachable from a given commit, filtered by a cutoff derived from
//! that same commit's timestamp, is therefore a fixed value: the same key can
//! never legitimately name two different answers. That is the property a
//! measurement cache has to have before it is allowed anywhere near a digest,
//! and it is why the wall-clock window this engine refuses to implement would
//! have been uncacheable as well as non-reproducible.
//!
//! # What it costs and what it saves
//!
//! Reading the window is two git spawns and a walk bounded by the window. A hit
//! is **zero spawns** — which is what keeps the process family off the warm
//! path's budget (PREMORTEM T6). A miss on a repository whose window holds
//! years of commits is the expensive case, and it is paid once per anchor
//! commit rather than once per measurement.
//!
//! The entry stores the commit list rather than per-path totals, because change
//! coupling is a question about which paths appear together and a per-path
//! aggregate has already thrown that away. Size is linear in the window's
//! path-touches.
//!
//! # Nothing here evicts, and that is a decision routed rather than made
//!
//! An entry is written per anchor commit, and no entry is ever removed. On a
//! busy repository measured every commit, that is one entry per commit measured,
//! each linear in the window's path-touches — roughly 156 bytes per touch,
//! measured on a 300-commit fixture. It grows without bound.
//!
//! No eviction is implemented here **on purpose**. Cache lifecycle is not a
//! property of the process family: P3's clone index, P5a's assembled fast lane,
//! and P9's verifier all put state under the git directory, and three phases
//! each inventing a retention policy is how a repository ends up with three. The
//! decision — a size cap, an age cap, an `andon cache prune`, or a documented
//! "delete the directory" — belongs to whichever phase first owns cache
//! lifecycle across the workspace, which the plan puts at **P5a or P9**.
//!
//! What is safe to rely on in the meantime: every entry is a derived value, so
//! the directory can be deleted at any moment and the only cost is a slower next
//! run. It lives under the git directory, so a fresh clone starts empty and
//! removing the clone removes it.
//!
//! # Over-keying, deliberately
//!
//! [`andon_core::cache::CacheKey`] carries a `policy_hash`, and the window does
//! not depend on policy beyond `history.window_days`, which the key already
//! carries separately. The hash is supplied honestly anyway rather than stubbed:
//! the field means "the policy in force", a lie there would be a lie in a
//! digest-adjacent structure, and the only cost of telling the truth is that a
//! policy edit re-walks the history once.

use std::path::{Path, PathBuf};

use andon_core::cache::{CacheError, CacheKey, CacheStore, CACHE_KEY_VERSION};
use andon_core::git::{EndpointKey, Git};
use andon_core::policy::Policy;

use crate::history::{HistoryError, HistoryWindow};

/// Engine id the history cache keys under.
///
/// Distinct from the process engine's own id on purpose: this cache holds the
/// *input* to the process metrics, not their results, and an engine-result entry
/// arriving under the same key would be a wrong hit rather than a miss.
pub const HISTORY_CACHE_ID: &str = "process-history";

/// Directory the per-repository cache lives in, under the git directory.
///
/// Inside `.git` because that is where per-checkout derived state belongs: it is
/// ignored by construction, it is removed when the clone is, and it never
/// appears in a diff or a `status`. A worktree has its own git directory, so two
/// worktrees of one repository keep separate caches — correct, since they can be
/// at different commits.
pub const CACHE_SUBDIR: &str = "andon/history";

/// Reading or writing the cached window failed.
#[derive(Debug, thiserror::Error)]
pub enum HistoryCacheError {
    /// The underlying store failed.
    #[error(transparent)]
    Cache(#[from] CacheError),
    /// The history itself could not be read.
    #[error(transparent)]
    History(#[from] HistoryError),
    /// The policy in force could not be hashed, so no key can be built.
    #[error("the policy in force could not be hashed for the cache key: {0}")]
    Policy(#[from] andon_core::policy::PolicyError),
}

/// A cache of windowed histories, keyed by anchor commit.
#[derive(Debug, Clone)]
pub struct HistoryCache {
    store: CacheStore,
}

impl HistoryCache {
    /// Open the cache belonging to this repository.
    pub fn for_repo(git: &Git) -> Result<Self, CacheError> {
        Self::at(git.facts().git_dir.join(CACHE_SUBDIR))
    }

    /// Open a cache rooted at an explicit path.
    pub fn at(root: impl Into<PathBuf>) -> Result<Self, CacheError> {
        Ok(HistoryCache {
            store: CacheStore::open(root)?,
        })
    }

    /// Where entries are written.
    pub fn root(&self) -> &Path {
        self.store.root()
    }

    /// The window for `anchor_oid`, from the cache or from git.
    ///
    /// A stored entry that does not describe what was asked for is treated as a
    /// miss rather than trusted or reported: the store's contract is that a key
    /// names the bytes written under it, and anything else in that file is
    /// something no writer of this version put there. Recomputing is always
    /// available and always correct, so there is nothing to gain by believing it.
    pub fn load_or_read(
        &self,
        git: &Git,
        anchor_oid: &str,
        policy: &Policy,
        engine_version: &str,
    ) -> Result<HistoryWindow, HistoryCacheError> {
        let window_days = policy.history.window_days;
        let key = self.key(anchor_oid, policy, engine_version, git.version())?;

        if let Some(bytes) = self.store.get(&key)? {
            if let Ok(window) = serde_json::from_slice::<HistoryWindow>(&bytes) {
                if window.describes(anchor_oid, window_days, git.version())
                    && window.answers_this_clone(git.facts().shallow)
                {
                    return Ok(window);
                }
            }
        }

        let window = HistoryWindow::read(git, anchor_oid, window_days)?;
        // A failed write is propagated rather than swallowed: a cache that
        // silently never persists turns every measurement into a cold one, and
        // that is the PREMORTEM T6 regression nobody would see. Serialization
        // itself cannot fail for this shape — string keys, integers, no floats —
        // so `?` on `put` is the only failure this line has.
        let bytes = serde_json::to_vec(&window).map_err(|err| CacheError::Io {
            path: self.store.root().display().to_string(),
            source: std::io::Error::other(err),
        })?;
        self.store.put(&key, &bytes)?;
        Ok(window)
    }

    fn key(
        &self,
        anchor_oid: &str,
        policy: &Policy,
        engine_version: &str,
        git_version: &str,
    ) -> Result<CacheKey, HistoryCacheError> {
        let anchor = EndpointKey::Commit {
            oid: anchor_oid.to_string(),
        };
        Ok(CacheKey {
            version: CACHE_KEY_VERSION,
            // The window is anchored at one commit, so both endpoints are that
            // commit. The key type is shaped for a range; this entry is not one.
            base: anchor.clone(),
            head: anchor,
            policy_hash: policy.policy_hash()?,
            engine_id: HISTORY_CACHE_ID.to_string(),
            engine_version: engine_version.to_string(),
            history_window_days: policy.history.window_days,
            git_version: git_version.to_string(),
        })
    }
}

impl HistoryWindow {
    /// Whether a loaded entry answers the question that was asked.
    pub fn describes(&self, anchor_oid: &str, window_days: u32, git_version: &str) -> bool {
        self.version == crate::history::WINDOW_VERSION
            && self.anchor_oid == anchor_oid
            && self.window_days == window_days
            && self.git_version == git_version
    }

    /// Whether a loaded entry was computed under a clone that could answer the
    /// question this one is being asked.
    ///
    /// # The hole in the one-key-one-answer argument
    ///
    /// The key is an anchor commit, and a commit is immutable — which is what
    /// licenses this cache to exist at all. But **truncation is a property of
    /// the clone, not of the commit**. The same anchor answers differently
    /// before and after `git fetch --unshallow`, so an entry written while the
    /// clone was shallow is not a cached answer to the question a complete clone
    /// is asking. Without this check, an agent that measured at `--depth 1` and
    /// then fetched kept being told its history was truncated, and the only way
    /// to see the real numbers was to bypass the cache. PLAN P9 requires the
    /// verifier to unshallow before recomputing; a cache that ignored the fetch
    /// would have defeated that doctrine silently.
    ///
    /// # Why this is deliberately one-directional
    ///
    /// A **truncated entry in a complete clone** is stale: it describes less
    /// than the repository can now witness, so it is refused and recomputed.
    ///
    /// A **complete entry in a clone that has since been re-shallowed** is
    /// served. It is not stale — it was computed from real commits for this
    /// exact anchor, and those commits did not stop having existed because a
    /// later fetch narrowed what this clone keeps. Refusing it would throw away
    /// a correct answer to buy symmetry, and would make the recomputed
    /// replacement *worse*: markers where there were numbers. The asymmetry is
    /// the point — the rule is "never serve less than the clone can witness",
    /// not "always match the clone".
    ///
    /// Nothing about either direction can produce a false accusation: a
    /// truncated side and a complete side emit results at different scopes, so
    /// they never pair, and `compare` returns `unwitnessed` rather than
    /// `divergent` (see `crate::engine`, and `tests/compare_asymmetry.rs`).
    pub fn answers_this_clone(&self, clone_is_shallow: bool) -> bool {
        !self.truncated || clone_is_shallow
    }
}
