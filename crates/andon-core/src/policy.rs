//! `.andon.toml` — the policy schema.
//!
//! Defaults are conservative on purpose (PLAN P0): tamper signals and test
//! failures block, C-tier evidence can only advise, and MED+ severity is
//! reachable only on diff-actionable metrics. Every knob that a phase might
//! otherwise hardcode lives here instead — the iteration cap and the perf
//! budgets especially, because a hardcoded budget is a number nobody can
//! ledger a change to.
//!
//! The verifier loads policy from the **base** commit, so editing thresholds
//! inside the PR being measured gains nothing. Those edits surface as an
//! advisory `policy-change` finding rather than a tamper accusation, and block
//! only when they loosen policy without a ledgered justification (PLAN B6).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::{self, CanonicalError};
use crate::schema::enums::EvidenceTier;

/// Iteration cap default. Three passes is enough for an agent to act on a
/// finding and confirm the fix; past that it is grinding (PREMORTEM A4/S6).
pub const DEFAULT_ITERATION_CAP: u32 = 3;
/// Agent-mode profile budget, in tokens.
pub const DEFAULT_AGENT_PROFILE_TOKEN_BUDGET: u32 = 1500;
/// Bytes-per-token divisor for the budget estimator. Deterministic by design;
/// see `AgentProfileBounds::from_token_budget`.
pub const DEFAULT_BYTES_PER_TOKEN: u32 = 4;
/// Shipped claim tuples for v1, set ex ante (PLAN advisor gate D1 defaults).
/// The bound is "what one person can re-review in a week, once a year"
/// (PREMORTEM S2).
pub const DEFAULT_CLAIM_BUDGET: u32 = 24;
/// Expiry stagger: at most this many claims may fall due in one calendar month.
/// At the budget of 24 a year, two a month is the even spread; three leaves
/// slack without allowing a cliff.
pub const DEFAULT_MAX_CLAIMS_EXPIRING_PER_MONTH: u32 = 3;
/// Default wall-clock cap on the user test command. Generous on purpose: the
/// sandbox is a fresh temporary worktree, so a compiled suite pays a cold
/// build before its first test runs.
pub const DEFAULT_TEST_TIMEOUT_MS: u32 = 600_000;

/// The whole of `.andon.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// Policy schema version. Only `1` is accepted.
    pub schema_version: u32,
    /// What may block, and what evidence is strong enough to.
    pub severity: SeverityPolicy,
    /// Agent-loop guardrails, including the iteration cap.
    #[serde(rename = "loop")]
    pub loop_policy: LoopPolicy,
    /// Agent-mode payload budget.
    pub agent: AgentPolicy,
    /// Latency and spawn budgets, ledgered rather than hardcoded.
    pub perf: PerfPolicy,
    /// History window for the process family.
    pub history: HistoryPolicy,
    /// Evidence-registry governance: claim budget and expiry stagger.
    pub registry: RegistryPolicy,
    /// Rules for Andon measuring itself.
    pub self_measure: SelfMeasurePolicy,
    /// The code-exec lane: the async feature flag, the sandbox limits, and the
    /// user test command (P7).
    pub sandbox: SandboxPolicy,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            severity: SeverityPolicy::default(),
            loop_policy: LoopPolicy::default(),
            agent: AgentPolicy::default(),
            perf: PerfPolicy::default(),
            history: HistoryPolicy::default(),
            registry: RegistryPolicy::default(),
            self_measure: SelfMeasurePolicy::default(),
            sandbox: SandboxPolicy::default(),
        }
    }
}

/// What is allowed to stop the line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct SeverityPolicy {
    /// A tamper signal blocks. Conservative default, and the product's point.
    pub block_on_tamper: bool,
    // Read by `verdict::severity::stops_the_line` since P7 — the disposition
    // the original declared-and-unread note reserved for P0 and P7 to make
    // together. It keys on the tests engine's failure FLAG, never on the
    // result's severity: both tests-lane claims are tier N, so the tier
    // ceiling caps every suite result at `Low` and a severity-keyed rule
    // could never stop the line for a failed suite at all — the same
    // construction, for the same reason, as `block_on_tamper` (P5a muzzle
    // rule). `severity::tests::` pins both directions.
    //
    // A plain comment rather than a doc comment on purpose: doc comments on
    // this struct become `description` strings in the committed JSON schema.
    /// A failing test suite blocks.
    pub block_on_test_failure: bool,
    /// The strongest severity a C-tier claim may reach. Weak evidence advises.
    pub max_severity_for_c_tier: crate::schema::enums::Severity,
    /// MED+ severity requires a diff-actionable metric. Blocking on something
    /// the agent cannot fix is the uninstall loop of PREMORTEM A4.
    pub med_plus_requires_diff_actionable: bool,
    /// Evidence tiers that may reach MED+ at all.
    pub med_plus_tiers: Vec<EvidenceTier>,
}

impl Default for SeverityPolicy {
    fn default() -> Self {
        Self {
            block_on_tamper: true,
            block_on_test_failure: true,
            max_severity_for_c_tier: crate::schema::enums::Severity::Low,
            med_plus_requires_diff_actionable: true,
            med_plus_tiers: vec![EvidenceTier::A, EvidenceTier::B],
        }
    }
}

/// Agent-loop guardrails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LoopPolicy {
    /// Passes around the loop before `escalate_to_human`. A policy field, never
    /// a constant in the verdict code.
    pub iteration_cap: u32,
    /// Whether context-informational findings advance the counter. Default
    /// `false`: an agent must not burn its budget on what it cannot fix.
    pub count_context_informational: bool,
}

impl Default for LoopPolicy {
    fn default() -> Self {
        Self {
            iteration_cap: DEFAULT_ITERATION_CAP,
            count_context_informational: false,
        }
    }
}

/// Agent-mode payload budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct AgentPolicy {
    /// Token ceiling for the agent-mode profile.
    pub profile_token_budget: u32,
    /// Divisor converting the token budget into a byte budget. Deliberately a
    /// fixed estimate rather than a real tokenizer: a guardrail that is stable
    /// across models beats one that is accurate for one of them.
    pub bytes_per_token: u32,
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            profile_token_budget: DEFAULT_AGENT_PROFILE_TOKEN_BUDGET,
            bytes_per_token: DEFAULT_BYTES_PER_TOKEN,
        }
    }
}

/// Latency budgets. Here rather than in the perf harness so that changing one is
/// a ledgered policy edit and not a quiet ratchet (PREMORTEM T6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PerfPolicy {
    /// Warm-cache p95 target for the fast lane, with a watching fsmonitor
    /// daemon. The headline number.
    pub fast_lane_warm_p95_ms: u32,
    /// Warm-cache p95 target for the dirty-tree path with **no** watching
    /// fsmonitor daemon.
    ///
    /// A second budget rather than a second-class one. Builtin fsmonitor is
    /// absent on Linux and can decline anywhere, so the un-accelerated
    /// arrangement is what a real fraction of users run — and on a 100k-file
    /// repository it costs the best part of a second more than the accelerated
    /// one. Holding it to the headline budget would mean either a red gate on
    /// every Linux run or the number quietly not being gated at all, and the
    /// second is what happened: 1306.9 ms went unreported against a 1000 ms
    /// figure the gate was passing.
    ///
    /// So it is disclosed, gated, and separate. Raising either is a ledgered
    /// policy edit; the gap between them is the cost of not having a daemon, and
    /// it is meant to be visible.
    pub fast_lane_warm_fallback_p95_ms: u32,
    /// Hard cold cap; past it the fast lane spills to async with
    /// `completeness: partial` (APPROACH graft 4).
    pub fast_lane_cold_cap_ms: u32,
    /// Asserted, not observed: a regression that doubles git spawns shows up
    /// here before it shows up as latency on someone else's machine.
    pub max_git_spawns_per_measure: u32,
}

impl Default for PerfPolicy {
    fn default() -> Self {
        Self {
            fast_lane_warm_p95_ms: 1000,
            fast_lane_warm_fallback_p95_ms: 2000,
            fast_lane_cold_cap_ms: 10_000,
            max_git_spawns_per_measure: 64,
        }
    }
}

/// History window for process metrics. Part of the process `measurement_regime`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct HistoryPolicy {
    /// Days of history the process family reads. Stamped into the process
    /// `measurement_regime`, so changing it makes old and new numbers
    /// incomparable rather than silently different.
    pub window_days: u32,
}

impl Default for HistoryPolicy {
    fn default() -> Self {
        Self { window_days: 365 }
    }
}

/// Evidence-registry governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RegistryPolicy {
    /// Enforced count. Exceeding it fails the lint, and therefore the build.
    pub claim_budget: u32,
    /// Expiry stagger bound, enforced by the lint.
    pub max_claims_expiring_per_month: u32,
}

impl Default for RegistryPolicy {
    fn default() -> Self {
        Self {
            claim_budget: DEFAULT_CLAIM_BUDGET,
            max_claims_expiring_per_month: DEFAULT_MAX_CLAIMS_EXPIRING_PER_MONTH,
        }
    }
}

/// How Andon measures itself (PREMORTEM S3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct SelfMeasurePolicy {
    /// Which binary is allowed to measure this repository.
    pub binary: SelfMeasureBinary,
    /// Paths excluded from self-measurement — the adversarial fixtures, which
    /// exist to fire the tamper suite and would otherwise block every build.
    /// Declared here rather than hidden in the runner, so the exclusion is
    /// reviewable and the drift signal has something to compare against.
    pub excluded_paths: Vec<String>,
    /// Emit a finding when the excluded set grows. An exclusion list that
    /// quietly widens is how dogfood circularity stops being visible.
    pub exclusion_drift_signal: bool,
}

impl Default for SelfMeasurePolicy {
    fn default() -> Self {
        Self {
            binary: SelfMeasureBinary::LastAttestedRelease,
            excluded_paths: vec![
                "fixtures/gamed/**".to_string(),
                "fixtures/adversarial/**".to_string(),
                "crates/andon-registry-lint/tests/fixtures/**".to_string(),
            ],
            exclusion_drift_signal: true,
        }
    }
}

/// The code-exec lane (PLAN P7, Codex #19).
///
/// Everything here is off or empty by default: the async lane is feature-flagged
/// (`enabled` is the flag, and the P7 rollback path), and the only v1 code-exec
/// occupant — the user's own test command — exists only where an operator
/// declares one. A repository that never touches this section measures exactly
/// as it did before the lane existed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct SandboxPolicy {
    /// The async lane's feature flag. While `false`, no code-exec engine joins
    /// a measurement and the fast lane never spills work to the async lane —
    /// `perf.fast_lane_cold_cap_ms` goes back to being unenforced, which is the
    /// pre-P7 behaviour and the rollback path.
    pub enabled: bool,
    /// The user's test command, run by the tests engine inside the sandbox
    /// through the platform shell (`sh -c` / `cmd /C`). `None` means this
    /// deployment ships no code-exec engine at all: the tests engine is absent
    /// from the expected-engine roster, not present-and-failing.
    ///
    /// Declared here rather than taken as a flag so that the command is policy:
    /// the verifier reads it from the base commit, and editing it inside the
    /// change under measurement surfaces as a `policy-change` finding (the
    /// trusted-command half of Codex #19).
    pub test_command: Option<String>,
    /// Wall-clock cap on the test command, in milliseconds. At the cap the
    /// whole process tree is killed and the engine reports a timeout — which is
    /// an unanswered question (`engine-unavailable`), never a test failure.
    pub test_timeout_ms: u32,
    /// Environment variable names passed through to the suite beyond the base
    /// allowlist (`andon-sandbox` documents the base list). Default-deny is the
    /// rule: nothing else crosses, so secrets in the invoking environment never
    /// reach repository code.
    pub env_allow: Vec<String>,
    /// Best-effort memory cap for the suite's process tree, in MiB. `None`
    /// means no cap. Best-effort by name because the mechanisms differ per OS
    /// (job-object limit on Windows, address-space rlimit elsewhere) and
    /// neither is a security boundary.
    pub memory_limit_mb: Option<u64>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            test_command: None,
            test_timeout_ms: DEFAULT_TEST_TIMEOUT_MS,
            env_allow: Vec::new(),
            memory_limit_mb: None,
        }
    }
}

/// Which binary performs self-measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SelfMeasureBinary {
    /// The rule: measure with the last attested release, so a broken detector
    /// cannot bless its own fix.
    LastAttestedRelease,
    /// The bootstrap exception: legal only until the first attested release
    /// exists (decision log, 2026-08-16).
    CurrentBuild,
}

/// Failed to read or parse a policy file.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The file is not valid TOML, or carries a key the schema does not define.
    #[error("policy is not valid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// The file declares a schema version this binary does not implement.
    #[error("unsupported policy schema_version {found} (expected {expected})")]
    UnsupportedVersion {
        /// Version the file declared.
        found: u32,
        /// Version this binary implements.
        expected: u32,
    },
    /// The policy could not be canonically serialized for hashing.
    #[error("policy could not be hashed: {0}")]
    Canonical(#[from] CanonicalError),
}

impl Policy {
    /// Parse `.andon.toml` contents. Missing sections take conservative defaults.
    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        let policy: Policy = toml::from_str(text)?;
        if policy.schema_version != 1 {
            return Err(PolicyError::UnsupportedVersion {
                found: policy.schema_version,
                expected: 1,
            });
        }
        Ok(policy)
    }

    /// Digest of the policy in force.
    ///
    /// Stamped on records and used in P1's cache key. Deliberately **not** part
    /// of any per-result digest — see `ResultDigestInput`.
    pub fn policy_hash(&self) -> Result<String, PolicyError> {
        Ok(canonical::digest(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let policy = Policy::default();
        assert!(policy.severity.block_on_tamper);
        assert!(policy.severity.block_on_test_failure);
        assert!(policy.severity.med_plus_requires_diff_actionable);
        assert_eq!(
            policy.severity.max_severity_for_c_tier,
            crate::schema::enums::Severity::Low,
            "C-tier evidence must never reach a blocking severity"
        );
        assert_eq!(policy.loop_policy.iteration_cap, DEFAULT_ITERATION_CAP);
        assert_eq!(policy.registry.claim_budget, DEFAULT_CLAIM_BUDGET);
    }

    #[test]
    fn an_empty_file_yields_the_conservative_defaults() {
        assert_eq!(
            Policy::from_toml("schema_version = 1").unwrap(),
            Policy::default()
        );
    }

    #[test]
    fn unknown_keys_are_rejected_rather_than_silently_ignored() {
        // A typo'd threshold that silently keeps the default is a policy the
        // operator believes is in force and is not.
        let err = Policy::from_toml("schema_version = 1\n[loop]\niteraton_cap = 9\n");
        assert!(err.is_err());
    }

    #[test]
    fn a_future_schema_version_is_refused() {
        assert!(matches!(
            Policy::from_toml("schema_version = 2"),
            Err(PolicyError::UnsupportedVersion { found: 2, .. })
        ));
    }

    #[test]
    fn policy_hash_tracks_content_not_field_order() {
        let a = Policy::from_toml("schema_version = 1\n[loop]\niteration_cap = 5\n").unwrap();
        let b = Policy::from_toml("schema_version = 1\n[loop]\niteration_cap = 5\n").unwrap();
        assert_eq!(a.policy_hash().unwrap(), b.policy_hash().unwrap());
        let c = Policy::from_toml("schema_version = 1\n[loop]\niteration_cap = 6\n").unwrap();
        assert_ne!(a.policy_hash().unwrap(), c.policy_hash().unwrap());
    }
}
