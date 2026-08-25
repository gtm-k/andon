//! `measurement_regime` — the engine-and-configuration tuple a number was
//! produced under.
//!
//! Two measurements are only comparable when their regimes are equal. This is
//! the mechanism behind PREMORTEM S4: a local binary with a newer tree-sitter
//! grammar and a CI binary with an older one will legitimately disagree, and the
//! verifier must say `unwitnessed-version-skew` rather than accuse anyone of
//! tampering. Every engine family carries one, and every per-result digest binds
//! it, so a regime change cannot silently pass as an equal measurement.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::enums::EngineFamily;

/// The configuration tuple for one engine family.
///
/// `BTreeMap` throughout, never `HashMap`: iteration order reaches the canonical
/// serializer, and randomized ordering is one of the three independent
/// byte-nondeterminism sources named in PREMORTEM Story 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "family", rename_all = "kebab-case")]
pub enum MeasurementRegime {
    /// tree-sitter parsing engines (P2).
    Static {
        /// Version of the static-metrics engine.
        engine_version: String,
        /// Revision of the clean-room metric specification implemented.
        spec_revision: String,
        /// Language name to vendored grammar version, e.g. `typescript` -> `0.21.0`.
        grammars: BTreeMap<String, String>,
    },
    /// Token clone detection (P3).
    Clones {
        /// Version of the clone-detection engine.
        engine_version: String,
        /// e.g. `rabin-karp`.
        algorithm: String,
        /// Minimum clone length in tokens.
        min_tokens: u32,
        /// Rolling window width in tokens.
        window_tokens: u32,
        /// Revision of the token-normalization rules.
        normalization_revision: String,
    },
    /// Static tamper detectors (P3).
    Tamper {
        /// Version of the tamper engine.
        engine_version: String,
        /// Which detectors were active, as a revision of the set.
        detector_set_revision: String,
        /// Version of the suppression/threshold rule pack.
        rule_pack_version: String,
    },
    /// git-history signals (P4).
    Process {
        /// Version of the process engine.
        engine_version: String,
        /// Captured from `git --version`; part of the regime because git's
        /// rename-detection defaults change across releases.
        git_version: String,
        /// History window in days, from policy.
        history_window_days: u32,
    },
    /// Coverage-report parsers (P4). Parse-only, never executing.
    Artifacts {
        /// Version of the artifacts engine.
        engine_version: String,
        /// Report format to parser version, e.g. `lcov` -> `1.0`.
        parser_versions: BTreeMap<String, String>,
    },
    /// The user test-command engine (P7) — the one `code-exec` regime.
    Tests {
        /// Version of the tests engine.
        engine_version: String,
        /// The command run, verbatim from `[sandbox] test_command`. Part of
        /// the regime because two runs are comparable only when they ran the
        /// same command.
        command: String,
        /// The isolation class the sandbox provided. `no-net-isolation` in
        /// v1: the suite runs in a temporary worktree with a default-deny
        /// environment and a process-tree kill, and with **no** network
        /// isolation — the disclosed limitation (VISION §5, Codex #19).
        /// Carried in the payload so the disclosure survives serialization.
        sandbox: String,
    },
}

impl MeasurementRegime {
    /// The family this regime belongs to.
    pub fn family(&self) -> EngineFamily {
        match self {
            MeasurementRegime::Static { .. } => EngineFamily::Static,
            MeasurementRegime::Clones { .. } => EngineFamily::Clones,
            MeasurementRegime::Tamper { .. } => EngineFamily::Tamper,
            MeasurementRegime::Process { .. } => EngineFamily::Process,
            MeasurementRegime::Artifacts { .. } => EngineFamily::Artifacts,
            MeasurementRegime::Tests { .. } => EngineFamily::Tests,
        }
    }

    /// The engine version, whichever variant this is.
    pub fn engine_version(&self) -> &str {
        match self {
            MeasurementRegime::Static { engine_version, .. }
            | MeasurementRegime::Clones { engine_version, .. }
            | MeasurementRegime::Tamper { engine_version, .. }
            | MeasurementRegime::Process { engine_version, .. }
            | MeasurementRegime::Artifacts { engine_version, .. }
            | MeasurementRegime::Tests { engine_version, .. } => engine_version,
        }
    }
}
