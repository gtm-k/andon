//! The user test-command occupant — the only v1 `code-exec` engine.
//!
//! # What this engine measures, and how little
//!
//! One question: did the command `[sandbox] test_command` declares exit zero in
//! a clean worktree of the measured snapshot? Two results carry the answer —
//! `tests.suite-failure`, a flag, and `tests.suite-outcome`, the human-readable
//! sentence — and both ride the **async lane**: a test suite does not fit a
//! sub-second fast lane, so this engine is never run inline by `measure`; it is
//! queued and completed by `andon wait` (`andon-cli`'s async module).
//!
//! # A timeout is not a failure
//!
//! A suite killed at `[sandbox] test_timeout_ms` produced no answer, and this
//! engine returns [`EngineError::Failed`] for it — the `engine-unavailable`
//! path, record completeness floored at `partial` — rather than a fired flag.
//! A fired flag over a suite that never finished would be a tamper-adjacent
//! false accusation on possibly-honest code, which is the failure class this
//! project ranks above missed detection (PREMORTEM T1's discipline, applied to
//! execution). The distinction is enforced by the type:
//! [`ExecOutcome`](andon_core::engine::ExecOutcome) carries
//! `timed_out` beside the optional exit code, so conflating them takes effort.
//!
//! # Where the block comes from
//!
//! Not from here, and not from severity. Both claims are tier N, which the
//! default policy caps at `Low` — the evidence is honest about being
//! definitional rather than validated. The line stops because
//! `severity.block_on_test_failure` keys on the failure flag itself
//! (`andon_core::verdict::severity`), the same construction as
//! `block_on_tamper` and the P5a muzzle rule.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use andon_core::engine::{
    EngineDescriptor, EngineError, ExecSpec, MeasureContext, MeasureEngine, MetricDescriptor,
};
use andon_core::registry::EngineRegistryFile;
use andon_core::schema::enums::{Completeness, EngineClass, EngineFamily, Lane, Severity};
use andon_core::schema::payload::{
    CacheState, EvidenceRef, Freshness, MeasurementResult, MetricValue, ResultScope, ScopeKind,
};
use andon_core::schema::regime::MeasurementRegime;
use andon_core::verdict::ladder::SeverityLadder;

use crate::SANDBOX_ISOLATION;

/// Stable engine id. Matches the `engine =` header of `registry/tests.toml`.
pub const ENGINE_ID: &str = "tests";

/// The flag the verdict's test-failure rule keys on — one spelling, declared
/// beside the rule that reads it, shared by this engine and the registry
/// drift test so the three cannot disagree.
pub use andon_core::verdict::severity::SUITE_FAILURE_METRIC;

/// The sentence result beside the flag.
pub const SUITE_OUTCOME_METRIC: &str = "tests.suite-outcome";

/// The shipped evidence registry, compiled in. See the process engine's note on
/// why this is `include_str!` and not a file read.
const REGISTRY_TOML: &str = include_str!("../../../registry/tests.toml");

/// The compiled-in registry file, parsed once.
pub fn registry_file() -> Result<&'static EngineRegistryFile, String> {
    static PARSED: OnceLock<Result<EngineRegistryFile, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            andon_core::registry::parse_file("registry/tests.toml", REGISTRY_TOML)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Every metric this engine can emit, from the registry file itself — the
/// declaration and the emission cannot disagree, because one is read from the
/// other.
pub fn metric_descriptors() -> Vec<MetricDescriptor> {
    let file = match registry_file() {
        Ok(file) => file,
        Err(_) => return Vec::new(),
    };
    file.metrics
        .iter()
        .map(|m| MetricDescriptor {
            metric_id: m.metric_id.clone(),
            claim_id: m.claim_id.clone(),
            class: m.class,
            deterministic: m.deterministic,
        })
        .collect()
}

/// The declared ladders: the failure flag fires `Critical` (policy then caps
/// it by tier — the block keys on the flag, not the number), and the outcome
/// sentence declines to rank itself.
pub fn severity_ladders() -> BTreeMap<String, SeverityLadder> {
    BTreeMap::from([
        (
            SUITE_FAILURE_METRIC.to_string(),
            SeverityLadder::Flag(Severity::Critical),
        ),
        (SUITE_OUTCOME_METRIC.to_string(), SeverityLadder::NoOpinion),
    ])
}

/// The engine. Constructed from the policy in force; carries the command so
/// that [`MeasureEngine::regime`], which has no context argument, can stamp it.
#[derive(Debug)]
pub struct TestCommandEngine {
    command: String,
}

impl TestCommandEngine {
    /// The engine the policy declares, or `None` where it declares none.
    ///
    /// `None` when the lane is disabled or no command is set — and that `None`
    /// means *absent from the roster*, not present-and-failing: a repository
    /// that never opted in gets a payload identical to one from a build with
    /// no sandbox crate at all.
    pub fn from_policy(policy: &andon_core::policy::Policy) -> Option<Self> {
        if !policy.sandbox.enabled {
            return None;
        }
        policy
            .sandbox
            .test_command
            .as_ref()
            .map(|command| TestCommandEngine {
                command: command.clone(),
            })
    }
}

impl MeasureEngine for TestCommandEngine {
    fn descriptor(&self) -> EngineDescriptor {
        EngineDescriptor {
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Tests,
            class: EngineClass::CodeExec,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn metrics(&self) -> Vec<MetricDescriptor> {
        metric_descriptors()
    }

    fn severity_ladders(&self) -> BTreeMap<String, SeverityLadder> {
        severity_ladders()
    }

    fn regime(&self) -> MeasurementRegime {
        MeasurementRegime::Tests {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            command: self.command.clone(),
            // The payload half of the disclosure. The docs half is
            // docs/sandbox.md; both spell the one constant.
            sandbox: SANDBOX_ISOLATION.to_string(),
        }
    }

    fn measure(&self, ctx: &MeasureContext) -> Result<Vec<MeasurementResult>, EngineError> {
        // Defence in depth: `run_engine` refuses a code-exec engine with no
        // sandbox before `measure` is reached, but this method is callable
        // directly and must not become the path around the boundary.
        let Some(sandbox) = &ctx.sandbox else {
            return Err(EngineError::SandboxRequired {
                engine_id: ENGINE_ID.to_string(),
            });
        };
        // The command this engine was built from is the command the policy in
        // force declares. A caller that mixes policies would run one command
        // and stamp another into the regime — refused, because a regime that
        // misdescribes its run poisons every comparison against it.
        if ctx.policy.sandbox.test_command.as_deref() != Some(self.command.as_str()) {
            return Err(EngineError::Failed {
                engine_id: ENGINE_ID.to_string(),
                reason: format!(
                    "the context's policy declares test_command {:?} but this engine was built \
                     for {:?}; one measurement, one command",
                    ctx.policy.sandbox.test_command, self.command
                ),
            });
        }

        let spec = ExecSpec {
            command: self.command.clone(),
            timeout_ms: ctx.policy.sandbox.test_timeout_ms,
            env_allow: ctx.policy.sandbox.env_allow.clone(),
            memory_limit_mb: ctx.policy.sandbox.memory_limit_mb,
        };
        let outcome = sandbox.run(&spec).map_err(|reason| EngineError::Failed {
            engine_id: ENGINE_ID.to_string(),
            reason,
        })?;

        if outcome.timed_out {
            return Err(EngineError::Failed {
                engine_id: ENGINE_ID.to_string(),
                reason: format!(
                    "the test command was killed at the {} ms cap without finishing; a timeout \
                     is an unanswered question, never a test failure",
                    spec.timeout_ms
                ),
            });
        }

        // `Some(0)` is the one passing shape. A signal death on Unix reports
        // no exit code, and a suite that died without exiting did not pass.
        let failed = outcome.exit_code != Some(0);
        let sentence = match outcome.exit_code {
            Some(0) => format!("exited 0 in {} ms", outcome.duration_ms),
            Some(code) => format!("exited {code} in {} ms", outcome.duration_ms),
            None => format!(
                "died without an exit code after {} ms (killed by a signal)",
                outcome.duration_ms
            ),
        };

        let evidence = self.evidence()?;
        Ok(vec![
            self.result(
                SUITE_FAILURE_METRIC,
                MetricValue::Flag(failed),
                outcome.duration_ms,
                evidence.clone(),
            ),
            self.result(
                SUITE_OUTCOME_METRIC,
                MetricValue::Text(sentence),
                outcome.duration_ms,
                evidence,
            ),
        ])
    }
}

impl TestCommandEngine {
    fn evidence(&self) -> Result<EvidenceRef, EngineError> {
        let file = registry_file().map_err(|reason| EngineError::Failed {
            engine_id: ENGINE_ID.to_string(),
            reason,
        })?;
        let claim = file.claims.first().ok_or_else(|| EngineError::Failed {
            engine_id: ENGINE_ID.to_string(),
            reason: "the compiled-in registry declares no claim".to_string(),
        })?;
        Ok(EvidenceRef {
            claim_id: claim.claim_id.clone(),
            tier: claim.tier,
            citation: claim.citation.clone(),
            does_not_predict: claim.does_not_predict.clone(),
            // A claim's staleness is a function of the run date, which is the
            // loader's to answer: assembly's `resolve_evidence` overwrites
            // this from the merged registry on every path to a payload.
            stale: false,
        })
    }

    fn result(
        &self,
        metric_id: &str,
        value: MetricValue,
        duration_ms: u64,
        evidence: EvidenceRef,
    ) -> MeasurementResult {
        let descriptor = metric_descriptors()
            .into_iter()
            .find(|d| d.metric_id == metric_id)
            .expect("the registry declares both metrics");
        MeasurementResult {
            metric_id: descriptor.metric_id.clone(),
            claim_id: descriptor.claim_id.clone(),
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Tests,
            engine_class: EngineClass::CodeExec,
            metric_class: descriptor.class,
            scope: ResultScope {
                kind: ScopeKind::Change,
                path: None,
                blob_oid: None,
                symbol: None,
                line_span: None,
            },
            value,
            // No delta: the base's suite was not run, so there is nothing
            // honest to subtract.
            delta: None,
            // The floor; `run_engine` assigns from the declared ladder.
            severity: Severity::Info,
            completeness: Completeness::Complete,
            measurement_regime: self.regime(),
            evidence,
            deterministic: descriptor.deterministic,
            digest: String::new(),
            freshness: Freshness {
                // Engines in this workspace do not stamp wall-clock times
                // (the artifacts engine is the precedent); the ledger's note
                // carries when the record landed. What the async lane *does*
                // stamp is its identity and its cost.
                measured_at: String::new(),
                duration_ms,
                lane: Lane::Async,
                cache: CacheState::Cold,
            },
        }
    }
}
