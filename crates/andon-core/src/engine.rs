//! The `MeasureEngine` trait — the abstraction every measurement enters through.
//!
//! Two properties are enforced here rather than left to convention:
//!
//! - **Every metric names its claim.** A [`MetricDescriptor`] cannot be built
//!   without a `claim_id`, and the registry lint fails the build when that id
//!   does not resolve to a claim tuple. There is no path from an engine to a
//!   reported number that skips the evidence registry (APPROACH graft 3).
//! - **`code-exec` engines cannot run in a `static-safe` context.** The class is
//!   part of the descriptor and [`run_engine`] refuses the combination, so an
//!   engine that executes repository code cannot be invoked by a caller that
//!   promised not to (Codex #19).
//! - **Every metric declares how its numbers become a severity.** The ladder is
//!   declared once per metric ([`MeasureEngine::severity_ladders`]) and applied
//!   here, so a result-construction site cannot write a severity of its own and
//!   a metric that declares nothing is a refusal rather than a silent `Info`
//!   (PLAN decision log, mini-G2 ruling; [`crate::verdict::ladder`]).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::parse_health;
use crate::policy::Policy;
use crate::schema::enums::{EngineClass, EngineFamily, MetricClass};
use crate::schema::payload::{CompareContext, MeasurementResult};
use crate::schema::regime::MeasurementRegime;
use crate::verdict::ladder::SeverityLadder;

/// Identity of an engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EngineDescriptor {
    /// Stable id, e.g. `static-metrics`. Matches the registry file stem.
    pub engine_id: String,
    /// Which of the five families this engine belongs to.
    pub family: EngineFamily,
    /// Whether running it executes repository code.
    pub class: EngineClass,
    /// Engine version, carried into the `measurement_regime`.
    pub version: String,
}

/// Declaration of one metric an engine emits.
///
/// The registry file for the engine must contain the identical set, and each
/// engine's tests assert that (see `registry::EngineRegistry::check_engine`), so
/// the declarative manifest the lint reads can never drift from the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MetricDescriptor {
    /// Stable id, e.g. `static.cognitive-complexity`.
    pub metric_id: String,
    /// The claim tuple this metric's numbers stand on.
    pub claim_id: String,
    /// Whether the agent can act on this metric inside its own change.
    pub class: MetricClass,
    /// Whether results are seed-free and byte-reproducible, and so belong in the
    /// digest compare set.
    pub deterministic: bool,
}

/// What an engine is given to measure.
///
/// Deliberately thin at P0: git resolution, content access, and caching are P1's
/// to add. Engines depend on this type, so widening it later is additive.
#[derive(Debug, Clone)]
pub struct MeasureContext {
    /// The `(base_oid, head_oid)` tuple being measured.
    pub compare_context: CompareContext,
    /// Policy in force. Loaded from the base commit when the verifier runs.
    pub policy: Policy,
    /// Repository-relative paths touched by the change, as git spells them.
    pub changed_paths: Vec<String>,
    /// Whether a sandbox is available for `code-exec` engines. P7 replaces the
    /// flag with a real handle.
    pub sandbox_available: bool,
}

/// Why an engine could not produce results.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// A `code-exec` engine was asked to run without a sandbox.
    #[error("engine '{engine_id}' executes repository code and requires a sandbox")]
    SandboxRequired {
        /// The engine that was refused.
        engine_id: String,
    },
    /// The inputs the engine needed were not available. Reported as
    /// `completeness: unwitnessed`, never as a zero.
    #[error("engine '{engine_id}' had no inputs: {reason}")]
    NoInputs {
        /// The engine that had nothing to measure.
        engine_id: String,
        /// What was missing, e.g. "shallow clone: no history".
        reason: String,
    },
    /// Anything else, kept opaque so engines can carry their own errors.
    #[error("engine '{engine_id}' failed: {reason}")]
    Failed {
        /// The engine that failed.
        engine_id: String,
        /// Engine-supplied detail.
        reason: String,
    },
}

/// One measurement engine.
pub trait MeasureEngine {
    /// Who this engine is.
    fn descriptor(&self) -> EngineDescriptor;

    /// Every metric this engine can emit. Must equal the engine's registry file.
    fn metrics(&self) -> Vec<MetricDescriptor>;

    /// How each metric's own numbers become a pre-policy severity.
    ///
    /// One entry per metric id in [`Self::metrics`] — the declaration
    /// [`run_engine`] applies, and the only place a shipped severity comes from.
    /// Required rather than defaulted: a default empty map would make "this
    /// engine forgot" and "this engine has no opinion" the same observation,
    /// which is the seam the mini-G2 ruling exists to close.
    /// [`crate::verdict::ladder::SeverityLadder::NoOpinion`] says the second one
    /// out loud.
    fn severity_ladders(&self) -> BTreeMap<String, SeverityLadder>;

    /// The configuration tuple results will be stamped with.
    fn regime(&self) -> MeasurementRegime;

    /// Measure. Results come back unsealed; the caller seals them against the
    /// compare context via [`MeasurementResult::seal`].
    fn measure(&self, ctx: &MeasureContext) -> Result<Vec<MeasurementResult>, EngineError>;
}

/// Run an engine with the class rule enforced.
///
/// The one supported way to invoke an engine. Calling `measure` directly skips
/// the sandbox check, which is why every caller in the workspace goes through
/// here.
///
/// # The family stamp is checked before sealing, not after
///
/// `family` is inside [`crate::schema::payload::ResultDigestInput`] and so is
/// the `measurement_regime` that implies it. A result stamped with the wrong
/// family therefore seals *consistently*: the agent and the verifier both make
/// the same mistake, both digests agree, and the compare returns `confirmed`
/// over a number filed under an engine family it never came from. Nothing
/// downstream can detect it, because the mechanism that detects disagreement is
/// the one thing that agrees.
///
/// So it is caught here, where the three statements of the same fact are all in
/// scope: the result's own stamp, the engine's descriptor, and the family its
/// regime belongs to. A refusal rather than a panic — this runs inside an agent
/// loop, and the caller's job is to report the engine as unavailable, not to
/// take the process down (PLAN wave-1 integration, P5a-entry note 1).
///
/// # Severity is assigned here, not written by the engine
///
/// Each result's `severity` is set from the ladder its metric declares
/// ([`MeasureEngine::severity_ladders`]), then capped by the completeness
/// ceiling — the same cap [`crate::parse_health::demote`] applies, restated here
/// because assignment happens after the engine has finished demoting and would
/// otherwise undo it.
///
/// Assigning rather than checking is the point. An engine that hardcodes a
/// severity at a result-construction site has nowhere to put it: the field is
/// overwritten from the declaration on the way through, so the declaration is
/// not merely the intended source, it is the only one. That is what makes the
/// accepted "five places to drift" risk bounded by construction.
///
/// `severity` sits outside [`crate::schema::payload::ResultDigestInput`], so
/// assigning it before sealing cannot move a digest — and the verifier, running
/// the same engines through the same boundary, reaches the same pre-policy
/// answer before applying the base commit's policy over the top.
pub fn run_engine(
    engine: &dyn MeasureEngine,
    ctx: &MeasureContext,
) -> Result<Vec<MeasurementResult>, EngineError> {
    let descriptor = engine.descriptor();
    if descriptor.class == EngineClass::CodeExec && !ctx.sandbox_available {
        return Err(EngineError::SandboxRequired {
            engine_id: descriptor.engine_id,
        });
    }

    let declared = engine.regime().family();
    if declared != descriptor.family {
        return Err(EngineError::Failed {
            engine_id: descriptor.engine_id.clone(),
            reason: format!(
                "engine reports family {:?} but its regime belongs to {declared:?}",
                descriptor.family
            ),
        });
    }

    let ladders = engine.severity_ladders();
    let mut results = engine.measure(ctx)?;
    for result in &mut results {
        let regime_family = result.measurement_regime.family();
        if result.family != descriptor.family || result.family != regime_family {
            return Err(EngineError::Failed {
                engine_id: descriptor.engine_id.clone(),
                reason: format!(
                    "result '{}' is stamped {:?} but the engine reports {:?} and the result's \
                     regime belongs to {regime_family:?}",
                    result.metric_id, result.family, descriptor.family
                ),
            });
        }
        assign_severity(result, &ladders, &descriptor.engine_id)?;
        result
            .seal(&ctx.compare_context)
            .map_err(|e| EngineError::Failed {
                engine_id: descriptor.engine_id.clone(),
                reason: format!("digest: {e}"),
            })?;
    }
    Ok(results)
}

/// Set one result's pre-policy severity from its metric's declared ladder.
///
/// A metric with no declaration is refused. The alternative — defaulting to
/// `Info` — is precisely the state the whole workspace was in before the
/// mini-G2 ruling: every engine reporting the honest floor, nothing able to
/// reach the MED+ band, and no test anywhere that could tell the difference
/// between "declines to rank this" and "nobody wrote the ranking".
fn assign_severity(
    result: &mut MeasurementResult,
    ladders: &BTreeMap<String, SeverityLadder>,
    engine_id: &str,
) -> Result<(), EngineError> {
    let Some(ladder) = ladders.get(&result.metric_id) else {
        return Err(EngineError::Failed {
            engine_id: engine_id.to_string(),
            reason: format!(
                "metric '{}' declares no severity ladder; every metric states one, and \
                 `SeverityLadder::NoOpinion` is how a metric says it declines to rank itself",
                result.metric_id
            ),
        });
    };
    let declared = ladder
        .severity_for(&result.value)
        .map_err(|e| EngineError::Failed {
            engine_id: engine_id.to_string(),
            reason: format!("metric '{}': {e}", result.metric_id),
        })?
        // `PerResult`: the engine has already written it, from a rule of its own.
        .unwrap_or(result.severity);
    result.severity = declared.min(parse_health::severity_ceiling(result.completeness));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::enums::{Completeness, EngineFamily, Severity};
    use crate::testing::{sample_compare_context, sample_regime, sample_result};
    use crate::verdict::ladder::{Rung, Threshold};

    /// An engine that can be told to lie about a family, one lie at a time.
    ///
    /// Three places state the same fact — the descriptor, the regime, and the
    /// stamp on each result — so there are three ways to make them disagree and
    /// each needs its own case.
    struct Stamper {
        descriptor_family: EngineFamily,
        regime: MeasurementRegime,
        result_family: EngineFamily,
        result_regime: MeasurementRegime,
        /// The ladder declared for the one metric it emits, or none declared at
        /// all — the refusal case.
        ladder: Option<SeverityLadder>,
        /// What the engine writes into `severity` before the boundary sees it.
        result_severity: Severity,
        /// What the engine writes into `completeness`.
        result_completeness: Completeness,
    }

    /// The three-rung ladder the honest `Stamper` declares.
    const RUNGS: &[Rung] = &[
        Rung {
            at: Threshold::Count(10),
            severity: Severity::Medium,
        },
        Rung {
            at: Threshold::Count(40),
            severity: Severity::High,
        },
    ];

    impl Default for Stamper {
        /// Honest: every statement of the family agrees with the others.
        fn default() -> Self {
            Stamper {
                descriptor_family: EngineFamily::Static,
                regime: sample_regime(),
                result_family: EngineFamily::Static,
                result_regime: sample_regime(),
                ladder: Some(SeverityLadder::Thresholds(RUNGS)),
                result_severity: Severity::Info,
                result_completeness: Completeness::Complete,
            }
        }
    }

    /// A regime belonging to a family that is not `static`.
    fn foreign_regime() -> MeasurementRegime {
        MeasurementRegime::Process {
            engine_version: "0.1.0".to_string(),
            git_version: "git version 2.51.0".to_string(),
            history_window_days: 365,
        }
    }

    impl MeasureEngine for Stamper {
        fn descriptor(&self) -> EngineDescriptor {
            EngineDescriptor {
                engine_id: "stamper".to_string(),
                family: self.descriptor_family,
                class: EngineClass::StaticSafe,
                version: "0.1.0".to_string(),
            }
        }

        fn metrics(&self) -> Vec<MetricDescriptor> {
            Vec::new()
        }

        fn severity_ladders(&self) -> BTreeMap<String, SeverityLadder> {
            self.ladder
                .map(|ladder| [(sample_result().metric_id, ladder)].into())
                .unwrap_or_default()
        }

        fn regime(&self) -> MeasurementRegime {
            self.regime.clone()
        }

        fn measure(&self, _ctx: &MeasureContext) -> Result<Vec<MeasurementResult>, EngineError> {
            let mut result = sample_result();
            result.engine_id = "stamper".to_string();
            result.family = self.result_family;
            result.measurement_regime = self.result_regime.clone();
            result.severity = self.result_severity;
            result.completeness = self.result_completeness;
            // Unsealed, as the trait requires: `run_engine` seals, and the
            // family check has to happen before it does.
            result.digest = String::new();
            Ok(vec![result])
        }
    }

    fn context() -> MeasureContext {
        MeasureContext {
            compare_context: sample_compare_context(),
            policy: Policy::default(),
            changed_paths: Vec::new(),
            sandbox_available: false,
        }
    }

    fn refusal(engine: Stamper) -> String {
        match run_engine(&engine, &context()) {
            Err(EngineError::Failed { reason, .. }) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_honest_engine_runs_and_its_results_are_sealed() {
        let results = run_engine(&Stamper::default(), &context()).expect("measures");
        assert_eq!(results.len(), 1);
        assert!(!results[0].digest.is_empty(), "run_engine seals");
    }

    #[test]
    fn an_engine_whose_regime_belongs_to_another_family_is_refused() {
        // The engine misdeclares itself: descriptor says `static`, regime says
        // `process`. Caught before it measures anything at all.
        let reason = refusal(Stamper {
            regime: foreign_regime(),
            ..Stamper::default()
        });
        assert!(reason.contains("Static"), "{reason}");
        assert!(reason.contains("Process"), "{reason}");
    }

    #[test]
    fn a_result_stamped_with_another_family_is_refused() {
        // The stamp disagrees with the engine that produced it. Without this,
        // the result seals with `family: clones` inside the digest input and the
        // verifier — making the identical mistake — confirms it.
        let reason = refusal(Stamper {
            result_family: EngineFamily::Clones,
            ..Stamper::default()
        });
        assert!(reason.contains("static.cognitive-complexity"), "{reason}");
        assert!(reason.contains("Clones"), "{reason}");
    }

    #[test]
    fn a_result_whose_regime_belongs_to_another_family_is_refused() {
        // The subtlest of the three: descriptor and stamp agree, and the regime
        // — which is *also* inside the digest input — says something else.
        let reason = refusal(Stamper {
            result_regime: foreign_regime(),
            ..Stamper::default()
        });
        assert!(reason.contains("Process"), "{reason}");
    }

    #[test]
    fn a_refused_result_is_never_sealed() {
        // The order matters. A digest computed over a wrong family is a digest
        // the verifier will reproduce exactly, so the refusal has to land before
        // `seal` rather than after it.
        let engine = Stamper {
            result_family: EngineFamily::Clones,
            ..Stamper::default()
        };
        assert!(run_engine(&engine, &context()).is_err());
        let unsealed = engine
            .measure(&context())
            .expect("the engine itself is happy");
        assert!(
            unsealed[0].digest.is_empty(),
            "nothing sealed a result the boundary refused"
        );
    }

    #[test]
    fn severity_comes_from_the_declaration_and_not_from_the_engine() {
        // `sample_result()` carries `MetricValue::Count(17)`, which reaches the
        // `Medium` rung and not the `High` one.
        let results = run_engine(&Stamper::default(), &context()).expect("measures");
        assert_eq!(results[0].severity, Severity::Medium);
    }

    #[test]
    fn a_hardcoded_severity_at_a_result_site_has_nowhere_to_land() {
        // The failure this boundary exists to make impossible. An engine that
        // writes its own severity — in either direction — is overwritten from
        // the declaration, so a hardcode is not merely discouraged, it has no
        // effect at all.
        let shouting = Stamper {
            result_severity: Severity::Critical,
            ..Stamper::default()
        };
        let quiet = Stamper {
            result_severity: Severity::Info,
            ..Stamper::default()
        };
        let loud = run_engine(&shouting, &context()).expect("measures");
        let hushed = run_engine(&quiet, &context()).expect("measures");
        assert_eq!(loud[0].severity, Severity::Medium);
        assert_eq!(hushed[0].severity, Severity::Medium);
    }

    #[test]
    fn a_metric_with_no_declared_ladder_is_refused() {
        // Not defaulted to `Info`. A default is what made a whole workspace of
        // engines look like they had declined to rank their findings when in
        // fact nobody had written the ranking.
        let reason = refusal(Stamper {
            ladder: None,
            ..Stamper::default()
        });
        assert!(reason.contains("declares no severity ladder"), "{reason}");
        assert!(reason.contains("static.cognitive-complexity"), "{reason}");
    }

    #[test]
    fn assignment_still_respects_the_completeness_ceiling() {
        // Assignment happens after the engine has finished demoting, so the cap
        // `parse_health::demote` applied would be undone if it were not restated
        // here. A number computed over a partial tree must not reach MED+
        // whatever its ladder says (PREMORTEM T3).
        let degraded = Stamper {
            result_completeness: Completeness::ParseDegraded,
            ..Stamper::default()
        };
        let results = run_engine(&degraded, &context()).expect("measures");
        assert_eq!(results[0].completeness, Completeness::ParseDegraded);
        assert!(
            !results[0].severity.is_med_plus(),
            "{:?}",
            results[0].severity
        );
    }

    #[test]
    fn a_per_result_ladder_keeps_what_the_engine_wrote() {
        // The tamper suite's case: severity declared per detector rather than
        // per metric. The boundary defers, and still caps by completeness.
        let engine = Stamper {
            ladder: Some(SeverityLadder::PerResult),
            result_severity: Severity::High,
            ..Stamper::default()
        };
        assert_eq!(
            run_engine(&engine, &context()).expect("measures")[0].severity,
            Severity::High
        );

        let demoted = Stamper {
            ladder: Some(SeverityLadder::PerResult),
            result_severity: Severity::High,
            result_completeness: Completeness::ParseDegraded,
            ..Stamper::default()
        };
        assert!(!run_engine(&demoted, &context()).expect("measures")[0]
            .severity
            .is_med_plus());
    }

    #[test]
    fn a_ladder_that_cannot_read_its_own_metrics_values_is_refused() {
        let reason = refusal(Stamper {
            ladder: Some(SeverityLadder::Flag(Severity::High)),
            ..Stamper::default()
        });
        assert!(reason.contains("flag ladder"), "{reason}");
    }

    #[test]
    fn severity_is_assigned_before_the_digest_is_computed_and_does_not_move_it() {
        // `severity` is outside `ResultDigestInput` by P0's design, which is what
        // lets policy lower one after sealing. Assigning it before sealing has to
        // be equally invisible to the digest, or the verifier and the agent would
        // seal different bytes over the same measurement.
        let low = run_engine(&Stamper::default(), &context()).expect("measures");
        let high = run_engine(
            &Stamper {
                ladder: Some(SeverityLadder::NoOpinion),
                ..Stamper::default()
            },
            &context(),
        )
        .expect("measures");
        assert_ne!(low[0].severity, high[0].severity);
        assert_eq!(low[0].digest, high[0].digest);
    }

    #[test]
    fn a_code_exec_engine_still_needs_a_sandbox() {
        // The pre-existing rule, pinned alongside the new one so that a future
        // edit to this function cannot drop one while satisfying the other.
        struct Exec;
        impl MeasureEngine for Exec {
            fn descriptor(&self) -> EngineDescriptor {
                EngineDescriptor {
                    engine_id: "exec".to_string(),
                    family: EngineFamily::Static,
                    class: EngineClass::CodeExec,
                    version: "0.1.0".to_string(),
                }
            }
            fn metrics(&self) -> Vec<MetricDescriptor> {
                Vec::new()
            }
            fn severity_ladders(&self) -> BTreeMap<String, SeverityLadder> {
                BTreeMap::new()
            }
            fn regime(&self) -> MeasurementRegime {
                sample_regime()
            }
            fn measure(
                &self,
                _ctx: &MeasureContext,
            ) -> Result<Vec<MeasurementResult>, EngineError> {
                panic!("a code-exec engine must never reach `measure` without a sandbox")
            }
        }
        assert!(matches!(
            run_engine(&Exec, &context()),
            Err(EngineError::SandboxRequired { .. })
        ));
    }
}
