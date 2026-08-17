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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::policy::Policy;
use crate::schema::enums::{EngineClass, EngineFamily, MetricClass};
use crate::schema::payload::{CompareContext, MeasurementResult};
use crate::schema::regime::MeasurementRegime;

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
    let mut results = engine.measure(ctx)?;
    for result in &mut results {
        result
            .seal(&ctx.compare_context)
            .map_err(|e| EngineError::Failed {
                engine_id: descriptor.engine_id.clone(),
                reason: format!("digest: {e}"),
            })?;
    }
    Ok(results)
}
