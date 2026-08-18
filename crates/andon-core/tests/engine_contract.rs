//! The two properties the `MeasureEngine` boundary enforces.
//!
//! Both are stated as rules elsewhere in the plan; here they are executable. The
//! test doubles below are also the worked example an engine author in P2, P3, or
//! P4 can copy — including the registry drift check every engine crate is
//! expected to run against its own manifest.

use andon_core::engine::{
    run_engine, EngineDescriptor, EngineError, MeasureContext, MeasureEngine, MetricDescriptor,
};
use andon_core::policy::Policy;
use andon_core::registry::{parse_file, Registry};
use andon_core::schema::enums::{EngineClass, EngineFamily, MetricClass};
use andon_core::schema::payload::MeasurementResult;
use andon_core::schema::regime::MeasurementRegime;
use andon_core::testing::{sample_compare_context, sample_regime, sample_result};
use andon_core::verdict::ladder::SeverityLadder;

use std::collections::BTreeMap;

const CLAIM: &str = "andon.static.cognitive@1|typescript|comprehension-time";
const METRIC: &str = "sample.metric";

struct TestEngine {
    class: EngineClass,
    metrics: Vec<MetricDescriptor>,
}

impl TestEngine {
    fn new(class: EngineClass) -> Self {
        Self {
            class,
            metrics: vec![MetricDescriptor {
                metric_id: METRIC.to_string(),
                claim_id: CLAIM.to_string(),
                class: MetricClass::DiffActionable,
                deterministic: true,
            }],
        }
    }
}

impl MeasureEngine for TestEngine {
    fn descriptor(&self) -> EngineDescriptor {
        EngineDescriptor {
            engine_id: "static-metrics".to_string(),
            family: EngineFamily::Static,
            class: self.class,
            version: "0.1.0".to_string(),
        }
    }

    fn metrics(&self) -> Vec<MetricDescriptor> {
        self.metrics.clone()
    }

    fn severity_ladders(&self) -> BTreeMap<String, SeverityLadder> {
        self.metrics
            .iter()
            .map(|d| (d.metric_id.clone(), SeverityLadder::NoOpinion))
            .collect()
    }

    fn regime(&self) -> MeasurementRegime {
        sample_regime()
    }

    fn measure(&self, _ctx: &MeasureContext) -> Result<Vec<MeasurementResult>, EngineError> {
        // Unsealed: sealing is `run_engine`'s job, which is what the digest test
        // below checks.
        let mut result = sample_result();
        result.digest = String::new();
        Ok(vec![result])
    }
}

fn context(sandbox_available: bool) -> MeasureContext {
    MeasureContext {
        compare_context: sample_compare_context(),
        policy: Policy::default(),
        changed_paths: vec!["src/index.ts".to_string()],
        sandbox_available,
    }
}

/// A `code-exec` engine cannot run in a context that promised static analysis.
///
/// Enforced at the boundary rather than by convention, because "the caller
/// should check" is how repository code ends up executing somewhere nobody
/// expected it to (Codex #19).
#[test]
fn a_code_exec_engine_is_refused_without_a_sandbox() {
    let engine = TestEngine::new(EngineClass::CodeExec);
    let error = run_engine(&engine, &context(false)).expect_err("must be refused");
    assert!(
        matches!(error, EngineError::SandboxRequired { ref engine_id } if engine_id == "static-metrics"),
        "expected SandboxRequired, got {error:?}"
    );
}

#[test]
fn a_code_exec_engine_runs_when_a_sandbox_is_available() {
    let engine = TestEngine::new(EngineClass::CodeExec);
    assert_eq!(run_engine(&engine, &context(true)).unwrap().len(), 1);
}

/// A `static-safe` engine never needs the sandbox, so its availability is
/// irrelevant to whether it runs.
#[test]
fn a_static_safe_engine_runs_either_way() {
    let engine = TestEngine::new(EngineClass::StaticSafe);
    assert_eq!(run_engine(&engine, &context(false)).unwrap().len(), 1);
    assert_eq!(run_engine(&engine, &context(true)).unwrap().len(), 1);
}

/// `run_engine` seals every result, so an engine cannot emit an unsealed one.
#[test]
fn results_come_back_sealed_against_the_compare_context() {
    let engine = TestEngine::new(EngineClass::StaticSafe);
    let results = run_engine(&engine, &context(false)).unwrap();
    let digest = &results[0].digest;
    assert_eq!(digest.len(), 64, "expected a hex SHA-256, got {digest:?}");

    // Sealing against a different tuple must produce a different digest — the
    // binding that makes a digest meaningful only for the change it describes.
    let mut other = context(false);
    other.compare_context.head_oid = "9".repeat(40);
    let rebound = run_engine(&engine, &other).unwrap();
    assert_ne!(&rebound[0].digest, digest);
}

const MANIFEST: &str = r#"
schema_version = 1
engine = "static-metrics"
family = "static"

[[metric]]
metric_id = "sample.metric"
claim_id = "andon.static.cognitive@1|typescript|comprehension-time"
class = "diff-actionable"
deterministic = true
"#;

/// The drift check that makes the declarative registry manifest trustworthy.
///
/// The lint reads metrics from TOML so it can run without building an engine.
/// That is only sound while the TOML and the code agree, which is what this
/// check enforces — and every engine crate is expected to run it against its own
/// registry file.
#[test]
fn an_engine_matching_its_manifest_passes_the_drift_check() {
    let file = parse_file("static.toml", MANIFEST).unwrap();
    let engine = TestEngine::new(EngineClass::StaticSafe);
    Registry::check_engine(&file, &engine).expect("manifest and engine agree");
}

#[test]
fn a_metric_emitted_but_not_declared_is_caught() {
    let file = parse_file("static.toml", MANIFEST).unwrap();
    let mut engine = TestEngine::new(EngineClass::StaticSafe);
    engine.metrics.push(MetricDescriptor {
        metric_id: "static.undeclared".to_string(),
        claim_id: CLAIM.to_string(),
        class: MetricClass::DiffActionable,
        deterministic: true,
    });
    let problems = Registry::check_engine(&file, &engine).expect_err("drift must be caught");
    assert!(
        problems
            .iter()
            .any(|p| p.contains("static.undeclared") && p.contains("absent from the registry")),
        "got {problems:?}"
    );
}

#[test]
fn a_metric_declared_but_never_emitted_is_caught() {
    let file = parse_file("static.toml", MANIFEST).unwrap();
    let mut engine = TestEngine::new(EngineClass::StaticSafe);
    engine.metrics.clear();
    let problems = Registry::check_engine(&file, &engine).expect_err("drift must be caught");
    assert!(
        problems.iter().any(|p| p.contains("never emits it")),
        "got {problems:?}"
    );
}

/// The subtle drift: the metric exists on both sides but cites different
/// evidence. Without this check the registry would look complete while a number
/// stood on a claim nobody reviewed for it.
#[test]
fn a_metric_citing_a_different_claim_in_code_is_caught() {
    let file = parse_file("static.toml", MANIFEST).unwrap();
    let mut engine = TestEngine::new(EngineClass::StaticSafe);
    engine.metrics[0].claim_id = "andon.static.cognitive@2|typescript|comprehension-time".into();
    let problems = Registry::check_engine(&file, &engine).expect_err("drift must be caught");
    assert!(
        problems.iter().any(|p| p.contains("in code and")),
        "got {problems:?}"
    );
}

#[test]
fn a_determinism_disagreement_is_caught() {
    // Determinism decides whether a result enters the digest compare, so a
    // disagreement here would silently change what the verifier checks.
    let file = parse_file("static.toml", MANIFEST).unwrap();
    let mut engine = TestEngine::new(EngineClass::StaticSafe);
    engine.metrics[0].deterministic = false;
    let problems = Registry::check_engine(&file, &engine).expect_err("drift must be caught");
    assert!(
        problems.iter().any(|p| p.contains("determinism")),
        "got {problems:?}"
    );
}

#[test]
fn an_engine_identity_mismatch_is_caught() {
    let file = parse_file("static.toml", MANIFEST).unwrap();
    struct Renamed(TestEngine);
    impl MeasureEngine for Renamed {
        fn descriptor(&self) -> EngineDescriptor {
            EngineDescriptor {
                engine_id: "clones".to_string(),
                family: EngineFamily::Clones,
                ..self.0.descriptor()
            }
        }
        fn metrics(&self) -> Vec<MetricDescriptor> {
            self.0.metrics()
        }
        fn severity_ladders(&self) -> BTreeMap<String, SeverityLadder> {
            self.0.severity_ladders()
        }
        fn regime(&self) -> MeasurementRegime {
            self.0.regime()
        }
        fn measure(&self, ctx: &MeasureContext) -> Result<Vec<MeasurementResult>, EngineError> {
            self.0.measure(ctx)
        }
    }
    let engine = Renamed(TestEngine::new(EngineClass::StaticSafe));
    let problems = Registry::check_engine(&file, &engine).expect_err("drift must be caught");
    assert_eq!(
        problems.len(),
        2,
        "engine id and family both differ: {problems:?}"
    );
}
