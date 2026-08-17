//! Sample values for tests.
//!
//! Compiled into the library rather than hidden behind `#[cfg(test)]` so that
//! integration tests, the registry-lint crate, and later phases all build their
//! fixtures from one shape. When the schema grows a required field, this module
//! stops compiling and every test that depends on the shape is updated in one
//! place.

use std::collections::BTreeMap;

use crate::schema::enums::*;
use crate::schema::payload::*;
use crate::schema::regime::MeasurementRegime;

/// A regime for the static family, for tests that need any valid one.
pub fn sample_regime() -> MeasurementRegime {
    let mut grammars = BTreeMap::new();
    grammars.insert("typescript".to_string(), "0.21.0".to_string());
    MeasurementRegime::Static {
        engine_version: "0.1.0".to_string(),
        spec_revision: "2026-08-16".to_string(),
        grammars,
    }
}

/// A compare context with well-formed OIDs.
pub fn sample_compare_context() -> CompareContext {
    CompareContext {
        base_oid: "1".repeat(40),
        head_oid: "2".repeat(40),
        git_version: "2.39.0".to_string(),
        base_resolution: "merge-base".to_string(),
    }
}

/// One sealed result.
pub fn sample_result() -> MeasurementResult {
    let mut result = MeasurementResult {
        metric_id: "static.cognitive-complexity".to_string(),
        claim_id: "andon.static.cognitive@1|typescript|comprehension-time".to_string(),
        engine_id: "static-metrics".to_string(),
        family: EngineFamily::Static,
        engine_class: EngineClass::StaticSafe,
        metric_class: MetricClass::DiffActionable,
        scope: ResultScope {
            kind: ScopeKind::Function,
            path: Some("src/index.ts".to_string()),
            blob_oid: Some("3".repeat(40)),
            symbol: Some("handleRequest".to_string()),
            line_span: Some(LineSpan { start: 10, end: 48 }),
        },
        value: MetricValue::Count(17),
        delta: Some(MetricValue::Integer(4)),
        severity: Severity::Medium,
        completeness: Completeness::Complete,
        measurement_regime: sample_regime(),
        evidence: EvidenceRef {
            claim_id: "andon.static.cognitive@1|typescript|comprehension-time".to_string(),
            tier: EvidenceTier::B,
            citation: "Munoz Baron, Wyrich & Wagner, ESEM 2020".to_string(),
            does_not_predict: vec!["defect density".to_string(), "correctness".to_string()],
            stale: false,
        },
        deterministic: true,
        digest: String::new(),
        freshness: Freshness {
            measured_at: "2026-08-17T09:00:00Z".to_string(),
            duration_ms: 42,
            lane: Lane::Fast,
            cache: CacheState::Warm,
        },
    };
    result
        .seal(&sample_compare_context())
        .expect("sample result must seal");
    result
}

/// A complete self-reported record, unwitnessed as every fresh record is.
pub fn sample_record() -> MeasurementRecord {
    MeasurementRecord {
        schema_version: SCHEMA_VERSION,
        record_kind: RecordKind::SelfReport,
        tool: ToolIdentity {
            name: "andon".to_string(),
            version: "0.1.0".to_string(),
            build_oid: "4".repeat(40),
            attested_release: false,
        },
        compare_context: sample_compare_context(),
        invocation: Invocation {
            source: InvocationSource::Hook,
            harness: Some("claude-code".to_string()),
            model: Some("test-model".to_string()),
            author: Some("gtm-k".to_string()),
            iteration: 1,
        },
        reserved: Reserved::default(),
        policy_hash: "5".repeat(64),
        results: vec![sample_result()],
        completeness: Completeness::Complete,
        verdict: VerdictSummary {
            verdict: Verdict::Advise,
            reasons: vec![VerdictReason {
                code: "metric-delta".to_string(),
                severity: Severity::Medium,
                message: "cognitive complexity rose by 4".to_string(),
                metric_ids: vec!["static.cognitive-complexity".to_string()],
            }],
            iteration: IterationState {
                count: 1,
                cap: crate::policy::DEFAULT_ITERATION_CAP,
                escalated: false,
            },
        },
        attestation: AttestationBlock::default(),
    }
}
