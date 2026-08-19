//! Sample values for tests.
//!
//! Compiled into the library rather than hidden behind `#[cfg(test)]` so that
//! integration tests, the registry-lint crate, and later phases all build their
//! fixtures from one shape. When the schema grows a required field, this module
//! stops compiling and every test that depends on the shape is updated in one
//! place.
//!
//! # These fixtures supply a *shape* and never a finding
//!
//! [`sample_result`] used to name `static-metrics` as its engine and carry
//! `Severity::Medium`. Both were false, and together they were the reason a
//! defect survived six phases of review: the assembly and verdict suites looked
//! like they exercised the MED+ band against the static engine, when the static
//! engine had never produced a severity above `Info` in its life and nothing in
//! the shipped configuration could reach the band at all. A fixture wearing a
//! shipped engine's name is a fixture that answers questions about that engine,
//! and it answers them wrongly.
//!
//! So the identity here is deliberately one no engine has: `sample-engine`
//! emitting `sample.metric`. The severity is `Info`, the floor a result carries
//! before anything has evaluated it — a test that needs a finding states the
//! severity itself, at the test, where a reader can see that it was chosen
//! rather than measured. `shipped_severity_band` pins the non-impersonation
//! against the real engine ids, which this crate cannot see.
//!
//! The `claim_id` is a real one from `registry/static.toml`, and that is not the
//! same mistake: assembly resolves evidence by claim, so a fixture citing a
//! claim nobody declares would test the refusal path instead of the path under
//! test. The claim says what evidence the number would stand on. The engine id
//! would have said who measured it, and nobody did.

use std::collections::BTreeMap;

use crate::schema::enums::*;
use crate::schema::payload::*;
use crate::schema::regime::MeasurementRegime;

/// The engine id every fixture here carries.
///
/// Deliberately not one of the five. `shipped_severity_band` asserts that,
/// against the real ids, which this crate cannot see from here.
pub const SAMPLE_ENGINE_ID: &str = "sample-engine";

/// The metric id every fixture here carries. No registry declares it.
pub const SAMPLE_METRIC_ID: &str = "sample.metric";

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
        head_kind: HeadKind::Commit,
        base_resolution: "merge-base".to_string(),
    }
}

/// One sealed result, in a shape no shipped engine claims.
///
/// See the module documentation for why the identity is synthetic. The metric id
/// is the one this fixture emits and not one any registry declares; the claim id
/// is real, because assembly resolves evidence by claim.
pub fn sample_result() -> MeasurementResult {
    let mut result = MeasurementResult {
        metric_id: SAMPLE_METRIC_ID.to_string(),
        claim_id: "andon.static.cognitive@1|typescript|comprehension-time".to_string(),
        engine_id: SAMPLE_ENGINE_ID.to_string(),
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
        // The floor. A fixture that arrived pre-ranked is a fixture that answers
        // "can this reach MED+" without anyone having measured anything — see
        // the module documentation. Tests that need a finding say so themselves.
        severity: Severity::Info,
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
        substitution: None,
        unreadable_paths: Vec::new(),
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
                severity: Severity::Low,
                message: "the sample metric rose by 4".to_string(),
                metric_ids: vec![SAMPLE_METRIC_ID.to_string()],
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
