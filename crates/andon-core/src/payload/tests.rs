//! Assembly tests.
//!
//! # Why the engines here are synthetic
//!
//! `andon-core` is the contract crate: every engine depends on it and it depends
//! on none of them, which is what keeps the payload schema stable while engines
//! move. The subject of these tests is the assembler, not any engine, so the
//! outputs are built from the contract's own types: all five
//! [`MeasurementRegime`] variants are constructible in this crate, and the claim
//! ids are the ones the shipped `registry/` actually declares — so
//! `five_engine_families_assemble_into_one_record` fails if a shipped registry
//! stops resolving a shipped metric.
//!
//! # One question this file cannot answer, and where it moved to
//!
//! Synthetic outputs can prove that the assembler refuses what it should refuse.
//! They cannot answer whether anything a *shipped engine actually emits* can
//! reach the MED+ band — and the answer, through six phases of review, was no.
//! Nothing here could have caught that, because every input was chosen by the
//! test.
//!
//! `tests/shipped_severity_band.rs` asks that question, over real engines
//! measuring a real repository, through a dev-dependency cycle onto the five
//! engine crates. The cycle is confined to that file's purpose: it never enters
//! the built library, and these tests stay synthetic on the reasoning above.

use std::collections::BTreeMap;

use super::*;
use crate::date::Date;
use crate::policy::RegistryPolicy;
use crate::registry::EngineRegistryFile;
use crate::schema::enums::{
    EngineClass, EngineFamily, EvidenceTier, InvocationSource, MetricClass, Severity, TamperSignal,
    Verdict,
};
use crate::schema::payload::{EvidenceRef, Freshness, MetricValue, ScopeKind};
use crate::schema::regime::MeasurementRegime;
use crate::verdict::iteration::Advance;
use crate::verdict::reason;

fn as_of() -> Date {
    "2026-08-17".parse().expect("a valid date")
}

fn compare_context() -> CompareContext {
    crate::testing::sample_compare_context()
}

/// The repository's own registry, loaded the way a measurement would load it.
fn shipped_registry() -> LoadedRegistry {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("registry");
    registry_load::load(&dir, &RegistryPolicy::default(), as_of())
        .expect("the shipped registry must load")
}

/// A registry assembled from TOML written here, for cases the shipped one cannot
/// express.
fn registry_from(files: &[(&str, &str)]) -> LoadedRegistry {
    let parsed: Vec<(String, EngineRegistryFile)> = files
        .iter()
        .map(|(name, text)| {
            (
                (*name).to_string(),
                crate::registry::parse_file(name, text).expect("fixture registry parses"),
            )
        })
        .collect();
    registry_load::load_files(&parsed, &RegistryPolicy::default(), as_of(), "test")
        .expect("fixture registry lints")
}

fn regime(family: EngineFamily) -> MeasurementRegime {
    match family {
        EngineFamily::Static => MeasurementRegime::Static {
            engine_version: "0.1.0".to_string(),
            spec_revision: "p2-static-2".to_string(),
            grammars: BTreeMap::from([("typescript".to_string(), "0.23.2".to_string())]),
        },
        EngineFamily::Clones => MeasurementRegime::Clones {
            engine_version: "0.1.0".to_string(),
            algorithm: "rabin-karp".to_string(),
            min_tokens: 50,
            window_tokens: 25,
            normalization_revision: "rules2".to_string(),
        },
        EngineFamily::Tamper => MeasurementRegime::Tamper {
            engine_version: "0.1.0".to_string(),
            detector_set_revision: "d1".to_string(),
            rule_pack_version: "pack2".to_string(),
        },
        EngineFamily::Process => MeasurementRegime::Process {
            engine_version: "0.1.0".to_string(),
            git_version: "git version 2.51.0".to_string(),
            history_window_days: 365,
        },
        EngineFamily::Artifacts => MeasurementRegime::Artifacts {
            engine_version: "0.1.0".to_string(),
            parser_versions: BTreeMap::from([("lcov".to_string(), "1.0".to_string())]),
        },
    }
}

/// One sealed result, shaped the way an engine would leave it.
fn result(
    engine_id: &str,
    family: EngineFamily,
    metric_id: &str,
    claim_id: &str,
    value: MetricValue,
) -> MeasurementResult {
    let mut result = MeasurementResult {
        metric_id: metric_id.to_string(),
        claim_id: claim_id.to_string(),
        engine_id: engine_id.to_string(),
        family,
        engine_class: EngineClass::StaticSafe,
        metric_class: MetricClass::DiffActionable,
        scope: ResultScope {
            kind: ScopeKind::Change,
            path: None,
            blob_oid: None,
            symbol: None,
            line_span: None,
        },
        value,
        delta: None,
        severity: Severity::Info,
        completeness: Completeness::Complete,
        measurement_regime: regime(family),
        evidence: EvidenceRef {
            claim_id: claim_id.to_string(),
            tier: EvidenceTier::B,
            citation: "as the engine resolved it".to_string(),
            does_not_predict: Vec::new(),
            stale: false,
        },
        deterministic: true,
        digest: String::new(),
        freshness: Freshness {
            measured_at: "2026-08-17T09:00:00Z".to_string(),
            duration_ms: 1,
            lane: crate::schema::enums::Lane::Fast,
            cache: crate::schema::payload::CacheState::Cold,
        },
    };
    result.seal(&compare_context()).expect("seals");
    result
}

fn descriptor(engine_id: &str, family: EngineFamily) -> EngineDescriptor {
    EngineDescriptor {
        engine_id: engine_id.to_string(),
        family,
        class: EngineClass::StaticSafe,
        version: "0.1.0".to_string(),
    }
}

fn output(engine_id: &str, family: EngineFamily, results: Vec<MeasurementResult>) -> EngineOutput {
    EngineOutput {
        descriptor: descriptor(engine_id, family),
        results,
    }
}

/// One output per family, citing claims the shipped registry declares.
fn five_engines() -> Vec<EngineOutput> {
    vec![
        output(
            "static-metrics",
            EngineFamily::Static,
            vec![result(
                "static-metrics",
                EngineFamily::Static,
                "static.cognitive-complexity.typescript",
                "andon.static.cognitive@1|typescript|comprehension-time",
                MetricValue::Count(12),
            )],
        ),
        output(
            "clones",
            EngineFamily::Clones,
            vec![result(
                "clones",
                EngineFamily::Clones,
                "clones.duplicated-tokens",
                "andon.clones.token-duplication@1|any|token-duplication",
                MetricValue::Count(0),
            )],
        ),
        output(
            "tamper",
            EngineFamily::Tamper,
            vec![result(
                "tamper",
                EngineFamily::Tamper,
                "tamper.test-removal",
                "andon.tamper.test-evidence@1|any|test-evidence-withdrawal",
                MetricValue::Flag(false),
            )],
        ),
        output(
            "process",
            EngineFamily::Process,
            vec![result(
                "process",
                EngineFamily::Process,
                "process.churn-commits",
                "andon.process.churn@1|any|defect-proneness",
                MetricValue::Count(4),
            )],
        ),
        output(
            "artifacts",
            EngineFamily::Artifacts,
            vec![result(
                "artifacts",
                EngineFamily::Artifacts,
                "artifacts.uncovered-changed-lines",
                "andon.artifacts.diff-coverage@1|any|test-gap",
                MetricValue::Count(0),
            )],
        ),
    ]
}

fn request<'a>(
    policy: &'a Policy,
    registry: &'a LoadedRegistry,
    engines: Vec<EngineOutput>,
) -> AssembleRequest<'a> {
    AssembleRequest {
        tool: ToolIdentity {
            name: "andon".to_string(),
            version: "0.1.0".to_string(),
            build_oid: "4".repeat(40),
            attested_release: false,
        },
        record_kind: RecordKind::SelfReport,
        compare_context: compare_context(),
        invocation: Invocation {
            source: InvocationSource::Hook,
            harness: Some("claude-code".to_string()),
            model: None,
            author: None,
            iteration: 1,
        },
        reserved: Reserved::default(),
        policy,
        registry,
        engines,
        engine_failures: Vec::new(),
        policy_change: None,
    }
}

fn advance(count: u32, cap: u32) -> Advance {
    Advance {
        state: crate::schema::payload::IterationState {
            count,
            cap,
            escalated: count > cap,
        },
        recovered: false,
    }
}

// --- the join -------------------------------------------------------------

#[test]
fn five_engine_families_assemble_into_one_record() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let prepared = prepare(request(&policy, &registry, five_engines())).expect("assembles");
    let record = prepared.finish(advance(0, 3));

    assert_eq!(record.results.len(), 5);
    let families: BTreeSet<EngineFamily> = record.results.iter().map(|r| r.family).collect();
    assert_eq!(
        families.len(),
        5,
        "one result from each of the five families"
    );
    assert_eq!(record.schema_version, SCHEMA_VERSION);
    assert_eq!(record.completeness, Completeness::Complete);
    assert_eq!(record.verdict.verdict, Verdict::Pass);
}

#[test]
fn the_record_does_not_depend_on_the_order_engines_were_registered_in() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let forwards = prepare(request(&policy, &registry, five_engines()))
        .expect("assembles")
        .finish(advance(0, 3));
    let mut reversed = five_engines();
    reversed.reverse();
    let backwards = prepare(request(&policy, &registry, reversed))
        .expect("assembles")
        .finish(advance(0, 3));
    assert_eq!(forwards, backwards);
}

#[test]
fn assembly_never_attests() {
    // Trust is earned from CI. A record that could set its own attestation value
    // is a record that can pass itself.
    let policy = Policy::default();
    let registry = shipped_registry();
    let record = prepare(request(&policy, &registry, five_engines()))
        .expect("assembles")
        .finish(advance(0, 3));
    assert_eq!(
        record.attestation.value,
        crate::schema::enums::Attestation::Unwitnessed
    );
    assert!(record.attestation.verifier.is_none());
    assert!(record.attestation.compare.is_none());
    assert!(!record.attestation.value.counts_downstream());
}

#[test]
fn a_fired_detector_reaches_the_records_signal_list() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    let tamper = engines
        .iter_mut()
        .find(|e| e.descriptor.engine_id == "tamper")
        .unwrap();
    tamper.results[0].value = MetricValue::Flag(true);
    tamper.results[0].severity = Severity::High;
    tamper.results[0].seal(&compare_context()).unwrap();

    let record = prepare(request(&policy, &registry, engines))
        .expect("assembles")
        .finish(advance(1, 3));
    assert_eq!(
        record.attestation.tamper_signals,
        vec![TamperSignal::TestRemoval]
    );
    assert_eq!(record.verdict.verdict, Verdict::Block);
}

// --- grouping: note 2 -----------------------------------------------------

/// Two engines, one family — the shape P5a-entry note 2 is about.
const COLLIDING_REGISTRY: &str = r#"
schema_version = 1
engine = "static-metrics"
family = "static"

[[metric]]
metric_id = "static.sloc"
claim_id = "andon.static.sloc@1|any|maintenance-effort"
class = "context-informational"
deterministic = true

[[claim]]
claim_id = "andon.static.sloc@1|any|maintenance-effort"
implementation = "andon.static.sloc"
implementation_version = "1"
language = "any"
outcome = "maintenance-effort"
tier = "B"
citation = "test fixture"
population = "test fixture"
effect = "test fixture"
does_not_predict = ["anything, this is a fixture"]
owner = "gtm-k"
expiry = "2027-02-01"
"#;

const SPIKE_REGISTRY: &str = r#"
schema_version = 1
engine = "spike-size"
family = "static"

[[metric]]
metric_id = "spike.changed-files"
claim_id = "andon.spike.changed-files@1|any|change-size"
class = "context-informational"
deterministic = true

[[claim]]
claim_id = "andon.spike.changed-files@1|any|change-size"
implementation = "andon.spike.changed-files"
implementation_version = "1"
language = "any"
outcome = "change-size"
tier = "N"
citation = "test fixture"
population = "test fixture"
effect = "test fixture"
does_not_predict = ["anything, this is a fixture"]
owner = "gtm-k"
expiry = "2027-04-01"
"#;

#[test]
fn two_engines_sharing_a_family_stay_separate() {
    // P5a-entry note 2. `spike-size` reports the `static` family, exactly as P2's
    // `static-metrics` does, so grouping by family would merge the trust spike's
    // numbers into a production engine's. The grouping key is the engine id, and
    // this pins it against the collision rather than against a comment.
    let policy = Policy::default();
    let registry = registry_from(&[
        ("static.toml", COLLIDING_REGISTRY),
        ("spike.toml", SPIKE_REGISTRY),
    ]);
    let engines = vec![
        output(
            "static-metrics",
            EngineFamily::Static,
            vec![result(
                "static-metrics",
                EngineFamily::Static,
                "static.sloc",
                "andon.static.sloc@1|any|maintenance-effort",
                MetricValue::Count(120),
            )],
        ),
        output(
            "spike-size",
            EngineFamily::Static,
            vec![result(
                "spike-size",
                EngineFamily::Static,
                "spike.changed-files",
                "andon.spike.changed-files@1|any|change-size",
                MetricValue::Count(3),
            )],
        ),
    ];
    let record = prepare(request(&policy, &registry, engines))
        .expect("assembles")
        .finish(advance(0, 3));

    assert!(
        record
            .results
            .iter()
            .all(|r| r.family == EngineFamily::Static),
        "the collision is real: both report the same family"
    );
    let grouped = group_by_engine(&record.results);
    assert_eq!(
        grouped.keys().collect::<Vec<_>>(),
        vec![&"spike-size", &"static-metrics"]
    );
    assert_eq!(grouped["spike-size"].len(), 1);
    assert_eq!(grouped["static-metrics"].len(), 1);
}

// --- refusals -------------------------------------------------------------

#[test]
fn a_result_stamped_with_the_wrong_family_is_refused() {
    // A mis-stamp seals consistently and passes the verifier's compare, because
    // both sides make the same mistake. It has to be caught where the stamp is
    // set against something that knows better (PLAN wave-1 integration, note 1).
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    engines[0].results[0].family = EngineFamily::Clones;
    engines[0].results[0].seal(&compare_context()).unwrap();

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    assert!(
        matches!(err, AssemblyError::FamilyMismatch { .. }),
        "{err:?}"
    );
}

#[test]
fn a_regime_from_another_family_is_refused_even_when_the_stamps_agree() {
    // The subtler half: `family` and the descriptor agree, and the regime — which
    // is inside the digest — says something else.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    engines[0].results[0].measurement_regime = regime(EngineFamily::Process);
    engines[0].results[0].seal(&compare_context()).unwrap();

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    let AssemblyError::FamilyMismatch { regime, result, .. } = err else {
        panic!("expected a family mismatch");
    };
    assert_eq!(result, EngineFamily::Static);
    assert_eq!(regime, EngineFamily::Process);
}

#[test]
fn a_result_whose_claim_the_registry_does_not_declare_is_refused() {
    // The build-failing lint, live in the measurement path: no number reaches a
    // payload without evidence behind it.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    engines[0].results[0].claim_id = "andon.invented@1|any|nothing".to_string();
    engines[0].results[0].seal(&compare_context()).unwrap();

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    assert_eq!(
        err,
        AssemblyError::UnknownClaim {
            metric_id: "static.cognitive-complexity.typescript".to_string(),
            claim_id: "andon.invented@1|any|nothing".to_string(),
        }
    );
}

#[test]
fn an_unsealed_result_is_refused() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    engines[0].results[0].digest = String::new();

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    assert!(matches!(err, AssemblyError::Unsealed { .. }), "{err:?}");
}

#[test]
fn two_results_sharing_a_pairing_key_are_refused() {
    // The verifier pairs on `(metric_id, scope)` and takes the first match, so a
    // duplicate is a place a forged result can shadow an honest one.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    let duplicate = engines[0].results[0].clone();
    engines[0].results.push(duplicate);

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    assert!(
        matches!(err, AssemblyError::DuplicateResult { .. }),
        "{err:?}"
    );
}

#[test]
fn the_same_metric_at_two_scopes_is_fine() {
    // The other side of the same rule: per-file results share a metric id by
    // design, and only the pair has to be unique.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    let mut second = engines[0].results[0].clone();
    second.scope.kind = ScopeKind::File;
    second.scope.path = Some("src/other.ts".to_string());
    second.seal(&compare_context()).unwrap();
    engines[0].results.push(second);

    let record = prepare(request(&policy, &registry, engines))
        .expect("assembles")
        .finish(advance(0, 3));
    assert_eq!(record.results.len(), 6);
}

#[test]
fn an_engine_contributing_twice_is_refused() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    engines.push(engines[0].clone());

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    assert!(
        matches!(err, AssemblyError::DuplicateEngine { .. }),
        "{err:?}"
    );
}

#[test]
fn a_result_that_names_another_engine_is_refused() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    engines[0].results[0].engine_id = "clones".to_string();
    engines[0].results[0].seal(&compare_context()).unwrap();

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    assert!(
        matches!(err, AssemblyError::EngineMismatch { .. }),
        "{err:?}"
    );
}

#[test]
fn a_tamper_flag_whose_id_names_no_signal_is_refused() {
    // The drift check that keeps the signal mapping table-free. A detector
    // renamed away from its enum variant fails here rather than silently
    // dropping out of `tamper_signals`.
    let policy = Policy::default();
    let registry = registry_from(&[(
        "tamper.toml",
        r#"
schema_version = 1
engine = "tamper"
family = "tamper"

[[metric]]
metric_id = "tamper.renamed-detector"
claim_id = "andon.tamper.x@1|any|x"
class = "diff-actionable"
deterministic = true

[[claim]]
claim_id = "andon.tamper.x@1|any|x"
implementation = "andon.tamper.x"
implementation_version = "1"
language = "any"
outcome = "x"
tier = "N"
citation = "test fixture"
population = "test fixture"
effect = "test fixture"
does_not_predict = ["anything, this is a fixture"]
owner = "gtm-k"
expiry = "2027-02-01"
"#,
    )]);
    let engines = vec![output(
        "tamper",
        EngineFamily::Tamper,
        vec![result(
            "tamper",
            EngineFamily::Tamper,
            "tamper.renamed-detector",
            "andon.tamper.x@1|any|x",
            MetricValue::Flag(true),
        )],
    )];

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    assert_eq!(
        err,
        AssemblyError::UnknownTamperSignal {
            metric_id: "tamper.renamed-detector".to_string(),
        }
    );
}

// --- evidence -------------------------------------------------------------

#[test]
fn the_registry_supplies_the_honesty_lines_the_engine_lacked() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let record = prepare(request(&policy, &registry, five_engines()))
        .expect("assembles")
        .finish(advance(0, 3));
    assert!(
        record
            .results
            .iter()
            .all(|r| !r.evidence.does_not_predict.is_empty()),
        "every claim in the registry says what it does not predict"
    );
}

#[test]
fn a_parse_degradation_caveat_survives_evidence_resolution() {
    // The one that would be easy to break: overwriting `does_not_predict` from
    // the registry erases the line saying the number came off a partial tree,
    // which is the only line that changes how to read it.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    let health = parse_health::ParseHealth {
        error_nodes: 2,
        missing_nodes: 0,
        total_nodes: 90,
    };
    parse_health::demote(&mut engines[0].results[0], health);
    engines[0].results[0].seal(&compare_context()).unwrap();

    let record = prepare(request(&policy, &registry, engines))
        .expect("assembles")
        .finish(advance(0, 3));
    let degraded = record
        .results
        .iter()
        .find(|r| r.completeness == Completeness::ParseDegraded)
        .expect("the demotion survives");
    assert!(
        degraded.evidence.does_not_predict[0].contains(parse_health::PARSE_DEGRADED_CAVEAT),
        "{:?}",
        degraded.evidence.does_not_predict
    );
    assert!(
        degraded.evidence.does_not_predict.len() > 1,
        "and the registry's own lines are still there too"
    );
    assert_eq!(record.completeness, Completeness::ParseDegraded);
}

#[test]
fn the_loader_decides_staleness_not_the_engine() {
    // `EvidenceRef::stale` is documented as the loader's to set: it is a function
    // of the run date, and a record read back later must not carry yesterday's
    // answer.
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("registry");
    let registry = registry_load::load(
        &dir,
        &RegistryPolicy::default(),
        "2099-01-01".parse().unwrap(),
    )
    .expect("loads");
    let policy = Policy::default();
    let record = prepare(request(&policy, &registry, five_engines()))
        .expect("assembles")
        .finish(advance(0, 3));
    assert!(
        record.results.iter().all(|r| r.evidence.stale),
        "every claim is past expiry in 2099, whatever the engine thought"
    );
}

// --- completeness and failures --------------------------------------------

#[test]
fn a_failed_engine_makes_the_record_partial() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut req = request(&policy, &registry, five_engines());
    req.engine_failures = vec![EngineFailure {
        engine_id: "clones".to_string(),
        reason: "index lock held by another process".to_string(),
    }];
    let prepared = prepare(req).expect("assembles");
    assert_eq!(prepared.completeness(), Completeness::Partial);

    let record = prepared.finish(advance(0, 3));
    assert_eq!(record.completeness, Completeness::Partial);
    assert_eq!(
        record.verdict.verdict,
        Verdict::Advise,
        "an engine that could not run is not evidence against the change"
    );
    assert!(record
        .verdict
        .reasons
        .iter()
        .any(|r| r.code == reason::ENGINE_UNAVAILABLE));
}

#[test]
fn a_failed_engine_does_not_mask_a_weaker_completeness() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    engines[0].results[0].completeness = Completeness::Unwitnessed;
    engines[0].results[0].seal(&compare_context()).unwrap();
    let mut req = request(&policy, &registry, engines);
    req.engine_failures = vec![EngineFailure {
        engine_id: "clones".to_string(),
        reason: "unavailable".to_string(),
    }];
    assert_eq!(
        prepare(req).expect("assembles").completeness(),
        Completeness::Unwitnessed,
        "the record takes the weakest, not the most recently applied"
    );
}

#[test]
fn a_record_with_no_results_at_all_is_partial_when_engines_failed() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut req = request(&policy, &registry, Vec::new());
    req.engine_failures = vec![EngineFailure {
        engine_id: "static-metrics".to_string(),
        reason: "every grammar failed to load".to_string(),
    }];
    let record = prepare(req).expect("assembles").finish(advance(0, 3));
    assert!(record.results.is_empty());
    assert_eq!(
        record.completeness,
        Completeness::Partial,
        "an empty record must not claim to be complete"
    );
}

// --- the iteration seam ---------------------------------------------------

#[test]
fn a_clean_run_has_nothing_for_the_counter_to_count() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let prepared = prepare(request(&policy, &registry, five_engines())).expect("assembles");
    assert!(!prepared.has_countable_finding());
}

#[test]
fn a_fired_detector_is_something_for_the_counter_to_count() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines();
    let tamper = engines
        .iter_mut()
        .find(|e| e.descriptor.engine_id == "tamper")
        .unwrap();
    tamper.results[0].value = MetricValue::Flag(true);
    tamper.results[0].severity = Severity::High;
    tamper.results[0].seal(&compare_context()).unwrap();

    let prepared = prepare(request(&policy, &registry, engines)).expect("assembles");
    assert!(prepared.has_countable_finding());
    assert_eq!(
        prepared.finish(advance(4, 3)).verdict.verdict,
        Verdict::EscalateToHuman
    );
}

#[test]
fn the_cap_in_the_record_is_the_one_the_caller_read_from_policy() {
    // The cap is a policy field, never a constant in the verdict code. The record
    // carries the value that was in force, so a reader can see which cap applied.
    let policy = Policy::default();
    let registry = shipped_registry();
    let record = prepare(request(&policy, &registry, five_engines()))
        .expect("assembles")
        .finish(advance(2, policy.loop_policy.iteration_cap));
    assert_eq!(
        record.verdict.iteration.cap,
        policy.loop_policy.iteration_cap
    );
    assert_eq!(record.verdict.iteration.count, 2);
}

// --- the whole loop, through the real store -------------------------------

#[test]
fn the_loop_runs_to_escalation_and_a_fix_ends_it() {
    use crate::verdict::iteration::IterationStore;

    let dir = tempfile::tempdir().expect("a temp dir");
    let store = IterationStore::open(dir.path()).expect("opens");
    let policy = Policy::default();
    let registry = shipped_registry();
    let cap = policy.loop_policy.iteration_cap;

    let firing = || {
        let mut engines = five_engines();
        let tamper = engines
            .iter_mut()
            .find(|e| e.descriptor.engine_id == "tamper")
            .unwrap();
        tamper.results[0].value = MetricValue::Flag(true);
        tamper.results[0].severity = Severity::High;
        tamper.results[0].seal(&compare_context()).unwrap();
        engines
    };

    // Passes 1..=cap: the detector keeps firing, and the tool keeps blocking.
    for pass in 1..=cap {
        let prepared = prepare(request(&policy, &registry, firing())).expect("assembles");
        let advance = store
            .advance("feat/a", cap, prepared.has_countable_finding())
            .expect("advances");
        let record = prepared.finish(advance);
        assert_eq!(record.verdict.iteration.count, pass);
        assert_eq!(record.verdict.verdict, Verdict::Block, "pass {pass}");
    }

    // One more, and the tool stops asking the agent.
    let prepared = prepare(request(&policy, &registry, firing())).expect("assembles");
    let advance = store
        .advance("feat/a", cap, prepared.has_countable_finding())
        .expect("advances");
    let record = prepared.finish(advance);
    assert_eq!(record.verdict.verdict, Verdict::EscalateToHuman);
    assert!(record.verdict.iteration.escalated);

    // The agent fixes it. The loop is over, so the count resets and the next
    // unrelated finding on this branch starts from one.
    let prepared = prepare(request(&policy, &registry, five_engines())).expect("assembles");
    let advance = store
        .advance("feat/a", cap, prepared.has_countable_finding())
        .expect("advances");
    let record = prepared.finish(advance);
    assert_eq!(record.verdict.verdict, Verdict::Pass);
    assert_eq!(record.verdict.iteration.count, 0);
    assert!(!record.verdict.iteration.escalated);
}

// --- policy edits ---------------------------------------------------------

#[test]
fn an_unjustified_loosening_of_andons_own_policy_blocks() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut head = policy.clone();
    head.severity.block_on_tamper = false;
    let change = crate::verdict::policy_change::evaluate(&policy, &head, None);

    let mut req = request(&policy, &registry, five_engines());
    req.policy_change = Some(change);
    let prepared = prepare(req).expect("assembles");
    assert!(
        prepared.has_countable_finding(),
        "adding the justification is something the agent can do"
    );
    let record = prepared.finish(advance(1, 3));
    assert_eq!(record.verdict.verdict, Verdict::Block);
    assert!(record
        .verdict
        .reasons
        .iter()
        .any(|r| r.code == reason::POLICY_CHANGE_LOOSENING));
}

#[test]
fn a_neutral_policy_edit_advises_and_carries_the_delta() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut head = policy.clone();
    head.history.window_days = 90;
    let change = crate::verdict::policy_change::evaluate(&policy, &head, None);

    let mut req = request(&policy, &registry, five_engines());
    req.policy_change = Some(change);
    let record = prepare(req).expect("assembles").finish(advance(0, 3));
    assert_eq!(record.verdict.verdict, Verdict::Advise);
    let finding = record
        .verdict
        .reasons
        .iter()
        .find(|r| r.code == reason::POLICY_CHANGE)
        .expect("every policy edit is reported");
    assert!(
        finding.message.contains("history.window_days: 365 -> 90"),
        "{}",
        finding.message
    );
}

// --- the contract the record has to keep ----------------------------------

#[test]
fn an_assembled_record_serializes_canonically_and_reproducibly() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let record = prepare(request(&policy, &registry, five_engines()))
        .expect("assembles")
        .finish(advance(0, 3));
    let once = crate::canonical::to_canonical_string(&record).expect("serializes");
    let twice = crate::canonical::to_canonical_string(&record).expect("serializes");
    assert_eq!(once, twice);
    let round_tripped: MeasurementRecord = serde_json::from_str(&once).expect("round trips");
    assert_eq!(round_tripped, record);
}

#[test]
fn assembly_does_not_disturb_a_sealed_digest() {
    // Everything assembly writes — severity, evidence — is outside
    // `ResultDigestInput` by P0's design. If that ever stops being true, the
    // verifier reports `divergent` on honest work.
    let policy = Policy::default();
    let registry = shipped_registry();
    let engines = five_engines();
    let before: Vec<String> = engines
        .iter()
        .flat_map(|e| e.results.iter().map(|r| r.digest.clone()))
        .collect();

    let record = prepare(request(&policy, &registry, engines))
        .expect("assembles")
        .finish(advance(0, 3));
    for result in &record.results {
        assert!(before.contains(&result.digest), "{}", result.metric_id);
        let recomputed =
            crate::canonical::digest(&result.digest_input(&record.compare_context)).unwrap();
        assert_eq!(result.digest, recomputed, "{}", result.metric_id);
    }
}

#[test]
fn the_countable_answer_survives_the_round_trip() {
    // `prepare` answers "is there anything to act on?" so the caller can advance
    // the counter, and `finish` asks the same question again to decide whether
    // the cap fired. The two must agree: if they ever drifted, the counter would
    // advance against a verdict that had already decided there was nothing to
    // count, and a branch would escalate for work it had finished.
    let policy = Policy::default();
    let registry = shipped_registry();

    let firing = || {
        let mut engines = five_engines();
        let tamper = engines
            .iter_mut()
            .find(|e| e.descriptor.engine_id == "tamper")
            .unwrap();
        tamper.results[0].value = MetricValue::Flag(true);
        tamper.results[0].severity = Severity::High;
        tamper.results[0].seal(&compare_context()).unwrap();
        engines
    };

    // Both shapes, and both directions of the recovery flag that `prepare` has
    // to guess at because the counter has not been read yet.
    for (engines, expected) in [(five_engines(), false), (firing(), true)] {
        let prepared = prepare(request(&policy, &registry, engines)).expect("assembles");
        assert_eq!(prepared.has_countable_finding(), expected);

        for recovered in [false, true] {
            let record = prepared.clone().finish(Advance {
                state: crate::schema::payload::IterationState {
                    count: 9,
                    cap: 3,
                    escalated: true,
                },
                recovered,
            });
            // `escalate_to_human` fires exactly when the counter had something
            // to count, which is the answer `prepare` handed out.
            assert_eq!(
                record.verdict.verdict == Verdict::EscalateToHuman,
                expected,
                "recovered={recovered}"
            );
        }
    }
}
