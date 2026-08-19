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
    registry: &LoadedRegistry,
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
        // Read off the shipped declaration rather than asserted here. Assembly
        // now refuses a result that disagrees with the registry about what kind
        // of metric it is, and a fixture that hardcoded `diff-actionable` and
        // `deterministic` would have been testing its own opinion — the
        // artifacts metric is neither.
        metric_class: declared(registry, metric_id).0,
        deterministic: declared(registry, metric_id).1,
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
        // Tier and citation as the engine would have resolved them, from its
        // own copy of the registry. Hardcoding a tier here made every fixture
        // disagree with the shipped registry about four of the five engines,
        // which is a real condition — an old binary — and not one a fixture
        // should be simulating by accident.
        evidence: EvidenceRef {
            claim_id: claim_id.to_string(),
            tier: registry
                .registry
                .claims
                .get(claim_id)
                .map_or(EvidenceTier::B, |c| c.claim.tier),
            citation: "as the engine resolved it".to_string(),
            does_not_predict: Vec::new(),
            stale: false,
        },
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

/// What the registry under test declares for a metric.
///
/// Read rather than asserted, because assembly now refuses a result that
/// disagrees with the registry about what kind of metric it is. A fixture that
/// hardcoded `diff-actionable` and `deterministic` would have been stating its
/// own opinion over the declaration — and would have been wrong about the
/// artifacts metric, which is neither.
fn declared(registry: &LoadedRegistry, metric_id: &str) -> (MetricClass, bool) {
    let decl = registry
        .registry
        .metrics
        .get(metric_id)
        .unwrap_or_else(|| panic!("the registry under test declares '{metric_id}'"));
    (decl.class, decl.deterministic)
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
fn five_engines(registry: &LoadedRegistry) -> Vec<EngineOutput> {
    vec![
        output(
            "static-metrics",
            EngineFamily::Static,
            vec![result(
                registry,
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
                registry,
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
                registry,
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
                registry,
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
                registry,
                "artifacts",
                EngineFamily::Artifacts,
                "artifacts.uncovered-changed-lines",
                "andon.artifacts.diff-coverage@1|any|test-gap",
                MetricValue::Count(0),
            )],
        ),
    ]
}

/// A request whose engine roster is complete by construction.
///
/// Assembly requires every engine the registry declares to appear exactly once
/// (`account_for_every_engine`), which is the point of that rule — but almost
/// every test here is about one engine's results and should not have to build
/// five to say so. So the roster is padded: any declared engine the caller did
/// not supply is added as an output with no results, which is the honest shape
/// of an engine that ran over a change it had nothing to say about, and leaves
/// `completeness` alone.
///
/// The tests that are *about* the roster call [`bare_request`] and build it
/// themselves.
fn request<'a>(
    policy: &'a Policy,
    registry: &'a LoadedRegistry,
    engines: Vec<EngineOutput>,
) -> AssembleRequest<'a> {
    let mut engines = engines;
    let supplied: std::collections::BTreeSet<String> = engines
        .iter()
        .map(|e| e.descriptor.engine_id.clone())
        .collect();
    for engine_id in &registry.expected_engines {
        if !supplied.contains(engine_id) {
            engines.push(output(engine_id, family_of(engine_id), Vec::new()));
        }
    }
    bare_request(policy, registry, engines)
}

/// The family each shipped engine reports, for the roster padding above.
fn family_of(engine_id: &str) -> EngineFamily {
    match engine_id {
        "static-metrics" => EngineFamily::Static,
        "clones" => EngineFamily::Clones,
        "tamper" => EngineFamily::Tamper,
        "process" => EngineFamily::Process,
        "artifacts" => EngineFamily::Artifacts,
        other => panic!("no family known for engine '{other}'"),
    }
}

/// Move an engine from the output list to the failure list.
///
/// The two are exclusive by construction now — an engine that both produced
/// results and reported a failure has made two statements one of which is false,
/// and assembly cannot tell which — so a test declaring a failure has to take
/// the output away as well.
fn failed<'a>(mut req: AssembleRequest<'a>, engine_id: &str, reason: &str) -> AssembleRequest<'a> {
    req.engines
        .retain(|output| output.descriptor.engine_id != engine_id);
    req.engine_failures.push(EngineFailure {
        engine_id: engine_id.to_string(),
        reason: reason.to_string(),
    });
    req
}

/// A request with exactly the engines the caller named, and no padding.
fn bare_request<'a>(
    policy: &'a Policy,
    registry: &'a LoadedRegistry,
    engines: Vec<EngineOutput>,
) -> AssembleRequest<'a> {
    AssembleRequest {
        substitution: None,
        unreadable_paths: Vec::new(),
        self_measure: None,
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
        contended: false,
        state: crate::schema::payload::IterationState {
            count,
            cap,
            escalated: count > cap,
        },
        recovered: false,
    }
}

// --- the two registries behind one evidence reference ----------------------

#[test]
fn a_tier_the_two_registries_grade_differently_is_reported() {
    // One `EvidenceRef` filled from two places: `stale` and the honesty lines
    // from the loaded registry, `tier` and `citation` from the engine's compiled
    // one. The split is deliberate — the severity ceiling reads the tier, and a
    // tier the change under measurement could edit would let the change choose
    // its own ceiling — but nothing said so, and a disagreement was silent.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    engines[0].results[0].evidence.tier = EvidenceTier::A;

    let record = prepare(request(&policy, &registry, engines))
        .expect("assembles")
        .finish(advance(0, 3));
    let notice = record
        .verdict
        .reasons
        .iter()
        .find(|r| r.code == reason::EVIDENCE_REGISTRY_SKEW)
        .expect("a disagreement between two registries is never silent");
    assert_eq!(notice.severity, Severity::Info);
    assert!(
        notice
            .message
            .contains("andon.static.cognitive@1|typescript|comprehension-time"),
        "{}",
        notice.message
    );

    // The ceiling still came from the engine's tier, which is the half a reader
    // cannot otherwise account for.
    let reported = record
        .results
        .iter()
        .find(|r| r.metric_id == "static.cognitive-complexity.typescript")
        .expect("the result is in the record");
    assert_eq!(reported.evidence.tier, EvidenceTier::A);

    let agreeing = prepare(request(&policy, &registry, five_engines(&registry)))
        .expect("assembles")
        .finish(advance(0, 3));
    assert!(
        !agreeing
            .verdict
            .reasons
            .iter()
            .any(|r| r.code == reason::EVIDENCE_REGISTRY_SKEW),
        "and two registries that agree say nothing"
    );
}

#[test]
fn a_re_review_schedule_never_stops_a_measurement() {
    // `registry.expiry-stagger` counts claims falling due in one month and fails
    // the build above the limit, which is right in CI and was catastrophic here:
    // a binary whose registry had four claims expiring in March refused to
    // measure anything at all, on every change, for a reason unrelated to any
    // number it would have reported.
    let tight = RegistryPolicy {
        max_claims_expiring_per_month: 1,
        ..RegistryPolicy::default()
    };
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("registry");
    let loaded = registry_load::load(&dir, &tight, as_of())
        .expect("a scheduling breach must not stop a measurement");
    assert!(
        loaded
            .notices
            .iter()
            .any(|d| d.code == "registry.expiry-stagger"),
        "and it is still reported: {:?}",
        loaded.notices.iter().map(|d| d.code).collect::<Vec<_>>()
    );

    // The evidence rules are untouched and still refuse.
    let over_budget = RegistryPolicy {
        claim_budget: 1,
        ..RegistryPolicy::default()
    };
    assert!(
        registry_load::load(&dir, &over_budget, as_of()).is_err(),
        "a claim budget breach is about evidence and still refuses"
    );
}

// --- the loop counter's inputs ---------------------------------------------

#[test]
fn a_measurement_that_could_not_see_does_not_clear_the_budget() {
    // The reset an agent can reach for. `has_countable_finding` answers "nothing
    // to act on" identically whether the run was clean or blind, and the counter
    // used to take that boolean — so breaking the engine that keeps finding the
    // problem cleared the budget and the cap started again from one.
    let policy = Policy::default();
    let registry = shipped_registry();

    let clean = prepare(request(&policy, &registry, five_engines(&registry))).expect("assembles");
    assert!(!clean.has_countable_finding());
    assert_eq!(clean.completeness(), Completeness::Complete);
    assert_eq!(
        clean.loop_outcome(),
        crate::verdict::iteration::LoopOutcome::Finished,
        "a clean look at everything ends the loop"
    );

    let blinded = prepare(failed(
        request(&policy, &registry, five_engines(&registry)),
        "artifacts",
        "no coverage report in the tree",
    ))
    .expect("assembles");
    assert!(!blinded.has_countable_finding());
    assert_eq!(
        blinded.loop_outcome(),
        crate::verdict::iteration::LoopOutcome::Inconclusive,
        "a run that could not see is not evidence that the loop ended"
    );
}

#[test]
fn a_path_nothing_could_read_does_not_clear_the_budget_either() {
    // The same reset, through a field that did not exist when `LoopOutcome` was
    // made three-valued. `every_question_was_answered` asked about engine
    // failures and about half-finished results, and not about a changed path
    // nothing could open — so a measurement that found nothing because it never
    // saw the file answered `Finished` and cleared the agent's count.
    //
    // "Break the engine" and "make the file unreadable" are the same move, and
    // the verdict already knows it: the record carries `change-not-read` and
    // exits 1. The counter was the last consumer still blind to it.
    let policy = Policy::default();
    let registry = shipped_registry();

    let mut req = request(&policy, &registry, five_engines(&registry));
    req.unreadable_paths = vec!["src/work.ts".to_string()];
    let blinded = prepare(req).expect("assembles");

    assert!(
        !blinded.has_countable_finding(),
        "an unreadable path is not something the agent's next edit answers, and counting it \
         would grind the loop to escalation over a permission bit"
    );
    assert_eq!(
        blinded.loop_outcome(),
        crate::verdict::iteration::LoopOutcome::Inconclusive,
        "a run over a path nothing could read is not evidence that the loop ended"
    );
}

#[test]
fn an_honest_absence_still_ends_the_loop() {
    // The other half, and the half that was dead in production. Engines emit
    // `unwitnessed` results by design for absences that are facts about the
    // repository — no coverage report, no history for a file added in this
    // change, no complexity input for a `.png`. Record completeness is the
    // weakest of the results, and `unwitnessed` is the weakest value there is,
    // so a reset gated on `Complete` never fired: measured across four real
    // repositories, 15 of 15 runs were `unwitnessed`.
    //
    // A counter that advances and never resets makes escalation guaranteed
    // rather than earned on any long-lived branch, which is PREMORTEM S6 — the
    // anti-grinding mechanism inverting into the flood it exists to prevent.
    let policy = Policy::default();
    let registry = shipped_registry();

    let mut engines = five_engines(&registry);
    let marker = engines
        .iter_mut()
        .find(|output| output.descriptor.engine_id == "artifacts")
        .expect("the artifacts engine is in the roster");
    for result in &mut marker.results {
        // What the engine really emits when there is no report to read: an
        // answer, not a failure to answer.
        result.completeness = Completeness::Unwitnessed;
        result.value = MetricValue::Text("unwitnessed: no coverage report found".to_string());
        result
            .seal(&compare_context())
            .expect("re-seals after the edit");
    }

    let honest = prepare(request(&policy, &registry, engines)).expect("assembles");
    assert!(!honest.has_countable_finding());
    assert_eq!(
        honest.completeness(),
        Completeness::Unwitnessed,
        "the record still reports the weakest of its results, which is the honest value"
    );
    assert_eq!(
        honest.loop_outcome(),
        crate::verdict::iteration::LoopOutcome::Finished,
        "an engine that looked and reported an absence has answered; the loop is over"
    );
}

#[test]
fn a_half_read_file_still_holds_the_budget() {
    // The distinction the reset now keys on, from the other side. `unwitnessed`
    // is an answer; `parse-degraded` is an answer about part of a file with the
    // rest unread, and a change can produce one on purpose (PREMORTEM T3). It
    // must not clear a budget.
    let policy = Policy::default();
    let registry = shipped_registry();

    let mut engines = five_engines(&registry);
    let degraded = engines
        .iter_mut()
        .find(|output| output.descriptor.engine_id == "static-metrics")
        .expect("the static engine is in the roster");
    for result in &mut degraded.results {
        result.completeness = Completeness::ParseDegraded;
        result
            .seal(&compare_context())
            .expect("re-seals after the edit");
    }

    let blinded = prepare(request(&policy, &registry, engines)).expect("assembles");
    assert!(!blinded.has_countable_finding());
    assert_eq!(
        blinded.loop_outcome(),
        crate::verdict::iteration::LoopOutcome::Inconclusive,
        "a number computed over a file the parser gave up on is not evidence the loop ended"
    );
}

#[test]
fn an_inconclusive_run_holds_the_count_rather_than_advancing_or_clearing_it() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = crate::verdict::iteration::IterationStore::open(dir.path()).expect("opens");
    use crate::verdict::iteration::LoopOutcome;

    // A distinct change per pass, because that is what a pass is: the counter
    // counts attempts at a change, and three readings of one change are one
    // attempt by construction.
    for pass in 0..3 {
        store
            .advance(
                "feat/a",
                3,
                LoopOutcome::Countable,
                &format!("base..head{pass}"),
            )
            .expect("advances");
    }
    assert_eq!(store.peek("feat/a", 3).count, 3);

    store
        .advance("feat/a", 3, LoopOutcome::Inconclusive, "base..head3")
        .expect("advances");
    assert_eq!(
        store.peek("feat/a", 3).count,
        3,
        "held: neither advanced nor cleared"
    );

    store
        .advance("feat/a", 3, LoopOutcome::Finished, "base..head4")
        .expect("advances");
    assert_eq!(store.peek("feat/a", 3).count, 0);
}

#[test]
fn the_counter_is_the_only_writer_of_the_pass_number() {
    // One record, one fact, and it used to have two writers: the caller filled
    // in `invocation.iteration` from whatever it believed, and the counter
    // produced `verdict.iteration.count`. Nothing said which a reader should
    // believe, and a process that had forgotten its own history is exactly why
    // the counter is on disk.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut req = request(&policy, &registry, five_engines(&registry));
    req.invocation.iteration = 99;
    let record = prepare(req).expect("assembles").finish(advance(2, 3));
    assert_eq!(record.verdict.iteration.count, 2);
    assert_eq!(
        record.invocation.iteration, 2,
        "the counter's answer, not the caller's belief"
    );
}

#[test]
fn a_measurement_that_did_not_see_everything_says_so_in_the_verdict() {
    // The blinding case, at the surface an actor can actually read. The engine
    // failure already advises; what was missing is the record-level statement,
    // which is the only thing a reader of the verdict alone can see about
    // whether the measurement was whole.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    engines[0].results[0].completeness = Completeness::Unwitnessed;
    engines[0].results[0].seal(&compare_context()).unwrap();

    let record = prepare(request(&policy, &registry, engines))
        .expect("assembles")
        .finish(advance(0, 3));
    let notice = record
        .verdict
        .reasons
        .iter()
        .find(|r| r.code == reason::MEASUREMENT_INCOMPLETE)
        .expect("incompleteness is never silent");
    assert_eq!(notice.severity, Severity::Info);
    assert!(notice.message.contains("unwitnessed"), "{}", notice.message);

    let whole = prepare(request(&policy, &registry, five_engines(&registry)))
        .expect("assembles")
        .finish(advance(0, 3));
    assert!(
        !whole
            .verdict
            .reasons
            .iter()
            .any(|r| r.code == reason::MEASUREMENT_INCOMPLETE),
        "and a complete measurement does not say it twice"
    );
}

// --- the justification seam ------------------------------------------------

#[test]
fn a_self_report_cannot_mint_a_verified_justification() {
    // The binary under measurement cannot mark its own excuse as checked. Same
    // argument as `assembly_never_attests`, applied to the other field that
    // turns a block into an advise: a record that could do both would be a
    // record that passes itself.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut req = request(&policy, &registry, five_engines(&registry));
    req.policy_change = Some(crate::verdict::policy_change::PolicyChange {
        deltas: Vec::new(),
        justification: Some(crate::verdict::policy_change::Justification::Verified {
            reference: "andon-ledger#12".to_string(),
            summary: "we checked our own homework".to_string(),
        }),
    });
    assert_eq!(
        prepare(req).expect_err("a self-report cannot verify anything"),
        AssemblyError::UnverifiableJustification {
            reference: "andon-ledger#12".to_string()
        }
    );
}

#[test]
fn a_self_report_may_carry_an_unverified_justification_and_it_suppresses_nothing() {
    // The honest half. An agent that has a ledger reference should say so — the
    // reader needs it, and P9's verifier is what turns it into the verified
    // form. What it must not do is act as though anyone had checked it.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut head = policy.clone();
    head.severity.block_on_tamper = false;
    let mut req = request(&policy, &registry, five_engines(&registry));
    req.policy_change = Some(crate::verdict::policy_change::evaluate(
        &policy,
        &head,
        Some(crate::verdict::policy_change::Justification::Unverified {
            reference: "andon-ledger#12".to_string(),
            summary: "queued for review".to_string(),
        }),
    ));
    let record = prepare(req).expect("assembles").finish(advance(0, 3));
    assert_eq!(record.verdict.verdict, Verdict::Block);
    assert!(record
        .verdict
        .reasons
        .iter()
        .any(|r| r.message.contains("andon-ledger#12")));
}

#[test]
fn a_verifier_may_carry_a_verified_justification() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut head = policy.clone();
    head.severity.block_on_tamper = false;
    let mut req = request(&policy, &registry, five_engines(&registry));
    req.record_kind = RecordKind::Attestation;
    req.policy_change = Some(crate::verdict::policy_change::evaluate(
        &policy,
        &head,
        Some(crate::verdict::policy_change::Justification::Verified {
            reference: "andon-ledger#12".to_string(),
            summary: "read from the ledger by the verifier".to_string(),
        }),
    ));
    let record = prepare(req).expect("assembles").finish(advance(0, 3));
    assert_eq!(record.verdict.verdict, Verdict::Advise);
}

// --- the roster ------------------------------------------------------------

#[test]
fn an_empty_success_set_cannot_be_complete_or_pass() {
    // CODEX'S PROBE, VERBATIM IN INTENT. Before the roster check this produced a
    // record with no results, `completeness: complete` and `verdict: pass` — a
    // clean bill of health from a run in which no engine was invoked. The
    // reported artifact was `left: (Complete, Pass), right: (Complete, Pass)`.
    let policy = Policy::default();
    let registry = shipped_registry();
    let err = prepare(bare_request(&policy, &registry, Vec::new()))
        .expect_err("a payload from no engines is not a measurement");
    let AssemblyError::MissingEngine { engine_id } = err else {
        panic!("expected a missing-engine refusal, got {err:?}");
    };
    assert!(
        registry.expected_engines.contains(&engine_id),
        "the refusal names an engine the registry declares: {engine_id}"
    );
}

#[test]
fn every_declared_engine_must_appear_exactly_once() {
    let policy = Policy::default();
    let registry = shipped_registry();
    assert_eq!(
        registry.expected_engines.len(),
        5,
        "the shipped registry declares five engines: {:?}",
        registry.expected_engines
    );

    // Four of five, and the fifth neither ran nor was reported as unavailable.
    let mut four = five_engines(&registry);
    four.retain(|e| e.descriptor.engine_id != "process");
    let err = prepare(bare_request(&policy, &registry, four))
        .expect_err("a silently absent engine is not a measurement");
    assert_eq!(
        err,
        AssemblyError::MissingEngine {
            engine_id: "process".to_string()
        }
    );
}

#[test]
fn an_engine_the_registry_does_not_declare_cannot_contribute() {
    // The other direction. A result whose claim resolves can still come from an
    // engine no registry file declares — the P1.5 spike is exactly such an
    // engine, and it reports the `static` family, so a family-keyed rule would
    // have let it stand in for `static-metrics`.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    engines.push(output(
        "spike-size",
        EngineFamily::Static,
        vec![result(
            &registry,
            "spike-size",
            EngineFamily::Static,
            "static.cognitive-complexity.typescript",
            "andon.static.cognitive@1|typescript|comprehension-time",
            MetricValue::Count(3),
        )],
    ));
    assert_eq!(
        prepare(bare_request(&policy, &registry, engines)).expect_err("refused"),
        AssemblyError::UnknownEngine {
            engine_id: "spike-size".to_string()
        }
    );
}

#[test]
fn an_engine_cannot_both_produce_results_and_report_a_failure() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut req = bare_request(&policy, &registry, five_engines(&registry));
    req.engine_failures = vec![EngineFailure {
        engine_id: "clones".to_string(),
        reason: "index lock held".to_string(),
    }];
    assert_eq!(
        prepare(req).expect_err("two statements, one of them false"),
        AssemblyError::EngineSucceededAndFailed {
            engine_id: "clones".to_string()
        }
    );
}

#[test]
fn an_engine_cannot_fail_twice() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    engines.retain(|e| e.descriptor.engine_id != "clones");
    let mut req = bare_request(&policy, &registry, engines);
    req.engine_failures = vec![
        EngineFailure {
            engine_id: "clones".to_string(),
            reason: "index lock held".to_string(),
        },
        EngineFailure {
            engine_id: "clones".to_string(),
            reason: "and something else".to_string(),
        },
    ];
    assert_eq!(
        prepare(req).expect_err("refused"),
        AssemblyError::DuplicateFailure {
            engine_id: "clones".to_string()
        }
    );
}

#[test]
fn an_unknown_engine_cannot_hide_in_the_failure_list() {
    // A failure entry is a claim about an engine that was asked. Naming one
    // nobody declares would let a caller satisfy the roster with an invention.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    engines.retain(|e| e.descriptor.engine_id != "process");
    let mut req = bare_request(&policy, &registry, engines);
    req.engine_failures = vec![EngineFailure {
        engine_id: "prcoess".to_string(),
        reason: "a typo is a different engine".to_string(),
    }];
    assert_eq!(
        prepare(req).expect_err("refused"),
        AssemblyError::UnknownEngine {
            engine_id: "prcoess".to_string()
        }
    );
}

#[test]
fn five_engines_that_found_nothing_still_pass() {
    // The state the roster check must NOT refuse, and the reason it is about
    // accounting rather than about emptiness: a documentation-only change is a
    // change every engine looked at and none of them had anything to say about.
    // "Nobody was asked" and "everybody was asked and found nothing" are
    // different records, and only the first is a bug.
    let policy = Policy::default();
    let registry = shipped_registry();
    let quiet: Vec<EngineOutput> = registry
        .expected_engines
        .iter()
        .map(|id| output(id, family_of(id), Vec::new()))
        .collect();
    let record = prepare(bare_request(&policy, &registry, quiet))
        .expect("five engines with nothing to report is a measurement")
        .finish(advance(0, 3));
    assert!(record.results.is_empty());
    assert_eq!(record.completeness, Completeness::Complete);
    assert_eq!(record.verdict.verdict, Verdict::Pass);
}

#[test]
fn the_expected_roster_comes_from_the_registry_and_not_from_a_constant() {
    // A deployment shipping one registry file expects one engine. Writing the
    // five down here would make the check pass on a tree that had lost four.
    let registry = registry_from(&[("clones.toml", ONE_ENGINE_REGISTRY)]);
    assert_eq!(
        registry.expected_engines,
        std::collections::BTreeSet::from(["clones".to_string()])
    );

    let policy = Policy::default();
    let one = vec![output(
        "clones",
        EngineFamily::Clones,
        vec![result(
            &registry,
            "clones",
            EngineFamily::Clones,
            "clones.duplicated-tokens",
            "andon.clones.token-duplication@1|any|token-duplication",
            MetricValue::Count(0),
        )],
    )];
    prepare(bare_request(&policy, &registry, one)).expect("one declared engine, one contribution");
}

/// A registry declaring a single engine, for the roster-derivation test.
const ONE_ENGINE_REGISTRY: &str = r#"
schema_version = 1
engine = "clones"
family = "clones"

[[metric]]
metric_id = "clones.duplicated-tokens"
claim_id = "andon.clones.token-duplication@1|any|token-duplication"
class = "diff-actionable"
deterministic = true

[[claim]]
claim_id = "andon.clones.token-duplication@1|any|token-duplication"
implementation = "andon.clones.token-duplication"
implementation_version = "1"
language = "any"
outcome = "token-duplication"
tier = "N"
citation = "Novel."
population = "none"
effect = "none claimed"
does_not_predict = ["anything"]
owner = "gtm-k"
expiry = "2027-01-01"
"#;

// --- the join -------------------------------------------------------------

#[test]
fn five_engine_families_assemble_into_one_record() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let prepared =
        prepare(request(&policy, &registry, five_engines(&registry))).expect("assembles");
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
    let forwards = prepare(request(&policy, &registry, five_engines(&registry)))
        .expect("assembles")
        .finish(advance(0, 3));
    let mut reversed = five_engines(&registry);
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
    let record = prepare(request(&policy, &registry, five_engines(&registry)))
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
    let mut engines = five_engines(&registry);
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
                &registry,
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
                &registry,
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
    let mut engines = five_engines(&registry);
    engines[0].results[0].family = EngineFamily::Clones;
    engines[0].results[0].seal(&compare_context()).unwrap();

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    assert!(
        matches!(err, AssemblyError::FamilyMismatch { .. }),
        "{err:?}"
    );
}

#[test]
fn a_result_consistent_with_itself_and_wrong_about_its_engine_is_refused() {
    // The descriptor half of the family check, at this boundary. A result that
    // says `clones` and carries a clones regime is internally consistent; only
    // the comparison against the engine that produced it sees the lie. Without
    // this, the clause is deletable and the suite stays green.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    engines[0].results[0].family = EngineFamily::Clones;
    engines[0].results[0].measurement_regime = regime(EngineFamily::Clones);
    engines[0].results[0].seal(&compare_context()).unwrap();

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    let AssemblyError::FamilyMismatch {
        result, descriptor, ..
    } = err
    else {
        panic!("expected a family mismatch, got {err:?}");
    };
    assert_eq!(result, EngineFamily::Clones);
    assert_eq!(descriptor, EngineFamily::Static);
}

#[test]
fn a_regime_from_another_family_is_refused_even_when_the_stamps_agree() {
    // The subtler half: `family` and the descriptor agree, and the regime — which
    // is inside the digest — says something else.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
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
    // payload without evidence behind it. The refusal is now the stronger one —
    // the registry declares exactly one claim per metric, so a claim nobody
    // declared and a claim declared for some *other* metric are the same
    // mistake and get the same answer.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    engines[0].results[0].claim_id = "andon.invented@1|any|nothing".to_string();
    engines[0].results[0].evidence.claim_id = "andon.invented@1|any|nothing".to_string();
    engines[0].results[0].seal(&compare_context()).unwrap();

    assert_eq!(
        prepare(request(&policy, &registry, engines)).expect_err("must refuse"),
        AssemblyError::MetricRebound {
            metric_id: "static.cognitive-complexity.typescript".to_string(),
            declared: "andon.static.cognitive@1|typescript|comprehension-time".to_string(),
            cited: "andon.invented@1|any|nothing".to_string(),
        }
    );
}

#[test]
fn a_metric_rebound_to_another_valid_claim_is_refused() {
    // CODEX'S PROBE. A known metric citing a claim that resolves perfectly well
    // — the clone engine's — used to assemble without complaint: a cognitive
    // complexity number standing on evidence gathered about token duplication,
    // carrying that claim's tier, citation and honesty lines.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    let clones_claim = "andon.clones.token-duplication@1|any|token-duplication";
    engines[0].results[0].claim_id = clones_claim.to_string();
    engines[0].results[0].evidence.claim_id = clones_claim.to_string();
    engines[0].results[0].seal(&compare_context()).unwrap();

    assert_eq!(
        prepare(request(&policy, &registry, engines)).expect_err("must refuse"),
        AssemblyError::MetricRebound {
            metric_id: "static.cognitive-complexity.typescript".to_string(),
            declared: "andon.static.cognitive@1|typescript|comprehension-time".to_string(),
            cited: clones_claim.to_string(),
        }
    );
}

#[test]
fn a_result_whose_two_claim_ids_disagree_is_refused() {
    // CODEX'S PROBE. `claim_id` is inside the digest input and
    // `evidence.claim_id` is not, so a result can carry one claim to the
    // verifier and a different one to the reader — and the reader's copy is what
    // carries the tier, the citation, and the "what this does not predict"
    // lines. Both used to be accepted on the same result.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    engines[0].results[0].evidence.claim_id =
        "andon.clones.token-duplication@1|any|token-duplication".to_string();

    assert_eq!(
        prepare(request(&policy, &registry, engines)).expect_err("must refuse"),
        AssemblyError::EvidenceClaimMismatch {
            metric_id: "static.cognitive-complexity.typescript".to_string(),
            claim_id: "andon.static.cognitive@1|typescript|comprehension-time".to_string(),
            evidence_claim_id: "andon.clones.token-duplication@1|any|token-duplication".to_string(),
        }
    );
}

#[test]
fn a_result_sealed_against_another_change_is_refused() {
    // CODEX'S PROBE. The digest was checked for being non-empty, which proves
    // only that something sealed something at some point. A result sealed
    // against a different (base, head) is a measurement of a different change,
    // and it assembled into a payload claiming this one.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    let other = CompareContext {
        base_oid: "a".repeat(40),
        head_oid: "b".repeat(40),
        ..compare_context()
    };
    engines[0].results[0].seal(&other).expect("seals");

    let err = prepare(request(&policy, &registry, engines)).expect_err("must refuse");
    let AssemblyError::DigestMismatch {
        metric_id,
        base_oid,
        ..
    } = err
    else {
        panic!("expected a digest mismatch, got {err:?}");
    };
    assert_eq!(metric_id, "static.cognitive-complexity.typescript");
    assert_eq!(base_oid, compare_context().base_oid);
}

#[test]
fn a_result_edited_after_sealing_is_refused() {
    // The same check from the other side: the digest covers the contents, so a
    // value changed after the seal no longer matches it. `severity` and
    // `evidence` are deliberately outside the digest input and must stay
    // editable — `severity::apply` and `resolve_evidence` both run after this.
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    engines[0].results[0].value = MetricValue::Count(9_999);
    assert!(matches!(
        prepare(request(&policy, &registry, engines)).expect_err("must refuse"),
        AssemblyError::DigestMismatch { .. }
    ));

    let mut editable = five_engines(&registry);
    editable[0].results[0].severity = Severity::Critical;
    editable[0].results[0].evidence.stale = true;
    prepare(request(&policy, &registry, editable))
        .expect("the unsigned fields stay editable after sealing");
}

#[test]
fn a_result_that_disagrees_with_its_declaration_is_refused() {
    // `class` decides whether a finding may ever block and `deterministic`
    // decides whether the verifier will compare it. A result carrying its own
    // answer to either decides both for itself — the second one is E4's hole
    // recurring one layer up.
    let policy = Policy::default();
    let registry = shipped_registry();

    let mut reclassed = five_engines(&registry);
    reclassed[0].results[0].metric_class = MetricClass::ContextInformational;
    reclassed[0].results[0].seal(&compare_context()).unwrap();
    assert!(matches!(
        prepare(request(&policy, &registry, reclassed)).expect_err("must refuse"),
        AssemblyError::MetricDeclarationMismatch { field: "class", .. }
    ));

    let mut excused = five_engines(&registry);
    excused[0].results[0].deterministic = false;
    excused[0].results[0].seal(&compare_context()).unwrap();
    assert!(matches!(
        prepare(request(&policy, &registry, excused)).expect_err("must refuse"),
        AssemblyError::MetricDeclarationMismatch {
            field: "deterministic",
            ..
        }
    ));
}

#[test]
fn a_result_naming_a_metric_no_registry_declares_is_refused() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
    engines[0].results[0].metric_id = "static.invented".to_string();
    engines[0].results[0].seal(&compare_context()).unwrap();

    assert_eq!(
        prepare(request(&policy, &registry, engines)).expect_err("must refuse"),
        AssemblyError::UndeclaredMetric {
            engine_id: "static-metrics".to_string(),
            metric_id: "static.invented".to_string(),
        }
    );
}

#[test]
fn a_declared_metric_whose_claim_is_missing_is_refused() {
    // `LoadedRegistry`'s fields are public, so a caller can hand assembly a
    // registry the lint would have refused. The evidence rule holds anyway.
    let policy = Policy::default();
    let mut registry = shipped_registry();
    let claim_id = "andon.static.cognitive@1|typescript|comprehension-time";
    let engines = five_engines(&registry);
    registry.registry.claims.remove(claim_id);

    assert_eq!(
        prepare(request(&policy, &registry, engines)).expect_err("must refuse"),
        AssemblyError::UnknownClaim {
            metric_id: "static.cognitive-complexity.typescript".to_string(),
            claim_id: claim_id.to_string(),
        }
    );
}

#[test]
fn an_unsealed_result_is_refused() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
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
    let mut engines = five_engines(&registry);
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
    let mut engines = five_engines(&registry);
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
    let mut engines = five_engines(&registry);
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
    let mut engines = five_engines(&registry);
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
            &registry,
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
    let record = prepare(request(&policy, &registry, five_engines(&registry)))
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
    let mut engines = five_engines(&registry);
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
    let record = prepare(request(&policy, &registry, five_engines(&registry)))
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
    let req = failed(
        request(&policy, &registry, five_engines(&registry)),
        "clones",
        "index lock held by another process",
    );
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
    let mut engines = five_engines(&registry);
    engines[0].results[0].completeness = Completeness::Unwitnessed;
    engines[0].results[0].seal(&compare_context()).unwrap();
    let req = failed(
        request(&policy, &registry, engines),
        "clones",
        "unavailable",
    );
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
    let req = failed(
        request(&policy, &registry, Vec::new()),
        "static-metrics",
        "every grammar failed to load",
    );
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
    let prepared =
        prepare(request(&policy, &registry, five_engines(&registry))).expect("assembles");
    assert!(!prepared.has_countable_finding());
}

#[test]
fn a_fired_detector_is_something_for_the_counter_to_count() {
    let policy = Policy::default();
    let registry = shipped_registry();
    let mut engines = five_engines(&registry);
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
    let record = prepare(request(&policy, &registry, five_engines(&registry)))
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
        let mut engines = five_engines(&registry);
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
            .advance(
                "feat/a",
                cap,
                prepared.loop_outcome(),
                &format!("base..pass{pass}"),
            )
            .expect("advances");
        let record = prepared.finish(advance);
        assert_eq!(record.verdict.iteration.count, pass);
        assert_eq!(record.verdict.verdict, Verdict::Block, "pass {pass}");
    }

    // One more, and the tool stops asking the agent.
    let prepared = prepare(request(&policy, &registry, firing())).expect("assembles");
    let advance = store
        .advance("feat/a", cap, prepared.loop_outcome(), "base..one-too-many")
        .expect("advances");
    let record = prepared.finish(advance);
    assert_eq!(record.verdict.verdict, Verdict::EscalateToHuman);
    assert!(record.verdict.iteration.escalated);

    // The agent fixes it. The loop is over, so the count resets and the next
    // unrelated finding on this branch starts from one.
    let prepared =
        prepare(request(&policy, &registry, five_engines(&registry))).expect("assembles");
    let advance = store
        .advance("feat/a", cap, prepared.loop_outcome(), "base..fixed")
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

    let mut req = request(&policy, &registry, five_engines(&registry));
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

    let mut req = request(&policy, &registry, five_engines(&registry));
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
    let record = prepare(request(&policy, &registry, five_engines(&registry)))
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
    let engines = five_engines(&registry);
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
        let mut engines = five_engines(&registry);
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
    for (engines, expected) in [(five_engines(&registry), false), (firing(), true)] {
        let prepared = prepare(request(&policy, &registry, engines)).expect("assembles");
        assert_eq!(prepared.has_countable_finding(), expected);

        for recovered in [false, true] {
            let record = prepared.clone().finish(Advance {
                contended: false,
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
