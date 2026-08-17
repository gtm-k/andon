//! The wire spellings, pinned.
//!
//! Every string here is copied verbatim from PLAN.md's P0 acceptance criteria.
//! They are load-bearing in a way that is easy to miss: the CI verifier maps
//! attestation values to check conclusions, agents branch on the verdict, and
//! the ledger aggregates by `invocation_source`. A rename during a refactor
//! would be a silent breaking change to a published contract, and a `serde`
//! attribute is easy to lose.
//!
//! The spellings are also *inconsistent* — `escalate_to_human` is snake_case
//! while `confirmed-static` and `parse-degraded` are kebab-case. That is
//! deliberate: PLAN.md is the contract, and reproducing its inconsistency costs
//! less than a schema version bump to tidy it. Pinning them here stops a
//! well-meaning future edit from "fixing" the inconsistency.

use andon_core::canonical::to_canonical_string;
use andon_core::registry::{Claim, ResolvedClaim};
use andon_core::schema::enums::*;
use andon_core::schema::payload::Reserved;
use andon_core::testing::sample_record;

fn wire<T: serde::Serialize>(value: &T) -> String {
    to_canonical_string(value)
        .unwrap()
        .trim_matches('"')
        .to_string()
}

#[test]
fn verdict_values_are_exactly_as_specified() {
    assert_eq!(wire(&Verdict::Pass), "pass");
    assert_eq!(wire(&Verdict::Advise), "advise");
    assert_eq!(wire(&Verdict::Block), "block");
    assert_eq!(wire(&Verdict::EscalateToHuman), "escalate_to_human");
}

#[test]
fn all_six_attestation_values_are_exactly_as_specified() {
    let expected = [
        (Attestation::Confirmed, "confirmed"),
        (Attestation::ConfirmedStatic, "confirmed-static"),
        (Attestation::Divergent, "divergent"),
        (Attestation::Unwitnessed, "unwitnessed"),
        (
            Attestation::UnwitnessedVersionSkew,
            "unwitnessed-version-skew",
        ),
        (
            Attestation::UnwitnessedBaseMismatch,
            "unwitnessed-base-mismatch",
        ),
    ];
    for (value, spelling) in expected {
        assert_eq!(wire(&value), spelling);
    }
    assert_eq!(expected.len(), 6, "the enum has exactly six values");
}

/// Only `confirmed` and `confirmed-static` are passes.
///
/// The `unwitnessed-*` family exists precisely so that a non-tamper explanation
/// is still not a confirmation (PLAN R2-4). Treating one as countable would let
/// a stale-base measurement count downstream.
#[test]
fn only_confirmed_values_count_downstream() {
    assert!(Attestation::Confirmed.counts_downstream());
    assert!(Attestation::ConfirmedStatic.counts_downstream());
    for value in [
        Attestation::Divergent,
        Attestation::Unwitnessed,
        Attestation::UnwitnessedVersionSkew,
        Attestation::UnwitnessedBaseMismatch,
    ] {
        assert!(!value.counts_downstream(), "{value:?} must not count");
    }
}

#[test]
fn completeness_values_are_exactly_as_specified() {
    assert_eq!(wire(&Completeness::Complete), "complete");
    assert_eq!(wire(&Completeness::Partial), "partial");
    assert_eq!(wire(&Completeness::ParseDegraded), "parse-degraded");
    assert_eq!(wire(&Completeness::Unwitnessed), "unwitnessed");
}

/// Seven detectors from P3 plus the verifier-raised `base-fabrication`.
#[test]
fn the_tamper_vocabulary_is_complete_and_includes_base_fabrication() {
    let expected = [
        (TamperSignal::SuppressionDensity, "suppression-density"),
        (TamperSignal::TestRemoval, "test-removal"),
        (
            TamperSignal::CoverageExclusionDrift,
            "coverage-exclusion-drift",
        ),
        (TamperSignal::AssertionFreeTest, "assertion-free-test"),
        (TamperSignal::ThresholdConfigEdit, "threshold-config-edit"),
        (TamperSignal::LookupTableBlowup, "lookup-table-blowup"),
        (TamperSignal::ParseErrorDelta, "parse-error-delta"),
        (TamperSignal::BaseFabrication, "base-fabrication"),
    ];
    for (value, spelling) in expected {
        assert_eq!(wire(&value), spelling);
    }
    assert_eq!(
        expected.len(),
        8,
        "seven P3 detectors plus base-fabrication"
    );
}

#[test]
fn invocation_source_values_are_exactly_as_specified() {
    assert_eq!(wire(&InvocationSource::Hook), "hook");
    assert_eq!(wire(&InvocationSource::AgentInitiated), "agent-initiated");
    assert_eq!(wire(&InvocationSource::HumanCli), "human-cli");
    assert_eq!(wire(&InvocationSource::CiVerifier), "ci-verifier");
}

#[test]
fn engine_and_metric_classes_are_exactly_as_specified() {
    assert_eq!(wire(&EngineClass::StaticSafe), "static-safe");
    assert_eq!(wire(&EngineClass::CodeExec), "code-exec");
    assert_eq!(wire(&MetricClass::DiffActionable), "diff-actionable");
    assert_eq!(
        wire(&MetricClass::ContextInformational),
        "context-informational"
    );
}

#[test]
fn every_engine_family_is_present() {
    for (family, spelling) in [
        (EngineFamily::Static, "static"),
        (EngineFamily::Clones, "clones"),
        (EngineFamily::Tamper, "tamper"),
        (EngineFamily::Process, "process"),
        (EngineFamily::Artifacts, "artifacts"),
    ] {
        assert_eq!(wire(&family), spelling);
    }
}

/// Reserved fields are always present, `null` when unset.
///
/// If they were skipped when empty the shape of a record would vary with its
/// content, and a consumer written against a record that happened to carry a
/// `run_id` would break on one that did not.
#[test]
fn reserved_fields_serialize_as_null_rather_than_being_omitted() {
    assert_eq!(
        to_canonical_string(&Reserved::default()).unwrap(),
        r#"{"package_scope":null,"run_id":null,"workspace_id":null}"#
    );

    let record = to_canonical_string(&sample_record()).unwrap();
    for field in ["run_id", "workspace_id", "package_scope"] {
        assert!(
            record.contains(&format!("\"{field}\":null")),
            "{field} must appear in every record"
        );
    }
}

/// `base_oid` and `head_oid` appear on every record, because a record that
/// cannot say what it measured cannot be compared.
#[test]
fn the_compare_tuple_is_present_on_every_record() {
    let record = to_canonical_string(&sample_record()).unwrap();
    assert!(record.contains("\"base_oid\""));
    assert!(record.contains("\"head_oid\""));
}

/// A fresh record is unwitnessed: trust is earned from CI, never assumed.
#[test]
fn a_fresh_record_does_not_default_to_a_pass() {
    let record = sample_record();
    assert_eq!(record.attestation.value, Attestation::Unwitnessed);
    assert!(!record.attestation.value.counts_downstream());
}

fn claim(expiry: &str) -> Claim {
    Claim {
        claim_id: "andon.static.cognitive@1|typescript|comprehension-time".into(),
        implementation: "andon.static.cognitive".into(),
        implementation_version: "1".into(),
        language: "typescript".into(),
        outcome: "comprehension-time".into(),
        tier: EvidenceTier::B,
        citation: "Munoz Baron, Wyrich & Wagner, ESEM 2020".into(),
        citation_ref: None,
        population: "427 snippets".into(),
        effect: "correlates with comprehension time".into(),
        does_not_predict: vec!["defect density".into()],
        owner: "gtm-k".into(),
        expiry: expiry.parse().unwrap(),
    }
}

/// The S2 demotion, mechanically: an expired claim cannot reach a payload
/// without its `stale` flag, because `to_evidence_ref` is the only way to build
/// an `EvidenceRef` from a claim.
#[test]
fn an_expired_claim_carries_its_staleness_into_the_payload() {
    let fresh = ResolvedClaim {
        claim: claim("2027-03-15"),
        stale: false,
    };
    assert!(!fresh.to_evidence_ref().stale);

    let expired = ResolvedClaim {
        claim: claim("2026-01-15"),
        stale: true,
    };
    let evidence = expired.to_evidence_ref();
    assert!(evidence.stale, "the demotion must reach the payload");
    assert_eq!(evidence.tier, EvidenceTier::B, "the tier is not rewritten");
    assert_eq!(
        evidence.does_not_predict,
        vec!["defect density".to_string()],
        "the honesty field survives the projection"
    );
}
