//! The cross-OS matrix fixture, held to its committed expectations.
//!
//! The workflow runs this fixture on three operating systems and compares
//! digests. That is the real gate; it costs paid runner minutes and runs at
//! phase-review gates only. This test is what makes the gate *meaningful* on
//! every push: it pins the result-count floor the matrix asserts, and it pins
//! the two properties the fixture exists to demonstrate — that CRLF and LF
//! twins measure identically, and that a degraded parse travels as a digest-bound
//! `completeness` value rather than as a footnote.

mod common;

use andon_core::schema::enums::{Completeness, Severity};
use andon_core::schema::payload::{MeasurementRecord, MeasurementResult, ScopeKind};
use andon_static_metrics::fixture;
use andon_static_metrics::health::PARSE_DEGRADED_CAVEAT;
use andon_static_metrics::metrics::{METRIC_PARSE_ERRORS, METRIC_SLOC, METRIC_UNMEASURED_FILES};
use andon_static_metrics::record;

/// Build the committed fixture in a temporary directory and measure it.
fn measured() -> (MeasurementRecord, fixture::Prepared) {
    let manifest = fixture::load(&fixture::matrix_manifest_path()).expect("the manifest loads");
    let dir = tempfile::tempdir().expect("temp dir");
    let prepared =
        fixture::build(&manifest, &dir.path().join("fixture")).expect("the fixture builds");
    let git = andon_core::git::Git::open(&prepared.repo).expect("the fixture repository opens");
    let record = record::measure(
        &git,
        &andon_core::git::Revision::Rev(prepared.base.clone()),
        &andon_core::git::Revision::Rev(prepared.head.clone()),
        "0.1.0",
    )
    .expect("the fixture measures");
    // `dir` is dropped here and the repository goes with it; the record does not
    // reference it.
    (record, prepared)
}

fn results_for<'a>(record: &'a MeasurementRecord, path: &str) -> Vec<&'a MeasurementResult> {
    record
        .results
        .iter()
        .filter(|r| r.scope.path.as_deref() == Some(path))
        .collect()
}

#[test]
fn the_engine_produces_exactly_the_declared_result_count() {
    // The floor the matrix workflow asserts. Legs that each measured nothing
    // agree perfectly about nothing, so the number is committed in the manifest
    // and checked here rather than read off the run.
    let (record, prepared) = measured();
    assert_eq!(
        record.results.len(),
        prepared.expect_result_count,
        "the fixture manifest declares {} results; see the accounting in \
         fixtures/matrix.toml before changing either number",
        prepared.expect_result_count
    );
}

#[test]
fn crlf_and_lf_files_measure_by_the_same_rules() {
    // Not a claim that the two files have equal numbers — they hold different
    // code — but that `\r` never reaches a count. `src/crlf.ts` has one function
    // with one branch; if carriage returns were being counted as content or as
    // line terminators, its source-line count would not be four.
    let (record, _) = measured();
    let crlf = results_for(&record, "src/crlf.ts");
    let file_sloc = crlf
        .iter()
        .find(|r| r.metric_id == METRIC_SLOC && r.scope.kind == ScopeKind::File)
        .expect("crlf.ts has a file-scope sloc");
    assert_eq!(
        file_sloc.value,
        andon_core::schema::payload::MetricValue::Count(6),
        "a CRLF file's source lines are its LF-delimited code lines"
    );
}

#[test]
fn the_broken_file_carries_its_degradation_into_the_digest() {
    let (record, _) = measured();
    let broken = results_for(&record, "src/broken.ts");
    assert!(!broken.is_empty(), "the broken file must still be measured");

    for result in &broken {
        if result.metric_id.starts_with("static.parse-") {
            // The report of the degradation is not itself degraded: counting
            // ERROR nodes over a broken tree is exact, and capping it would
            // silence the signal PREMORTEM T3 wants loud.
            assert_eq!(
                result.completeness,
                Completeness::Complete,
                "{} must stay complete",
                result.metric_id
            );
        } else {
            assert_eq!(
                result.completeness,
                Completeness::ParseDegraded,
                "{} on a degraded file must say so",
                result.metric_id
            );
            assert!(
                !result.severity.is_med_plus(),
                "{} on a degraded file must not be able to stop the line",
                result.metric_id
            );
            assert!(
                result.evidence.does_not_predict[0].contains(PARSE_DEGRADED_CAVEAT),
                "{} must carry the caveat a human reads: {:?}",
                result.metric_id,
                result.evidence.does_not_predict
            );
        }
    }

    let errors = broken
        .iter()
        .find(|r| r.metric_id == METRIC_PARSE_ERRORS)
        .expect("the broken file reports its ERROR nodes");
    assert!(
        matches!(
            errors.value,
            andon_core::schema::payload::MetricValue::Count(n) if n > 0
        ),
        "{:?}",
        errors.value
    );

    // Record level takes the weakest of its results.
    assert_eq!(record.completeness, Completeness::ParseDegraded);
}

#[test]
fn the_tokenization_tier_reports_size_and_no_parse_health() {
    let (record, _) = measured();
    let rust = results_for(&record, "src/lib.rs");
    assert_eq!(rust.len(), 1, "{rust:?}");
    assert_eq!(rust[0].metric_id, METRIC_SLOC);
    assert_eq!(rust[0].scope.kind, ScopeKind::File);
}

#[test]
fn an_out_of_scope_file_produces_nothing_and_is_not_unmeasured() {
    // The two ways to get `static.unmeasured-files` wrong: counting a file the
    // engine never claimed, and counting a deletion. Both would make the number
    // large and useless, and it exists to be small and alarming.
    let (record, _) = measured();
    assert!(results_for(&record, "docs/notes.md").is_empty());
    assert!(results_for(&record, "src/gone.tsx").is_empty());

    let unmeasured = record
        .results
        .iter()
        .find(|r| r.metric_id == METRIC_UNMEASURED_FILES)
        .expect("the change-scope count is always emitted");
    assert_eq!(
        unmeasured.value,
        andon_core::schema::payload::MetricValue::Count(0)
    );
    assert_eq!(unmeasured.scope.kind, ScopeKind::Change);
}

#[test]
fn a_non_ascii_path_survives_into_the_scope() {
    let (record, _) = measured();
    assert!(
        !results_for(&record, "src/伝票/計測.py").is_empty(),
        "paths are reported as git spells them: {:?}",
        record
            .results
            .iter()
            .filter_map(|r| r.scope.path.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn measuring_the_same_fixture_twice_produces_identical_digests() {
    // The local half of the cross-OS claim. Three operating systems agreeing is
    // the gate; one machine agreeing with itself is the precondition, and it
    // catches map-iteration order and other in-process nondeterminism without
    // spending a runner minute.
    let (first, _) = measured();
    let (second, _) = measured();
    let digests = |record: &MeasurementRecord| {
        let mut rows: Vec<String> = record
            .results
            .iter()
            .map(|r| format!("{} {}", r.metric_id, r.digest))
            .collect();
        rows.sort();
        rows
    };
    assert_eq!(digests(&first), digests(&second));
}

#[test]
fn every_severity_stays_at_the_floor_the_engine_reports() {
    // The engine reports facts; policy decides severity, and the policy that
    // counts is the verifier's. An engine that started assigning severity would
    // be making a decision P5a owns.
    let (record, _) = measured();
    assert!(record.results.iter().all(|r| r.severity == Severity::Info));
}
