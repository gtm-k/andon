//! The cross-OS matrix specimen still fires everything.
//!
//! `fixtures/matrix/all-seven` exists so the standing determinism matrix has
//! something non-trivial to compare (PLAN B4, R2-1). A digest comparison over
//! results that are all `false` and all `0` is green whatever the engines do —
//! it would prove three operating systems agree about nothing.
//!
//! The matrix job checks this too, in its own way. This test checks it on every
//! push, which is where it belongs: the expensive legs run at phase-review gates
//! (user decision D2), so without this a specimen that had gone quiet would sit
//! undetected until the next dispatch, and the run that noticed would be the one
//! that was supposed to be proving something else.

use std::path::{Path, PathBuf};

use andon_engine_tamper::corpus::{self, CaseManifest};
use andon_engine_tamper::detectors;
use andon_engine_tamper::TamperEngine;

fn specimen() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("fixtures")
        .join("matrix")
        .join("all-seven")
        .canonicalize()
        .expect("the matrix specimen is committed")
}

/// The specimen is not a corpus case — it has no `case.toml` and is loaded by
/// nothing that scores — so its change view is assembled here from the same two
/// directories the probe's `build-fixture` commits.
fn change() -> andon_engine_tamper::ChangeView {
    let manifest = CaseManifest {
        title: "cross-OS matrix specimen".to_string(),
        expect: Vec::new(),
        note: "assembled in-test".to_string(),
        renames: Vec::new(),
    };
    corpus::change_from_trees(&specimen(), &manifest).expect("the specimen loads")
}

#[test]
fn all_seven_detectors_fire_on_the_specimen() {
    let engine = TamperEngine::for_view(change());
    let quiet: Vec<&str> = engine
        .outcomes()
        .iter()
        .filter(|(_, outcome)| !outcome.fired)
        .map(|(detector, _)| detectors::signal_name(detector.signal()))
        .collect();
    assert!(
        quiet.is_empty(),
        "the matrix specimen no longer fires: {}\n\
         Every detector must fire on it, or the cross-OS matrix compares results that are all \
         false and passes without measuring anything.",
        quiet.join(", ")
    );
    assert_eq!(engine.signals().len(), 7);
}

#[test]
fn the_specimen_produces_the_result_count_the_matrix_patch_asserts() {
    use andon_core::engine::{run_engine, MeasureContext};
    use andon_core::policy::Policy;
    use andon_core::schema::payload::{CompareContext, HeadKind};

    let engine = TamperEngine::for_view(change());
    let results = run_engine(
        &engine,
        &MeasureContext {
            compare_context: CompareContext {
                base_oid: "a".repeat(40),
                head_oid: "b".repeat(40),
                git_version: "git version 2.51.0".to_string(),
                head_kind: HeadKind::Commit,
                base_resolution: "explicit".to_string(),
            },
            policy: Policy::default(),
            changed_paths: Vec::new(),
            sandbox_available: false,
        },
    )
    .expect("measures");
    // `docs/patches/p3-spike-matrix-join.md` passes `--expect-results 14`, and
    // `compare-records` treats it as an exact count. The two numbers have to
    // move together or the matrix goes red for a reason that is not a
    // determinism failure.
    assert_eq!(results.len(), 14);
}
