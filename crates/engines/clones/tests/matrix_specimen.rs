//! The cross-OS matrix specimen still contains a clone worth comparing.
//!
//! `fixtures/matrix/all-seven` carries a Type-2 clone — the `subtotal` body
//! duplicated into `src/checkout.ts` with every identifier renamed — so that the
//! standing determinism matrix compares numbers rather than zeros (PLAN B4).
//! A byte-identical copy would have been found by `diff` and would prove nothing
//! about token normalization, which is the thing under test.
//!
//! The matrix legs run at phase-review gates (user decision D2), so this test is
//! what notices on a push that the specimen has gone quiet.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::policy::Policy;
use andon_core::schema::payload::CompareContext;
use andon_engine_clones::index::FileInput;
use andon_engine_clones::{syntax, ClonesEngine};

fn specimen_head() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("fixtures")
        .join("matrix")
        .join("all-seven")
        .join("head")
        .canonicalize()
        .expect("the matrix specimen is committed")
}

/// The head tree, as the engine's file inputs.
///
/// Read here rather than borrowed from the tamper crate's corpus loader: an
/// engine crate depending on another engine crate to read a directory would be
/// a dependency edge bought for eighteen lines.
fn inputs() -> Vec<FileInput> {
    let root = specimen_head();
    let mut found: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(&root)
                .expect("walked from root")
                .to_string_lossy()
                .replace('\\', "/");
            found.insert(relative, std::fs::read(&path).expect("readable"));
        }
    }
    found
        .into_iter()
        .map(|(path, source)| FileInput {
            // The engine keys reuse on this; git's OID is what the probe
            // supplies, and a content hash is the same identity here.
            blob_oid: format!("{:040x}", syntax::fnv1a(&source)),
            path,
            source,
        })
        .collect()
}

#[test]
fn the_specimen_still_carries_a_cross_file_clone() {
    let engine = ClonesEngine::for_files(inputs(), None).expect("builds");
    let report = engine.report();
    let cross_file = report.groups.iter().find(|group| {
        group
            .fragments
            .windows(2)
            .any(|pair| pair[0].path != pair[1].path)
    });
    let group = cross_file.unwrap_or_else(|| {
        panic!(
            "the matrix specimen no longer contains a clone spanning two files: {:#?}",
            report.groups
        )
    });
    assert!(
        group.token_len >= 50,
        "the clone is {} tokens, under the reporting floor",
        group.token_len
    );
    assert!(report.duplicated_tokens() > 0);
}

#[test]
fn the_specimen_produces_the_result_count_the_matrix_patch_asserts() {
    let engine = ClonesEngine::for_files(inputs(), None).expect("builds");
    let results = run_engine(
        &engine,
        &MeasureContext {
            compare_context: CompareContext {
                base_oid: "a".repeat(40),
                head_oid: "b".repeat(40),
                git_version: "git version 2.51.0".to_string(),
                base_resolution: "explicit".to_string(),
            },
            policy: Policy::default(),
            changed_paths: Vec::new(),
            sandbox_available: false,
        },
    )
    .expect("measures");
    // Four change-scoped metrics plus one per measured file. Five of the
    // specimen's head files are ones a vendored grammar reads, so nine — the
    // exact count `docs/patches/p3-spike-matrix-join.md` passes to
    // `compare-records --expect-results`. The two have to move together.
    assert_eq!(
        results.len(),
        9,
        "{:#?}",
        results
            .iter()
            .map(|r| (&r.metric_id, &r.scope.path))
            .collect::<Vec<_>>()
    );
}
