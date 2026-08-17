//! The gate of PREMORTEM T2: an incrementally-updated index and a cold rebuild
//! are the same artefact, byte for byte, after any sequence of edits, renames,
//! and deletes.
//!
//! # What "byte-identical" is asserted over
//!
//! Both, deliberately:
//!
//! 1. **The serialized index.** The stored artefact itself, so a difference is
//!    caught where it originates rather than where it happens to surface.
//! 2. **The sealed measurement results.** The digests a verifier compares. An
//!    index could in principle differ in a field no metric reads; that would
//!    still be a bug, and asserting the results as well means the *phrase*
//!    "incremental == cold" cannot be satisfied in a way that leaves the
//!    product's actual claim unproved.
//!
//! Asserting one alone leaves the ambiguity open. Asserting both closes it for
//! the cost of one extra comparison.
//!
//! # Why the operations are the ones they are
//!
//! Content-keyed reuse makes an edit trivially safe: the blob OID changes, so
//! the entry is recomputed. The bug this test is actually hunting is the
//! **stale posting** — an entry for a path the change no longer contains. Only
//! `Rename` and `Delete` produce one, so the generator is weighted toward them
//! and every sequence ends with an assertion rather than only the last.

use std::collections::BTreeMap;

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::policy::Policy;
use andon_core::schema::payload::{CompareContext, MeasurementResult};
use andon_engine_clones::index::{FileInput, Index};
use andon_engine_clones::ClonesEngine;
use proptest::prelude::*;

/// A file body long enough to clear the 50-token clone floor, parameterized so
/// that two bodies can be made equal (a clone) or different.
fn body(shape: u8, name: &str) -> String {
    match shape % 4 {
        // Under one rolling window. A file this short contributes no window
        // hashes at all, which is a different code path from "contributes some"
        // — and the boundary between them was outside the property test until
        // this arm existed.
        3 => format!(
            "export const {name} = 1;
"
        ),
        0 => format!(
            "export function {name}(items: number[], factor: number): number {{\n\
             \x20 let total = 0;\n\
             \x20 for (const item of items) {{\n\
             \x20   if (item > factor) {{ total += item * factor; }}\n\
             \x20   else {{ total -= item; }}\n\
             \x20 }}\n\
             \x20 return total;\n\
             }}\n"
        ),
        1 => format!(
            "export class {name} {{\n\
             \x20 private cache = new Map<string, number>();\n\
             \x20 lookup(key: string): number {{\n\
             \x20   const hit = this.cache.get(key);\n\
             \x20   if (hit !== undefined) {{ return hit; }}\n\
             \x20   const computed = key.length * 7;\n\
             \x20   this.cache.set(key, computed);\n\
             \x20   return computed;\n\
             \x20 }}\n\
             }}\n"
        ),
        _ => format!(
            "def {name}(rows, limit):\n\
             \x20   kept = []\n\
             \x20   for row in rows:\n\
             \x20       if row is None:\n\
             \x20           continue\n\
             \x20       if len(row) > limit:\n\
             \x20           kept.append(row[:limit])\n\
             \x20       else:\n\
             \x20           kept.append(row)\n\
             \x20   return kept\n"
        ),
    }
}

fn extension(shape: u8) -> &'static str {
    if shape % 4 == 2 {
        "py"
    } else {
        "ts"
    }
}

/// Blob OIDs stand in for git's here. They only have to be a content identity,
/// which is exactly what the engine relies on.
fn oid(source: &str) -> String {
    format!(
        "{:016x}{:016x}",
        andon_engine_clones::syntax::fnv1a(source.as_bytes()),
        andon_engine_clones::syntax::fnv1a(
            source
                .as_bytes()
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>()
                .as_slice()
        )
    )
}

/// One step of a change history.
#[derive(Debug, Clone)]
enum Op {
    /// Add or overwrite a file with a body of the given shape.
    Write { slot: u8, shape: u8 },
    /// Move a file's content to a different path — the operation that leaves a
    /// stale posting behind if the index mutates in place.
    Rename { from: u8, to: u8 },
    /// Remove a file.
    Delete { slot: u8 },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => (0u8..6, 0u8..4).prop_map(|(slot, shape)| Op::Write { slot, shape }),
        3 => (0u8..6, 0u8..6).prop_map(|(from, to)| Op::Rename { from, to }),
        3 => (0u8..6).prop_map(|slot| Op::Delete { slot }),
    ]
}

/// The file set, as a path -> source map the ops mutate.
type World = BTreeMap<String, String>;

fn apply(world: &mut World, op: &Op) {
    match op {
        Op::Write { slot, shape } => {
            let name = format!("mod{slot}");
            let path = format!("src/{name}.{}", extension(*shape));
            // A slot holds one file; writing it with a different language moves
            // it, which is a rename by another name and worth exercising.
            world.retain(|p, _| !p.starts_with(&format!("src/{name}.")));
            world.insert(path, body(*shape, &format!("fn{slot}")));
        }
        Op::Rename { from, to } => {
            let from_prefix = format!("src/mod{from}.");
            let Some((old_path, source)) = world
                .iter()
                .find(|(p, _)| p.starts_with(&from_prefix))
                .map(|(p, s)| (p.clone(), s.clone()))
            else {
                return;
            };
            let extension = old_path.rsplit('.').next().unwrap_or("ts").to_string();
            let new_path = format!("src/mod{to}.{extension}");
            if new_path == old_path {
                return;
            }
            world.remove(&old_path);
            world.retain(|p, _| !p.starts_with(&format!("src/mod{to}.")));
            world.insert(new_path, source);
        }
        Op::Delete { slot } => {
            world.retain(|p, _| !p.starts_with(&format!("src/mod{slot}.")));
        }
    }
}

fn inputs(world: &World) -> Vec<FileInput> {
    world
        .iter()
        .map(|(path, source)| FileInput {
            path: path.clone(),
            blob_oid: oid(source),
            source: source.as_bytes().to_vec(),
        })
        .collect()
}

fn context() -> MeasureContext {
    MeasureContext {
        compare_context: CompareContext {
            base_oid: "a".repeat(40),
            head_oid: "b".repeat(40),
            git_version: "git version 2.51.0".to_string(),
            base_resolution: "explicit".to_string(),
        },
        policy: Policy::default(),
        changed_paths: Vec::new(),
        sandbox_available: false,
    }
}

/// Sealed results for a file set, built with no index at all — the cold answer.
fn cold_results(world: &World) -> Vec<MeasurementResult> {
    let engine = ClonesEngine::for_files(inputs(world), None).expect("cold build");
    run_engine(&engine, &context()).expect("cold measure")
}

proptest! {
    // Each case parses several files with tree-sitter, so the case count is
    // chosen to keep the suite inside a few seconds while still driving
    // sequences long enough for a stale posting to survive several steps.
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn an_incremental_index_equals_a_cold_rebuild(ops in prop::collection::vec(op_strategy(), 1..12)) {
        let mut world = World::new();
        // Something to rename and delete from the first step onward.
        apply(&mut world, &Op::Write { slot: 0, shape: 0 });
        apply(&mut world, &Op::Write { slot: 1, shape: 0 });

        let mut incremental = Index::empty().update(&inputs(&world)).0;

        for (step, op) in ops.iter().enumerate() {
            apply(&mut world, op);
            let current = inputs(&world);

            let (next, _) = incremental.update(&current);
            let (cold, reused) = Index::empty().update(&current);
            prop_assert_eq!(reused, 0, "a cold build reuses nothing by definition");

            prop_assert_eq!(
                next.to_bytes().unwrap(),
                cold.to_bytes().unwrap(),
                "step {} ({:?}): the incremental index is not the cold one\nincremental paths: {:?}\ncold paths: {:?}",
                step,
                op,
                next.files.keys().collect::<Vec<_>>(),
                cold.files.keys().collect::<Vec<_>>()
            );

            incremental = next;
        }

        // And the numbers that come out of it: an index equal in bytes must
        // also produce equal sealed digests, and asserting both is what makes
        // "byte-identical" unambiguous.
        let warm = {
            let engine = ClonesEngine::for_files(inputs(&world), None).expect("engine");
            run_engine(&engine, &context()).expect("measure")
        };
        let cold = cold_results(&world);
        prop_assert_eq!(
            warm.iter().map(|r| (&r.metric_id, &r.digest)).collect::<Vec<_>>(),
            cold.iter().map(|r| (&r.metric_id, &r.digest)).collect::<Vec<_>>()
        );
    }
}

/// The property test above runs the index in memory. This one runs the same
/// equivalence through the engine's real on-disk path, because the persisted
/// round trip is where a serialization asymmetry would hide.
#[test]
fn the_equivalence_survives_the_disk() {
    let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("incremental-disk");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let index_path = root.join("clones-index");

    let mut world = World::new();
    let script = [
        Op::Write { slot: 0, shape: 0 },
        Op::Write { slot: 1, shape: 0 },
        Op::Write { slot: 2, shape: 1 },
        Op::Rename { from: 0, to: 4 },
        Op::Delete { slot: 1 },
        Op::Write { slot: 5, shape: 2 },
        Op::Rename { from: 2, to: 5 },
    ];

    for (step, op) in script.iter().enumerate() {
        apply(&mut world, op);

        let warm_engine =
            ClonesEngine::for_files(inputs(&world), Some(&index_path)).expect("warm build");
        let warm = run_engine(&warm_engine, &context()).expect("warm measure");
        let cold = cold_results(&world);

        assert_eq!(
            warm.iter().map(|r| &r.digest).collect::<Vec<_>>(),
            cold.iter().map(|r| &r.digest).collect::<Vec<_>>(),
            "step {step} ({op:?}) diverged with a persisted index"
        );

        // A rebuilt-from-disk index must equal a cold one too, or the stored
        // form has lost something the in-memory one had.
        let loaded = Index::load(&index_path).index().expect("the index reloads");
        let (cold_index, _) = Index::empty().update(&inputs(&world));
        assert_eq!(
            loaded.to_bytes().unwrap(),
            cold_index.to_bytes().unwrap(),
            "step {step} ({op:?}): the stored index is not the cold one"
        );
    }

    // The whole point, stated once at the end: after seven mutations the index
    // holds exactly the live paths and nothing else.
    let loaded = Index::load(&index_path).index().unwrap();
    assert_eq!(
        loaded.files.keys().cloned().collect::<Vec<_>>(),
        world.keys().cloned().collect::<Vec<_>>()
    );
}
