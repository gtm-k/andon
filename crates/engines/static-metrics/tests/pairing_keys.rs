//! Two callbacks on one line, measured rather than refused.
//!
//! # The failure this file exists to prevent
//!
//! `andon_core::payload::prepare` builds a `(metric_id, scope)` set and refuses
//! the whole payload if one pair repeats, because a pairing key that names two
//! results is where a forged result shadows an honest one. That refusal is
//! correct. What was not correct is that this engine manufactured the collision
//! out of ordinary code: two anonymous functions on one line shared a name and a
//! line span, so they shared a scope, so `andon measure` exited 1 with nothing
//! measured on any repository containing `.map().filter()`, `.then().catch()`, a
//! jQuery chain, a Python lambda pair, or a minified bundle.
//!
//! So this suite asserts the pairing key at the level assembly computes it — the
//! canonical bytes of the scope, not a paraphrase of them — over results the real
//! engine produced from a real repository. A unit test on names could pass while
//! the serialized scope still collided.

mod common;

use std::collections::BTreeMap;

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::git::{ChangedSet, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_core::schema::payload::{MeasurementResult, ScopeKind};
use andon_static_metrics::StaticMetricsEngine;

/// The four shapes the defect was reported on, one file each.
const CHAINS: &[(&str, &str)] = &[
    (
        "src/chain.ts",
        "export const out = xs.map(x => x * 2).filter(x => x > 0);\n",
    ),
    (
        "src/promise.js",
        "fetch(u).then(r => r.json()).catch(e => log(e));\n",
    ),
    (
        "src/jquery.js",
        "$(\".a\").on(\"click\", function () { hide(); }).on(\"blur\", function () { hide(); });\n",
    ),
    (
        "src/lambdas.py",
        "xs = list(map(lambda x: x + 1, filter(lambda x: x > 0, ys)))\n",
    ),
];

/// Measure `base..WORKTREE` and return every result.
fn measure_worktree(repo: &common::Repo, base: &str) -> Vec<MeasurementResult> {
    let range = ResolvedRange::resolve(
        &repo.git,
        &Revision::Rev(base.to_string()),
        &Revision::Worktree,
    )
    .expect("the range resolves");
    let changed = ChangedSet::enumerate(&repo.git, &range).expect("the change enumerates");
    let engine = StaticMetricsEngine::for_change(&repo.git, &changed, "0.1.0")
        .expect("the engine reads its blobs");
    let ctx = MeasureContext {
        compare_context: andon_core::testing::sample_compare_context(),
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox: None,
    };
    run_engine(&engine, &ctx).expect("the engine measures")
}

/// The pairing key exactly as `payload::prepare` computes it.
fn pairing_key(result: &MeasurementResult) -> (String, String) {
    (
        result.metric_id.clone(),
        andon_core::canonical::to_canonical_string(&result.scope).expect("a scope serializes"),
    )
}

fn repo_with_chains() -> (common::Repo, String) {
    let mut repo = common::Repo::init();
    repo.write("src/keep.ts", b"export const keep = 1;\n");
    let base = repo.commit("base");
    for (path, source) in CHAINS {
        repo.write(path, source.as_bytes());
    }
    repo.add_all();
    (repo, base)
}

#[test]
fn a_method_chain_produces_no_two_results_on_one_pairing_key() {
    let (repo, base) = repo_with_chains();
    let results = measure_worktree(&repo, &base);

    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for result in &results {
        *seen.entry(pairing_key(result)).or_insert(0) += 1;
    }
    let shared: Vec<_> = seen.iter().filter(|(_, count)| **count > 1).collect();
    assert!(
        shared.is_empty(),
        "assembly would refuse this payload: {shared:#?}"
    );
}

#[test]
fn both_callbacks_on_a_line_are_reported_rather_than_one() {
    // The other half of the fix: the collision could also have been resolved by
    // dropping a site, which would have turned a refusal into a silently
    // incomplete measurement. Every chain file has two callbacks, so every chain
    // file has two function-scope sites, so its `static.sloc` appears twice.
    let (repo, base) = repo_with_chains();
    let results = measure_worktree(&repo, &base);

    for (path, _) in CHAINS {
        let sites: Vec<&MeasurementResult> = results
            .iter()
            .filter(|r| {
                r.scope.kind == ScopeKind::Function
                    && r.scope.path.as_deref() == Some(path)
                    && r.metric_id == andon_static_metrics::metrics::METRIC_SLOC
            })
            .collect();
        assert_eq!(sites.len(), 2, "{path}: {sites:#?}");
        let symbols: Vec<&str> = sites
            .iter()
            .filter_map(|r| r.scope.symbol.as_deref())
            .collect();
        assert_ne!(symbols[0], symbols[1], "{path}");
    }
}

#[test]
fn a_file_whose_functions_already_differ_keeps_its_bare_symbols() {
    // The property that keeps this fix out of the version constants: a file
    // whose names and spans already tell its functions apart produces the
    // symbols it always produced, so its scope bytes and its digests do not
    // move. A column appended unconditionally would have made every
    // function-scope digest in every repository new, and a new digest under an
    // unchanged regime is what `compare::classify` calls divergent — the tool
    // accusing an honest change of tampering.
    let mut repo = common::Repo::init();
    repo.write("src/keep.ts", b"export const keep = 1;\n");
    let base = repo.commit("base");
    repo.write(
        "src/plain.ts",
        b"export function top(a: number) { return a }\n\
          export const arrow = (b: number) => b;\n\
          export default function () { return 1 }\n",
    );
    repo.add_all();

    let results = measure_worktree(&repo, &base);
    let symbols: std::collections::BTreeSet<&str> = results
        .iter()
        .filter(|r| r.scope.kind == ScopeKind::Function)
        .filter_map(|r| r.scope.symbol.as_deref())
        .collect();
    assert_eq!(
        symbols,
        ["<anonymous>", "arrow", "top"].into_iter().collect(),
        "an unqualified file grew a qualifier"
    );
}
