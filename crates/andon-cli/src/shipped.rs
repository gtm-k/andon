//! The roster: every engine this build ships, and the three things a surface
//! needs to ask each one.
//!
//! # Why this table exists
//!
//! P5b inherits an entry note from P5a: *"the `shipped_ladders()` roster is
//! hand-written in three places — a sixth engine joins none of them silently"*,
//! filed as E19's recorded lesson recurring in a different medium. The lesson is
//! that anything kept in sync by hand eventually is not, and the fix is always
//! the same shape: state it once, and bind the statement to something that
//! cannot be edited independently.
//!
//! So the binary has exactly one roster — [`SHIPPED`] — and the test
//! `the_roster_is_the_registry_the_binary_compiles_in` below asserts its ids
//! equal the `engine =` headers of the registry files those same crates compile
//! in. An engine added to the registry and not to this table reddens; a table
//! entry for an engine with no registry reddens. The roster cannot silently
//! disagree with the deployment.
//!
//! # What it deliberately does not include
//!
//! `spike-size`, from `andon-ledger-min`. It is the P1.5 trust spike: it
//! declares `NoOpinion` throughout, its registry lives inside its own crate
//! rather than in `registry/`, and it reports the `static` family — so including
//! it would let a spike result stand in for the production static engine's in
//! any family-keyed reading. `payload::prepare` would refuse it as an
//! `UnknownEngine` regardless; the reason is recorded here so the omission reads
//! as a decision rather than an oversight.

use std::collections::BTreeMap;

use andon_core::engine::MetricDescriptor;
use andon_core::registry::EngineRegistryFile;
use andon_core::verdict::ladder::SeverityLadder;

/// One engine, and the three questions a surface asks it without a repository.
pub struct ShippedEngine {
    /// Stable engine id. Matches the `engine =` header of its registry file.
    pub engine_id: &'static str,
    /// The registry the crate compiles into itself.
    pub registry_file: fn() -> Result<&'static EngineRegistryFile, String>,
    /// Every metric it can emit.
    pub metrics: fn() -> Vec<MetricDescriptor>,
    /// How each of those metrics' numbers become a pre-policy severity.
    pub ladders: fn() -> BTreeMap<String, SeverityLadder>,
}

/// Every engine this build ships. The one roster.
pub const SHIPPED: &[ShippedEngine] = &[
    ShippedEngine {
        engine_id: "static-metrics",
        registry_file: static_registry,
        metrics: andon_static_metrics::metrics::descriptors,
        ladders: andon_static_metrics::metrics::severity_ladders,
    },
    ShippedEngine {
        engine_id: "clones",
        registry_file: clones_registry,
        metrics: andon_engine_clones::engine::metric_descriptors,
        ladders: andon_engine_clones::engine::severity_ladders,
    },
    ShippedEngine {
        engine_id: "tamper",
        registry_file: tamper_registry,
        metrics: andon_engine_tamper::engine::metric_descriptors,
        ladders: andon_engine_tamper::engine::severity_ladders,
    },
    ShippedEngine {
        engine_id: "process",
        registry_file: process_registry,
        metrics: andon_engine_process::engine::metric_descriptors,
        ladders: andon_engine_process::engine::severity_ladders,
    },
    ShippedEngine {
        engine_id: "artifacts",
        registry_file: artifacts_registry,
        metrics: andon_engine_artifacts::engine::metric_descriptors,
        ladders: andon_engine_artifacts::engine::severity_ladders,
    },
    // The code-exec lane's occupant (P7). On the roster because the binary
    // carries it — the roster describes the deployment — while whether a given
    // MEASUREMENT expects it is policy's call, decided in one place:
    // `andon_core::payload::expected_engines`. A repository that never enables
    // `[sandbox]` gets payloads identical to a build without this entry.
    ShippedEngine {
        engine_id: "tests",
        registry_file: andon_sandbox::engine::registry_file,
        metrics: andon_sandbox::engine::metric_descriptors,
        ladders: andon_sandbox::engine::severity_ladders,
    },
];

/// The engine that declares `metric_id`, and its ladder for it.
pub fn engine_for_metric(metric_id: &str) -> Option<(&'static ShippedEngine, MetricDescriptor)> {
    SHIPPED.iter().find_map(|engine| {
        (engine.metrics)()
            .into_iter()
            .find(|d| d.metric_id == metric_id)
            .map(|descriptor| (engine, descriptor))
    })
}

/// The ladder declared for `metric_id`, if this build declares one.
pub fn ladder_for(metric_id: &str) -> Option<SeverityLadder> {
    SHIPPED
        .iter()
        .find_map(|engine| (engine.ladders)().get(metric_id).copied())
}

/// Every metric id this build can emit, sorted.
pub fn all_metric_ids() -> Vec<String> {
    let mut ids: Vec<String> = SHIPPED
        .iter()
        .flat_map(|engine| (engine.metrics)())
        .map(|d| d.metric_id)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

// Thin adapters, one per crate. Each engine's registry accessor carries its own
// error type, and a `fn` pointer needs one signature; flattening to `String`
// here keeps the table a table rather than a match.
fn static_registry() -> Result<&'static EngineRegistryFile, String> {
    andon_static_metrics::engine::registry_file().map_err(|e| e.to_string())
}
fn clones_registry() -> Result<&'static EngineRegistryFile, String> {
    andon_engine_clones::engine::registry_file().map_err(|e| e.to_string())
}
fn tamper_registry() -> Result<&'static EngineRegistryFile, String> {
    andon_engine_tamper::engine::registry_file().map_err(|e| e.to_string())
}
fn process_registry() -> Result<&'static EngineRegistryFile, String> {
    andon_engine_process::engine::registry_file().map_err(|e| e.to_string())
}
fn artifacts_registry() -> Result<&'static EngineRegistryFile, String> {
    andon_engine_artifacts::engine::registry_file().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_roster_is_the_registry_the_binary_compiles_in() {
        // The guard the entry note asks for. A sixth engine that lands a
        // registry file and not a table entry reddens here, and so does a table
        // entry whose crate ships no registry — so the roster and the
        // deployment cannot drift apart without a red test.
        let listed: BTreeSet<&str> = SHIPPED.iter().map(|e| e.engine_id).collect();
        let declared: BTreeSet<String> = SHIPPED
            .iter()
            .map(|e| {
                (e.registry_file)()
                    .unwrap_or_else(|err| panic!("{} ships no registry: {err}", e.engine_id))
                    .engine
                    .clone()
            })
            .collect();
        let listed_owned: BTreeSet<String> = listed.iter().map(|s| s.to_string()).collect();
        assert_eq!(listed_owned, declared);
    }

    #[test]
    fn every_metric_the_roster_names_declares_a_ladder() {
        // The same rule `run_engine` enforces at measurement time, asked here so
        // that a metric added without a ladder fails a test rather than one
        // engine's whole run.
        for engine in SHIPPED {
            let ladders = (engine.ladders)();
            for descriptor in (engine.metrics)() {
                assert!(
                    ladders.contains_key(&descriptor.metric_id),
                    "{} declares {} with no severity ladder",
                    engine.engine_id,
                    descriptor.metric_id
                );
            }
        }
    }

    #[test]
    fn the_registry_a_crate_compiles_in_declares_the_metrics_it_emits() {
        for engine in SHIPPED {
            let file = (engine.registry_file)().expect("a registry");
            let declared: BTreeSet<&str> =
                file.metrics.iter().map(|m| m.metric_id.as_str()).collect();
            let emitted: BTreeSet<String> = (engine.metrics)()
                .into_iter()
                .map(|d| d.metric_id)
                .collect();
            let emitted_refs: BTreeSet<&str> = emitted.iter().map(|s| s.as_str()).collect();
            assert_eq!(declared, emitted_refs, "{}", engine.engine_id);
        }
    }

    #[test]
    fn the_trust_spike_is_not_on_the_roster() {
        // Recorded as a decision rather than left as an absence somebody might
        // read as a bug. `spike-size` shares the `static` family with the
        // production engine and would stand in for it in any family-keyed view.
        assert!(!SHIPPED.iter().any(|e| e.engine_id == "spike-size"));
    }
}
