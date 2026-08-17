//! The `MeasureEngine` implementation: from a change to sealed results.
//!
//! # Where the bytes come in
//!
//! `MeasureContext` carries paths, policy, and the compare tuple, and no
//! content — P0 wrote it thin and said so, leaving content access to a later
//! widening. Three engine phases run in the same wave and cannot all widen one
//! P0-owned type, so the content arrives through the engine's own constructor
//! instead: [`ClonesEngine::for_change`] reads head blobs and holds them, and
//! `measure` uses the context for everything else. The seam is P5a's to
//! consolidate when it assembles all five engines and can see the shape the
//! trait actually needs.
//!
//! # Every compared byte is a blob byte
//!
//! [`ClonesEngine::for_change`] reads through `ChangedSet::read_head_blobs`,
//! which takes OIDs. A worktree read cannot reach a fingerprint from here, which
//! is the whole cross-OS argument for the clone digests (PREMORTEM T1): a file
//! committed with CRLF tokenizes identically on Windows and Linux because both
//! read the same blob.
//!
//! # What is deliberately not measured
//!
//! Nothing about the index reaches a result. Whether an entry was reused, how
//! many were, whether the index existed at all — each is a fact about this
//! machine's cache rather than about the change, and PLAN P3 admits only
//! cold-reproducible values to the compare set. They are reported through
//! [`ClonesEngine::index_state`] for diagnostics and stop there.

use std::path::{Path, PathBuf};

use andon_core::date::Date;
use andon_core::engine::{
    EngineDescriptor, EngineError, MeasureContext, MeasureEngine, MetricDescriptor,
};
use andon_core::git::{ChangedSet, ContentOrigin, Git};
use andon_core::registry::{lint, parse_file, EngineRegistryFile, Registry};
use andon_core::schema::enums::{Completeness, EngineClass, EngineFamily, Severity};
use andon_core::schema::payload::{
    CacheState, EvidenceRef, Freshness, MeasurementResult, MetricValue, ResultScope, ScopeKind,
};
use andon_core::schema::regime::MeasurementRegime;
use std::sync::OnceLock;

use crate::detect::{self, CloneReport};
use crate::fingerprint;
use crate::index::{FileInput, Index, IndexError, IndexLock};
use crate::syntax;

/// The engine id. Equals the registry file stem, which `check_engine` asserts.
pub const ENGINE_ID: &str = "clones";

/// Tokens covered by a clone, across the measured set.
pub const METRIC_DUPLICATED_TOKENS: &str = "clones.duplicated-tokens";
/// Duplicated tokens as a proportion of the measured set.
pub const METRIC_DUPLICATED_RATIO: &str = "clones.duplicated-token-ratio";
/// Duplicated tokens in one file.
pub const METRIC_FILE_DUPLICATED_TOKENS: &str = "clones.file-duplicated-tokens";
/// Distinct duplicated sequences.
pub const METRIC_CLONE_GROUPS: &str = "clones.clone-groups";
/// Length of the longest clone.
pub const METRIC_LARGEST_CLONE: &str = "clones.largest-clone-tokens";

/// The registry, compiled in rather than read from disk.
///
/// Same reason as the spike's (DEFERRED-APPROVALS E4): the `deterministic` flag
/// that decides compare-set membership must come from the reader's own build,
/// never from a file a hostile checkout could have moved. `include_str!` binds
/// it at build time.
const REGISTRY_TOML: &str = include_str!("../../../../registry/clones.toml");

/// Anything that stopped the engine from measuring.
#[derive(Debug, thiserror::Error)]
pub enum CloneEngineError {
    /// Reading head blobs failed.
    #[error(transparent)]
    Blob(#[from] andon_core::git::BlobError),
    /// The index could not be read or written.
    #[error(transparent)]
    Index(#[from] IndexError),
    /// The compiled-in registry does not parse or does not lint. A build-time
    /// bug surfaced at runtime, because `include_str!` checks only existence.
    #[error("the compiled-in clones registry is invalid: {0}")]
    Registry(String),
    /// The clock could not be read, so claim expiry cannot be evaluated.
    #[error(transparent)]
    Clock(#[from] andon_core::date::ClockError),
}

/// The compiled-in registry file, parsed once.
pub fn registry_file() -> Result<&'static EngineRegistryFile, CloneEngineError> {
    static PARSED: OnceLock<Result<EngineRegistryFile, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| parse_file("clones.toml", REGISTRY_TOML).map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| CloneEngineError::Registry(e.clone()))
}

/// The engine's claims, resolved against `as_of`.
pub fn registry(as_of: Date) -> Result<Registry, CloneEngineError> {
    let files = vec![("clones.toml".to_string(), registry_file()?.clone())];
    let (registry, report) = lint(
        &files,
        &andon_core::policy::RegistryPolicy::default(),
        as_of,
    );
    if report.failed() {
        let messages: Vec<String> = report
            .errors()
            .map(|d| format!("{}: {}", d.code, d.message))
            .collect();
        return Err(CloneEngineError::Registry(messages.join("; ")));
    }
    Ok(registry)
}

/// Every metric this engine emits.
pub fn metric_descriptors() -> Vec<MetricDescriptor> {
    [
        METRIC_DUPLICATED_TOKENS,
        METRIC_DUPLICATED_RATIO,
        METRIC_FILE_DUPLICATED_TOKENS,
        METRIC_CLONE_GROUPS,
        METRIC_LARGEST_CLONE,
    ]
    .iter()
    .map(|metric_id| {
        let decl = registry_file()
            .expect("the compiled registry parses")
            .metrics
            .iter()
            .find(|m| m.metric_id == *metric_id)
            .unwrap_or_else(|| panic!("{metric_id} is declared in registry/clones.toml"));
        MetricDescriptor {
            metric_id: decl.metric_id.clone(),
            claim_id: decl.claim_id.clone(),
            class: decl.class,
            deterministic: decl.deterministic,
        }
    })
    .collect()
}

/// The clone-detection engine, holding the content it measured.
#[derive(Debug, Clone)]
pub struct ClonesEngine {
    report: CloneReport,
    blob_by_path: std::collections::BTreeMap<String, String>,
    index_state: &'static str,
    index_reused: usize,
}

impl ClonesEngine {
    /// Measure a resolved change.
    ///
    /// `index_path` is where the incremental index lives. `None` runs cold —
    /// correct, slower, and the right default for a caller with nowhere durable
    /// to put derived state. The results are the same either way, which is the
    /// property `tests/incremental_equivalence.rs` gates the phase on.
    pub fn for_change(
        git: &Git,
        changed: &ChangedSet,
        index_path: Option<&Path>,
    ) -> Result<Self, CloneEngineError> {
        let mut inputs = Vec::new();
        for (path, content) in changed.read_head_blobs(git)? {
            let ContentOrigin::Blob { oid } = content.origin().clone() else {
                // `read_head_blobs` only ever returns blob-origin content. The
                // arm exists so that a future widening of that function cannot
                // quietly route worktree bytes into a compared digest.
                continue;
            };
            inputs.push(FileInput {
                path,
                blob_oid: oid,
                source: content.into_bytes(),
            });
        }
        Self::for_files(inputs, index_path)
    }

    /// Measure an explicit file set. The seam the corpus harness and the probe
    /// binary use, and the one that keeps the detector testable without a
    /// repository.
    pub fn for_files(
        inputs: Vec<FileInput>,
        index_path: Option<&Path>,
    ) -> Result<Self, CloneEngineError> {
        let previous = match index_path {
            Some(path) => {
                let outcome = Index::load(path);
                let code = outcome.code();
                (outcome.index().unwrap_or_else(Index::empty), code)
            }
            None => (Index::empty(), "disabled"),
        };
        let (index, reused) = previous.0.update(&inputs);

        if let Some(path) = index_path {
            // The lock covers the write only. Two processes reading and
            // computing at once is harmless — they compute the same answer —
            // and holding a lock across the measurement would serialize work
            // that has no reason to be serial.
            let lock = IndexLock::acquire(path)?;
            index.store(path)?;
            drop(lock);
        }

        let paths: Vec<String> = inputs.iter().map(|i| i.path.clone()).collect();
        let report = detect::detect(&index, &paths);
        let blob_by_path = inputs
            .into_iter()
            .map(|input| (input.path, input.blob_oid))
            .collect();
        Ok(ClonesEngine {
            report,
            blob_by_path,
            index_state: previous.1,
            index_reused: reused,
        })
    }

    /// What happened to the index on this run: `loaded`, `absent`,
    /// `checksum-mismatch`, `regime-mismatch`, `version-mismatch`,
    /// `unreadable`, or `disabled`. Diagnostic only — never a measured value.
    pub fn index_state(&self) -> &'static str {
        self.index_state
    }

    /// How many entries were carried over rather than recomputed. Diagnostic
    /// only, for the same reason.
    pub fn index_reused(&self) -> usize {
        self.index_reused
    }

    /// The detection result behind the metrics.
    pub fn report(&self) -> &CloneReport {
        &self.report
    }
}

impl MeasureEngine for ClonesEngine {
    fn descriptor(&self) -> EngineDescriptor {
        EngineDescriptor {
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Clones,
            // Parsing is reading. Nothing here executes repository code, which
            // is what lets the engine run outside a sandbox (Codex #19).
            class: EngineClass::StaticSafe,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn metrics(&self) -> Vec<MetricDescriptor> {
        metric_descriptors()
    }

    fn regime(&self) -> MeasurementRegime {
        let (window_tokens, min_tokens) = detect::parameters();
        MeasurementRegime::Clones {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            algorithm: fingerprint::ALGORITHM.to_string(),
            min_tokens,
            window_tokens,
            // Carries the grammar pins — see `syntax::normalization_revision`.
            normalization_revision: syntax::normalization_revision(),
        }
    }

    fn measure(&self, ctx: &MeasureContext) -> Result<Vec<MeasurementResult>, EngineError> {
        let _ = ctx;
        let as_of = Date::today_utc().map_err(|e| EngineError::Failed {
            engine_id: ENGINE_ID.to_string(),
            reason: e.to_string(),
        })?;
        let registry = registry(as_of).map_err(|e| EngineError::Failed {
            engine_id: ENGINE_ID.to_string(),
            reason: e.to_string(),
        })?;
        let descriptors = metric_descriptors();
        let evidence_for = |metric_id: &str| -> EvidenceRef {
            let descriptor = descriptors
                .iter()
                .find(|d| d.metric_id == metric_id)
                .expect("every emitted metric has a descriptor");
            registry
                .claims
                .get(&descriptor.claim_id)
                .expect("the registry lint proved every claim resolves")
                .to_evidence_ref()
        };

        let change_scope = || ResultScope {
            kind: ScopeKind::Change,
            path: None,
            blob_oid: None,
            symbol: None,
            line_span: None,
        };

        // The four change-scoped metrics are emitted unconditionally, zeros
        // included. A metric that appears only when it is interesting makes the
        // compare set depend on the answer: two honest sides measuring a change
        // with no duplication would have nothing to compare, and "nothing
        // disagreed" would be indistinguishable from "nothing was checked"
        // (PLAN B4's matrix would go green on an empty table).
        let ratio = andon_core::schema::payload::quantize_ratio(self.report.duplicated_ratio())
            .map_err(|e| EngineError::Failed {
                engine_id: ENGINE_ID.to_string(),
                reason: e.to_string(),
            })?;
        let duplicated = self.report.duplicated_tokens();
        let mut results = vec![
            self.result(
                METRIC_DUPLICATED_TOKENS,
                change_scope(),
                MetricValue::Count(duplicated),
                severity_for(duplicated > 0),
                evidence_for(METRIC_DUPLICATED_TOKENS),
            ),
            self.result(
                METRIC_DUPLICATED_RATIO,
                change_scope(),
                MetricValue::Ratio(ratio),
                severity_for(duplicated > 0),
                evidence_for(METRIC_DUPLICATED_RATIO),
            ),
            self.result(
                METRIC_CLONE_GROUPS,
                change_scope(),
                MetricValue::Count(self.report.groups.len() as u64),
                severity_for(!self.report.groups.is_empty()),
                evidence_for(METRIC_CLONE_GROUPS),
            ),
            self.result(
                METRIC_LARGEST_CLONE,
                change_scope(),
                MetricValue::Count(self.report.largest_clone_tokens()),
                Severity::Info,
                evidence_for(METRIC_LARGEST_CLONE),
            ),
        ];

        // Per file, in path order — `tokens_by_path` is a `BTreeMap`, so the
        // order of these results is the sorted path order on every machine.
        for path in self.report.tokens_by_path.keys() {
            let duplicated = self
                .report
                .duplicated_tokens_by_path
                .get(path)
                .copied()
                .unwrap_or(0);
            results.push(self.result(
                METRIC_FILE_DUPLICATED_TOKENS,
                ResultScope {
                    kind: ScopeKind::File,
                    path: Some(path.clone()),
                    // The blob the tokens came from, named on the wire: a reader
                    // who doubts a digest can fetch exactly these bytes.
                    blob_oid: self.blob_by_path.get(path).cloned(),
                    symbol: None,
                    line_span: None,
                },
                MetricValue::Count(duplicated as u64),
                severity_for(duplicated > 0),
                evidence_for(METRIC_FILE_DUPLICATED_TOKENS),
            ));
        }
        Ok(results)
    }
}

/// Engine-side severity. Never above `Low`.
///
/// The engine knows what it found; policy decides what that is worth, from the
/// BASE commit, in the verifier. `severity` is outside the digest input for
/// exactly that reason, so nothing here can move a compare.
fn severity_for(found: bool) -> Severity {
    if found {
        Severity::Low
    } else {
        Severity::Info
    }
}

impl ClonesEngine {
    fn result(
        &self,
        metric_id: &str,
        scope: ResultScope,
        value: MetricValue,
        severity: Severity,
        evidence: EvidenceRef,
    ) -> MeasurementResult {
        let descriptor = metric_descriptors()
            .into_iter()
            .find(|d| d.metric_id == metric_id)
            .expect("every emitted metric has a descriptor");
        MeasurementResult {
            metric_id: metric_id.to_string(),
            claim_id: descriptor.claim_id,
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Clones,
            engine_class: EngineClass::StaticSafe,
            metric_class: descriptor.class,
            scope,
            value,
            // No base-side comparison in v1: a duplication delta needs the base
            // tree tokenized as well, which doubles the work for a number
            // nobody has asked for yet. Absent rather than zero — a zero here
            // would claim the base was measured.
            delta: None,
            severity,
            completeness: Completeness::Complete,
            measurement_regime: self.regime(),
            evidence,
            deterministic: descriptor.deterministic,
            digest: String::new(),
            freshness: Freshness {
                measured_at: String::new(),
                duration_ms: 0,
                lane: andon_core::schema::enums::Lane::Fast,
                cache: CacheState::Cold,
            },
        }
    }
}

/// Where the index lives by default, relative to a repository root.
///
/// A default and not a policy: the caller passes a path, and P5b's CLI is what
/// decides whether to use one at all. Named here so every caller spells it the
/// same way.
pub fn default_index_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".andon").join("clones-index")
}

#[cfg(test)]
mod tests {
    use super::*;
    use andon_core::engine::run_engine;
    use andon_core::policy::Policy;
    use andon_core::schema::payload::CompareContext;

    fn context() -> MeasureContext {
        MeasureContext {
            compare_context: CompareContext {
                base_oid: "0".repeat(40),
                head_oid: "1".repeat(40),
                git_version: "git version 2.51.0".to_string(),
                base_resolution: "explicit".to_string(),
            },
            policy: Policy::default(),
            changed_paths: Vec::new(),
            sandbox_available: false,
        }
    }

    fn input(path: &str, source: &str) -> FileInput {
        FileInput {
            path: path.to_string(),
            blob_oid: format!("{:040x}", syntax::fnv1a(source.as_bytes())),
            source: source.as_bytes().to_vec(),
        }
    }

    fn block(name: &str) -> String {
        format!(
            "export function {name}(items: number[], factor: number): number {{\n\
             \x20 let total = 0;\n\
             \x20 for (const item of items) {{\n\
             \x20   if (item > factor) {{ total += item * factor; }}\n\
             \x20   else {{ total -= item; }}\n\
             \x20 }}\n\
             \x20 return total;\n\
             }}\n"
        )
    }

    #[test]
    fn the_compiled_registry_parses_and_lints() {
        let as_of: Date = "2026-08-17".parse().expect("a valid date");
        let registry = registry(as_of).expect("the compiled registry must lint clean");
        assert_eq!(registry.metrics.len(), 5);
        assert_eq!(registry.claims.len(), 2);
    }

    #[test]
    fn the_engine_and_its_registry_do_not_drift() {
        let engine = ClonesEngine::for_files(Vec::new(), None).unwrap();
        Registry::check_engine(registry_file().unwrap(), &engine)
            .unwrap_or_else(|problems| panic!("{}", problems.join("\n")));
    }

    #[test]
    fn every_change_scoped_metric_is_emitted_even_at_zero() {
        let engine = ClonesEngine::for_files(vec![input("a.ts", "const x = 1;\n")], None).unwrap();
        let results = run_engine(&engine, &context()).unwrap();
        for metric in [
            METRIC_DUPLICATED_TOKENS,
            METRIC_DUPLICATED_RATIO,
            METRIC_CLONE_GROUPS,
            METRIC_LARGEST_CLONE,
        ] {
            assert!(
                results.iter().any(|r| r.metric_id == metric),
                "{metric} missing from an empty result"
            );
        }
        assert!(results.iter().all(|r| !r.digest.is_empty()), "sealed");
    }

    #[test]
    fn a_clone_moves_the_numbers() {
        let engine = ClonesEngine::for_files(
            vec![input("a.ts", &block("one")), input("b.ts", &block("two"))],
            None,
        )
        .unwrap();
        let results = run_engine(&engine, &context()).unwrap();
        let groups = results
            .iter()
            .find(|r| r.metric_id == METRIC_CLONE_GROUPS)
            .unwrap();
        assert_eq!(groups.value, MetricValue::Count(1));
        // Two file-scoped results, both non-zero.
        let per_file: Vec<_> = results
            .iter()
            .filter(|r| r.metric_id == METRIC_FILE_DUPLICATED_TOKENS)
            .collect();
        assert_eq!(per_file.len(), 2);
        assert!(per_file
            .iter()
            .all(|r| !matches!(r.value, MetricValue::Count(0))));
    }

    #[test]
    fn a_file_scoped_result_names_the_blob_it_came_from() {
        let file = input("a.ts", &block("one"));
        let expected = file.blob_oid.clone();
        let engine = ClonesEngine::for_files(vec![file], None).unwrap();
        let results = run_engine(&engine, &context()).unwrap();
        let per_file = results
            .iter()
            .find(|r| r.metric_id == METRIC_FILE_DUPLICATED_TOKENS)
            .unwrap();
        assert_eq!(per_file.scope.blob_oid.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn the_regime_carries_the_grammar_pins() {
        let engine = ClonesEngine::for_files(Vec::new(), None).unwrap();
        let MeasurementRegime::Clones {
            normalization_revision,
            algorithm,
            min_tokens,
            window_tokens,
            ..
        } = engine.regime()
        else {
            panic!("the clones engine reports a clones regime");
        };
        assert_eq!(algorithm, "rabin-karp");
        assert_eq!(min_tokens, fingerprint::MIN_CLONE_TOKENS);
        assert_eq!(window_tokens, fingerprint::WINDOW_TOKENS);
        for (name, version) in syntax::GRAMMAR_PINS {
            assert!(normalization_revision.contains(&format!("{name}@{version}")));
        }
    }
}
