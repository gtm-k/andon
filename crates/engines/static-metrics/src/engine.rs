//! The static family as a [`MeasureEngine`].
//!
//! # The seam: bytes in, facts out
//!
//! [`measure_blob`] takes a language and a slice of bytes and returns
//! [`FileFacts`]. Nothing in it knows about git, the working tree, or a change.
//! That is deliberate and it is where P5b plugs in: the compared lane hands it
//! blob bytes today, and the advisory lane can hand it working-tree bytes when
//! `andon measure` needs to report on a file that has not been committed — with
//! no change here and no new way for worktree bytes to reach a digest
//! (PREMORTEM T1).
//!
//! Everything above the seam — [`StaticMetricsEngine::for_change`] — is about
//! which bytes to fetch and what to do when there are none.
//!
//! # What counts as unmeasured
//!
//! `static.unmeasured-files` is the guard against a silent undercount (PREMORTEM
//! T3), so its definition has to be exactly the set that would otherwise vanish:
//! a path that is **present on the head side** of the change, is **not a
//! submodule pointer**, has an extension this engine **claims to measure**, and
//! still produced no numbers. Two ways in: the head blob was not readable — the
//! uncommitted-working-tree case, where P1 hands over no OID by construction —
//! or the bytes are not UTF-8.
//!
//! A deleted file is not unmeasured; there is nothing there to measure. A
//! markdown file is not unmeasured; this engine never claimed it. Widening the
//! count to either would turn a real signal into a number that is always large.
//!
//! # How many results this emits, and whose problem that is
//!
//! Every outermost function in every changed file gets three results. A change
//! touching one two-thousand-line module therefore produces a few hundred, and
//! the engine makes no attempt to rank or truncate them — deliberately. An
//! engine that decided which functions were worth reporting would be making a
//! policy decision without a policy, and the two consumers want opposite things:
//! the verifier needs **every** result, because a digest compare over a filtered
//! set is a compare an agent can duck by making its change large.
//!
//! So filtering lives downstream, where the budget is: P0's agent-mode profile
//! is a named schema view with an enforced token bound, and P5a's assembly is
//! what selects for it. Noted here as a P5a-entry consideration rather than
//! discovered there — the shape of a static payload on a large change is a fact
//! about this engine, and P5a should not have to find it out by measuring one.

use std::collections::BTreeMap;

use andon_core::date::Date;
use andon_core::engine::{
    EngineDescriptor, EngineError, MeasureContext, MeasureEngine, MetricDescriptor,
};
use andon_core::git::{BlobBatch, BlobError, ChangedEntry, ChangedSet, Git};
use andon_core::registry::{lint, parse_file, EngineRegistryFile, Registry};
use andon_core::schema::enums::{Completeness, EngineClass, EngineFamily, MetricClass, Severity};
use andon_core::schema::payload::{
    CacheState, EvidenceRef, Freshness, LineSpan, MeasurementResult, MetricValue, ResultScope,
    ScopeKind,
};
use andon_core::schema::regime::MeasurementRegime;

use crate::functions::functions;
use crate::health;
use crate::lang::{grammar_versions, Language, SPEC_REVISION};
use crate::metrics;
use crate::parse::{comment_ranges, ParseError, ParseHealth};
use crate::rustlex;
use crate::sloc::{sloc, sloc_range};

/// The shipped evidence registry, compiled in.
///
/// `include_str!` rather than a path read at runtime, for the reason P1.5
/// recorded (DEFERRED-APPROVALS E4): the verifier must resolve `deterministic`
/// and every claim from **its own** registry, never from a file a hostile
/// checkout could have moved. Binding it at build time removes the question.
const REGISTRY_TOML: &str = include_str!("../../../../registry/static.toml");

/// The engine could not read what it was asked to measure.
#[derive(Debug, thiserror::Error)]
pub enum StaticError {
    /// A blob read failed.
    #[error(transparent)]
    Blob(#[from] BlobError),
    /// The compiled-in registry does not parse or does not lint. A build-time
    /// bug, surfaced at runtime because `include_str!` cannot be validated
    /// earlier.
    #[error("the compiled-in static registry is invalid: {0}")]
    Registry(String),
    /// The system clock could not be read, so claim expiry cannot be evaluated.
    #[error(transparent)]
    Clock(#[from] andon_core::date::ClockError),
}

/// Everything measured from one blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFacts {
    /// Source lines in the whole file.
    pub sloc: u64,
    /// Parse health, or `None` for the tokenization tier, which has no parser
    /// and therefore no parse to report on.
    pub health: Option<ParseHealth>,
    /// One entry per outermost function, in source order.
    pub functions: Vec<FunctionFacts>,
}

/// Everything measured from one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionFacts {
    /// Class-qualified where a class is in scope.
    pub name: String,
    /// First line, 1-based inclusive.
    pub start_line: u32,
    /// Last line, 1-based inclusive.
    pub end_line: u32,
    /// Source lines in the function.
    pub sloc: u64,
    /// Cyclomatic complexity.
    pub cyclomatic: u64,
    /// Cognitive complexity.
    pub cognitive: u64,
}

/// Measure one blob. The seam: no git, no change, no worktree.
pub fn measure_blob(language: Language, bytes: &[u8]) -> Result<FileFacts, ParseError> {
    if !language.is_parsed() {
        // The tokenization tier. `health: None` rather than a zeroed
        // `ParseHealth`: there was no parse, and "zero parse errors" would be a
        // number about something that never happened.
        return Ok(FileFacts {
            sloc: sloc(bytes, &rustlex::comment_ranges(bytes)),
            health: None,
            functions: Vec::new(),
        });
    }

    let parsed = crate::parse::parse(language, bytes)?;
    let comments = comment_ranges(&parsed);
    let functions = functions(&parsed)
        .into_iter()
        .map(|site| FunctionFacts {
            sloc: sloc_range(
                bytes,
                &comments,
                site.node.start_byte(),
                site.node.end_byte(),
            ),
            cyclomatic: crate::cyclomatic::complexity(&parsed, site.node),
            cognitive: crate::cognitive::complexity(&parsed, site.node),
            name: site.name,
            start_line: site.start_line,
            end_line: site.end_line,
        })
        .collect();

    Ok(FileFacts {
        sloc: sloc(bytes, &comments),
        health: Some(parsed.health),
        functions,
    })
}

/// One changed file, measured on both sides where both exist.
#[derive(Debug, Clone)]
struct FileMeasurement {
    path: String,
    blob_oid: String,
    language: Language,
    head: FileFacts,
    /// The base side, when the base has this path in the same language.
    base: Option<FileFacts>,
}

/// The static engine, holding what it read.
///
/// Content access happens in [`StaticMetricsEngine::for_change`] rather than in
/// `measure`, because P0's [`MeasureContext`] carries no content handle. The
/// spike did the same; widening the context belongs to a phase that owns
/// `crates/andon-core`.
#[derive(Debug, Clone)]
pub struct StaticMetricsEngine {
    version: String,
    files: Vec<FileMeasurement>,
    unmeasured_files: u64,
}

impl StaticMetricsEngine {
    /// Read and measure every changed file the static family covers.
    ///
    /// One `cat-file --batch` for every blob on both sides, opened only when
    /// there is something to read: starting the process to read nothing costs
    /// around ninety milliseconds on Windows, a tenth of the warm budget.
    pub fn for_change(
        git: &Git,
        changed: &ChangedSet,
        engine_version: &str,
    ) -> Result<Self, StaticError> {
        let candidates: Vec<(&ChangedEntry, Language)> = changed
            .entries
            .iter()
            .filter(|entry| !entry.is_gitlink() && entry.dst_mode.is_some())
            .filter_map(|entry| Language::for_path(&entry.path).map(|language| (entry, language)))
            .collect();

        let mut files = Vec::new();
        let mut unmeasured_files = 0u64;

        if !candidates.is_empty() {
            let mut batch = BlobBatch::open(git).map_err(BlobError::from)?;
            for (entry, language) in candidates {
                let Some(oid) = entry.readable_blob() else {
                    // Present in the change, and its bytes are not in the object
                    // database — the uncommitted working-tree case. Counted, not
                    // guessed at.
                    unmeasured_files += 1;
                    continue;
                };
                let head_bytes = batch.read(oid)?;
                let head = match measure_blob(language, head_bytes.bytes()) {
                    Ok(facts) => facts,
                    // Not source this engine can read. Visible as a count rather
                    // than as an absence.
                    Err(_) => {
                        unmeasured_files += 1;
                        continue;
                    }
                };

                // The base side, for the file-scope deltas. A rename that also
                // changes language has no comparable base: the number would be a
                // delta between two different measurements.
                let base = match base_side(entry) {
                    Some((base_oid, base_language)) if base_language == language => {
                        let bytes = batch.read(base_oid)?;
                        measure_blob(language, bytes.bytes()).ok()
                    }
                    _ => None,
                };

                files.push(FileMeasurement {
                    path: entry.path.clone(),
                    blob_oid: oid.to_string(),
                    language,
                    head,
                    base,
                });
            }
        }

        // Sorted so the emitted order is a property of the data rather than of
        // enumeration. Pairing is by `(metric_id, scope)`, so order cannot change
        // a verdict — but an engine whose output order drifts is an engine whose
        // diffs are unreadable, and unreadable diffs are where a real change
        // hides.
        files.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(StaticMetricsEngine {
            version: engine_version.to_string(),
            files,
            unmeasured_files,
        })
    }

    /// How many changed files produced no measurement.
    pub fn unmeasured_files(&self) -> u64 {
        self.unmeasured_files
    }
}

/// The base-side blob and the language it should be read as.
///
/// Mirrors [`ChangedEntry::readable_blob`] for the source side: a gitlink OID
/// names a commit in another repository, and a null OID names nothing. The
/// language comes from `old_path` where there is one, because a rename measures
/// the file it came from.
fn base_side(entry: &ChangedEntry) -> Option<(&str, Language)> {
    if entry.is_gitlink() {
        return None;
    }
    let oid = entry
        .src_oid
        .as_deref()
        .filter(|oid| !oid.bytes().all(|b| b == b'0'))?;
    let path = entry.old_path.as_deref().unwrap_or(&entry.path);
    Some((oid, Language::for_path(path)?))
}

/// The compiled-in registry file, parsed once.
pub fn registry_file() -> Result<&'static EngineRegistryFile, StaticError> {
    static PARSED: std::sync::OnceLock<Result<EngineRegistryFile, String>> =
        std::sync::OnceLock::new();
    PARSED
        .get_or_init(|| {
            parse_file("registry/static.toml", REGISTRY_TOML).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| StaticError::Registry(e.clone()))
}

/// The engine's claims, resolved against a run date.
///
/// Linting at load is not ceremony: the drift check in `Registry::check_engine`
/// compares the file against compiled descriptors, and a file that failed to
/// parse would make that check vacuous.
pub fn registry(as_of: Date) -> Result<Registry, StaticError> {
    let file = registry_file()?;
    let files = vec![("registry/static.toml".to_string(), file.clone())];
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
        return Err(StaticError::Registry(messages.join("; ")));
    }
    Ok(registry)
}

impl MeasureEngine for StaticMetricsEngine {
    fn descriptor(&self) -> EngineDescriptor {
        EngineDescriptor {
            engine_id: metrics::ENGINE_ID.to_string(),
            family: EngineFamily::Static,
            // Blobs are read and bytes are parsed. Nothing here executes
            // repository code, and the class says so at the trait boundary
            // rather than in a comment (Codex #19).
            class: EngineClass::StaticSafe,
            version: self.version.clone(),
        }
    }

    fn metrics(&self) -> Vec<MetricDescriptor> {
        metrics::descriptors()
    }

    fn regime(&self) -> MeasurementRegime {
        MeasurementRegime::Static {
            engine_version: self.version.clone(),
            spec_revision: SPEC_REVISION.to_string(),
            grammars: grammar_versions(),
        }
    }

    fn measure(&self, ctx: &MeasureContext) -> Result<Vec<MeasurementResult>, EngineError> {
        let failed = |reason: String| EngineError::Failed {
            engine_id: metrics::ENGINE_ID.to_string(),
            reason,
        };
        let as_of = Date::today_utc().map_err(|e| failed(e.to_string()))?;
        let registry = registry(as_of).map_err(|e| failed(e.to_string()))?;
        let descriptors = metrics::descriptors();
        let _ = ctx;

        let evidence_of = |metric_id: &str| -> Result<(MetricClass, EvidenceRef), EngineError> {
            let descriptor = descriptors
                .iter()
                .find(|d| d.metric_id == metric_id)
                .ok_or_else(|| failed(format!("metric '{metric_id}' has no descriptor")))?;
            let claim = registry.claims.get(&descriptor.claim_id).ok_or_else(|| {
                failed(format!(
                    "claim '{}' for metric '{metric_id}' is not in the registry",
                    descriptor.claim_id
                ))
            })?;
            Ok((descriptor.class, claim.to_evidence_ref()))
        };

        let mut results = Vec::new();

        // Change scope. Emitted even at zero: a count that disappears when it is
        // zero is indistinguishable from an engine that stopped counting.
        results.push(self.result(
            metrics::METRIC_UNMEASURED_FILES,
            ResultScope {
                kind: ScopeKind::Change,
                path: None,
                blob_oid: None,
                symbol: None,
                line_span: None,
            },
            MetricValue::Count(self.unmeasured_files),
            None,
            evidence_of(metrics::METRIC_UNMEASURED_FILES)?,
        ));

        for file in &self.files {
            let file_scope = || ResultScope {
                kind: ScopeKind::File,
                path: Some(file.path.clone()),
                // The blob the numbers came from, named on the wire. A reader who
                // doubts a digest can fetch exactly these bytes.
                blob_oid: Some(file.blob_oid.clone()),
                symbol: None,
                line_span: None,
            };
            let degraded = file.head.health.filter(|health| health.is_degraded());

            let mut sloc_result = self.result(
                metrics::METRIC_SLOC,
                file_scope(),
                MetricValue::Count(file.head.sloc),
                file.base
                    .as_ref()
                    .map(|base| MetricValue::Integer(file.head.sloc as i64 - base.sloc as i64)),
                evidence_of(metrics::METRIC_SLOC)?,
            );
            if let Some(health) = degraded {
                health::demote(&mut sloc_result, health);
            }
            results.push(sloc_result);

            if let Some(health) = file.head.health {
                // Parse health is NOT demoted — see `crate::health`. Counting
                // ERROR nodes over a tree full of them is exact, and capping it
                // would silence the signal T3 wants loud.
                let base_health = file.base.as_ref().and_then(|base| base.health);
                results.push(self.result(
                    metrics::METRIC_PARSE_ERRORS,
                    file_scope(),
                    MetricValue::Count(health.error_nodes),
                    base_health.map(|base| {
                        MetricValue::Integer(health.error_nodes as i64 - base.error_nodes as i64)
                    }),
                    evidence_of(metrics::METRIC_PARSE_ERRORS)?,
                ));
                results.push(self.result(
                    metrics::METRIC_PARSE_MISSING,
                    file_scope(),
                    MetricValue::Count(health.missing_nodes),
                    base_health.map(|base| {
                        MetricValue::Integer(
                            health.missing_nodes as i64 - base.missing_nodes as i64,
                        )
                    }),
                    evidence_of(metrics::METRIC_PARSE_MISSING)?,
                ));
            }

            for function in &file.head.functions {
                let scope = || ResultScope {
                    kind: ScopeKind::Function,
                    path: Some(file.path.clone()),
                    blob_oid: Some(file.blob_oid.clone()),
                    symbol: Some(function.name.clone()),
                    line_span: Some(LineSpan {
                        start: function.start_line,
                        end: function.end_line,
                    }),
                };
                // No function-scope deltas. Matching a function across two
                // revisions needs an identity — a name that may have changed, a
                // position that certainly has — and inventing one would attach a
                // delta to a comparison nobody made.
                for (metric_id, value) in [
                    (metrics::METRIC_SLOC.to_string(), function.sloc),
                    (
                        metrics::cyclomatic_metric_id(file.language),
                        function.cyclomatic,
                    ),
                    (
                        metrics::cognitive_metric_id(file.language),
                        function.cognitive,
                    ),
                ] {
                    let mut result = self.result(
                        &metric_id,
                        scope(),
                        MetricValue::Count(value),
                        None,
                        evidence_of(&metric_id)?,
                    );
                    if let Some(health) = degraded {
                        health::demote(&mut result, health);
                    }
                    results.push(result);
                }
            }
        }
        Ok(results)
    }
}

impl StaticMetricsEngine {
    fn result(
        &self,
        metric_id: &str,
        scope: ResultScope,
        value: MetricValue,
        delta: Option<MetricValue>,
        (metric_class, evidence): (MetricClass, EvidenceRef),
    ) -> MeasurementResult {
        MeasurementResult {
            metric_id: metric_id.to_string(),
            claim_id: evidence.claim_id.clone(),
            engine_id: metrics::ENGINE_ID.to_string(),
            family: EngineFamily::Static,
            engine_class: EngineClass::StaticSafe,
            metric_class,
            scope,
            value,
            delta,
            // The engine reports facts; policy decides how serious they are, and
            // the policy that counts is the verifier's — which is why `severity`
            // is outside the digest input. `Info` is the honest floor for a
            // number nobody has evaluated yet. `crate::health::severity_ceiling`
            // is the bound P5a must respect when it does.
            severity: Severity::Info,
            completeness: Completeness::Complete,
            measurement_regime: self.regime(),
            evidence,
            deterministic: true,
            // Filled by `MeasurementResult::seal`, which `run_engine` calls.
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

/// Grammar and spec versions as a flat map, for the corpus baseline.
///
/// The same tuple the regime carries, plus `spec_revision`, so a recorded
/// baseline can assert it was taken under the configuration in force.
pub fn regime_stamp() -> BTreeMap<String, String> {
    let mut stamp = grammar_versions();
    stamp.insert("spec_revision".to_string(), SPEC_REVISION.to_string());
    stamp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_compiled_registry_parses_and_lints() {
        let as_of: Date = "2026-08-17".parse().expect("a valid date");
        let registry = registry(as_of).expect("the compiled registry must lint clean");
        assert_eq!(registry.metrics.len(), metrics::descriptors().len());
        assert_eq!(registry.claims.len(), 8, "the P2 share of the budget of 24");
    }

    #[test]
    fn the_engine_and_its_registry_file_do_not_drift() {
        let engine = StaticMetricsEngine {
            version: "0.1.0".to_string(),
            files: Vec::new(),
            unmeasured_files: 0,
        };
        Registry::check_engine(registry_file().expect("parses"), &engine)
            .expect("the engine and its registry file must not drift");
    }

    #[test]
    fn the_regime_carries_every_grammar_and_the_spec_revision() {
        let engine = StaticMetricsEngine {
            version: "0.1.0".to_string(),
            files: Vec::new(),
            unmeasured_files: 0,
        };
        match engine.regime() {
            MeasurementRegime::Static {
                engine_version,
                spec_revision,
                grammars,
            } => {
                assert_eq!(engine_version, "0.1.0");
                assert_eq!(spec_revision, SPEC_REVISION);
                assert_eq!(grammars, grammar_versions());
                assert!(grammars.contains_key("tree-sitter"));
            }
            other => panic!("the static engine has a static regime, got {other:?}"),
        }
    }

    #[test]
    fn the_regime_carries_no_git_version() {
        // Load-bearing for the matrix, exactly as it was for the spike: three
        // runners ship three gits, and a git version in the regime would make
        // every leg mutually skewed and the digest compare would never run.
        let engine = StaticMetricsEngine {
            version: "0.1.0".to_string(),
            files: Vec::new(),
            unmeasured_files: 0,
        };
        let json = serde_json::to_string(&engine.regime()).expect("regimes serialize");
        assert!(!json.contains("git_version"), "{json}");
    }

    #[test]
    fn the_tokenization_tier_reports_no_parse_health() {
        let facts = measure_blob(Language::Rust, b"// c\nfn main() {}\n").expect("scans");
        assert_eq!(facts.sloc, 1);
        assert_eq!(facts.health, None, "there was no parse to report on");
        assert!(facts.functions.is_empty());
    }

    #[test]
    fn a_parsed_file_yields_functions_and_health() {
        let facts = measure_blob(
            Language::Python,
            b"# c\ndef f(a):\n    if a:\n        return 1\n    return 2\n",
        )
        .expect("parses");
        assert_eq!(facts.sloc, 4);
        assert_eq!(
            facts.health,
            Some(ParseHealth {
                error_nodes: 0,
                missing_nodes: 0,
                total_nodes: facts.health.expect("health").total_nodes,
            })
        );
        assert_eq!(facts.functions.len(), 1);
        assert_eq!(facts.functions[0].cyclomatic, 2);
        assert_eq!(facts.functions[0].cognitive, 1);
    }

    #[test]
    fn a_non_utf8_blob_is_refused_by_the_seam() {
        assert!(matches!(
            measure_blob(Language::TypeScript, b"const a = \"\xff\";"),
            Err(ParseError::NotUtf8 { .. })
        ));
    }
}
