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
//! # A number over a file the parser did not finish is marked as one
//!
//! tree-sitter recovers from anything, so a half-understood file still
//! tokenizes and still yields a duplication figure — over less code than the
//! file contains. Since the wave-1 integration converged the grammar pins, the
//! same degraded input reaches this engine, the static engine, and the tamper
//! suite; the static engine has marked its numbers `parse-degraded` since P2,
//! and this one claimed `complete` on the identical file. That is not only a
//! false confidence, it is two engines disagreeing about a digest-bound field
//! (PREMORTEM T3, S4).
//!
//! So results are demoted through [`andon_core::parse_health`], the same
//! mechanism and the same prose the static engine uses: the per-file result of
//! a degraded file, and all four change-scoped results whenever *any* measured
//! file is degraded, because each of those four is computed over the set.
//! Severity is capped by the same call, and that cap now does real work: since
//! the mini-G2 ruling this engine's ladder reaches `High` on a change thick with
//! duplication, so a set the parser only partly read is capped back below the
//! MED+ band rather than arriving there on a lower-bound count.
//!
//! # What is deliberately not measured
//!
//! Nothing about the index reaches a result. Whether an entry was reused, how
//! many were, whether the index existed at all — each is a fact about this
//! machine's cache rather than about the change, and PLAN P3 admits only
//! cold-reproducible values to the compare set. They are reported through
//! [`ClonesEngine::index_state`] for diagnostics and stop there.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use andon_core::date::Date;
use andon_core::engine::{
    EngineDescriptor, EngineError, MeasureContext, MeasureEngine, MetricDescriptor,
};
use andon_core::git::{ChangedSet, ContentOrigin, Git};
use andon_core::parse_health::{self, ParseHealth};
use andon_core::registry::{lint, parse_file, EngineRegistryFile, Registry};
use andon_core::schema::enums::{Completeness, EngineClass, EngineFamily, Severity};
use andon_core::schema::payload::{
    CacheState, EvidenceRef, Freshness, LineSpan, MeasurementResult, MetricValue, ResultScope,
    ScopeKind,
};
use andon_core::schema::regime::MeasurementRegime;
use andon_core::verdict::ladder::SeverityLadder;
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

/// How each metric's own number becomes a pre-policy severity.
///
/// # Every rung here is project-declared, and the claim says why it has to be
///
/// `registry/clones.toml` is tier `N` and states it plainly: no study underlies
/// these numbers, and none of the clone literature establishes that removing a
/// given clone improves anything. So there is no published band to adopt, and
/// pretending otherwise would be the overstatement the registry exists to
/// prevent. What the rungs are anchored on instead is the detector's **own**
/// unit — `MIN_CLONE_TOKENS`, the 50-token fragment below which it reports
/// nothing at all — so the ladder says "one minimum clone", "five", "twenty",
/// which is a statement about this detector and not about software quality.
///
/// The floor is deliberately unchanged from what this engine shipped with: any
/// confirmed duplication at all is `Low`. What is new is that a change with
/// twenty minimum clones in it no longer reports the same strength as a change
/// with one.
///
/// Nothing here declares `Critical`. A tier-N count with no remediation evidence
/// behind it has not earned the top of the scale, and in the shipped
/// configuration it would never be seen anyway — `N` is outside the default
/// `med_plus_tiers`, so `andon_core::verdict::severity::apply` caps every result
/// from this engine at `Low` until an operator admits the tier. That cap is the
/// policy half doing its job, and it is not a reason for the engine half to
/// under-report: the verifier reads the same numbers under a different policy.
mod ladders {
    use super::*;
    use andon_core::verdict::ladder::{Rung, Threshold};

    /// One minimum-length clone fragment.
    const MIN_CLONE: u64 = fingerprint::MIN_CLONE_TOKENS as u64;

    /// Token counts: one minimum clone, five, twenty.
    const TOKENS: &[Rung] = &[
        Rung {
            at: Threshold::Count(1),
            severity: Severity::Low,
        },
        Rung {
            at: Threshold::Count(5 * MIN_CLONE),
            severity: Severity::Medium,
        },
        Rung {
            at: Threshold::Count(20 * MIN_CLONE),
            severity: Severity::High,
        },
    ];

    /// Distinct repeated sequences: one, five, twenty.
    const GROUPS: &[Rung] = &[
        Rung {
            at: Threshold::Count(1),
            severity: Severity::Low,
        },
        Rung {
            at: Threshold::Count(5),
            severity: Severity::Medium,
        },
        Rung {
            at: Threshold::Count(20),
            severity: Severity::High,
        },
    ];

    /// Duplicated proportion of the measured set. A twentieth, a fifth, two
    /// fifths — project-declared, and the only ladder here that is not anchored
    /// on the detector's own token unit, because a proportion has no such unit.
    const RATIO: &[Rung] = &[
        Rung {
            at: Threshold::Ratio(0.05),
            severity: Severity::Low,
        },
        Rung {
            at: Threshold::Ratio(0.20),
            severity: Severity::Medium,
        },
        Rung {
            at: Threshold::Ratio(0.40),
            severity: Severity::High,
        },
    ];

    /// The declaration `MeasureEngine::severity_ladders` returns.
    pub fn all() -> BTreeMap<String, SeverityLadder> {
        [
            (METRIC_DUPLICATED_TOKENS, SeverityLadder::Thresholds(TOKENS)),
            (METRIC_DUPLICATED_RATIO, SeverityLadder::Thresholds(RATIO)),
            (
                METRIC_FILE_DUPLICATED_TOKENS,
                SeverityLadder::Thresholds(TOKENS),
            ),
            (METRIC_CLONE_GROUPS, SeverityLadder::Thresholds(GROUPS)),
            // The longest single fragment. Ranked on the same token unit as the
            // totals: a 1000-token copy is one clone and is not a small finding.
            (METRIC_LARGEST_CLONE, SeverityLadder::Thresholds(TOKENS)),
        ]
        .into_iter()
        .map(|(id, ladder)| (id.to_string(), ladder))
        .collect()
    }
}

/// This engine's one severity declaration per metric.
///
/// Public alongside [`metric_descriptors`] and for the same reason: the pairing
/// of the two is a property of the engine, not of any measurement.
pub fn severity_ladders() -> BTreeMap<String, SeverityLadder> {
    ladders::all()
}

/// The clone-detection engine, holding the content it measured.
#[derive(Debug, Clone)]
pub struct ClonesEngine {
    report: CloneReport,
    blob_by_path: std::collections::BTreeMap<String, String>,
    health_by_path: std::collections::BTreeMap<String, ParseHealth>,
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
        // Read back off the index rather than off the inputs: the index is where
        // health lives, warm or cold, so a run that reused every entry marks the
        // same files degraded as a run that rebuilt them.
        let health_by_path = index
            .files
            .iter()
            .map(|(path, entry)| (path.clone(), entry.health))
            .collect();
        let blob_by_path = inputs
            .into_iter()
            .map(|input| (input.path, input.blob_oid))
            .collect();
        Ok(ClonesEngine {
            report,
            blob_by_path,
            health_by_path,
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

    /// How completely the parser read one measured file, or `None` when the file
    /// is not in the measured set.
    pub fn health_of(&self, path: &str) -> Option<ParseHealth> {
        self.health_by_path.get(path).copied()
    }

    /// The health of the measured set as a whole, with how many of its files
    /// were degraded.
    ///
    /// Returned as a triple rather than folded into one number because the
    /// change-scoped caveat needs all three, and because a merged `ParseHealth`
    /// on its own cannot say whether ten ERROR nodes were one bad file or ten.
    /// Where the longest clone is, for the result that reports its length.
    ///
    /// # A change-scoped number that is nonetheless about one place
    ///
    /// The other three change-scoped metrics are aggregates over the measured
    /// set and have no location: a duplicated-token total is about every file at
    /// once, and naming one of them would be picking a scapegoat. The longest
    /// clone is not an aggregate — it is a specific fragment — and it was the
    /// one number in this engine an agent could act on if only it said where.
    /// It shipped with `path: null` and `line_span: null` alongside the rest.
    ///
    /// So the kind stays `Change` (the *question* is still "what is the longest
    /// clone in this change") and the location is filled in. Deterministic: the
    /// groups are sorted longest-first and each group's fragments are sorted, so
    /// two machines name the same side of the same clone, which matters because
    /// `scope` is inside the per-result digest and is the pairing key.
    ///
    /// # What this cannot say, and where that goes
    ///
    /// A clone has at least two sides and `ResultScope` has room for one path.
    /// "Duplicated with `src/b.ts:12-40`" is what makes a duplication fixable,
    /// and it is computed and sitting in [`ClonesEngine::report`] — what is
    /// missing is a field to carry it. That is P0-owned schema, so this names
    /// one side and the twin is routed rather than crammed into `symbol`, which
    /// is typed as a function or class name and rendered as one.
    fn largest_clone_scope(&self) -> ResultScope {
        let Some(fragment) = self
            .report
            .groups
            .first()
            .and_then(|group| group.fragments.first())
        else {
            // No duplication found, so there is no longest clone and nothing to
            // point at. A location here would be a fabricated one.
            return ResultScope {
                kind: ScopeKind::Change,
                path: None,
                blob_oid: None,
                symbol: None,
                line_span: None,
            };
        };
        ResultScope {
            kind: ScopeKind::Change,
            path: Some(fragment.path.clone()),
            blob_oid: self.blob_by_path.get(&fragment.path).cloned(),
            symbol: None,
            line_span: Some(LineSpan {
                start: fragment.line_start,
                end: fragment.line_end,
            }),
        }
    }

    fn measured_set_health(&self) -> (ParseHealth, usize, usize) {
        let mut merged = ParseHealth::default();
        let mut degraded = 0usize;
        for health in self.health_by_path.values() {
            merged = merged.merge(*health);
            if health.is_degraded() {
                degraded += 1;
            }
        }
        (merged, degraded, self.health_by_path.len())
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

    fn severity_ladders(&self) -> BTreeMap<String, SeverityLadder> {
        severity_ladders()
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
                evidence_for(METRIC_DUPLICATED_TOKENS),
            ),
            self.result(
                METRIC_DUPLICATED_RATIO,
                change_scope(),
                MetricValue::Ratio(ratio),
                evidence_for(METRIC_DUPLICATED_RATIO),
            ),
            self.result(
                METRIC_CLONE_GROUPS,
                change_scope(),
                MetricValue::Count(self.report.groups.len() as u64),
                evidence_for(METRIC_CLONE_GROUPS),
            ),
            self.result(
                METRIC_LARGEST_CLONE,
                self.largest_clone_scope(),
                MetricValue::Count(self.report.largest_clone_tokens()),
                evidence_for(METRIC_LARGEST_CLONE),
            ),
        ];

        // Every one of the four is computed over the whole measured set, so one
        // file the parser did not finish reading makes all four numbers numbers
        // over less code than the change contains. The caveat names how many
        // files of how many, because "one of ninety" and "eighty of ninety" are
        // the same `parse-degraded` to the digest and very different things to
        // somebody deciding what to do about a duplication ratio.
        let (set_health, degraded_files, measured_files) = self.measured_set_health();
        if set_health.is_degraded() {
            let caveat = parse_health::caveat_over_set(set_health, degraded_files, measured_files);
            for result in &mut results {
                parse_health::demote_with_caveat(result, set_health, caveat.clone());
            }
        }

        // A bucket whose region walk hit `REGION_PAIR_BUDGET` was searched with
        // part of its candidate set never enumerated, and every change-scoped
        // number is taken over the whole set — so one sampled bucket makes all
        // four of them answers over less than they claim. Applied after the
        // parse demotion and never above it: `partial` lowers and does not
        // raise, so a set that was both unreadable and sampled keeps the
        // stronger caveat and gains this one.
        if !self.report.truncated_paths.is_empty() {
            let caveat = sampled_caveat(&self.report.truncated_paths);
            for result in &mut results {
                demote_to_partial(result, caveat.clone());
            }
        }

        // Per file, in path order — `tokens_by_path` is a `BTreeMap`, so the
        // order of these results is the sorted path order on every machine.
        for path in self.report.tokens_by_path.keys() {
            let duplicated = self
                .report
                .duplicated_tokens_by_path
                .get(path)
                .copied()
                .unwrap_or(0);
            let mut result = self.result(
                METRIC_FILE_DUPLICATED_TOKENS,
                ResultScope {
                    kind: ScopeKind::File,
                    path: Some(path.clone()),
                    // The blob the tokens came from, named on the wire: a reader
                    // who doubts a digest can fetch exactly these bytes.
                    blob_oid: self.blob_by_path.get(path).cloned(),
                    symbol: None,
                    // Where to start reading. A count with no location tells an
                    // agent that duplication happened and not where, which is
                    // one short of what it needs to act — see
                    // `CloneReport::duplicated_span_by_path` for why this is the
                    // longest unbroken stretch rather than the whole envelope.
                    // Absent, never a `1-1`, when the file holds no duplication.
                    line_span: self.report.duplicated_span_by_path.get(path).map(|range| {
                        LineSpan {
                            start: range.start,
                            end: range.end,
                        }
                    }),
                },
                MetricValue::Count(duplicated as u64),
                evidence_for(METRIC_FILE_DUPLICATED_TOKENS),
            );
            if let Some(health) = self
                .health_by_path
                .get(path)
                .copied()
                .filter(|health| health.is_degraded())
            {
                parse_health::demote(&mut result, health);
            }
            // Per file rather than for the whole set, because a per-file count
            // is a union over the matches confirmed *in that file* and a bucket
            // this engine sampled names the files it touched. Marking a file no
            // sampled bucket reached would be claiming a limitation the number
            // does not have.
            if self.report.truncated_paths.contains(path) {
                demote_to_partial(&mut result, sampled_caveat(&self.report.truncated_paths));
            }
            results.push(result);
        }
        Ok(results)
    }
}

impl ClonesEngine {
    fn result(
        &self,
        metric_id: &str,
        scope: ResultScope,
        value: MetricValue,
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
            // The floor, and the only value this constructor writes.
            // `andon_core::engine::run_engine` assigns the real pre-policy
            // severity from `ladders::all`, which is where this engine's one
            // declaration per metric lives.
            severity: Severity::Info,
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

/// The honesty line a result carries when a saturated bucket was sampled.
///
/// Names the files, for the same reason the parse caveat names how many of how
/// many: "one generated table was too repetitive to search exhaustively" and
/// "every file in this change was" are the same `partial` to the digest and
/// very different things to whoever has to decide what the duplication number
/// is worth.
fn sampled_caveat(paths: &std::collections::BTreeSet<String>) -> String {
    format!(
        "the whole of the duplication in {}: repetition dense enough there to \
         exceed this engine's pairing budget was searched by sampling the \
         regions rather than by walking them, so this number is the union of \
         what was confirmed and is a lower bound on what is there",
        paths.iter().cloned().collect::<Vec<_>>().join(", ")
    )
}

/// Mark a result as an answer over part of its subject.
///
/// The same demotion `andon_engine_tamper` applies to a detector that read its
/// own subject and could not rank it, for the same reason and with the same
/// three-way visibility: `Completeness::ParseDegraded` would be a false
/// statement here — the parser read every token — and `Partial` is the nearest
/// true value in P0's vocabulary.
///
/// Lowers and never raises, so a result that arrived weaker for another reason
/// keeps the weaker value; and caps severity through the same public ceiling
/// the parse path uses, so the two demotions cannot disagree about what an
/// incomplete answer is allowed to do.
fn demote_to_partial(result: &mut MeasurementResult, caveat: String) {
    if parse_health::weakness_rank(Completeness::Partial)
        < parse_health::weakness_rank(result.completeness)
    {
        result.completeness = Completeness::Partial;
    }
    result.severity = result
        .severity
        .min(parse_health::severity_ceiling(Completeness::Partial));
    if !result.evidence.does_not_predict.contains(&caveat) {
        result.evidence.does_not_predict.insert(0, caveat);
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
                head_kind: andon_core::schema::payload::HeadKind::Commit,
                base_resolution: "explicit".to_string(),
            },
            policy: Policy::default(),
            changed_paths: Vec::new(),
            sandbox: None,
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
        // One claim for five metrics: they are one measurement at three
        // granularities and two framings, and the wave allocation gives P3
        // seven tuples for both engines (orchestrator directive, 2026-08-17).
        assert_eq!(registry.claims.len(), 1);
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
    fn a_number_over_an_unparseable_file_says_so() {
        // The whole of PREMORTEM T3 in one assertion set: the same input that
        // makes the tamper suite's parse-error delta fire must not produce a
        // `complete` clone number on the file it fired about.
        let engine = ClonesEngine::for_files(
            vec![
                input("src/clean.ts", &block("one")),
                input("src/broken.ts", "export function f( { !!! \n"),
            ],
            None,
        )
        .unwrap();
        let results = run_engine(&engine, &context()).unwrap();

        let per_file = |path: &str| {
            results
                .iter()
                .find(|r| {
                    r.metric_id == METRIC_FILE_DUPLICATED_TOKENS
                        && r.scope.path.as_deref() == Some(path)
                })
                .unwrap_or_else(|| panic!("{path} has a result"))
        };
        let broken = per_file("src/broken.ts");
        assert_eq!(broken.completeness, Completeness::ParseDegraded);
        assert!(!broken.severity.is_med_plus());
        assert!(
            broken.evidence.does_not_predict[0]
                .contains(andon_core::parse_health::PARSE_DEGRADED_CAVEAT),
            "{:?}",
            broken.evidence.does_not_predict
        );

        // The clean file in the same change keeps its full-confidence claim.
        // Demotion follows the file, not the run.
        assert_eq!(
            per_file("src/clean.ts").completeness,
            Completeness::Complete
        );

        // The four change-scoped numbers are computed over both files, so they
        // are over a partial view and say which part.
        for metric in [
            METRIC_DUPLICATED_TOKENS,
            METRIC_DUPLICATED_RATIO,
            METRIC_CLONE_GROUPS,
            METRIC_LARGEST_CLONE,
        ] {
            let result = results.iter().find(|r| r.metric_id == metric).unwrap();
            assert_eq!(
                result.completeness,
                Completeness::ParseDegraded,
                "{metric} is computed over the whole measured set"
            );
            assert!(
                result.evidence.does_not_predict[0].contains("1 of 2 file(s)"),
                "{metric}: {:?}",
                result.evidence.does_not_predict
            );
        }
    }

    #[test]
    fn a_number_over_a_sampled_bucket_says_so() {
        // The other way this engine can answer over less than it claims, and
        // the parser is not involved in it. A file alternating a short row run
        // with an identical helper a hundred times puts four thousand
        // occurrences of one window hash against a hundred regions, which is
        // four times the pairing budget — so the region list is sampled, and a
        // sampled search is not a search of everywhere.
        //
        // What must not happen is the answer arriving as `complete`. That is
        // the shape of the defect this whole file's saturation work exists
        // about: a number that is a lower bound, stamped as the whole one.
        let mut source = String::from("export const t = [\n");
        for _ in 0..100 {
            let rows: Vec<String> = (0..20).map(|i| format!("  [{i}, {}],", i * 3)).collect();
            source.push_str(&rows.join("\n"));
            source.push('\n');
            source.push_str(&block("helper"));
        }
        source.push_str("];\n");
        let engine = ClonesEngine::for_files(
            vec![
                input("generated.ts", &source),
                input("plain.ts", "const x = 1;\n"),
            ],
            None,
        )
        .unwrap();
        let results = run_engine(&engine, &context()).unwrap();

        for result in &results {
            let sampled = result.scope.path.as_deref() != Some("plain.ts");
            if sampled {
                assert_eq!(
                    result.completeness,
                    Completeness::Partial,
                    "{} over a sampled bucket",
                    result.metric_id
                );
                assert!(
                    !result.severity.is_med_plus(),
                    "{} must not stop the line on an answer it cannot finish",
                    result.metric_id
                );
                assert!(
                    result.evidence.does_not_predict[0].contains("generated.ts"),
                    "{}: the caveat has to name the file, or a reader cannot \
                     tell which number to distrust: {:?}",
                    result.metric_id,
                    result.evidence.does_not_predict
                );
            } else {
                // Demotion follows the bucket, not the run: a file no sampled
                // bucket reached keeps its full-confidence claim.
                assert_eq!(
                    result.completeness,
                    Completeness::Complete,
                    "{} on a file the sampling never touched",
                    result.metric_id
                );
            }
        }
    }

    #[test]
    fn an_ordinary_generated_table_is_not_demoted_for_being_repetitive() {
        // The counterweight. The cap engages on any literal table worth the
        // name, and if `partial` arrived with it then every generated file in
        // every repository would carry a caveat, the caveat would mean nothing,
        // and thirty-three copies of a helper would buy a severity cap that
        // thirty-two do not. Only a bucket the engine actually sampled is
        // demoted.
        let rows: Vec<String> = (0..3000).map(|i| format!("  [{i}, {}],", i * i)).collect();
        let source = format!(
            "export function f(x: number) {{\n  const t = [\n{}\n  ];\n  return t[x];\n}}\n",
            rows.join("\n")
        );
        let engine = ClonesEngine::for_files(vec![input("table.ts", &source)], None).unwrap();
        let results = run_engine(&engine, &context()).unwrap();
        assert!(
            results
                .iter()
                .all(|r| r.completeness == Completeness::Complete),
            "{:?}",
            results
                .iter()
                .map(|r| (&r.metric_id, r.completeness))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_change_the_parser_read_completely_claims_so() {
        let engine = ClonesEngine::for_files(
            vec![input("a.ts", &block("one")), input("b.ts", &block("two"))],
            None,
        )
        .unwrap();
        let results = run_engine(&engine, &context()).unwrap();
        assert!(
            results
                .iter()
                .all(|r| r.completeness == Completeness::Complete),
            "a clean change must not acquire a caveat"
        );
        assert!(results.iter().all(|r| r
            .evidence
            .does_not_predict
            .iter()
            .all(|line| !line.contains(andon_core::parse_health::PARSE_DEGRADED_CAVEAT))));
    }

    #[test]
    fn a_warm_index_marks_the_same_files_degraded_as_a_cold_one() {
        // The demotion reads health off the index, so a run that carried every
        // entry over must reach the same completeness as one that rebuilt them.
        // A cache that could quietly upgrade a degraded file to `complete` would
        // be a wrong answer served faster.
        let dir = std::env::temp_dir().join(format!(
            "andon-clones-health-warm-{}-{}",
            std::process::id(),
            "1"
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let index_path = dir.join("clones-index");
        let files = || {
            vec![
                input("src/clean.ts", &block("one")),
                input("src/broken.ts", "export function f( { !!! \n"),
            ]
        };

        let cold = ClonesEngine::for_files(files(), Some(&index_path)).unwrap();
        let warm = ClonesEngine::for_files(files(), Some(&index_path)).unwrap();
        assert_eq!(warm.index_reused(), 2, "the second run reused the index");

        let cold_results = run_engine(&cold, &context()).unwrap();
        let warm_results = run_engine(&warm, &context()).unwrap();
        assert_eq!(
            warm_results
                .iter()
                .map(|r| (&r.metric_id, r.completeness, &r.digest))
                .collect::<Vec<_>>(),
            cold_results
                .iter()
                .map(|r| (&r.metric_id, r.completeness, &r.digest))
                .collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&dir);
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
        // The saturation cap rides in the algorithm string because it can
        // change a reported value, and a result-changing parameter outside the
        // regime is a disagreement the verifier reads as tampering.
        assert_eq!(algorithm, fingerprint::ALGORITHM);
        assert!(algorithm.contains("sat32"));
        assert_eq!(min_tokens, fingerprint::MIN_CLONE_TOKENS);
        assert_eq!(window_tokens, fingerprint::WINDOW_TOKENS);
        for (name, version) in syntax::GRAMMAR_PINS {
            assert!(normalization_revision.contains(&format!("{name}@{version}")));
        }
    }

    #[test]
    fn every_clone_metric_ranks_its_own_number() {
        // CONTENT, not keys. `andon-core`'s
        // `every_shipped_metric_declares_exactly_one_ladder` compares the metric
        // ids a ladder exists for against the ids this engine declares —
        // presence on both sides, and never a word about what the ladder says.
        // So setting `clones.clone-groups` to `NoOpinion` took this engine's
        // opinion away one metric at a time with the whole workspace green,
        // which is the dead band the mini-G2 ruling exists to prevent, arriving
        // by the back door.
        let ladders = severity_ladders();
        let declared: std::collections::BTreeSet<String> = metric_descriptors()
            .into_iter()
            .map(|d| d.metric_id)
            .collect();
        let ranking: std::collections::BTreeSet<String> = ladders
            .iter()
            .filter(|(_, ladder)| ladder.strongest() > Severity::Info)
            .map(|(id, _)| id.clone())
            .collect();
        assert_eq!(
            ranking, declared,
            "every clone metric ranks its own number — none of the five declines"
        );

        // And the top of the scale, which the module item above argues for: a
        // tier-N count with no remediation evidence behind it has not earned
        // `Critical`, and a ladder that quietly reached it would be this engine
        // over-reporting under a policy that admitted the tier.
        for (metric_id, ladder) in &ladders {
            assert_eq!(ladder.strongest(), Severity::High, "{metric_id}");
        }
    }

    #[test]
    fn the_clone_rungs_are_pinned_at_their_boundaries() {
        // No threshold value in this engine was pinned anywhere. Moving the
        // token rungs to figures no change could reach — disabling the ladder
        // outright — left every test in the workspace green.
        //
        // The token literals are written out rather than derived from
        // `fingerprint::MIN_CLONE_TOKENS`, deliberately: the rungs are five and
        // twenty minimum clones, so a change to the token unit moves them, and
        // it should move them in a diff somebody reads rather than silently.
        assert_eq!(
            fingerprint::MIN_CLONE_TOKENS,
            50,
            "the rungs below are 5x and 20x this"
        );

        let cases: &[(&str, MetricValue, Severity)] = &[
            // Tokens covered by a clone: one minimum clone, five, twenty.
            (
                METRIC_DUPLICATED_TOKENS,
                MetricValue::Count(0),
                Severity::Info,
            ),
            (
                METRIC_DUPLICATED_TOKENS,
                MetricValue::Count(1),
                Severity::Low,
            ),
            (
                METRIC_DUPLICATED_TOKENS,
                MetricValue::Count(249),
                Severity::Low,
            ),
            (
                METRIC_DUPLICATED_TOKENS,
                MetricValue::Count(250),
                Severity::Medium,
            ),
            (
                METRIC_DUPLICATED_TOKENS,
                MetricValue::Count(999),
                Severity::Medium,
            ),
            (
                METRIC_DUPLICATED_TOKENS,
                MetricValue::Count(1_000),
                Severity::High,
            ),
            // The same table, and the mapping to it is part of what is pinned.
            (
                METRIC_FILE_DUPLICATED_TOKENS,
                MetricValue::Count(250),
                Severity::Medium,
            ),
            (
                METRIC_LARGEST_CLONE,
                MetricValue::Count(1_000),
                Severity::High,
            ),
            // Distinct repeated sequences: one, five, twenty.
            (METRIC_CLONE_GROUPS, MetricValue::Count(0), Severity::Info),
            (METRIC_CLONE_GROUPS, MetricValue::Count(1), Severity::Low),
            (METRIC_CLONE_GROUPS, MetricValue::Count(4), Severity::Low),
            (METRIC_CLONE_GROUPS, MetricValue::Count(5), Severity::Medium),
            (
                METRIC_CLONE_GROUPS,
                MetricValue::Count(19),
                Severity::Medium,
            ),
            (METRIC_CLONE_GROUPS, MetricValue::Count(20), Severity::High),
            // Duplicated proportion: a twentieth, a fifth, two fifths.
            (
                METRIC_DUPLICATED_RATIO,
                MetricValue::Ratio(0.04),
                Severity::Info,
            ),
            (
                METRIC_DUPLICATED_RATIO,
                MetricValue::Ratio(0.05),
                Severity::Low,
            ),
            (
                METRIC_DUPLICATED_RATIO,
                MetricValue::Ratio(0.19),
                Severity::Low,
            ),
            (
                METRIC_DUPLICATED_RATIO,
                MetricValue::Ratio(0.20),
                Severity::Medium,
            ),
            (
                METRIC_DUPLICATED_RATIO,
                MetricValue::Ratio(0.39),
                Severity::Medium,
            ),
            (
                METRIC_DUPLICATED_RATIO,
                MetricValue::Ratio(0.40),
                Severity::High,
            ),
        ];

        let ladders = severity_ladders();
        for (metric_id, value, expected) in cases {
            let got = ladders[*metric_id]
                .severity_for(value)
                .expect("the declared ladder applies to the value the metric emits")
                .expect("not a per-result ladder");
            assert_eq!(got, *expected, "{metric_id} at {value:?}");
        }
    }
}
