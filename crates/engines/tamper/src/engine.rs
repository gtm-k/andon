//! The `MeasureEngine` implementation for the tamper suite.
//!
//! Fourteen results, always: a fired/not-fired flag and a magnitude for each of
//! the seven detectors. **Always** is the load-bearing word. A suite that
//! emitted results only when something fired would make the digest compare set
//! depend on the answer — two honest sides measuring a clean change would have
//! nothing to compare, the cross-OS matrix would go green on an empty table,
//! and "the detectors agreed" would be indistinguishable from "the detectors
//! did not run" (PLAN B4, R2-1: *all seven* join the matrix).
//!
//! # Where the bytes come in
//!
//! Same seam as the clone engine's, for the same reason: `MeasureContext` is
//! P0-owned and carries no content, and three engine phases in one wave cannot
//! all widen it. [`TamperEngine::for_change`] reads both sides' blobs and holds
//! them; `measure` uses the context for the rest. Base-side bytes are needed
//! here in a way they are not for clones, because every detector is a delta.
//!
//! # A detector that did not read all of the change says so
//!
//! Every result here is change-scoped, so there is no per-file result to mark
//! when the parser gives up on a file. What is marked instead is per *detector*,
//! and the scope is what that detector read: three of the seven parse
//! (`test-removal`, `assertion-free-test`, `lookup-table-blowup`), and the other
//! four read bytes — suppression markers, coverage config, threshold config, and
//! the fault counts themselves — which an ERROR node hides nothing from. Marking
//! all seven because one file in the change was unparseable would put a caveat
//! on results a parse failure cannot touch; that is claiming a limitation rather
//! than disclosing one, and it would widen the blast radius of a degraded file
//! for nothing. See [`crate::detectors::Outcome::view_health`].
//!
//! The case this closes is the whole of PREMORTEM T3 in one sentence: a test
//! deleted out of a region the parser could not read was never counted at the
//! base either, so `test-removal` reports no removal — and, before this,
//! reported it `complete`, on the same file `parse-error-delta` was
//! simultaneously reporting as degraded. The flag and the magnitude are
//! unchanged and stay in the digest; what changes is that they stop claiming to
//! be a complete answer, and the caveat says the error is one-directional.
//!
//! `parse-error-delta` is exempt, for the reason `andon_core::parse_health`
//! gives: a report of a blind spot demoted by the blind spot it reports is the
//! one signal T3 wants loud, silenced by its own finding.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use andon_core::date::Date;
use andon_core::engine::{
    EngineDescriptor, EngineError, MeasureContext, MeasureEngine, MetricDescriptor,
};
use andon_core::git::{BlobBatch, ChangeStatus, ChangedSet, Git};
use andon_core::parse_health::{self, ParseHealth};
use andon_core::registry::{lint, parse_file, EngineRegistryFile, Registry};
use andon_core::schema::enums::{Completeness, EngineClass, EngineFamily, Severity, TamperSignal};
use andon_core::schema::payload::{
    CacheState, EvidenceRef, Freshness, MeasurementResult, MetricValue, ResultScope, ScopeKind,
};
use andon_core::schema::regime::MeasurementRegime;
use andon_core::verdict::ladder::SeverityLadder;

use crate::change::{ChangeKind, ChangeView, FileChange};
use crate::detectors::{self, Outcome};
use crate::syntax;

/// The engine id. Equals the registry file stem.
pub const ENGINE_ID: &str = "tamper";

/// The registry, compiled in (DEFERRED-APPROVALS E4).
const REGISTRY_TOML: &str = include_str!("../../../../registry/tamper.toml");

/// Anything that stopped the engine from measuring.
#[derive(Debug, thiserror::Error)]
pub enum TamperEngineError {
    /// Reading blobs failed.
    #[error(transparent)]
    Blob(#[from] andon_core::git::BlobError),
    /// Opening the blob reader failed.
    #[error(transparent)]
    Git(#[from] andon_core::git::GitError),
    /// The compiled-in registry does not parse or does not lint.
    #[error("the compiled-in tamper registry is invalid: {0}")]
    Registry(String),
    /// The clock could not be read, so claim expiry cannot be evaluated.
    #[error(transparent)]
    Clock(#[from] andon_core::date::ClockError),
}

/// The compiled-in registry file, parsed once.
pub fn registry_file() -> Result<&'static EngineRegistryFile, TamperEngineError> {
    static PARSED: OnceLock<Result<EngineRegistryFile, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| parse_file("tamper.toml", REGISTRY_TOML).map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| TamperEngineError::Registry(e.clone()))
}

/// The engine's claims, resolved against `as_of`.
pub fn registry(as_of: Date) -> Result<Registry, TamperEngineError> {
    let files = vec![("tamper.toml".to_string(), registry_file()?.clone())];
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
        return Err(TamperEngineError::Registry(messages.join("; ")));
    }
    Ok(registry)
}

/// Every metric this engine emits: two per detector, in detector order.
pub fn metric_descriptors() -> Vec<MetricDescriptor> {
    let file = registry_file().expect("the compiled registry parses");
    detectors::all()
        .into_iter()
        .flat_map(|detector| [detector.metric_id(), detector.magnitude_metric_id()])
        .map(|metric_id| {
            let decl = file
                .metrics
                .iter()
                .find(|m| m.metric_id == metric_id)
                .unwrap_or_else(|| panic!("{metric_id} is declared in registry/tamper.toml"));
            MetricDescriptor {
                metric_id: decl.metric_id.clone(),
                claim_id: decl.claim_id.clone(),
                class: decl.class,
                deterministic: decl.deterministic,
            }
        })
        .collect()
}

/// This suite's severity declaration: every metric defers to its detector.
///
/// See the trait method for why. Public alongside [`metric_descriptors`] so the
/// enumeration test that pins `PerResult` to this engine and no other can read
/// it without constructing a change.
pub fn severity_ladders() -> BTreeMap<String, SeverityLadder> {
    metric_descriptors()
        .into_iter()
        .map(|d| (d.metric_id, SeverityLadder::PerResult))
        .collect()
}

/// The tamper engine, holding the change it measured.
#[derive(Debug, Clone)]
pub struct TamperEngine {
    change: ChangeView,
}

impl TamperEngine {
    /// Measure a resolved change, reading both sides from git blobs.
    ///
    /// Both sides, and blobs on both: a detector that read the working tree for
    /// its head bytes would produce a number that differs between an honest
    /// Windows agent and an honest Linux verifier, which is PREMORTEM T1
    /// arriving through the tamper suite of all places.
    pub fn for_change(git: &Git, changed: &ChangedSet) -> Result<Self, TamperEngineError> {
        let mut batch: Option<BlobBatch> = None;
        let mut read = |oid: Option<&str>| -> Result<Option<Vec<u8>>, TamperEngineError> {
            let Some(oid) = oid else { return Ok(None) };
            if batch.is_none() {
                batch = Some(BlobBatch::open(git)?);
            }
            let content = batch.as_mut().expect("just opened").read(oid)?;
            Ok(Some(content.into_bytes()))
        };

        let mut files = Vec::new();
        for entry in &changed.entries {
            if entry.is_gitlink() {
                // A submodule pointer names a commit in another repository.
                // There is no content here to detect anything in.
                continue;
            }
            let kind = match entry.status {
                ChangeStatus::Added => ChangeKind::Added,
                ChangeStatus::Deleted => ChangeKind::Deleted,
                ChangeStatus::Renamed | ChangeStatus::Copied => ChangeKind::Renamed,
                _ => ChangeKind::Modified,
            };
            let head_oid = entry.readable_blob().map(str::to_string);
            let base = read(entry.src_oid.as_deref())?;
            let head = read(head_oid.as_deref())?;
            files.push(FileChange {
                path: entry.path.clone(),
                old_path: entry.old_path.clone(),
                kind,
                base,
                head,
                head_blob_oid: head_oid,
            });
        }
        Ok(TamperEngine {
            change: ChangeView::new(files),
        })
    }

    /// Measure an explicit change view. The seam the corpus harness uses.
    pub fn for_view(change: ChangeView) -> Self {
        TamperEngine { change }
    }

    /// The change being measured.
    pub fn change(&self) -> &ChangeView {
        &self.change
    }

    /// Run every detector, in order.
    pub fn outcomes(&self) -> Vec<(&'static dyn detectors::Detector, Outcome)> {
        detectors::all()
            .into_iter()
            .map(|detector| {
                let outcome = detector.run(&self.change);
                (detector, outcome)
            })
            .collect()
    }

    /// Every signal that fired, for the payload's `tamper_signals` array.
    pub fn signals(&self) -> Vec<TamperSignal> {
        self.outcomes()
            .into_iter()
            .filter(|(_, outcome)| outcome.fired)
            .map(|(detector, _)| detector.signal())
            .collect()
    }
}

impl MeasureEngine for TamperEngine {
    fn descriptor(&self) -> EngineDescriptor {
        EngineDescriptor {
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Tamper,
            class: EngineClass::StaticSafe,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn metrics(&self) -> Vec<MetricDescriptor> {
        metric_descriptors()
    }

    /// Every metric here defers to the detector that produced it.
    ///
    /// This suite is the one engine whose severity is declared per *detector*
    /// rather than per metric — `detectors::Detector::severity_when_fired`, with
    /// `parse_error_delta` lowering its own firing per outcome — and that
    /// declaration predates the ladder, is reviewed, and is what the muzzle rule
    /// in `andon_core::verdict::severity` was written against. Restating it as a
    /// threshold table would produce a second copy of a rule the whole phase
    /// turns on, and two copies of that rule is how one of them ends up wrong
    /// while both suites stay green.
    ///
    /// `SeverityLadder::PerResult` says exactly that, and the boundary still
    /// applies the completeness ceiling on the way out — so a detector firing
    /// over a partly-unreadable view is still capped, and still stops the line
    /// on its flag rather than on the capped number.
    fn severity_ladders(&self) -> BTreeMap<String, SeverityLadder> {
        severity_ladders()
    }

    fn regime(&self) -> MeasurementRegime {
        MeasurementRegime::Tamper {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            detector_set_revision: syntax::DETECTOR_SET_REVISION.to_string(),
            // Carries the grammar pins — see `syntax::rule_pack_version`.
            rule_pack_version: syntax::rule_pack_version(),
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

        let mut results = Vec::with_capacity(14);
        for (detector, outcome) in self.outcomes() {
            let severity = if outcome.fired {
                // A detector may report this firing at a different strength than
                // its default — see `Outcome::severity`.
                outcome
                    .severity
                    .unwrap_or_else(|| detector.severity_when_fired())
            } else {
                Severity::Info
            };
            let mut flag = self.result(
                detector.metric_id(),
                MetricValue::Flag(outcome.fired),
                severity,
                evidence_for(detector.metric_id()),
                &descriptors,
            );
            let mut magnitude = self.result(
                detector.magnitude_metric_id(),
                MetricValue::Integer(outcome.magnitude),
                Severity::Info,
                evidence_for(detector.magnitude_metric_id()),
                &descriptors,
            );
            if outcome.view_health.is_degraded() {
                let caveat = degraded_view_caveat(outcome.view_health);
                parse_health::demote_with_caveat(&mut flag, outcome.view_health, caveat.clone());
                parse_health::demote_with_caveat(&mut magnitude, outcome.view_health, caveat);
            }
            results.push(flag);
            results.push(magnitude);
        }
        Ok(results)
    }
}

/// The honesty line a detector's results carry when it read a partial tree.
///
/// The static engine's caveat says a *number* was computed over a partial tree.
/// A detector's answer needs the other half said out loud: the error is
/// one-directional. Code inside a region the parser could not read is code this
/// detector never examined, so a firing is a lower bound and a silence is not a
/// finding of absence — which is exactly the shape of the false negative
/// PREMORTEM T3 describes, and the reason a quiet detector over a degraded view
/// may not be read as a clean bill of health.
fn degraded_view_caveat(health: ParseHealth) -> String {
    format!(
        "{} all of them ({} ERROR, {} MISSING node(s) in what this detector parsed); \
         code inside a region the parser could not read was never examined, so this \
         result is a lower bound and a quiet one is not evidence of absence",
        parse_health::PARSE_DEGRADED_SET_CAVEAT,
        health.error_nodes,
        health.missing_nodes
    )
}

impl TamperEngine {
    fn result(
        &self,
        metric_id: &str,
        value: MetricValue,
        severity: Severity,
        evidence: EvidenceRef,
        descriptors: &[MetricDescriptor],
    ) -> MeasurementResult {
        let descriptor = descriptors
            .iter()
            .find(|d| d.metric_id == metric_id)
            .expect("every emitted metric has a descriptor");
        MeasurementResult {
            metric_id: metric_id.to_string(),
            claim_id: descriptor.claim_id.clone(),
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Tamper,
            engine_class: EngineClass::StaticSafe,
            metric_class: descriptor.class,
            // Change-scoped by construction: every detector answers about the
            // change as a whole, because the honest answers are net answers.
            // The per-file detail lives in the findings, which the report
            // renders and the digest does not cover.
            scope: ResultScope {
                kind: ScopeKind::Change,
                path: None,
                blob_oid: None,
                symbol: None,
                line_span: None,
            },
            value,
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
            sandbox_available: false,
        }
    }

    #[test]
    fn the_compiled_registry_parses_and_lints() {
        let as_of: Date = "2026-08-17".parse().expect("a valid date");
        let registry = registry(as_of).expect("the compiled registry must lint clean");
        assert_eq!(registry.metrics.len(), 14);
        // Four claims, seven detectors: one claim per *outcome*, because two
        // detectors asking the same question by different mechanisms do not
        // need two evidence stories. See registry/tamper.toml on why merging is
        // honest for tier-N claims and would not be for cited ones.
        assert_eq!(registry.claims.len(), 4);
    }

    #[test]
    fn the_engine_and_its_registry_do_not_drift() {
        let engine = TamperEngine::for_view(ChangeView::default());
        Registry::check_engine(registry_file().unwrap(), &engine)
            .unwrap_or_else(|problems| panic!("{}", problems.join("\n")));
    }

    #[test]
    fn all_fourteen_results_are_emitted_on_a_clean_change() {
        let view = ChangeView::new(vec![FileChange::added("src/a.ts", "export const x = 1;\n")]);
        let engine = TamperEngine::for_view(view);
        let results = run_engine(&engine, &context()).expect("measures");
        assert_eq!(
            results.len(),
            14,
            "all seven detectors join the compare set"
        );
        assert!(results.iter().all(|r| !r.digest.is_empty(),));
        // Every flag is false, and every one of them is still a sealed result.
        assert_eq!(
            results
                .iter()
                .filter(|r| r.value == MetricValue::Flag(true))
                .count(),
            0
        );
        assert!(engine.signals().is_empty());
    }

    #[test]
    fn a_fired_detector_shows_up_as_a_flag_and_a_signal() {
        let view = ChangeView::new(vec![FileChange::deleted(
            "src/a.test.ts",
            "it('a', () => { expect(1).toBe(1); });\n",
        )]);
        let engine = TamperEngine::for_view(view);
        let results = run_engine(&engine, &context()).expect("measures");
        let flag = results
            .iter()
            .find(|r| r.metric_id == "tamper.test-removal")
            .unwrap();
        assert_eq!(flag.value, MetricValue::Flag(true));
        assert_eq!(flag.severity, Severity::High);
        assert_eq!(engine.signals(), vec![TamperSignal::TestRemoval]);
    }

    #[test]
    fn the_regime_carries_the_grammar_pins() {
        let engine = TamperEngine::for_view(ChangeView::default());
        let MeasurementRegime::Tamper {
            rule_pack_version,
            detector_set_revision,
            ..
        } = engine.regime()
        else {
            panic!("the tamper engine reports a tamper regime");
        };
        assert_eq!(detector_set_revision, syntax::DETECTOR_SET_REVISION);
        for (name, version) in syntax::GRAMMAR_PINS {
            assert!(rule_pack_version.contains(&format!("{name}@{version}")));
        }
    }

    #[test]
    fn results_come_out_in_detector_order_on_every_run() {
        let view = ChangeView::new(vec![FileChange::added("src/a.ts", "export const x = 1;\n")]);
        let engine = TamperEngine::for_view(view);
        let first: Vec<String> = run_engine(&engine, &context())
            .unwrap()
            .into_iter()
            .map(|r| r.metric_id)
            .collect();
        let second: Vec<String> = run_engine(&engine, &context())
            .unwrap()
            .into_iter()
            .map(|r| r.metric_id)
            .collect();
        assert_eq!(first, second);
        assert_eq!(first[0], "tamper.test-removal");
        assert_eq!(first[13], "tamper.parse-error-delta.magnitude");
    }
}
