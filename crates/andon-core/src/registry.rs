//! The evidence registry: claim tuples, the metrics that cite them, and the
//! lint that fails the build when the two disagree.
//!
//! # Why a metric declaration lives beside the claim
//!
//! The lint has to answer "does every emitted metric have a claim?" without
//! building and running the engines — it is a standalone tool that ships in P0,
//! years before some of those engines exist. So each engine's registry file
//! declares both the metrics it emits and the claims they cite. The obvious risk
//! is drift between that declaration and the code, which [`Registry::check_engine`]
//! closes: every engine crate asserts its `metrics()` equals its manifest.
//!
//! # Expiry has fire semantics
//!
//! An expired claim does not fail the build — stopping the release train because
//! a citation aged is how the moat rots *and* shipping stops (PREMORTEM S2).
//! It auto-demotes: [`ResolvedClaim::stale`] is set, every rendering shows
//! `evidence: stale`, and the lint emits a visible notice. Silence is the one
//! outcome ruled out.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::date::Date;
use crate::engine::MeasureEngine;
use crate::policy::RegistryPolicy;
use crate::schema::enums::{EngineFamily, EvidenceTier, MetricClass};
use crate::schema::payload::EvidenceRef;

/// One engine's registry file, e.g. `registry/static.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineRegistryFile {
    /// Registry schema version. Only `1` is accepted.
    pub schema_version: u32,
    /// Engine id; must match the engine's descriptor.
    pub engine: String,
    /// Family; must match the engine's descriptor.
    pub family: EngineFamily,
    /// Metrics this engine emits.
    #[serde(default, rename = "metric")]
    pub metrics: Vec<MetricDecl>,
    /// Claim tuples the metrics cite. Disjoint per engine so that phases running
    /// in parallel never edit the same file (PLAN R2-2).
    #[serde(default, rename = "claim")]
    pub claims: Vec<Claim>,
}

/// A metric declaration — the manifest half of the drift check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricDecl {
    /// Stable metric id the engine emits.
    pub metric_id: String,
    /// The claim tuple it cites. Must resolve, or the lint fails the build.
    pub claim_id: String,
    /// Whether the agent can act on it inside its own change.
    pub class: MetricClass,
    /// Whether it belongs in the digest compare set.
    pub deterministic: bool,
}

/// A claim tuple: this implementation, at this version, in this language,
/// predicts this outcome.
///
/// Claim-scoped, never family-wide (PRE-DECISIONS hard constraint). "Cyclomatic
/// complexity predicts defects" is not a claim this registry can express, and
/// that is the point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// Canonical form `implementation@version|language|outcome`, so the id and
    /// the tuple can never drift apart.
    pub claim_id: String,
    /// The measuring implementation, e.g. `andon.static.cognitive`. Claims are
    /// scoped to an implementation because two tools computing "cognitive
    /// complexity" do not compute the same number.
    pub implementation: String,
    /// Version of that implementation the evidence was established against.
    pub implementation_version: String,
    /// Language the claim is scoped to, or `any` for language-agnostic families.
    pub language: String,
    /// The outcome predicted, e.g. `comprehension-time`.
    pub outcome: String,
    /// Evidence strength, graded as in `docs/metric-families.csv`.
    pub tier: EvidenceTier,
    /// Human-readable citation.
    pub citation: String,
    /// DOI or stable URL, checked for resolution by the P10a registry-PR gate.
    pub citation_ref: Option<String>,
    /// The studied population, e.g. "17.6M Java methods".
    pub population: String,
    /// The measured effect, in the source's own terms.
    pub effect: String,
    /// The honesty field: what this number is *not* evidence for. Required and
    /// non-empty — a claim that predicts everything predicts nothing.
    pub does_not_predict: Vec<String>,
    /// Who re-reviews this claim at expiry.
    pub owner: String,
    /// Re-review date. Past it the claim demotes to stale, visibly.
    pub expiry: Date,
}

impl Claim {
    /// The canonical id this claim's tuple implies.
    pub fn canonical_id(&self) -> String {
        format!(
            "{}@{}|{}|{}",
            self.implementation, self.implementation_version, self.language, self.outcome
        )
    }
}

/// A claim resolved against a run date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedClaim {
    /// The claim as written in the registry file.
    pub claim: Claim,
    /// True once `as_of` is past `expiry`. Surfaced as `evidence: stale`
    /// everywhere the claim is cited, never suppressed.
    pub stale: bool,
}

impl ResolvedClaim {
    /// Project into the [`EvidenceRef`] a measurement result carries.
    ///
    /// This is the demotion in PREMORTEM S2, made mechanical. Every path from a
    /// claim to a reported number goes through here, so an expired claim cannot
    /// reach a payload without its `stale` flag: there is no second way to build
    /// an `EvidenceRef` from a claim, and therefore no way to forget.
    pub fn to_evidence_ref(&self) -> EvidenceRef {
        EvidenceRef {
            claim_id: self.claim.claim_id.clone(),
            tier: self.claim.tier,
            citation: self.claim.citation.clone(),
            does_not_predict: self.claim.does_not_predict.clone(),
            stale: self.stale,
        }
    }
}

/// Every engine registry file, merged.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    /// Every claim, keyed by `claim_id`.
    pub claims: BTreeMap<String, ResolvedClaim>,
    /// Every declared metric, keyed by `metric_id`.
    pub metrics: BTreeMap<String, MetricDecl>,
    /// Which file each metric came from, for diagnostics.
    pub metric_sources: BTreeMap<String, String>,
}

/// How serious a lint finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    /// Fails the lint, and therefore the build.
    Error,
    /// Reported and visible; does not fail the build.
    Notice,
}

/// One lint finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Stable machine code, e.g. `registry.unmapped-metric`.
    pub code: &'static str,
    /// Whether this fails the build or is merely reported.
    pub severity: DiagnosticSeverity,
    /// Registry file the finding is about.
    pub location: String,
    /// What is wrong, and what to do.
    pub message: String,
}

impl Diagnostic {
    fn error(code: &'static str, location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: DiagnosticSeverity::Error,
            location: location.into(),
            message: message.into(),
        }
    }

    fn notice(code: &'static str, location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: DiagnosticSeverity::Notice,
            location: location.into(),
            message: message.into(),
        }
    }
}

/// The outcome of a lint run.
#[derive(Debug, Clone, Default)]
pub struct LintReport {
    /// Every finding, errors and notices alike.
    pub diagnostics: Vec<Diagnostic>,
    /// Claims in the merged registry, for the budget line in the summary.
    pub claim_count: usize,
    /// Metrics in the merged registry.
    pub metric_count: usize,
}

impl LintReport {
    /// Whether the build should fail.
    pub fn failed(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == DiagnosticSeverity::Error)
    }

    /// Findings that fail the build.
    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == DiagnosticSeverity::Error)
    }
}

/// A registry file that could not even be parsed.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The file is not valid TOML for the registry schema.
    #[error("{path}: not valid TOML: {source}")]
    Toml {
        /// Registry file that failed to parse.
        path: String,
        /// The underlying TOML error.
        #[source]
        source: toml::de::Error,
    },
}

/// Parse one registry file.
pub fn parse_file(path: &str, text: &str) -> Result<EngineRegistryFile, RegistryError> {
    toml::from_str(text).map_err(|source| RegistryError::Toml {
        path: path.to_string(),
        source,
    })
}

/// Lint a set of already-parsed registry files.
///
/// `as_of` decides staleness. It is a parameter and not `Date::today_utc()`
/// because a lint whose verdict depends on the day it runs cannot be tested, and
/// a green build that silently rots is worse than a red one.
pub fn lint(
    files: &[(String, EngineRegistryFile)],
    policy: &RegistryPolicy,
    as_of: Date,
) -> (Registry, LintReport) {
    let mut registry = Registry::default();
    let mut report = LintReport::default();

    for (path, file) in files {
        if file.schema_version != 1 {
            report.diagnostics.push(Diagnostic::error(
                "registry.schema-version",
                path,
                format!(
                    "unsupported registry schema_version {} (expected 1)",
                    file.schema_version
                ),
            ));
            continue;
        }

        for claim in &file.claims {
            let canonical = claim.canonical_id();
            if claim.claim_id != canonical {
                report.diagnostics.push(Diagnostic::error(
                    "registry.claim-id-format",
                    path,
                    format!(
                        "claim_id '{}' does not match its tuple; expected '{canonical}'",
                        claim.claim_id
                    ),
                ));
            }
            if claim.does_not_predict.is_empty() {
                report.diagnostics.push(Diagnostic::error(
                    "registry.missing-field",
                    path,
                    format!(
                        "claim '{}' has an empty does_not_predict; every claim must say what it does not support",
                        claim.claim_id
                    ),
                ));
            }
            for (field, value) in [
                ("citation", &claim.citation),
                ("population", &claim.population),
                ("effect", &claim.effect),
                ("owner", &claim.owner),
            ] {
                if value.trim().is_empty() {
                    report.diagnostics.push(Diagnostic::error(
                        "registry.missing-field",
                        path,
                        format!("claim '{}' has an empty {field}", claim.claim_id),
                    ));
                }
            }

            let stale = as_of > claim.expiry;
            if stale {
                report.diagnostics.push(Diagnostic::notice(
                    "registry.evidence-stale",
                    path,
                    format!(
                        "claim '{}' expired {} and is demoted to `evidence: stale`; owner {} re-reviews",
                        claim.claim_id, claim.expiry, claim.owner
                    ),
                ));
            }

            let resolved = ResolvedClaim {
                claim: claim.clone(),
                stale,
            };
            if registry
                .claims
                .insert(claim.claim_id.clone(), resolved)
                .is_some()
            {
                report.diagnostics.push(Diagnostic::error(
                    "registry.duplicate-claim",
                    path,
                    format!("claim_id '{}' is declared more than once", claim.claim_id),
                ));
            }
        }

        for metric in &file.metrics {
            if registry
                .metrics
                .insert(metric.metric_id.clone(), metric.clone())
                .is_some()
            {
                report.diagnostics.push(Diagnostic::error(
                    "registry.duplicate-metric",
                    path,
                    format!(
                        "metric_id '{}' is declared more than once",
                        metric.metric_id
                    ),
                ));
            }
            registry
                .metric_sources
                .insert(metric.metric_id.clone(), path.clone());
        }
    }

    // The rule the must-reject fixture exercises: an emitted metric with no
    // claim behind it fails the build. This is the whole point of the registry.
    for (metric_id, metric) in &registry.metrics {
        if !registry.claims.contains_key(&metric.claim_id) {
            let location = registry
                .metric_sources
                .get(metric_id)
                .cloned()
                .unwrap_or_default();
            report.diagnostics.push(Diagnostic::error(
                "registry.unmapped-metric",
                location,
                format!(
                    "metric '{metric_id}' cites claim '{}', which no registry file declares",
                    metric.claim_id
                ),
            ));
        }
    }

    // Claims nobody cites are dead weight against a budget of 24.
    for claim_id in registry.claims.keys() {
        if !registry.metrics.values().any(|m| &m.claim_id == claim_id) {
            report.diagnostics.push(Diagnostic::notice(
                "registry.unused-claim",
                "registry",
                format!("claim '{claim_id}' is not cited by any metric"),
            ));
        }
    }

    // Enforced count, not a documented intention (PREMORTEM S2).
    if registry.claims.len() > policy.claim_budget as usize {
        report.diagnostics.push(Diagnostic::error(
            "registry.claim-budget",
            "registry",
            format!(
                "{} claim tuples exceeds the budget of {}; the budget is what one owner can re-review in a week each year",
                registry.claims.len(),
                policy.claim_budget
            ),
        ));
    }

    // Staggered expiries: a cliff where a third of the registry falls due in one
    // month recreates the bottleneck the budget exists to prevent.
    let mut per_month: BTreeMap<String, usize> = BTreeMap::new();
    for resolved in registry.claims.values() {
        *per_month
            .entry(resolved.claim.expiry.year_month())
            .or_default() += 1;
    }
    for (month, count) in &per_month {
        if *count > policy.max_claims_expiring_per_month as usize {
            report.diagnostics.push(Diagnostic::error(
                "registry.expiry-stagger",
                "registry",
                format!(
                    "{count} claims expire in {month}, above the stagger limit of {}; spread the re-review load",
                    policy.max_claims_expiring_per_month
                ),
            ));
        }
    }

    report.claim_count = registry.claims.len();
    report.metric_count = registry.metrics.len();
    (registry, report)
}

impl Registry {
    /// Assert that an engine's compiled metric set equals its registry file.
    ///
    /// The drift check that makes the declarative manifest trustworthy. Every
    /// engine crate calls this from a test; a metric added in code but not in
    /// the registry fails there, and one added to the registry but not emitted
    /// fails here too.
    pub fn check_engine(
        file: &EngineRegistryFile,
        engine: &dyn MeasureEngine,
    ) -> Result<(), Vec<String>> {
        let descriptor = engine.descriptor();
        let mut problems = Vec::new();
        if file.engine != descriptor.engine_id {
            problems.push(format!(
                "registry declares engine '{}' but the engine identifies as '{}'",
                file.engine, descriptor.engine_id
            ));
        }
        if file.family != descriptor.family {
            problems.push(format!(
                "registry declares family {:?} but the engine reports {:?}",
                file.family, descriptor.family
            ));
        }

        let declared: BTreeMap<&str, &MetricDecl> = file
            .metrics
            .iter()
            .map(|m| (m.metric_id.as_str(), m))
            .collect();
        let emitted = engine.metrics();
        let emitted_map: BTreeMap<&str, &crate::engine::MetricDescriptor> =
            emitted.iter().map(|m| (m.metric_id.as_str(), m)).collect();

        for (metric_id, descriptor) in &emitted_map {
            match declared.get(metric_id) {
                None => problems.push(format!(
                    "metric '{metric_id}' is emitted by the engine but absent from the registry file"
                )),
                Some(decl) => {
                    if decl.claim_id != descriptor.claim_id {
                        problems.push(format!(
                            "metric '{metric_id}' cites '{}' in code and '{}' in the registry",
                            descriptor.claim_id, decl.claim_id
                        ));
                    }
                    if decl.class != descriptor.class {
                        problems.push(format!(
                            "metric '{metric_id}' is {:?} in code and {:?} in the registry",
                            descriptor.class, decl.class
                        ));
                    }
                    if decl.deterministic != descriptor.deterministic {
                        problems.push(format!(
                            "metric '{metric_id}' disagrees on determinism: code {} vs registry {}",
                            descriptor.deterministic, decl.deterministic
                        ));
                    }
                }
            }
        }
        for metric_id in declared.keys() {
            if !emitted_map.contains_key(metric_id) {
                problems.push(format!(
                    "metric '{metric_id}' is declared in the registry but the engine never emits it"
                ));
            }
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}
