//! Payload assembly: five engines' results become one record.
//!
//! # What assembly is for
//!
//! Each engine produces sealed [`MeasurementResult`]s and knows nothing about
//! the others. This is where they meet, and it is the only place in the system
//! that sees all of them at once — which makes it the right place, and the only
//! place, for the checks that are about the *set* rather than about any one
//! number:
//!
//! - **Nothing enters a payload without evidence.** Every result's `claim_id`
//!   must resolve in the merged registry, or assembly refuses. The registry lint
//!   has failed builds since P0; this is the same rule at the measurement
//!   boundary, so a binary cannot report a number whose claim nobody declared
//!   ([`registry_load`]).
//! - **No result may be stamped with a family it did not come from.** A
//!   mis-stamped `family` seals consistently and passes the verifier's compare,
//!   because both sides make the same mistake — so a wrong stamp is invisible
//!   exactly where it matters. Checked three ways here, and refused at the
//!   engine boundary too ([`crate::engine::run_engine`]).
//! - **Nothing pairs twice.** The verifier pairs results on
//!   `(metric_id, scope)`; two results sharing one pair make the pairing
//!   ambiguous, and an ambiguous pairing is a place a forged result can shadow
//!   an honest one.
//!
//! # Grouped by engine, never by family
//!
//! Two engines share the `static` family: P2's `static-metrics` and P1.5's
//! `spike-size` (`andon-ledger-min`, whose regime is `Static` with no grammars).
//! Grouping by family would merge a production engine's results with the trust
//! spike's in any per-group ordering or summary. The grouping key is
//! `engine_id` throughout, and [`group_by_engine`] is the only grouping this
//! module offers, so the mistake has nowhere to be made (PLAN wave-1 integration,
//! P5a-entry note 2).
//!
//! # What assembly deliberately does not do
//!
//! It does not attest. [`MeasurementRecord::attestation`] leaves here as
//! `unwitnessed` with the fired tamper signals attached and nothing else: trust
//! is earned from CI (`crate::compare`), and a record that could set its own
//! attestation value would be a record that could pass itself.

pub mod registry_load;
pub mod tamper_signals;

use std::collections::{BTreeMap, BTreeSet};

use crate::engine::EngineDescriptor;
use crate::parse_health;
use crate::policy::Policy;
use crate::schema::enums::{Completeness, RecordKind};
use crate::schema::payload::{
    AttestationBlock, CompareContext, Invocation, MeasurementRecord, MeasurementResult, Reserved,
    ResultScope, ToolIdentity, SCHEMA_VERSION,
};
use crate::verdict::iteration::Advance;
use crate::verdict::policy_change::PolicyChange;
use crate::verdict::{self, EngineFailure, VerdictContext};

use registry_load::LoadedRegistry;

/// One engine's contribution to a payload.
#[derive(Debug, Clone, PartialEq)]
pub struct EngineOutput {
    /// Who produced these, from the engine's own descriptor.
    pub descriptor: EngineDescriptor,
    /// Sealed results, in the order the engine emitted them. Assembly preserves
    /// that order: several engines document their emission order as meaningful
    /// (the tamper suite's is detector order), and reordering within an engine
    /// would discard information for no gain.
    pub results: Vec<MeasurementResult>,
}

/// Why a set of engine outputs could not become a payload.
///
/// Every variant is a bug in a producer, not a property of the change being
/// measured. There is no "and carry on" branch: a payload that quietly dropped a
/// result would be a record whose absence nobody can see.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssemblyError {
    /// Two outputs claim the same engine id.
    #[error("engine '{engine_id}' contributed twice to one payload")]
    DuplicateEngine {
        /// The engine named twice.
        engine_id: String,
    },
    /// A result does not name the engine that produced it.
    #[error("result '{metric_id}' says engine '{claimed}' but came from '{actual}'")]
    EngineMismatch {
        /// The metric.
        metric_id: String,
        /// What the result claims.
        claimed: String,
        /// What the descriptor says.
        actual: String,
    },
    /// A result's family, its engine's family, and its regime's family disagree.
    #[error(
        "result '{metric_id}' from '{engine_id}' is stamped {result:?} but the engine reports \
         {descriptor:?} and its regime is {regime:?}"
    )]
    FamilyMismatch {
        /// The engine.
        engine_id: String,
        /// The metric.
        metric_id: String,
        /// Family on the result.
        result: crate::schema::enums::EngineFamily,
        /// Family on the descriptor.
        descriptor: crate::schema::enums::EngineFamily,
        /// Family implied by the regime.
        regime: crate::schema::enums::EngineFamily,
    },
    /// A result reached assembly without a digest.
    #[error("result '{metric_id}' from '{engine_id}' was never sealed")]
    Unsealed {
        /// The engine.
        engine_id: String,
        /// The metric.
        metric_id: String,
    },
    /// Two results share a `(metric_id, scope)` pair.
    #[error("two results share the pairing key ('{metric_id}', {scope:?})")]
    DuplicateResult {
        /// The metric.
        metric_id: String,
        /// The scope both claim.
        scope: Box<ResultScope>,
    },
    /// A result cites a claim the merged registry does not declare.
    #[error("result '{metric_id}' cites claim '{claim_id}', which the registry does not declare")]
    UnknownClaim {
        /// The metric.
        metric_id: String,
        /// The claim it cites.
        claim_id: String,
    },
    /// A tamper flag's metric id does not name a signal.
    #[error(
        "tamper flag '{metric_id}' does not name a signal; every detector flag is \
         `tamper.<signal>` as `TamperSignal` spells it"
    )]
    UnknownTamperSignal {
        /// The metric.
        metric_id: String,
    },
    /// The policy in force could not be hashed for the record.
    ///
    /// Carried as text rather than as the source error so that this enum stays
    /// comparable: assembly failures are asserted on in tests across the
    /// workspace, and `toml::de::Error` is neither `Clone` nor `Eq`.
    #[error("the policy in force could not be hashed: {0}")]
    PolicyHash(String),
}

/// What a payload is being assembled from.
#[derive(Debug, Clone)]
pub struct AssembleRequest<'a> {
    /// Which binary produced this.
    pub tool: ToolIdentity,
    /// Self-report or verifier attestation.
    pub record_kind: RecordKind,
    /// The `(base_oid, head_oid)` tuple every result was sealed against.
    pub compare_context: CompareContext,
    /// Ledger dimensions.
    pub invocation: Invocation,
    /// Monorepo and orchestrator fields, unset in v1.
    pub reserved: Reserved,
    /// Policy in force. The verifier's copy comes from the base commit.
    pub policy: &'a Policy,
    /// The merged registry, already linted by [`registry_load::load`].
    pub registry: &'a LoadedRegistry,
    /// Every engine that produced results.
    pub engines: Vec<EngineOutput>,
    /// Every engine that was asked and could not.
    pub engine_failures: Vec<EngineFailure>,
    /// The `.andon.toml` edit inside this change, if any.
    pub policy_change: Option<PolicyChange>,
}

/// A validated payload, waiting only on the iteration counter.
///
/// Two steps rather than one because the counter needs an answer this step
/// produces: whether the run found anything an agent can act on decides whether
/// the count advances or resets, and that cannot be known before policy has been
/// applied. Splitting it keeps the counter's storage out of the assembly path —
/// a caller with no store can build an [`Advance`] itself.
#[derive(Debug, Clone)]
pub struct Prepared {
    tool: ToolIdentity,
    record_kind: RecordKind,
    compare_context: CompareContext,
    invocation: Invocation,
    reserved: Reserved,
    policy: Policy,
    policy_hash: String,
    results: Vec<MeasurementResult>,
    engine_failures: Vec<EngineFailure>,
    policy_change: Option<PolicyChange>,
    stale_claim_ids: Vec<String>,
    completeness: Completeness,
    countable: bool,
}

impl Prepared {
    /// Whether this run gives an agent something to act on.
    ///
    /// The input to [`crate::verdict::iteration::IterationStore::advance`].
    pub fn has_countable_finding(&self) -> bool {
        self.countable
    }

    /// The results as they will appear in the record.
    pub fn results(&self) -> &[MeasurementResult] {
        &self.results
    }

    /// Record-level completeness: the weakest of the results', demoted to
    /// `partial` when an engine could not run at all.
    pub fn completeness(&self) -> Completeness {
        self.completeness
    }

    /// Reach a verdict and emit the record.
    pub fn finish(self, iteration: Advance) -> MeasurementRecord {
        let context = VerdictContext {
            policy: &self.policy,
            policy_change: self.policy_change.as_ref(),
            engine_failures: &self.engine_failures,
            stale_claim_ids: &self.stale_claim_ids,
            iteration_state_recovered: iteration.recovered,
        };
        let verdict = verdict::evaluate(&self.results, &context, iteration.state);

        MeasurementRecord {
            schema_version: SCHEMA_VERSION,
            record_kind: self.record_kind,
            tool: self.tool,
            compare_context: self.compare_context,
            invocation: self.invocation,
            reserved: self.reserved,
            policy_hash: self.policy_hash,
            completeness: self.completeness,
            verdict,
            // Unwitnessed, and not by omission: trust is earned from CI, so a
            // record that set its own attestation value could pass itself. The
            // fired signals ride along because the deterministic tamper channel
            // is agent-visible by design (PRE-DECISIONS, trust model); the
            // verifier recomputes them regardless.
            attestation: AttestationBlock {
                tamper_signals: tamper_signals::fired_signals(&self.results),
                ..AttestationBlock::default()
            },
            results: self.results,
        }
    }
}

/// Validate engine outputs and apply policy, stopping short of the verdict.
pub fn prepare(request: AssembleRequest<'_>) -> Result<Prepared, AssemblyError> {
    let AssembleRequest {
        tool,
        record_kind,
        compare_context,
        invocation,
        reserved,
        policy,
        registry,
        engines,
        engine_failures,
        policy_change,
    } = request;

    // Engine order is the grouping key, and it is sorted so that the record does
    // not depend on the order a caller happened to register engines in. Within
    // an engine, emission order is preserved.
    let mut engines = engines;
    engines.sort_by(|a, b| a.descriptor.engine_id.cmp(&b.descriptor.engine_id));

    let mut seen_engines: BTreeSet<&str> = BTreeSet::new();
    for output in &engines {
        if !seen_engines.insert(output.descriptor.engine_id.as_str()) {
            return Err(AssemblyError::DuplicateEngine {
                engine_id: output.descriptor.engine_id.clone(),
            });
        }
    }

    let mut results: Vec<MeasurementResult> = Vec::new();
    let mut pairing_keys: BTreeSet<(String, String)> = BTreeSet::new();
    for output in engines {
        let descriptor = output.descriptor;
        for mut result in output.results {
            validate(&result, &descriptor)?;

            // The verifier pairs on exactly this key. Two results sharing it
            // make pairing ambiguous, and `crate::compare::pair_results` takes
            // the first match — so a duplicate could shadow an honest result
            // with a forged one and the compare would never see the original.
            let scope_key = scope_key(&result.scope);
            if !pairing_keys.insert((result.metric_id.clone(), scope_key)) {
                return Err(AssemblyError::DuplicateResult {
                    metric_id: result.metric_id.clone(),
                    scope: Box::new(result.scope.clone()),
                });
            }

            resolve_evidence(&mut result, registry)?;
            results.push(result);
        }
    }

    // Severity is outside the digest input, so applying policy after sealing
    // cannot invalidate a digest — and it has to be after, because the verifier
    // applies its own policy to the same sealed numbers.
    verdict::severity::apply(&mut results, policy);

    let completeness = record_completeness(&results, &engine_failures);
    let stale_claim_ids = registry.stale_claim_ids();
    let countable = verdict::has_countable_finding(
        &results,
        &VerdictContext {
            policy,
            policy_change: policy_change.as_ref(),
            engine_failures: &engine_failures,
            stale_claim_ids: &stale_claim_ids,
            iteration_state_recovered: false,
        },
    );

    let policy_hash = policy
        .policy_hash()
        .map_err(|e| AssemblyError::PolicyHash(e.to_string()))?;

    Ok(Prepared {
        tool,
        record_kind,
        compare_context,
        invocation,
        reserved,
        policy_hash,
        policy: policy.clone(),
        results,
        engine_failures,
        policy_change,
        stale_claim_ids,
        completeness,
        countable,
    })
}

/// Every check that is about one result.
fn validate(
    result: &MeasurementResult,
    descriptor: &EngineDescriptor,
) -> Result<(), AssemblyError> {
    if result.engine_id != descriptor.engine_id {
        return Err(AssemblyError::EngineMismatch {
            metric_id: result.metric_id.clone(),
            claimed: result.engine_id.clone(),
            actual: descriptor.engine_id.clone(),
        });
    }
    let regime_family = result.measurement_regime.family();
    if result.family != descriptor.family || result.family != regime_family {
        return Err(AssemblyError::FamilyMismatch {
            engine_id: descriptor.engine_id.clone(),
            metric_id: result.metric_id.clone(),
            result: result.family,
            descriptor: descriptor.family,
            regime: regime_family,
        });
    }
    if result.digest.is_empty() {
        return Err(AssemblyError::Unsealed {
            engine_id: descriptor.engine_id.clone(),
            metric_id: result.metric_id.clone(),
        });
    }
    if tamper_signals::is_tamper_flag(result)
        && tamper_signals::signal_for(&result.metric_id).is_none()
    {
        return Err(AssemblyError::UnknownTamperSignal {
            metric_id: result.metric_id.clone(),
        });
    }
    Ok(())
}

/// Reconcile a result's evidence against the merged registry.
///
/// The merged registry is authoritative for the two things that are properties
/// of the *repository* rather than of the binary:
///
/// - **`stale`**, which is a function of the run date and nothing else. The
///   `EvidenceRef` contract names the loader as what sets it.
/// - **`does_not_predict` lines the registry declares and the result lacks**,
///   which is how an honesty line added to the registry reaches a payload
///   produced by a binary built before it.
///
/// What is deliberately *not* overwritten is the whole array. Engines insert a
/// parse-degradation caveat at the front (`crate::parse_health`), and replacing
/// the array with the registry's copy would erase it — deleting the one line
/// that tells a reader the number came off a partial tree.
///
/// `tier` and `citation` are left as the engine resolved them. A binary whose
/// compiled registry disagrees with the checkout is an old binary, and the
/// mechanism for that already exists and is digest-bound: `engine_version` is
/// part of the `measurement_regime`, so the verifier reports
/// `unwitnessed-version-skew` rather than an accusation (PREMORTEM S4).
fn resolve_evidence(
    result: &mut MeasurementResult,
    registry: &LoadedRegistry,
) -> Result<(), AssemblyError> {
    let Some(resolved) = registry.registry.claims.get(&result.claim_id) else {
        // The registry lint, live in the measurement path.
        return Err(AssemblyError::UnknownClaim {
            metric_id: result.metric_id.clone(),
            claim_id: result.claim_id.clone(),
        });
    };
    result.evidence.stale = resolved.stale;
    for line in &resolved.claim.does_not_predict {
        if !result.evidence.does_not_predict.contains(line) {
            result.evidence.does_not_predict.push(line.clone());
        }
    }
    Ok(())
}

/// The record-level completeness.
///
/// The weakest of the results', and never stronger than `partial` when an engine
/// failed outright — a record that says `complete` while an engine produced
/// nothing is a record claiming to have measured what it did not.
fn record_completeness(
    results: &[MeasurementResult],
    engine_failures: &[EngineFailure],
) -> Completeness {
    let weakest = parse_health::weakest(results);
    if engine_failures.is_empty() {
        return weakest;
    }
    if parse_health::weakness_rank(weakest) < parse_health::weakness_rank(Completeness::Partial) {
        weakest
    } else {
        Completeness::Partial
    }
}

/// The scope half of the verifier's pairing key, as a comparable string.
fn scope_key(scope: &ResultScope) -> String {
    // Through the canonical serializer so that the key is the same bytes the
    // digest input would see, rather than a second opinion about what a scope is.
    crate::canonical::to_canonical_string(scope).unwrap_or_else(|_| format!("{scope:?}"))
}

/// Results grouped by the engine that produced them.
///
/// **The only grouping this module offers, and deliberately so.** Family is not
/// a partition of engines: `static-metrics` and the P1.5 trust spike both report
/// the `static` family, so a family-keyed group would merge a production engine's
/// numbers with the spike's (PLAN wave-1 integration, P5a-entry note 2).
pub fn group_by_engine(results: &[MeasurementResult]) -> BTreeMap<&str, Vec<&MeasurementResult>> {
    let mut grouped: BTreeMap<&str, Vec<&MeasurementResult>> = BTreeMap::new();
    for result in results {
        grouped
            .entry(result.engine_id.as_str())
            .or_default()
            .push(result);
    }
    grouped
}

#[cfg(test)]
mod tests;
