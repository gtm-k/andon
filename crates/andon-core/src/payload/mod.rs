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
//! - **Nothing enters a payload without evidence, and none of it is rebound.**
//!   Every result's `claim_id` must resolve in the merged registry *and* be the
//!   claim that registry declares for its metric, with the same actionability
//!   and the same determinism. The registry lint has failed builds since P0;
//!   this is the same rule at the measurement boundary, so a binary cannot
//!   report a number whose claim nobody declared — nor one standing on evidence
//!   gathered about a different metric ([`registry_load`]).
//! - **Every digest is recomputed here.** A non-empty `digest` proves only that
//!   something sealed something at some point. Assembly recomputes each one from
//!   the result's own contents against *this* payload's compare context, so a
//!   result sealed against another change cannot ride in.
//! - **No result may be stamped with a family it did not come from.** A
//!   mis-stamped `family` seals consistently and passes the verifier's compare,
//!   because both sides make the same mistake — so a wrong stamp is invisible
//!   exactly where it matters. Checked three ways here, and refused at the
//!   engine boundary too ([`crate::engine::run_engine`]).
//! - **Nothing pairs twice.** The verifier pairs results on
//!   `(metric_id, scope)`; two results sharing one pair make the pairing
//!   ambiguous, and an ambiguous pairing is a place a forged result can shadow
//!   an honest one.
//! - **Every engine the registry declares is accounted for.** Each appears
//!   exactly once, as an output or as a named failure, and nothing appears that
//!   no registry file declares ([`account_for_every_engine`]). "Assembly from
//!   all engines" is the phase's own acceptance criterion, and until this check
//!   existed nothing held it: a payload assembled from no engines at all came
//!   out `complete` and `pass`.
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
    /// A result's digest is not the digest of what it carries, against the
    /// tuple this payload is being assembled for.
    #[error(
        "result '{metric_id}' from '{engine_id}' carries a digest that is not the digest of \
         its own contents against ({base_oid}, {head_oid})"
    )]
    DigestMismatch {
        /// The engine.
        engine_id: String,
        /// The metric.
        metric_id: String,
        /// The base this payload is for.
        base_oid: String,
        /// The head this payload is for.
        head_oid: String,
    },
    /// A result reports a metric no registry file declares.
    #[error(
        "result '{metric_id}' from '{engine_id}' names a metric the registry does not declare"
    )]
    UndeclaredMetric {
        /// The engine.
        engine_id: String,
        /// The metric.
        metric_id: String,
    },
    /// A result cites a claim other than the one its metric declares.
    #[error(
        "metric '{metric_id}' is declared against claim '{declared}' and this result cites \
         '{cited}'"
    )]
    MetricRebound {
        /// The metric.
        metric_id: String,
        /// What the registry declares for it.
        declared: String,
        /// What the result cited instead.
        cited: String,
    },
    /// A result disagrees with the registry about what kind of metric it is.
    #[error("metric '{metric_id}' is declared {field} {declared} and this result says {carried}")]
    MetricDeclarationMismatch {
        /// The metric.
        metric_id: String,
        /// Which property disagrees: `class` or `deterministic`.
        field: &'static str,
        /// What the registry declares.
        declared: String,
        /// What the result carries.
        carried: String,
    },
    /// A result's top-level claim and its resolved evidence name different
    /// claims.
    #[error(
        "result '{metric_id}' cites claim '{claim_id}' and carries evidence for \
         '{evidence_claim_id}'"
    )]
    EvidenceClaimMismatch {
        /// The metric.
        metric_id: String,
        /// The top-level claim.
        claim_id: String,
        /// The claim the evidence names.
        evidence_claim_id: String,
    },
    /// An engine the registry declares contributed neither results nor a
    /// failure.
    #[error(
        "engine '{engine_id}' is declared in the registry and appears in this payload neither          as an output nor as a failure"
    )]
    MissingEngine {
        /// The engine nobody accounted for.
        engine_id: String,
    },
    /// An output or failure names an engine the registry does not declare.
    #[error("engine '{engine_id}' contributed to this payload and no registry file declares it")]
    UnknownEngine {
        /// The engine nobody declared.
        engine_id: String,
    },
    /// Two failure entries name the same engine.
    #[error("engine '{engine_id}' failed twice in one payload")]
    DuplicateFailure {
        /// The engine named twice.
        engine_id: String,
    },
    /// One engine both produced results and reported a failure.
    #[error("engine '{engine_id}' both produced results and reported a failure")]
    EngineSucceededAndFailed {
        /// The engine in both lists.
        engine_id: String,
    },
    /// A self-report carried a justification marked as verified.
    #[error(
        "this is a self-report and it carries a justification marked verified ({reference});          only a verifier writing an attestation record can mint one"
    )]
    UnverifiableJustification {
        /// The reference the justification claimed.
        reference: String,
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

    account_for_every_engine(&engines, &engine_failures, &registry.expected_engines)?;

    // The binary under measurement cannot mark its own excuse as checked. A
    // self-report that could would be a record that passes itself — the same
    // argument that keeps this module from setting its own attestation value,
    // applied to the one other field that turns a `block` into an `advise`. The
    // verifier writes attestation records and reads the ledger from the trusted
    // side, so it is the party that may (`crate::verdict::policy_change`).
    if record_kind == RecordKind::SelfReport {
        if let Some(verified) = policy_change
            .as_ref()
            .and_then(|c| c.justification.as_ref())
            .filter(|j| j.is_verified())
        {
            return Err(AssemblyError::UnverifiableJustification {
                reference: verified.reference().to_string(),
            });
        }
    }

    let mut results: Vec<MeasurementResult> = Vec::new();
    let mut pairing_keys: BTreeSet<(String, String)> = BTreeSet::new();
    for output in engines {
        let descriptor = output.descriptor;
        for mut result in output.results {
            let resolved = validate(&result, &descriptor, &compare_context, registry)?;

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

            resolve_evidence(&mut result, resolved);
            results.push(result);
        }
    }

    // Severity is outside the digest input, so applying policy after sealing
    // cannot invalidate a digest — and it has to be after, because the verifier
    // applies its own policy to the same sealed numbers.
    verdict::severity::apply(&mut results, policy);

    let completeness = record_completeness(&results, &engine_failures);
    let stale_claim_ids = registry.stale_claim_ids();
    // `iteration_state_recovered` is not known until the counter has been read,
    // which is the step this answer feeds. Passing `false` is safe rather than
    // merely convenient: `has_countable_finding` is a pure function of the
    // results, the policy, and the policy edit, all three of which `Prepared`
    // then owns unchanged — so the recomputation inside `finish` cannot reach a
    // different answer. `the_countable_answer_survives_the_round_trip` pins that,
    // because a future dependency on the recovery flag would make the two
    // disagree and the counter would advance against a verdict that had already
    // decided otherwise.
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

/// Every engine the registry declares appears exactly once, and nothing else
/// appears at all.
///
/// # Why an unaccounted engine is a bug and not a quiet zero
///
/// PLAN P5a's first acceptance criterion is "payload assembly **from all
/// engines**", and before this check there was nothing behind that phrase. An
/// empty engine list with no failures assembled into an empty payload marked
/// `complete` and `pass` — a record saying every engine ran and found nothing,
/// produced by a run in which no engine ran at all. The two states are
/// indistinguishable downstream, and the wrong one is the one that passes.
///
/// The consequence is not merely cosmetic. A record whose detectors were never
/// invoked is exactly what a change that wants to avoid a detector would like
/// to produce, and `completeness` is inside the digest input — so the honest
/// version of the same run (`partial`, with the engines named as failures) is a
/// *different record*, and the verifier can tell them apart. Without the check
/// there was no honest version to differ from.
///
/// The roster comes from the registry rather than from a constant: the
/// `engine =` header of every file the loader read. Five today; whatever the
/// deployment ships tomorrow.
fn account_for_every_engine(
    engines: &[EngineOutput],
    failures: &[EngineFailure],
    expected: &BTreeSet<String>,
) -> Result<(), AssemblyError> {
    let mut succeeded: BTreeSet<&str> = BTreeSet::new();
    for output in engines {
        let engine_id = output.descriptor.engine_id.as_str();
        if !succeeded.insert(engine_id) {
            return Err(AssemblyError::DuplicateEngine {
                engine_id: engine_id.to_string(),
            });
        }
    }

    let mut failed: BTreeSet<&str> = BTreeSet::new();
    for failure in failures {
        let engine_id = failure.engine_id.as_str();
        if !failed.insert(engine_id) {
            return Err(AssemblyError::DuplicateFailure {
                engine_id: engine_id.to_string(),
            });
        }
        if succeeded.contains(engine_id) {
            // Both at once is not a partial success to be merged. One of the two
            // statements is false and assembly cannot tell which.
            return Err(AssemblyError::EngineSucceededAndFailed {
                engine_id: engine_id.to_string(),
            });
        }
    }

    for engine_id in succeeded.iter().chain(failed.iter()) {
        if !expected.contains(*engine_id) {
            return Err(AssemblyError::UnknownEngine {
                engine_id: (*engine_id).to_string(),
            });
        }
    }
    for engine_id in expected {
        if !succeeded.contains(engine_id.as_str()) && !failed.contains(engine_id.as_str()) {
            return Err(AssemblyError::MissingEngine {
                engine_id: engine_id.clone(),
            });
        }
    }
    Ok(())
}

/// Every check that is about one result.
///
/// # What "sealed" has to mean here
///
/// Checking that `digest` is non-empty proves that something ran `seal` at some
/// point, over some contents, against some tuple. None of those are the question
/// assembly is asking. A result sealed against a different `(base_oid, head_oid)`
/// is a measurement of a different change, and it used to assemble cleanly into
/// a payload claiming this one — so the digest is recomputed from the result's
/// own contents against **this** payload's compare context and compared.
///
/// # And what the registry is authoritative for
///
/// A `claim_id` that resolves is not the same as a `claim_id` that belongs. The
/// registry declares, per metric, exactly one claim and exactly one answer to
/// "is this diff-actionable" and "is this in the compare set" — and a result may
/// not disagree with any of the three. Before this, a known metric rebound to
/// some *other* valid claim assembled without complaint, which is a number
/// standing on evidence that was gathered about something else. `class` and
/// `deterministic` matter for the same reason from the other end: they decide
/// whether a finding may block and whether the verifier will compare it, and a
/// result that carries its own answer decides both for itself.
fn validate<'r>(
    result: &MeasurementResult,
    descriptor: &EngineDescriptor,
    compare_context: &CompareContext,
    registry: &'r LoadedRegistry,
) -> Result<&'r crate::registry::ResolvedClaim, AssemblyError> {
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
    let recomputed = crate::canonical::digest(&result.digest_input(compare_context))
        .map_err(|e| AssemblyError::PolicyHash(format!("digest: {e}")))?;
    if recomputed != result.digest {
        return Err(AssemblyError::DigestMismatch {
            engine_id: descriptor.engine_id.clone(),
            metric_id: result.metric_id.clone(),
            base_oid: compare_context.base_oid.clone(),
            head_oid: compare_context.head_oid.clone(),
        });
    }

    let Some(declared) = registry.registry.metrics.get(&result.metric_id) else {
        return Err(AssemblyError::UndeclaredMetric {
            engine_id: descriptor.engine_id.clone(),
            metric_id: result.metric_id.clone(),
        });
    };
    if declared.claim_id != result.claim_id {
        return Err(AssemblyError::MetricRebound {
            metric_id: result.metric_id.clone(),
            declared: declared.claim_id.clone(),
            cited: result.claim_id.clone(),
        });
    }
    if declared.class != result.metric_class {
        return Err(AssemblyError::MetricDeclarationMismatch {
            metric_id: result.metric_id.clone(),
            field: "class",
            declared: format!("{:?}", declared.class),
            carried: format!("{:?}", result.metric_class),
        });
    }
    if declared.deterministic != result.deterministic {
        return Err(AssemblyError::MetricDeclarationMismatch {
            metric_id: result.metric_id.clone(),
            field: "deterministic",
            declared: declared.deterministic.to_string(),
            carried: result.deterministic.to_string(),
        });
    }
    // The two statements of the claim have to agree before the loader is allowed
    // to fill in `stale` and the honesty lines against one of them. Engines
    // insert caveats into the array, which is why `resolve_evidence` merges
    // rather than replaces — and a merge onto a disagreeing claim would attach
    // one claim's honesty lines to another claim's number.
    if result.evidence.claim_id != result.claim_id {
        return Err(AssemblyError::EvidenceClaimMismatch {
            metric_id: result.metric_id.clone(),
            claim_id: result.claim_id.clone(),
            evidence_claim_id: result.evidence.claim_id.clone(),
        });
    }

    if tamper_signals::is_tamper_flag(result)
        && tamper_signals::signal_for(&result.metric_id).is_none()
    {
        return Err(AssemblyError::UnknownTamperSignal {
            metric_id: result.metric_id.clone(),
        });
    }

    // The registry lint refuses a registry in which a declared metric cites a
    // claim nobody declares, and `registry_load` refuses to return one the lint
    // would fail — so reaching this arm means a caller built a `LoadedRegistry`
    // by hand from parts that do not agree. Its fields are public, so that is
    // possible; the refusal is what keeps it from becoming a payload citing
    // evidence that is not there.
    registry
        .registry
        .claims
        .get(&result.claim_id)
        .ok_or_else(|| AssemblyError::UnknownClaim {
            metric_id: result.metric_id.clone(),
            claim_id: result.claim_id.clone(),
        })
}

/// Reconcile a result's evidence against the claim [`validate`] resolved.
///
/// The claim is passed in rather than looked up again. Two lookups keyed on the
/// same string is one lookup and one opportunity for the two to answer
/// differently — and the second one used to carry the "no evidence" refusal,
/// which meant the rule lived in the function that had already been told the
/// answer.
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
fn resolve_evidence(result: &mut MeasurementResult, resolved: &crate::registry::ResolvedClaim) {
    result.evidence.stale = resolved.stale;
    for line in &resolved.claim.does_not_predict {
        if !result.evidence.does_not_predict.contains(line) {
            result.evidence.does_not_predict.push(line.clone());
        }
    }
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
