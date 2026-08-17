//! The verifier: recompute, resolve the base for itself, classify, attest.
//!
//! Four rules carry this module, and each one is a plan line that a plausible
//! shortcut would break.
//!
//! 1. **The checkout is pinned to the PR head SHA, and that is checked rather
//!    than trusted.** [`verify`] refuses when `HEAD` is not the commit it was
//!    asked to verify. GitHub's `pull_request` event checks out a *synthetic
//!    merge commit* by default — a commit that exists in no branch, that the
//!    agent never measured, and whose tuple therefore never matches. Verifying it
//!    would report `unwitnessed-base-mismatch` on every honest PR in the world
//!    (PLAN B3). A workflow that gets the checkout wrong now fails loudly at the
//!    verifier instead of quietly at the attestation.
//! 2. **The base is the verifier's own answer, never the record's.** It is
//!    `merge-base(trusted_branch, head)`, resolved here — which is also why
//!    *main advancing does not move it*, and why the moving-main fixture is a
//!    `confirmed` rather than a mismatch.
//! 3. **The base relation is classified, not merely detected** (PLAN R2-4). An
//!    ancestor base is a stale measurement or a rebase and demotes; a base that
//!    is not an ancestor, or that this repository has never heard of, is
//!    `base-fabrication` and forces `divergent`.
//! 4. **Compare-set membership is derived from the verifier's own registry.**
//!    [`crate::spike::metric_descriptors`] is compiled into this binary, so a
//!    self-report that flips `deterministic` to `false` changes what appears in
//!    `flag_disagreements` and nothing else (DEFERRED-APPROVALS E4).
//!
//! # Several self-reports on one commit
//!
//! `git notes append` and `cat_sort_uniq` both admit more than one record per
//! commit, legitimately: two engines, a re-run, a merged ledger. The verifier
//! classifies **every** self-report it finds and takes the worst outcome.
//!
//! Taking the best, or the first, or the newest would each hand an attacker the
//! same move: append one honest record beside the forged one and let the
//! verifier pick the flattering half. Worst-of has the opposite failure mode —
//! a stale record beside a fresh one demotes the pass — and demotion is the
//! direction R2-4 says to fail in.

use andon_core::compare::{classify, BaseRelation, Classification, CompareInputs};
use andon_core::git::{Git, GitError, Revision};
use andon_core::schema::enums::{Attestation, InvocationSource, RecordKind, Verdict};
use andon_core::schema::payload::{
    AttestationBlock, MeasurementRecord, VerdictReason, VerifierIdentity,
};

use crate::measure::{measure, MeasureError, TAMPER_SEVERITY};
use crate::notes::{Notes, NotesError};

/// Verification could not be performed.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// A git command failed.
    #[error(transparent)]
    Git(#[from] GitError),
    /// The recompute failed.
    #[error(transparent)]
    Measure(#[from] MeasureError),
    /// The ledger could not be read or written.
    #[error(transparent)]
    Notes(#[from] NotesError),
    /// The working tree is not checked out at the commit under verification.
    ///
    /// The guard behind PLAN B3. On GitHub's `pull_request` event the default
    /// checkout is a synthetic merge commit; verifying that instead of the PR
    /// head would make every honest PR a tuple mismatch.
    #[error(
        "the checkout is at {found}, not at the commit under verification ({expected}); \
         check out the PR head SHA (never the synthetic merge ref)"
    )]
    NotPinnedToHead {
        /// What the verifier was asked to verify.
        expected: String,
        /// What `HEAD` actually resolves to.
        found: String,
    },
    /// The commit or branch named does not resolve.
    #[error("{rev} does not resolve to a commit in this repository")]
    UnknownRevision {
        /// What was asked for.
        rev: String,
    },
}

/// What the verifier was asked to do.
#[derive(Debug, Clone)]
pub struct VerifyRequest {
    /// The PR head SHA. Must be what is checked out.
    pub head: String,
    /// The branch the verifier trusts, e.g. `origin/main`.
    pub trusted_branch: String,
    /// True for an unprivileged fork job, where notes refs do not travel
    /// (PREMORTEM T5). Wired here so the fork tier is representable; P9 owns the
    /// transport and the workflow-configuration assertions.
    pub fork_tier: bool,
}

/// Everything the verifier concluded.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    /// The attestation value, worst-of across every self-report found.
    pub attestation: Attestation,
    /// The verifier's own recompute, with its attestation block filled in. This
    /// is what is written to [`crate::notes::ATTEST_REF`].
    pub attest_record: MeasurementRecord,
    /// The base the verifier resolved for itself.
    pub trusted_base_oid: String,
    /// How many self-reports were found on the head commit.
    pub self_reports: usize,
    /// The base relation of the self-report that produced the outcome.
    pub base_relation: Option<BaseRelation>,
}

/// Recompute, compare, and produce an attestation.
///
/// Does not write anything. [`attest`] is the writing wrapper, so a caller that
/// wants the verdict without touching the ledger — a dry run, a test — is not
/// obliged to mutate the repository to get it.
pub fn verify(git: &Git, request: &VerifyRequest) -> Result<VerifyOutcome, VerifyError> {
    let head = resolve_commit(git, &request.head)?;
    let checked_out = resolve_commit(git, "HEAD")?;
    if head != checked_out {
        return Err(VerifyError::NotPinnedToHead {
            expected: head,
            found: checked_out,
        });
    }

    // The base is resolved as part of the recompute, so there is exactly one
    // answer and no chance of the classification and the measurement disagreeing
    // about what "the base" was.
    let (mut attest_record, _range) = measure(
        git,
        &Revision::merge_base(&request.trusted_branch),
        &Revision::Rev(head.clone()),
        RecordKind::Attestation,
        InvocationSource::CiVerifier,
        // The verifier's own version, always. Taking it from the record under
        // examination would make PREMORTEM S4's skew undetectable by
        // construction — the two regimes would agree because one side copied
        // the other.
        &crate::spike::engine_version(),
    )?;
    let trusted_base_oid = attest_record.compare_context.base_oid.clone();

    let reports = Notes::measure(git).read(&head)?;
    let classification = worst_classification(git, request, &reports, &attest_record)?;
    let base_relation = if reports.is_empty() {
        None
    } else {
        Some(base_relation_of(
            git,
            &reports[0].compare_context.base_oid,
            &trusted_base_oid,
            &request.trusted_branch,
        )?)
    };

    attest_record.attestation = AttestationBlock {
        value: classification.attestation,
        tamper_signals: classification.tamper_signals.clone(),
        verifier: Some(verifier_identity(&trusted_base_oid)),
        compare: classification.compare.clone(),
    };
    attest_record.verdict.verdict = verdict_for(classification.attestation);
    attest_record.verdict.reasons = reasons_for(&classification);

    Ok(VerifyOutcome {
        attestation: classification.attestation,
        attest_record,
        trusted_base_oid,
        self_reports: reports.len(),
        base_relation,
    })
}

/// Verify, then write the attestation to [`crate::notes::ATTEST_REF`].
pub fn attest(git: &Git, request: &VerifyRequest) -> Result<VerifyOutcome, VerifyError> {
    let outcome = verify(git, request)?;
    // `append`, not `write`: a second verifier run — a re-run of a job, a second
    // workflow — must not delete the first one's attestation. Two attestations
    // that disagree is information; one that silently replaced another is not.
    Notes::attest(git).append(
        &outcome.attest_record.compare_context.head_oid,
        &outcome.attest_record,
    )?;
    Ok(outcome)
}

/// Classify every self-report and keep the worst. See the module docs.
fn worst_classification(
    git: &Git,
    request: &VerifyRequest,
    reports: &[MeasurementRecord],
    recompute: &MeasurementRecord,
) -> Result<Classification, VerifyError> {
    if reports.is_empty() {
        return Ok(classify(
            None,
            recompute,
            CompareInputs {
                // Immaterial with no report to compare, and `Equal` is the
                // honest value: the verifier's base is its own.
                base_relation: BaseRelation::Equal,
                head_equal: true,
                fork_tier: request.fork_tier,
            },
        ));
    }

    let mut worst: Option<Classification> = None;
    for report in reports {
        let base_relation = base_relation_of(
            git,
            &report.compare_context.base_oid,
            &recompute.compare_context.base_oid,
            &request.trusted_branch,
        )?;
        let outcome = classify(
            Some(report),
            recompute,
            CompareInputs {
                base_relation,
                head_equal: report.compare_context.head_oid == recompute.compare_context.head_oid,
                fork_tier: request.fork_tier,
            },
        );
        let replace = match &worst {
            None => true,
            Some(current) => rank(outcome.attestation) > rank(current.attestation),
        };
        if replace {
            worst = Some(outcome);
        }
    }
    Ok(worst.expect("the report list is non-empty"))
}

/// How a claimed base relates to what the verifier trusts.
///
/// The order is the classification (PLAN R2-4): equality first, then existence,
/// then ancestry. An OID this repository has never seen cannot be tested for
/// ancestry at all, and `merge-base --is-ancestor` on it exits 128 — so
/// existence has to be settled before ancestry, or a fabricated OID would be
/// reported as a git failure rather than as the tamper signal it is.
pub fn base_relation_of(
    git: &Git,
    claimed: &str,
    trusted_base: &str,
    trusted_branch: &str,
) -> Result<BaseRelation, VerifyError> {
    if claimed == trusted_base {
        return Ok(BaseRelation::Equal);
    }
    // `^{commit}` and not `cat-file -e`: an OID that names a blob or a tree
    // exists, and is still not a base anything could have been measured against.
    let exists = git
        .cmd([
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &format!("{claimed}^{{commit}}"),
        ])
        .succeeds_with_output()?
        .is_some();
    if !exists {
        return Ok(BaseRelation::Unknown);
    }
    let is_ancestor = git
        .cmd(["merge-base", "--is-ancestor", claimed, trusted_branch])
        .succeeds()?;
    Ok(if is_ancestor {
        BaseRelation::Ancestor
    } else {
        BaseRelation::NotAncestor
    })
}

/// Worst-of ordering over attestation values.
///
/// Not derived from the enum's declaration order, which is a documentation
/// order: this is a trust ordering and it is spelled out so that adding a value
/// to the enum is a compile error here rather than a silent misplacement.
fn rank(value: Attestation) -> u8 {
    match value {
        Attestation::Confirmed => 0,
        Attestation::ConfirmedStatic => 1,
        Attestation::Unwitnessed => 2,
        Attestation::UnwitnessedVersionSkew => 3,
        Attestation::UnwitnessedBaseMismatch => 4,
        Attestation::Divergent => 5,
    }
}

/// The verdict the attest record carries.
///
/// One axis only. PLAN P9's two-axis rule takes the worse of this and the
/// verdict CI computes from its own recompute; the spike's three size counts
/// produce no findings, so the second axis has nothing to contribute yet and
/// pretending otherwise would be a claim this phase has not earned.
fn verdict_for(attestation: Attestation) -> Verdict {
    match attestation {
        Attestation::Divergent => Verdict::Block,
        Attestation::Confirmed | Attestation::ConfirmedStatic => Verdict::Pass,
        // The `unwitnessed-*` family is neutral, not negative: no measurement was
        // witnessed, and saying "advise" is how that reaches a reader without
        // becoming an accusation.
        Attestation::Unwitnessed
        | Attestation::UnwitnessedVersionSkew
        | Attestation::UnwitnessedBaseMismatch => Verdict::Advise,
    }
}

fn reasons_for(classification: &Classification) -> Vec<VerdictReason> {
    let mut reasons = Vec::new();
    for signal in &classification.tamper_signals {
        reasons.push(VerdictReason {
            code: "tamper-signal".to_string(),
            severity: TAMPER_SEVERITY,
            message: format!("{signal:?} raised by the attestation lane"),
            metric_ids: Vec::new(),
        });
    }
    if let Some(compare) = &classification.compare {
        if !compare.mismatched.is_empty() {
            reasons.push(VerdictReason {
                code: "digest-mismatch".to_string(),
                severity: TAMPER_SEVERITY,
                message: format!(
                    "{} result(s) recomputed to a different value than was self-reported",
                    compare.mismatched.len()
                ),
                metric_ids: compare.mismatched.clone(),
            });
        }
        if !compare.flag_disagreements.is_empty() {
            reasons.push(VerdictReason {
                code: "deterministic-flag-disagreement".to_string(),
                // Recorded, not accused: an engine version can legitimately
                // change whether a metric is seed-free. It is visible because a
                // signal nobody can see is a signal that does not exist.
                severity: andon_core::schema::enums::Severity::Low,
                message: format!(
                    "{} result(s) disagree with the verifier about the `deterministic` flag",
                    compare.flag_disagreements.len()
                ),
                metric_ids: compare.flag_disagreements.clone(),
            });
        }
    }
    reasons
}

/// Who attested, as far as v1 can say.
///
/// v1 trust is GitHub Actions provenance, not a signature: anyone with push
/// access can write `refs/notes/andon-attest`. Recorded in the record and
/// disclosed in `docs/trust-boundary.md`; sigstore signing is the named v1.5
/// hardening (advisor F4).
fn verifier_identity(trusted_base_oid: &str) -> VerifierIdentity {
    let on_actions = std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true");
    let run_ref = if on_actions {
        match (
            std::env::var("GITHUB_SERVER_URL"),
            std::env::var("GITHUB_REPOSITORY"),
            std::env::var("GITHUB_RUN_ID"),
        ) {
            (Ok(server), Ok(repo), Ok(run)) => Some(format!("{server}/{repo}/actions/runs/{run}")),
            _ => None,
        }
    } else {
        None
    };
    VerifierIdentity {
        provider: if on_actions {
            "github-actions".to_string()
        } else {
            // A local verifier run is a real thing — the fixture suite is one —
            // and calling it `github-actions` would put provenance in a record
            // that has none.
            "local".to_string()
        },
        run_ref,
        trusted_base_oid: trusted_base_oid.to_string(),
    }
}

fn resolve_commit(git: &Git, rev: &str) -> Result<String, VerifyError> {
    git.cmd([
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        &format!("{rev}^{{commit}}"),
    ])
    .succeeds_with_output()?
    .map(|text| text.trim().to_string())
    .filter(|oid| oid.len() >= 40)
    .ok_or_else(|| VerifyError::UnknownRevision {
        rev: rev.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_worst_of_ordering_puts_divergent_above_every_demotion() {
        // The property that closes "append an honest record beside a forged
        // one": whatever else is in the note, a divergence wins.
        for other in [
            Attestation::Confirmed,
            Attestation::ConfirmedStatic,
            Attestation::Unwitnessed,
            Attestation::UnwitnessedVersionSkew,
            Attestation::UnwitnessedBaseMismatch,
        ] {
            assert!(
                rank(Attestation::Divergent) > rank(other),
                "divergent must outrank {other:?}"
            );
        }
        // And a confirmation is the only thing a second record can be beaten
        // down from, never up to.
        assert_eq!(rank(Attestation::Confirmed), 0);
    }

    #[test]
    fn only_confirmations_pass() {
        for value in [Attestation::Confirmed, Attestation::ConfirmedStatic] {
            assert_eq!(verdict_for(value), Verdict::Pass);
            assert!(value.counts_downstream());
        }
        assert_eq!(verdict_for(Attestation::Divergent), Verdict::Block);
        for value in [
            Attestation::Unwitnessed,
            Attestation::UnwitnessedVersionSkew,
            Attestation::UnwitnessedBaseMismatch,
        ] {
            assert_eq!(
                verdict_for(value),
                Verdict::Advise,
                "{value:?} is neutral, never an accusation"
            );
            assert!(!value.counts_downstream());
        }
    }

    #[test]
    fn the_verifiers_compare_set_comes_from_its_own_registry() {
        // DEFERRED-APPROVALS E4, asserted at the source rather than only through
        // the fixture: the flag the verifier uses is compiled in, so there is no
        // path by which a self-report could supply it.
        for descriptor in crate::spike::metric_descriptors() {
            assert!(
                descriptor.deterministic,
                "{} must be deterministic for the E4 fixture to mean anything",
                descriptor.metric_id
            );
        }
    }
}
