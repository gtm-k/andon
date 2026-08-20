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
//!
//! # The version-skew laundering window, and what this module does about it
//!
//! `engine_version` is **self-asserted**, it is part of the measurement regime,
//! and [`classify`] checks regime equality *before* it compares a single digest.
//! Those three facts together are a cloak: a forger stamps any engine version
//! the verifier is not running, forges every number, and the outcome is
//! `unwitnessed-version-skew` with `matched`, `mismatched` and
//! `flag_disagreements` all empty. The record does not pass — the
//! `unwitnessed-*` family never counts downstream — but the forgery leaves no
//! trace, and the same move re-cloaks the E4 `deterministic` flip, because the
//! early return happens before the flag comparison the flip would otherwise
//! show up in.
//!
//! **The durable fix is not here.** It is PLAN P9's hermetic version-matched
//! recompute: a verifier that reproduces the claimed regime has nothing to skew
//! against, so the cloak has no window to live in. That acceptance criterion
//! already exists and this module cross-references it rather than inventing a
//! competing one.
//!
//! What this module does instead is refuse to let the window be *silent*, using
//! only what the payload schema already carries:
//!
//! - **Regime disagreements are reported.** A `regime-skew` verdict reason names
//!   the results whose digests were withheld from the compare and the two engine
//!   versions involved, so a reader sees that a comparison did not happen and
//!   why, rather than seeing a quiet non-answer.
//! - **Flag disagreements are computed here, independently of [`classify`].**
//!   `classify` returns before it can record them under a skew; this module
//!   pairs the results itself, so flip-plus-skew surfaces the flip anyway.
//! - **Repeated skew on one head escalates.** Following R2-4's precedent for
//!   repeated base mismatches: one skewed report is a stale binary, and
//!   [`REPEAT_ESCALATION_THRESHOLD`] of them on the same head is a party not
//!   responding to a signal that has already been reported twice.
//!
//! What none of that does is *distinguish* an honest stale binary from a forger
//! wearing one. It cannot: both produce exactly the same record. Saying so is
//! the point — see `docs/trust-boundary.md`.

use andon_core::compare::{classify, BaseRelation, Classification, CompareInputs};
use andon_core::git::{Git, GitError, Revision};
use andon_core::schema::enums::{Attestation, InvocationSource, RecordKind, Verdict};
use andon_core::schema::payload::{
    AttestationBlock, MeasurementRecord, MeasurementResult, VerdictReason, VerifierIdentity,
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

/// Distinct non-passing self-reports of one kind on a single head before the
/// outcome escalates to a human.
///
/// Set ex ante at three, and the reasoning is the same one R2-4 gives for
/// repeated base mismatches. One skewed or stale report is an ordinary stale
/// binary. Two is that binary run twice. A third, after the first two have
/// already come back as non-passing, is a party that is not reading the answer —
/// and a loop that keeps producing unusable records is exactly what
/// `escalate_to_human` exists for (PREMORTEM A4/S6).
///
/// A constant rather than a policy field **only because this is the spike**. It
/// belongs in `.andon.toml` beside the iteration cap, where changing it is a
/// ledgered edit; P8 moves it there.
pub const REPEAT_ESCALATION_THRESHOLD: usize = 3;

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
    /// The base relation of the self-report that **produced the outcome** — the
    /// decisive one under the worst-of rule, not whichever happened to be first
    /// in the note.
    pub base_relation: Option<BaseRelation>,
    /// How many self-reports on this head disagree with the recompute about the
    /// measurement regime. The size of the version-skew laundering window.
    pub skewed_reports: usize,
    /// How many self-reports on this head claim a base that is an ancestor of
    /// the trusted branch (stale base or rebase).
    pub base_mismatched_reports: usize,
    /// True once repeated non-passing reports of one kind crossed
    /// [`REPEAT_ESCALATION_THRESHOLD`].
    pub escalated: bool,
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
    let decision = decide(git, request, &reports, &attest_record)?;

    // Reasons are built while `attest_record` is still the pure recompute, so
    // the disagreement helpers below compare the report against what the
    // verifier measured rather than against a record that has already been
    // stamped with an attestation.
    let escalated = decision.skewed >= REPEAT_ESCALATION_THRESHOLD
        || decision.base_mismatched >= REPEAT_ESCALATION_THRESHOLD;
    let reasons = reasons_for(&decision, &reports, &attest_record, escalated);

    attest_record.attestation = AttestationBlock {
        value: decision.classification.attestation,
        tamper_signals: decision.classification.tamper_signals.clone(),
        verifier: Some(verifier_identity(&trusted_base_oid)),
        compare: decision.classification.compare.clone(),
    };
    attest_record.verdict.verdict = verdict_for(decision.classification.attestation, escalated);
    attest_record.verdict.iteration.escalated = escalated;
    attest_record.verdict.reasons = reasons;

    Ok(VerifyOutcome {
        attestation: decision.classification.attestation,
        attest_record,
        trusted_base_oid,
        self_reports: reports.len(),
        base_relation: decision.base_relation,
        skewed_reports: decision.skewed,
        base_mismatched_reports: decision.base_mismatched,
        escalated,
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

/// Everything the verifier worked out about one head before it is rendered.
struct Decision {
    /// The outcome, from the worst-of report.
    classification: Classification,
    /// Which report produced it. `None` when there were no reports.
    decisive: Option<usize>,
    /// The decisive report's base relation.
    base_relation: Option<BaseRelation>,
    /// Reports whose regime disagrees with the recompute.
    skewed: usize,
    /// Reports claiming an ancestor base.
    base_mismatched: usize,
}

/// Classify every self-report, keep the worst, and count the kinds.
///
/// The counts are taken over **all** reports rather than the decisive one,
/// because the escalation question is "how many times has this head been handed
/// a record nobody can use", not "what did the loudest one say".
fn decide(
    git: &Git,
    request: &VerifyRequest,
    reports: &[MeasurementRecord],
    recompute: &MeasurementRecord,
) -> Result<Decision, VerifyError> {
    if reports.is_empty() {
        return Ok(Decision {
            classification: classify(
                None,
                recompute,
                CompareInputs {
                    // Immaterial with no report to compare, and `Equal` is the
                    // honest value: the verifier's base is its own.
                    base_relation: BaseRelation::Equal,
                    head_equal: true,
                    fork_tier: request.fork_tier,
                },
            ),
            decisive: None,
            base_relation: None,
            skewed: 0,
            base_mismatched: 0,
        });
    }

    let mut worst: Option<(usize, Classification, BaseRelation)> = None;
    let mut skewed = 0;
    let mut base_mismatched = 0;
    for (index, report) in reports.iter().enumerate() {
        let base_relation = base_relation_of(
            git,
            &report.compare_context.base_oid,
            &recompute.compare_context.base_oid,
            &request.trusted_branch,
        )?;
        if base_relation == BaseRelation::Ancestor {
            base_mismatched += 1;
        }
        if !regime_disagreements(report, recompute).is_empty() {
            skewed += 1;
        }
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
            Some((_, current, _)) => {
                attestation_rank(outcome.attestation) > attestation_rank(current.attestation)
            }
        };
        if replace {
            worst = Some((index, outcome, base_relation));
        }
    }
    let (decisive, classification, base_relation) = worst.expect("the report list is non-empty");
    Ok(Decision {
        classification,
        decisive: Some(decisive),
        base_relation: Some(base_relation),
        skewed,
        base_mismatched,
    })
}

/// Results the two sides both produced, paired by `(metric_id, scope)`.
///
/// A local copy of the pairing `classify` does internally, because the
/// disagreements below have to be computable **after** `classify` has already
/// returned early — which is the whole point of computing them here.
fn pairs<'a>(
    report: &'a MeasurementRecord,
    recompute: &'a MeasurementRecord,
) -> Vec<(&'a MeasurementResult, &'a MeasurementResult)> {
    report
        .results
        .iter()
        .filter_map(|reported| {
            recompute
                .results
                .iter()
                .find(|r| r.metric_id == reported.metric_id && r.scope == reported.scope)
                .map(|recomputed| (reported, recomputed))
        })
        .collect()
}

/// Paired results whose measurement regimes disagree.
///
/// Returns `(metric_id, claimed engine version, verifier engine version)`. The
/// versions are carried because "the regimes differ" is not actionable and
/// "the report claims engine 0.0.1-pre-history where this verifier runs 0.1.0"
/// is.
fn regime_disagreements(
    report: &MeasurementRecord,
    recompute: &MeasurementRecord,
) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = pairs(report, recompute)
        .into_iter()
        .filter(|(a, b)| a.measurement_regime != b.measurement_regime)
        .map(|(a, b)| {
            (
                a.metric_id.clone(),
                a.measurement_regime.engine_version().to_string(),
                b.measurement_regime.engine_version().to_string(),
            )
        })
        .collect();
    out.sort();
    out
}

/// Paired results the two sides disagree about the `deterministic` flag on.
///
/// Computed here rather than read off `CompareOutcome`, because a regime
/// mismatch makes `classify` return before it records any — which is how a
/// forger re-cloaks the E4 flip by stamping a version alongside it.
fn flag_disagreements(report: &MeasurementRecord, recompute: &MeasurementRecord) -> Vec<String> {
    let mut out: Vec<String> = pairs(report, recompute)
        .into_iter()
        .filter(|(a, b)| a.deterministic != b.deterministic)
        .map(|(a, _)| a.metric_id.clone())
        .collect();
    out.sort();
    out.dedup();
    out
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
///
/// Public because this ordering is the ONE ordering: `andon-ledger`'s durable
/// worst-of consumption rule (PLAN P8; decision log P1.5 (a)) re-exports this
/// function rather than restating the table, so the verifier's in-run worst-of
/// and a downstream consumer's read of the finished ledger cannot rank the same
/// two values differently.
pub fn attestation_rank(value: Attestation) -> u8 {
    match value {
        Attestation::Confirmed => 0,
        Attestation::ConfirmedStatic => 1,
        Attestation::Unwitnessed => 2,
        Attestation::UnwitnessedVersionSkew => 3,
        Attestation::UnwitnessedBaseMismatch => 4,
        // Ranked below `divergent` and above the rest of its family. It is not
        // an accusation, so it must not outrank one; and it is the only value
        // that can never improve — every other `unwitnessed-*` describes a
        // recompute that has not happened or did not line up, while this one
        // describes a head no verifier can ever check out. Worst-of should
        // prefer a record that might still be confirmed over one that cannot.
        Attestation::UnwitnessedUncommitted => 5,
        Attestation::Divergent => 6,
    }
}

/// The verdict the attest record carries.
///
/// One axis only. PLAN P9's two-axis rule takes the worse of this and the
/// verdict CI computes from its own recompute; the spike's three size counts
/// produce no findings, so the second axis has nothing to contribute yet and
/// pretending otherwise would be a claim this phase has not earned.
fn verdict_for(attestation: Attestation, escalated: bool) -> Verdict {
    // Escalation outranks the neutral outcomes and nothing else: a `block` is
    // already the strongest thing this axis can say, and turning it into
    // `escalate_to_human` would soften an accusation into a request for
    // attention.
    if escalated && !matches!(attestation, Attestation::Divergent) {
        return Verdict::EscalateToHuman;
    }
    match attestation {
        Attestation::Divergent => Verdict::Block,
        Attestation::Confirmed | Attestation::ConfirmedStatic => Verdict::Pass,
        // The `unwitnessed-*` family is neutral, not negative: no measurement was
        // witnessed, and saying "advise" is how that reaches a reader without
        // becoming an accusation.
        Attestation::Unwitnessed
        | Attestation::UnwitnessedVersionSkew
        | Attestation::UnwitnessedBaseMismatch
        // Neutral for the same reason as the rest of the family: a measurement
        // of uncommitted work is real and useful to its author, and it is
        // outside the trust boundary by construction rather than by suspicion.
        | Attestation::UnwitnessedUncommitted => Verdict::Advise,
    }
}

/// Machine-readable reason codes this module emits.
///
/// Named constants because a workflow, a report, and the fixture manifests all
/// branch on them, and a code that exists only as a string literal in one
/// `format!` is a contract nobody can see.
pub mod reason {
    /// A tamper signal fired in the attestation lane.
    pub const TAMPER_SIGNAL: &str = "tamper-signal";
    /// Digests were compared and disagreed.
    pub const DIGEST_MISMATCH: &str = "digest-mismatch";
    /// The two sides disagree about a result's `deterministic` flag.
    pub const FLAG_DISAGREEMENT: &str = "deterministic-flag-disagreement";
    /// A regime mismatch withheld results from the compare.
    pub const REGIME_SKEW: &str = "regime-skew";
    /// Repeated skewed reports on one head.
    pub const REPEATED_REGIME_SKEW: &str = "repeated-regime-skew";
    /// Repeated ancestor-base reports on one head.
    pub const REPEATED_BASE_MISMATCH: &str = "repeated-base-mismatch";
}

/// Why the verdict is what it is, one entry per contributing cause.
fn reasons_for(
    decision: &Decision,
    reports: &[MeasurementRecord],
    recompute: &MeasurementRecord,
    escalated: bool,
) -> Vec<VerdictReason> {
    use andon_core::schema::enums::Severity;

    let classification = &decision.classification;
    let mut reasons = Vec::new();
    for signal in &classification.tamper_signals {
        reasons.push(VerdictReason {
            code: reason::TAMPER_SIGNAL.to_string(),
            severity: TAMPER_SEVERITY,
            message: format!("{signal:?} raised by the attestation lane"),
            metric_ids: Vec::new(),
        });
    }
    if let Some(compare) = &classification.compare {
        if !compare.mismatched.is_empty() {
            reasons.push(VerdictReason {
                code: reason::DIGEST_MISMATCH.to_string(),
                severity: TAMPER_SEVERITY,
                message: format!(
                    "{} result(s) recomputed to a different value than was self-reported",
                    compare.mismatched.len()
                ),
                metric_ids: compare.mismatched.clone(),
            });
        }
    }

    // The two disagreements below are computed from the decisive report rather
    // than read off `CompareOutcome`, so they survive an early return. Under a
    // regime mismatch `classify` never reaches the flag comparison, and a
    // forger who stamps a version alongside an E4 flip would otherwise buy
    // silence for both.
    if let Some(report) = decision.decisive.map(|index| &reports[index]) {
        let flags = flag_disagreements(report, recompute);
        if !flags.is_empty() {
            reasons.push(VerdictReason {
                code: reason::FLAG_DISAGREEMENT.to_string(),
                // Recorded, not accused: an engine version can legitimately
                // change whether a metric is seed-free. It is visible because a
                // signal nobody can see is a signal that does not exist.
                severity: Severity::Low,
                message: format!(
                    "{} result(s) disagree with the verifier about the `deterministic` flag",
                    flags.len()
                ),
                metric_ids: flags,
            });
        }

        let regimes = regime_disagreements(report, recompute);
        if !regimes.is_empty() {
            let (_, claimed, verifier) = &regimes[0];
            reasons.push(VerdictReason {
                code: reason::REGIME_SKEW.to_string(),
                // Not an accusation. A stale binary produces exactly this, and
                // so does a forger wearing one — the spike cannot tell them
                // apart, which is why the window is documented rather than
                // policed. What this reason buys is that the withheld compare
                // is *visible*: someone reading the record can see that a
                // comparison did not happen, over which results, and between
                // which two claimed engine versions.
                severity: Severity::Low,
                message: format!(
                    "{} result(s) were withheld from the digest compare: the report claims \
                     engine {claimed} where this verifier ran {verifier}. \
                     A version-matched recompute (PLAN P9) is what closes this.",
                    regimes.len()
                ),
                metric_ids: regimes.iter().map(|(id, _, _)| id.clone()).collect(),
            });
        }
    }

    if escalated {
        if decision.skewed >= REPEAT_ESCALATION_THRESHOLD {
            reasons.push(VerdictReason {
                code: reason::REPEATED_REGIME_SKEW.to_string(),
                severity: Severity::Medium,
                message: format!(
                    "{} self-reports on this head disagree with the verifier's regime; \
                     the measurement has now been unusable {} times and a human should \
                     look at why (PLAN R2-4 escalation precedent)",
                    decision.skewed, decision.skewed
                ),
                metric_ids: Vec::new(),
            });
        }
        if decision.base_mismatched >= REPEAT_ESCALATION_THRESHOLD {
            reasons.push(VerdictReason {
                code: reason::REPEATED_BASE_MISMATCH.to_string(),
                severity: Severity::Medium,
                message: format!(
                    "{} self-reports on this head claim a base that is merely an ancestor \
                     of the trusted branch; repeated mismatches on one PR escalate \
                     (PLAN R2-4)",
                    decision.base_mismatched
                ),
                metric_ids: Vec::new(),
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
                attestation_rank(Attestation::Divergent) > attestation_rank(other),
                "divergent must outrank {other:?}"
            );
        }
        // And a confirmation is the only thing a second record can be beaten
        // down from, never up to.
        assert_eq!(attestation_rank(Attestation::Confirmed), 0);
    }

    #[test]
    fn only_confirmations_pass() {
        for value in [Attestation::Confirmed, Attestation::ConfirmedStatic] {
            assert_eq!(verdict_for(value, false), Verdict::Pass);
            assert!(value.counts_downstream());
        }
        assert_eq!(verdict_for(Attestation::Divergent, false), Verdict::Block);
        for value in [
            Attestation::Unwitnessed,
            Attestation::UnwitnessedVersionSkew,
            Attestation::UnwitnessedBaseMismatch,
        ] {
            assert_eq!(
                verdict_for(value, false),
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
