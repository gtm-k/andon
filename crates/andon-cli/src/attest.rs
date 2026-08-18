//! `andon attest-stub` — the verifier's shape, and nothing hardened.
//!
//! # What "stub" means here, precisely
//!
//! P9 builds the verifier. It owns the hermetic version-matched recompute, the
//! HMAC-seeded held-out sampling, fork-PR transport, the `--unshallow` rule
//! without which no process metric can ever confirm, and the two-axis
//! composition that keeps a missing self-report from laundering a CI-side tamper
//! finding into a neutral notice.
//!
//! **None of that is here.** What is here is the shape: recompute the same
//! change independently, read the self-report the agent left in the notes, and
//! run `andon_core::compare::classify` — the one implementation of the ordering
//! that keeps honest changes out of the tamper bucket. It exists so that the
//! CLI's six subcommands are all real, and so that the compare path has a caller
//! outside a test before P9 arrives.
//!
//! It says so in its own output. A stub that printed `confirmed` without saying
//! what it did not check would be a trust claim this code cannot support, which
//! is the one thing a tool about trust may not do.
//!
//! # Two things it does get right, because getting them wrong is worse than
//! not shipping
//!
//! - **The base is resolved here, not taken from the record.** A verifier that
//!   believed the record's own claim about what it measured against is not a
//!   verifier. `BaseRelation` comes from this repository's own ancestry.
//! - **Policy comes from the base commit.** Editing a threshold inside the change
//!   under measurement gains nothing.

use std::fmt::Write as _;

use andon_core::compare::{self, BaseRelation, CompareInputs};
use andon_core::git::Git;
use andon_core::schema::enums::{Attestation, InvocationSource, RecordKind};
use andon_core::schema::payload::MeasurementRecord;
use andon_ledger_min::notes::{Notes, MEASURE_REF};

use crate::measure::{self, PolicySource};

/// What to attest.
#[derive(Debug, Clone)]
pub struct Request {
    /// The repository.
    pub repo: std::path::PathBuf,
    /// The head SHA under examination. The PR head, never a synthetic merge ref.
    pub head: String,
    /// The branch this verifier trusts, for resolving its own base.
    pub trusted_branch: String,
    /// An unprivileged fork job, where notes do not travel.
    pub fork_tier: bool,
}

/// The outcome of a stub attestation.
#[derive(Debug)]
pub struct Attested {
    /// The classification.
    pub classification: compare::Classification,
    /// The verifier's own recompute.
    pub recompute: MeasurementRecord,
    /// The self-report found, if any.
    pub self_report: Option<MeasurementRecord>,
    /// How the claimed base related to the trusted branch.
    pub base_relation: BaseRelation,
}

/// Recompute and classify.
pub fn attest(request: &Request) -> Result<Attested, String> {
    let git = Git::open(&request.repo).map_err(|e| e.to_string())?;

    // The verifier's own base. Resolved from the branch it trusts, never read
    // off the record it is examining.
    let trusted_base = git
        .cmd([
            "merge-base",
            "--",
            &request.trusted_branch,
            &request.head,
        ])
        .succeeds_with_output()
        .map_err(|e| e.to_string())?
        .map(|text| text.trim().to_string())
        .ok_or_else(|| {
            format!(
                "no merge base between {} and {}. The verifier cannot resolve a base it trusts, \
                 so there is nothing to attest.",
                request.trusted_branch, request.head
            )
        })?;

    let measurement = measure::measure(&measure::Request {
        repo: request.repo.clone(),
        base: Some(trusted_base.clone()),
        head: Some(request.head.clone()),
        // A verifier never falls back. If there is nothing to measure, that is
        // the answer.
        no_fallback: true,
        registry_dir: None,
        self_measure: false,
        source: InvocationSource::CiVerifier,
        harness: None,
        model: None,
        record_kind: RecordKind::Attestation,
        policy_source: PolicySource::Commit(trusted_base.clone()),
    })
    .map_err(|e| e.to_string())?;

    let self_report = read_self_report(&git, &request.head)?;
    let claimed_base = self_report
        .as_ref()
        .map(|r| r.compare_context.base_oid.clone());
    let base_relation = relate(&git, claimed_base.as_deref(), &trusted_base)?;
    let head_equal = self_report
        .as_ref()
        .map(|r| r.compare_context.head_oid == measurement.record.compare_context.head_oid)
        .unwrap_or(false);

    let classification = compare::classify(
        self_report.as_ref(),
        &measurement.record,
        CompareInputs {
            base_relation,
            head_equal,
            fork_tier: request.fork_tier,
        },
    );

    Ok(Attested {
        classification,
        recompute: measurement.record,
        self_report,
        base_relation,
    })
}

/// The most recent self-report on a commit, or none.
///
/// Worst-of is P8's rule for several reports on one head, and this stub does not
/// implement it: it takes the last written. Named here rather than left as an
/// unstated simplification, because "which report did the verifier read" is
/// exactly the question a forger wants nobody to ask.
fn read_self_report(git: &Git, head: &str) -> Result<Option<MeasurementRecord>, String> {
    let records = Notes::new(git, MEASURE_REF)
        .read(head)
        .map_err(|e| e.to_string())?;
    Ok(records.into_iter().next_back())
}

/// How a claimed base relates to the branch this verifier trusts.
fn relate(
    git: &Git,
    claimed: Option<&str>,
    trusted_base: &str,
) -> Result<BaseRelation, String> {
    let Some(claimed) = claimed else {
        // No self-report, so no claim to relate. `classify` short-circuits
        // before reading this, and `Equal` is the value that adds nothing.
        return Ok(BaseRelation::Equal);
    };
    if claimed == trusted_base {
        return Ok(BaseRelation::Equal);
    }
    let known = git
        .cmd(["cat-file", "-e", &format!("{claimed}^{{commit}}")])
        .succeeds()
        .map_err(|e| e.to_string())?;
    if !known {
        return Ok(BaseRelation::Unknown);
    }
    let ancestor = git
        .cmd(["merge-base", "--is-ancestor", claimed, trusted_base])
        .succeeds()
        .map_err(|e| e.to_string())?;
    Ok(if ancestor {
        BaseRelation::Ancestor
    } else {
        BaseRelation::NotAncestor
    })
}

/// Render an attestation for a reader, including what was not checked.
pub fn render(attested: &Attested) -> String {
    let mut out = String::new();
    let value = attested.classification.attestation;
    let _ = writeln!(out, "\n  attestation   {}", wire_name(value));
    let _ = writeln!(
        out,
        "  meaning       {}",
        crate::render::attestation_line(value)
    );
    let _ = writeln!(
        out,
        "  counts        {}",
        if value.counts_downstream() {
            "yes — a record with this value counts as evidence downstream"
        } else {
            "no — this record does not count as attested evidence downstream"
        }
    );
    let _ = writeln!(
        out,
        "  self-report   {}",
        match &attested.self_report {
            Some(record) => format!(
                "found, measured against {} ({:?} relative to the base this verifier resolved)",
                crate::resolve::short(&record.compare_context.base_oid),
                attested.base_relation
            ),
            None => "none in refs/notes/andon-measure on this commit".to_string(),
        }
    );

    if let Some(outcome) = &attested.classification.compare {
        let _ = writeln!(
            out,
            "  digests       {} matched, {} disagreed, {} unpaired",
            outcome.matched.len(),
            outcome.mismatched.len(),
            outcome.unpaired.len()
        );
        if !outcome.mismatched.is_empty() {
            for metric in &outcome.mismatched {
                let _ = writeln!(out, "                  disagreed: {metric}");
            }
        }
        if !outcome.flag_disagreements.is_empty() {
            let _ = writeln!(
                out,
                "  flag drift    {} metric(s) where the two sides disagree about whether the \
                 result is in the compare set: {}",
                outcome.flag_disagreements.len(),
                outcome.flag_disagreements.join(", ")
            );
        }
    }

    if !attested.classification.tamper_signals.is_empty() {
        let _ = writeln!(
            out,
            "  raised        {}",
            attested
                .classification
                .tamper_signals
                .iter()
                .map(|s| format!("{s:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // The verifier's own verdict, printed beside the attestation and explicitly
    // NOT combined with it. P9's two-axis rule composes the two and takes the
    // worse, so that a missing self-report cannot launder a CI-side finding into
    // a neutral notice. Composing them here would be that rule half-built, which
    // is the seam P5a's mini-G2 was about.
    let _ = writeln!(
        out,
        "\n  verifier's own verdict on this change, from its own recompute: {}",
        crate::render::verdict_word(attested.recompute.verdict.verdict)
    );
    for reason in &attested.recompute.verdict.reasons {
        let _ = writeln!(out, "    {:<26} {}", reason.code, reason.message);
    }
    let _ = writeln!(
        out,
        "  The two are reported side by side and not combined. Composing them is P9's two-axis \
         rule, and it is not implemented here."
    );

    let _ = writeln!(
        out,
        "\n  THIS IS A STUB. It recomputed the change and compared digests. It did NOT run a \
         hermetic version-matched recompute, did NOT run held-out verification sampling, did \
         NOT compose the verifier's own verdict with this attestation, and did NOT write an \
         attestation record to refs/notes/andon-attest. P9 builds the verifier; treat this \
         output as a demonstration of the compare path, not as an attestation anyone should \
         rely on.\n"
    );
    out
}

/// The wire spelling of an attestation value, as the schema serializes it.
fn wire_name(value: Attestation) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_name_is_the_schema_spelling_and_not_a_second_one() {
        // Read off the serializer rather than restated, so a schema rename
        // cannot leave this printing the old word.
        assert_eq!(wire_name(Attestation::ConfirmedStatic), "confirmed-static");
        assert_eq!(
            wire_name(Attestation::UnwitnessedVersionSkew),
            "unwitnessed-version-skew"
        );
    }
}
