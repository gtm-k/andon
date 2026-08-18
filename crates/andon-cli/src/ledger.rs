//! `andon ledger` — records in the commit, read and written.
//!
//! # What this is, and what P8 adds
//!
//! The ledger is the repository as a longitudinal dataset: every measurement
//! recorded against the commit it measured, in a git notes namespace, dimensioned
//! by who asked, through what harness, on which pass. **P8 owns the full
//! machinery** — the dimensions query, `ledger stats --distribution`, squash
//! migration as a supported operation, fault-injected push failures.
//!
//! What is here is the part the CLI needs to be useful on its own and no more:
//! append this measurement to the commit, list what is recorded, show one
//! commit's records, and clear the iteration counter once a human has looked at
//! an escalation. The notes plumbing itself is P1.5's
//! (`andon_ledger_min::notes`), already concurrency-safe and squash-aware; this
//! is a caller, not a second implementation.
//!
//! # `ack` is here rather than nowhere
//!
//! `IterationStore::reset` documents the exit from `escalate_to_human`: without
//! it a branch that once passed the cap escalates for ever, because escalation
//! has no other way out and the human whose decision it is has no way to record
//! having made it. That is a ledger operation — an actor recording a decision
//! against a branch — so it lives beside the other one.

use std::fmt::Write as _;

use andon_core::git::Git;
use andon_core::policy::Policy;
use andon_core::schema::payload::MeasurementRecord;
use andon_core::verdict::iteration::IterationStore;
use andon_ledger_min::notes::{Notes, MEASURE_REF};

use crate::store;

/// Append a record to `refs/notes/andon-measure` on the commit it measured.
pub fn record(git: &Git, record: &MeasurementRecord) -> Result<String, String> {
    let notes = Notes::new(git, MEASURE_REF);
    notes
        .append(&record.compare_context.head_oid, record)
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "recorded against {} in {MEASURE_REF}",
        crate::resolve::short(&record.compare_context.head_oid)
    ))
}

/// Every commit carrying a measurement record.
pub fn list(git: &Git) -> Result<String, String> {
    let notes = Notes::new(git, MEASURE_REF);
    let commits = notes.annotated_commits().map_err(|e| e.to_string())?;
    let mut out = String::new();
    if commits.is_empty() {
        let _ = writeln!(
            out,
            "\n  No measurement is recorded in {MEASURE_REF} in this checkout.\n  \
             `andon measure --record` writes one against the commit it measured.\n"
        );
        return Ok(out);
    }
    let _ = writeln!(out, "\n  {} commit(s) carry a record.\n", commits.len());
    for commit in commits {
        let records = notes.read(&commit).map_err(|e| e.to_string())?;
        let verdicts: Vec<String> = records
            .iter()
            .map(|r| {
                format!(
                    "{} ({:?})",
                    crate::render::verdict_word(r.verdict.verdict),
                    r.invocation.source
                )
            })
            .collect();
        let _ = writeln!(
            out,
            "    {}  {} record(s): {}",
            crate::resolve::short(&commit),
            records.len(),
            verdicts.join(", ")
        );
    }
    let _ = writeln!(out);
    Ok(out)
}

/// The records recorded against one commit.
pub fn show(git: &Git, commit: &str) -> Result<Vec<MeasurementRecord>, String> {
    Notes::new(git, MEASURE_REF)
        .read(commit)
        .map_err(|e| e.to_string())
}

/// Clear the iteration counter for a branch, the exit from `escalate_to_human`.
pub fn ack(git: &Git, branch: Option<&str>, policy: &Policy) -> Result<String, String> {
    let branch = match branch {
        Some(name) => name.to_string(),
        None => git
            .cmd(["symbolic-ref", "--quiet", "--short", "HEAD"])
            .succeeds_with_output()
            .map_err(|e| e.to_string())?
            .map(|name| name.trim().to_string())
            .ok_or_else(|| {
                "HEAD is detached, so there is no branch to acknowledge. Name one: \
                 `andon ledger ack --branch <name>`"
                    .to_string()
            })?,
    };
    let store = IterationStore::open(store::state_dir(git)).map_err(|e| e.to_string())?;
    let before = store.peek(&branch, policy.loop_policy.iteration_cap);
    store.reset(&branch).map_err(|e| e.to_string())?;
    Ok(format!(
        "  {branch}: the loop counter was at pass {} of a cap of {}; it now reads 0.\n  \
         The next measurement on this branch starts a fresh loop.\n",
        before.count, before.cap
    ))
}
