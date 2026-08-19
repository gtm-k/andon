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

/// Append a record to `refs/notes/andon-measure`, anchored to a commit.
///
/// # Why the anchor is not always `head_oid`
///
/// A git note is attached to an object, and `head_oid` is only an object when
/// `head_kind` says `commit`. For an uncommitted head it is the content hash of
/// a working-tree snapshot, which git has never heard of — so `notes append`
/// failed with `failed to resolve ... as a valid ref` and the process exited 1
/// **after printing a full report**. Exit 1 means "the tool could not do its
/// job", so a BLOCK verdict was masked by the failure to file it, and
/// `refs/notes/andon-measure` stayed empty on every dirty measurement.
///
/// The same guard the rest of this crate already uses answers it:
/// `head_kind.is_witnessable()` is read at two places in `measure` for exactly
/// this distinction. Where the head is a commit, that commit is the anchor.
/// Where it is not, the anchor is the commit the uncommitted work sat on top of,
/// which is where a reader would look for it.
///
/// # Why the anchor is a parameter and not `rev-parse HEAD`
///
/// It was `rev-parse HEAD`, asked **after** the measurement, and that is a
/// different commit from the one the measurement was taken under whenever
/// anything moves the ref in between — a hook that commits, a second agent, a
/// rebase in another terminal. Measured: a snapshot taken under `c664569` filed
/// its note against `376f2d9`, a commit with a different tree that was never
/// underneath the bytes in the record.
///
/// So the anchor is captured with the snapshot and carried here.
/// [`andon_core::git::Endpoint::anchor_oid`] is that value — for a dirty endpoint
/// it is `DirtySnapshot::head_oid`, read in the same `status` scan that produced
/// the entries, and for a commit endpoint it is the commit itself. One accessor
/// covers both kinds, so this function does not have to ask which it has in
/// order to know where the note goes.
///
/// This matters beyond the race. The attachment point is the only durable record
/// of what a dirty measurement was taken *from*: `head_oid` is the snapshot's
/// content hash and `base_oid` is the fork point, so neither says which commit
/// the working tree sat on. A note filed against the wrong commit is not a
/// misplaced file; it is a false statement about what the numbers describe, and
/// the sentence this function returns makes it out loud.
///
/// The refusal that used to live here — "HEAD does not name one yet" — is gone
/// with the `rev-parse`, and it was unreachable before that: a dirty endpoint is
/// built by `resolve_endpoint`, which resolves `HEAD` to a commit before it takes
/// the snapshot, so an unborn HEAD fails resolution and never reaches a record.
///
/// # Why this cannot launder the measurement onto a later commit
///
/// The anchor is an attachment point and never an identity. The record still
/// carries the snapshot hash in `head_oid` and `head_kind:
/// uncommitted-worktree` beside it, so every reader is told what the numbers
/// describe. And the anchor is the commit that existed *underneath* the work:
/// committing that work produces a new OID, which carries no note, so the
/// measurement never becomes a statement about the commit that eventually
/// contained it.
pub fn record(git: &Git, record: &MeasurementRecord, anchor: &str) -> Result<String, String> {
    let ctx = &record.compare_context;
    let notes = Notes::new(git, MEASURE_REF);

    if ctx.head_kind.is_witnessable() {
        // The record's own head, not the caller's anchor. They are the same
        // commit for a witnessable head — `anchor_oid` returns the OID for a
        // commit endpoint — and the record is the party that has to be right
        // about what it measured.
        notes
            .append(&ctx.head_oid, record)
            .map_err(|e| e.to_string())?;
        return Ok(format!(
            "recorded against {} in {MEASURE_REF}",
            crate::resolve::short(&ctx.head_oid)
        ));
    }

    notes.append(anchor, record).map_err(|e| e.to_string())?;
    Ok(format!(
        "recorded against {} in {MEASURE_REF} — the commit this uncommitted work sat on when \
         the snapshot was taken, because a working tree is not an object a note can hang on.\n  \
         The record is keyed to the snapshot ({}) and carries head_kind \
         `uncommitted-worktree`, so it does not read as a measurement of {}.",
        crate::resolve::short(anchor),
        crate::resolve::short(&ctx.head_oid),
        crate::resolve::short(anchor)
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
