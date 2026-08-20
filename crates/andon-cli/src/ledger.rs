//! `andon ledger` — records in the commit, read and written.
//!
//! # What this is, and what P8 adds
//!
//! The ledger is the repository as a longitudinal dataset: every measurement
//! recorded against the commit it measured, in a git notes namespace, dimensioned
//! by who asked, through what harness, on which pass. The full machinery is
//! P8's `andon-ledger` crate — the dimensions query, `ledger stats
//! --distribution` with the clustering warning and the cross-regime refusal,
//! squash migration as a supported operation, and the sync loop whose exhausted
//! push retries fail red rather than quietly.
//!
//! What is here is rendering and dispatch and no more: append this measurement
//! to the commit, list what is recorded, show one commit's records, clear the
//! iteration counter once a human has looked at an escalation, and turn the
//! ledger crate's answers into sentences. The notes plumbing itself is P1.5's
//! (`andon_ledger_min::notes`), already concurrency-safe and squash-aware; both
//! this module and `andon-ledger` are callers, not second implementations.
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
use andon_ledger::migrate::migrate_squash;
use andon_ledger::stats::{self, Dimension, Filter};
use andon_ledger::sync::{sync_all, Pushed, SyncOptions};
use andon_ledger_min::notes::{Notes, ATTEST_REF, MEASURE_REF};

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

/// What `andon ledger stats` was asked for.
pub struct StatsRequest {
    /// Which ledger ref to read (`measure` or `attest`).
    pub notes_ref: String,
    /// Whether to include per-metric value distributions.
    pub distribution: bool,
    /// Whether pooled cross-regime aggregates were explicitly requested.
    pub across_regimes: bool,
    /// Slice one dimension with a verdict breakdown.
    pub by: Option<Dimension>,
    /// Keep only records matching this dimension=value restriction.
    pub filter: Option<Filter>,
}

/// The stats rendering, and whether any threshold-clustering warning fired.
///
/// The second half is for `--check`: a warning that only exists as prose in a
/// log is invisible to the one actor the CI cron has — the exit code — so the
/// caller turns `true` into a nonzero exit rather than grepping its own output.
pub fn stats_report(git: &Git, request: &StatsRequest) -> Result<(String, bool), String> {
    let scan = stats::load_ref(git, &request.notes_ref).map_err(|e| e.to_string())?;
    let total_loaded = scan.entries.len();
    let mut entries = scan.entries;
    if let Some(filter) = &request.filter {
        entries.retain(|entry| filter.matches(&entry.record));
    }

    let mut out = String::new();
    let _ = writeln!(out, "\n  {}\n", stats::SCOPE_LINE);
    let commits: std::collections::BTreeSet<&str> =
        entries.iter().map(|e| e.commit.as_str()).collect();
    let _ = writeln!(
        out,
        "  {} record(s) on {} commit(s) in {} ({:.1} KB of note bodies).",
        entries.len(),
        commits.len(),
        scan.notes_ref,
        scan.body_bytes as f64 / 1024.0
    );
    if let Some(filter) = &request.filter {
        let _ = writeln!(
            out,
            "  Filtered: {}={} kept {} of {} record(s).",
            filter.dimension.name(),
            filter.value,
            entries.len(),
            total_loaded
        );
    }
    if entries.is_empty() {
        let _ = writeln!(
            out,
            "\n  Nothing to summarize. `andon measure --record` writes a record against the\n  \
             commit it measured; `andon ledger sync` brings the remote's ledger here.\n"
        );
        return Ok((out, false));
    }

    match request.by {
        Some(dimension) => {
            let _ = writeln!(out, "\n  by {}:", dimension.name());
            for (value, cell) in stats::slice(&entries, dimension) {
                let verdicts: Vec<String> = cell
                    .verdicts
                    .iter()
                    .map(|(verdict, n)| format!("{verdict} {n}"))
                    .collect();
                let _ = writeln!(
                    out,
                    "    {value}: {} record(s) — {}",
                    cell.records,
                    verdicts.join(", ")
                );
            }
        }
        None => {
            let _ = writeln!(out, "\n  dimensions (slice one with --by <name>):");
            for dimension in Dimension::ALL {
                let sliced = stats::slice(&entries, dimension);
                let cells: Vec<String> = sliced
                    .iter()
                    .map(|(value, cell)| format!("{value} {}", cell.records))
                    .collect();
                let _ = writeln!(out, "    {}: {}", dimension.name(), cells.join(" · "));
            }
        }
    }

    let mut clustered = false;
    if request.distribution {
        let built = stats::distribution(
            &entries,
            &crate::shipped::ladder_for,
            request.across_regimes,
        );
        let _ = writeln!(out, "\n  distribution (per metric, per regime):");
        for metric in &built.metrics {
            let _ = writeln!(out, "    {}", metric.metric_id);
            for group in &metric.groups {
                let _ = writeln!(
                    out,
                    "      [{}]\n        {}",
                    group.regime_label,
                    summary_line(&group.summary)
                );
            }
            if let Some(pooled) = &metric.pooled {
                let _ = writeln!(
                    out,
                    "      [mixed-regime, pooled across {} regimes by --across-regimes]\n        {}",
                    metric.groups.len(),
                    summary_line(pooled)
                );
            }
        }
        for refusal in &built.refusals {
            let _ = writeln!(out, "\n  {}", refusal.message.replace('\n', "\n  "));
        }
        for warning in &built.warnings {
            clustered = true;
            let _ = writeln!(out, "\n  WARNING: {}", warning.message);
        }
        if built.warnings.is_empty() {
            let _ = writeln!(
                out,
                "\n  No value distribution hugs a declared severity rung from below."
            );
        }
    }
    let _ = writeln!(out);
    Ok((out, clustered))
}

/// One summary line for a group of values.
fn summary_line(summary: &stats::ValueSummary) -> String {
    let mut parts = Vec::new();
    if summary.numeric > 0 {
        parts.push(format!(
            "{} numeric value(s): min {} · max {} · mean {:.2}",
            summary.numeric,
            trim_float(summary.min.unwrap_or(0.0)),
            trim_float(summary.max.unwrap_or(0.0)),
            summary.mean.unwrap_or(0.0)
        ));
    }
    if summary.fired + summary.unfired > 0 {
        parts.push(format!(
            "{} of {} flag(s) fired",
            summary.fired,
            summary.fired + summary.unfired
        ));
    }
    if summary.absent > 0 {
        parts.push(format!("{} absent (text marker)", summary.absent));
    }
    if parts.is_empty() {
        parts.push("no values".to_string());
    }
    parts.join(" · ")
}

/// Render a float without a trailing `.0` on whole numbers.
fn trim_float(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

/// Fetch, merge, and push both ledger refs.
pub fn sync(git: &Git, remote: &str, attempts: u32) -> Result<String, String> {
    let options = SyncOptions {
        attempts,
        ..SyncOptions::default()
    };
    // A failed sync propagates the loud message whole — including the
    // PushExhausted text that names the consequence and the recovery — and
    // main() turns it into exit 1.
    let synced = sync_all(git, remote, &options).map_err(|e| e.to_string())?;
    let mut out = String::new();
    for ref_sync in synced {
        let _ = match ref_sync.pushed {
            Pushed::NothingToPush => writeln!(
                out,
                "  {}: nothing recorded locally{}; nothing to push.",
                ref_sync.notes_ref,
                if ref_sync.fetched {
                    ""
                } else {
                    " and nothing on the remote"
                }
            ),
            Pushed::OnAttempt(1) => writeln!(
                out,
                "  {}: {}merged and pushed.",
                ref_sync.notes_ref,
                if ref_sync.fetched { "fetched, " } else { "" }
            ),
            Pushed::OnAttempt(n) => writeln!(
                out,
                "  {}: pushed on attempt {n} — the remote moved underneath the first push(es); \
                 the retry re-fetched, merged, and recovered every record.",
                ref_sync.notes_ref
            ),
        };
    }
    Ok(out)
}

/// One trailer line per record on `commit`, for a commit message.
///
/// The producing surface for the trailer digest option: notes refs do not
/// travel with a fork PR, and a commit message does, so a contributor on a
/// fork appends these lines to the commit message (`git commit --amend
/// --trailer "$(andon ledger trailer)"` or by hand) and P9's fork-tier
/// verifier compares against the digest with no notes transport at all.
///
/// The records come through the guarded reader — same path as `show` — so a
/// note line that cannot be believed refuses to become a trailer rather than
/// vouching for itself in a new medium.
pub fn trailer(git: &Git, commit: &str) -> Result<String, String> {
    let records = Notes::new(git, MEASURE_REF)
        .read(commit)
        .map_err(|e| e.to_string())?;
    if records.is_empty() {
        return Ok(format!(
            "\n  No record is recorded against {commit} in {MEASURE_REF}, so there is no \
             trailer to emit.\n  `andon measure --record` writes one against the commit it \
             measured.\n"
        ));
    }
    let mut out = String::new();
    for record in &records {
        let _ = writeln!(
            out,
            "{}",
            andon_ledger::trailer::trailer_line(record).map_err(|e| e.to_string())?
        );
    }
    Ok(out)
}

/// Carry both refs' records from a pre-squash head onto the landed commit.
pub fn migrate(git: &Git, from: &str, to: &str) -> Result<String, String> {
    let migrations = migrate_squash(git, from, to).map_err(|e| e.to_string())?;
    let mut out = String::new();
    let mut moved_any = false;
    for migration in migrations {
        if migration.source_records == 0 {
            let _ = writeln!(
                out,
                "  {}: no records on the source commit; nothing to migrate.",
                migration.notes_ref
            );
        } else {
            moved_any = true;
            let _ = writeln!(
                out,
                "  {}: {} record(s) migrated; the landed commit now carries {}.",
                migration.notes_ref, migration.source_records, migration.target_records
            );
        }
    }
    if moved_any {
        let _ = writeln!(
            out,
            "  The source notes stay in place — the pre-squash commits are still history and\n  \
             their records are still true of them. Run `andon ledger sync` to publish."
        );
    }
    Ok(out)
}

/// The notes ref a user-facing name selects.
pub fn ref_named(name: &str) -> Result<&'static str, String> {
    match name {
        "measure" => Ok(MEASURE_REF),
        "attest" => Ok(ATTEST_REF),
        other => Err(format!(
            "'{other}' is not a ledger ref name; the refs are 'measure' ({MEASURE_REF}) and \
             'attest' ({ATTEST_REF})"
        )),
    }
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
