//! Where the tool keeps its own state, and where the last record goes.
//!
//! Everything lives under the repository's **git directory**, never the working
//! tree. That is where per-checkout derived state belongs, for the reasons the
//! process cache gives for the same choice: it is ignored by construction, it
//! goes away when the clone does, and it never appears in a `git status` or in
//! somebody's diff. A tool that drops a state file into a stranger's working
//! tree on first run has made a mess in a repository it was invited to look at.
//!
//! A linked worktree has its own git directory, so two worktrees of one
//! repository keep separate iteration counters and separate last records —
//! correct, because they are at different commits and are different loops.
//!
//! # Why the last record is persisted at all
//!
//! `report`, `explain`, and `wait` all need a record to talk about, and asking
//! the operator to pipe JSON between two commands is a first-run experience that
//! fails PREMORTEM A1 in a smaller way. `andon measure` writes the record here;
//! the other subcommands read it, and say plainly when there is nothing to read
//! rather than rendering an empty page.

use std::path::{Path, PathBuf};

use andon_core::git::Git;
use andon_core::schema::payload::MeasurementRecord;

/// Directory under the git directory holding everything this tool writes.
pub const STATE_SUBDIR: &str = "andon";

/// File the most recent record is written to.
pub const LAST_RECORD_FILE: &str = "last-measure.json";

/// File the incremental clone index is written to.
pub const CLONES_INDEX_FILE: &str = "clones-index";

/// File describing work the fast lane spilled to the async lane, consumed by
/// `andon wait` (see `crate::jobs`).
pub const ASYNC_JOB_FILE: &str = "async-job.json";

/// File the last suite run's output tails are written to, for the operator a
/// verdict reason points here.
pub const SUITE_OUTPUT_FILE: &str = "test-suite-output.log";

/// The tool's state directory for this checkout.
pub fn state_dir(git: &Git) -> PathBuf {
    git.facts().git_dir.join(STATE_SUBDIR)
}

/// Where the last record is written.
pub fn last_record_path(git: &Git) -> PathBuf {
    state_dir(git).join(LAST_RECORD_FILE)
}

/// Where the clone engine's incremental index lives.
pub fn clones_index(git: &Git) -> PathBuf {
    state_dir(git).join(CLONES_INDEX_FILE)
}

/// Where the pending async job, if any, lives.
pub fn async_job_path(git: &Git) -> PathBuf {
    state_dir(git).join(ASYNC_JOB_FILE)
}

/// Where the last suite run's output tails are written.
pub fn suite_output_path(git: &Git) -> PathBuf {
    state_dir(git).join(SUITE_OUTPUT_FILE)
}

/// Persist a record as the last measurement of this checkout.
///
/// Written through the canonical serializer, so the bytes on disk are the same
/// bytes a digest would be taken over and `andon report --input` reads exactly
/// what `andon measure --json` printed.
///
/// # Two writers at once is the ordinary case, not the exotic one
///
/// A hook firing while an agent measures, two worktrees on one git directory,
/// a person running the command beside their editor: `andon measure` racing
/// itself in a single checkout is the arrangement P6's gate-shaped hooks
/// deliberately create. A fixed temporary filename makes that race destructive
/// — both writers open the same path, and on Windows the second `rename` fails
/// outright — so the temporary carries the writer's identity, the way the clone
/// index's does. The rename itself is atomic, so last-writer-wins is the only
/// contention left and both writers wrote a valid record.
pub fn write_last(git: &Git, record: &MeasurementRecord) -> Result<PathBuf, String> {
    let dir = state_dir(git);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(LAST_RECORD_FILE);
    let text = andon_core::canonical::to_canonical_string(record)
        .map_err(|e| format!("the record could not be serialized: {e}"))?;
    // A temporary beside the destination, then a rename: a crash mid-write
    // leaves the previous record rather than a truncated one that parses as far
    // as it goes. The temporary lives in the destination directory so the
    // rename stays on one filesystem — a cross-device rename is a copy, and a
    // copy is not atomic.
    let temp = dir.join(format!("{LAST_RECORD_FILE}.tmp-{}", std::process::id()));
    std::fs::write(&temp, text.as_bytes()).map_err(|e| format!("{}: {e}", temp.display()))?;
    if let Err(e) = std::fs::rename(&temp, &path) {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("{}: {e}", path.display()));
    }
    Ok(path)
}

/// Read a record from an explicit path.
pub fn read_record(path: &Path) -> Result<MeasurementRecord, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Read the last record of this checkout, or say there is none.
///
/// The absence is a first-class answer with an instruction attached, because the
/// person who hits it has just run `andon report` as their first command and the
/// only useful thing to tell them is what to run instead.
pub fn read_last(git: &Git) -> Result<MeasurementRecord, String> {
    let path = last_record_path(git);
    if !path.exists() {
        return Err(format!(
            "no measurement has been taken in this checkout yet.\n  Run `andon measure` first; \
             it writes its record to {}",
            path.display()
        ));
    }
    read_record(&path)
}
