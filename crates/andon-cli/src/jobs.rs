//! The async lane's other half: what `measure` spilled, executed and merged
//! back by `wait`.
//!
//! # The lane's shape: deferred execution, not a daemon
//!
//! `andon measure` never blocks on slow work. Past the cold cap
//! (`perf.fast_lane_cold_cap_ms`) the remaining content engines are deferred,
//! and the user test command — which executes repository code and does not fit
//! any fast-lane budget — is *always* deferred. What measure leaves behind is a
//! job file beside the record; **`andon wait` is what executes it**, in the
//! foreground of whoever asked, and merges the results into the record.
//!
//! No background process exists. A daemon would race the agent's next edit,
//! die unobserved with the session, and turn "is the suite still running?"
//! into a question nobody can answer from what they can see. Deferred
//! execution keeps every process in the foreground of an actor who can watch
//! it fail — and the record honestly says `partial` until someone chooses to
//! finish it.
//!
//! # The job carries the measurement's inputs, not references to them
//!
//! The policy snapshot, the enumerated change, the anchor commit and the
//! overlay blobs' OIDs all ride in the file. None can be re-derived at wait
//! time: the worktree has moved on, `.andon.toml` may have been edited, and a
//! merge computed against *today's* inputs would be a record stitched from two
//! different measurements. The merged record re-verdicts under the job's
//! policy — the same policy its `policy_hash` names.
//!
//! # What survives a crash
//!
//! The job file is written after the record and removed only after the merged
//! record replaces it. A crash mid-`wait` leaves both: the next `wait` simply
//! runs the job again. Running a suite twice is a cost; serving a record that
//! claims completeness it never earned would be a defect.

use std::path::Path;
use std::sync::{Arc, Mutex};

use andon_core::engine::{run_engine, ExecOutcome, ExecSpec, MeasureContext, SandboxExec};
use andon_core::git::{ChangedSet, Git};
use andon_core::payload::{AssembleRequest, EngineOutput};
use andon_core::policy::Policy;
use andon_core::schema::enums::RecordKind;
use andon_core::schema::payload::{CompareContext, MeasurementRecord};
use andon_core::verdict::iteration::Advance;
use andon_core::verdict::policy_change::PolicyChange;
use andon_core::verdict::EngineFailure;
use andon_sandbox::{OverlayEntry, Sandbox, TestCommandEngine};

use crate::measure::{self, MeasureError};
use crate::store;

/// Layout version of the job file. A file this binary does not understand is
/// refused with instructions, never guessed at.
pub const JOB_VERSION: u32 = 1;

/// Work the fast lane deferred, with everything needed to finish it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AsyncJob {
    /// [`JOB_VERSION`].
    pub job_version: u32,
    /// The binary that wrote this. `wait` refuses a mismatch: an engine from a
    /// different build would stamp a different regime, and a record merged
    /// across two binaries would misdescribe both.
    pub tool_version: String,
    /// The tuple the record this job belongs to was sealed against.
    pub compare_context: CompareContext,
    /// The policy in force when the measurement began — the one its
    /// `policy_hash` names, and the one the merged verdict is reached under.
    pub policy: Policy,
    /// The `.andon.toml` edit inside the change, if there was one.
    pub policy_change: Option<PolicyChange>,
    /// Engines that failed for real at measure time (never the deferred ones).
    /// Carried because the record keeps them only as prose in its reasons.
    pub failures: Vec<(String, String)>,
    /// The enumerated change, exactly as the fast lane measured it (after any
    /// self-measure exclusions), blob OIDs included.
    pub changed: ChangedSet,
    /// The commit the sandbox worktree materializes.
    pub anchor_oid: String,
    /// The measured change laid over the anchor, for an uncommitted head.
    /// Empty when the head is a commit.
    ///
    /// Under `--self-measure` the withheld paths are not replayed: their dirty
    /// content was never written to the object database, so the suite sees
    /// them as of the anchor commit. Disclosed in the completion notices.
    pub overlay: Vec<OverlayEntry>,
    /// Engine ids to run, in order.
    pub spilled: Vec<String>,
    /// `--registry <dir>` override, when the measurement used one.
    pub registry_dir: Option<std::path::PathBuf>,
    /// The commit the ledger files this measurement against, carried for
    /// `wait --record`.
    pub ledger_anchor: String,
    /// Whether `--self-measure` shaped the changed set.
    pub self_measure: bool,
}

/// Write the job beside the record.
pub fn write(git: &Git, job: &AsyncJob) -> Result<(), String> {
    let path = store::async_job_path(git);
    let text = serde_json::to_string_pretty(job).map_err(|e| e.to_string())?;
    // Same temp-then-rename shape as the record, same reason: a crash leaves
    // the old job or none, never half of one.
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temp, text.as_bytes()).map_err(|e| format!("{}: {e}", temp.display()))?;
    std::fs::rename(&temp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("{}: {e}", path.display())
    })
}

/// The pending job, if one exists.
pub fn read(git: &Git) -> Result<Option<AsyncJob>, String> {
    let path = store::async_job_path(git);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let job: AsyncJob = serde_json::from_str(&text).map_err(|e| {
        format!(
            "{}: {e}\n  The pending async job could not be read. Re-run `andon measure` to \
             supersede it.",
            path.display()
        )
    })?;
    if job.job_version != JOB_VERSION {
        return Err(format!(
            "the pending async job at {} has layout version {} and this binary reads {}. \
             Re-run `andon measure` to supersede it.",
            path.display(),
            job.job_version,
            JOB_VERSION
        ));
    }
    Ok(Some(job))
}

/// Remove any pending job. A new measurement supersedes the old one's
/// unfinished work; keeping the stale job would let `wait` merge yesterday's
/// suite into today's record.
pub fn clear(git: &Git) {
    let _ = std::fs::remove_file(store::async_job_path(git));
}

/// A completed job: the merged record and what completing it produced.
#[derive(Debug)]
pub struct Completion {
    /// The merged record, already written back to the store.
    pub record: MeasurementRecord,
    /// Operational notices: where the suite output went, what cleanup said.
    pub notices: Vec<String>,
    /// The ledger anchor carried from the measurement, for `--record`.
    pub ledger_anchor: String,
}

/// A sandbox that remembers what the last command did, so the completion can
/// persist the suite's output for the operator the verdict points at it.
#[derive(Debug)]
struct Recording {
    inner: Sandbox,
    last: Arc<Mutex<Option<ExecOutcome>>>,
}

impl SandboxExec for Recording {
    fn run(&self, spec: &ExecSpec) -> Result<ExecOutcome, String> {
        let outcome = self.inner.run(spec)?;
        *self.last.lock().expect("no panics hold this lock") = Some(outcome.clone());
        Ok(outcome)
    }
}

/// Execute the pending job, merge, and write the record back.
///
/// `Ok(None)` means there was nothing pending. Every other outcome is loud:
/// a job this binary cannot honour is an error with instructions, and a
/// completed job returns the merged record with its notices.
pub fn complete(repo: &Path) -> Result<Option<Completion>, String> {
    let git = Git::open(repo).map_err(|e| e.to_string())?;
    let Some(job) = read(&git)? else {
        return Ok(None);
    };
    let record = store::read_last(&git).map_err(|e| {
        format!("an async job is pending but the record it belongs to could not be read: {e}")
    })?;

    let current = env!("CARGO_PKG_VERSION");
    if job.tool_version != current {
        return Err(format!(
            "the pending job was written by andon {} and this is andon {current}. A record \
             merged across two builds would carry two regimes under one policy_hash; re-run \
             `andon measure` with this binary instead.",
            job.tool_version
        ));
    }
    if job.compare_context != record.compare_context {
        return Err(format!(
            "the pending job describes {}..{} but the stored record describes {}..{}; the \
             record was replaced without superseding the job. Re-run `andon measure`.",
            &job.compare_context.base_oid[..12.min(job.compare_context.base_oid.len())],
            &job.compare_context.head_oid[..12.min(job.compare_context.head_oid.len())],
            &record.compare_context.base_oid[..12.min(record.compare_context.base_oid.len())],
            &record.compare_context.head_oid[..12.min(record.compare_context.head_oid.len())]
        ));
    }
    if record.record_kind != RecordKind::SelfReport {
        return Err(
            "the pending job belongs to an attestation record, which never defers \
                    work; the state directory is inconsistent. Re-run `andon measure`."
                .to_string(),
        );
    }

    let mut notices: Vec<String> = Vec::new();
    let as_of = andon_core::date::Date::today_utc()
        .map_err(|_| "the system clock could not be read".to_string())?;
    let registry = measure::load_registry(job.registry_dir.as_deref(), &job.policy, as_of)
        .map_err(|e| e.to_string())?;

    // The sandbox exists only when the suite is on the docket, and it records
    // the outcome so the tails outlive the process. The concrete handle is
    // kept beside the trait object so the loud `close()` path — the one that
    // returns notices — can be reached once the engines are done.
    let suite_output = Arc::new(Mutex::new(None::<ExecOutcome>));
    let needs_sandbox = job.spilled.iter().any(|id| id == "tests");
    let recording: Option<Arc<Recording>> = if needs_sandbox {
        let entered = Sandbox::enter(&git, &job.anchor_oid, &job.overlay)
            .map_err(|e| format!("the sandbox could not be entered: {e}"))?;
        Some(Arc::new(Recording {
            inner: entered,
            last: Arc::clone(&suite_output),
        }))
    } else {
        None
    };
    let sandbox: Option<Arc<dyn SandboxExec>> =
        recording.clone().map(|arc| arc as Arc<dyn SandboxExec>);
    if job.self_measure && !job.overlay.is_empty() {
        notices.push(
            "self-measure: paths the policy withholds were not replayed into the sandbox; \
             the suite sees them as of the anchor commit."
                .to_string(),
        );
    }

    let ctx = MeasureContext {
        compare_context: job.compare_context.clone(),
        policy: job.policy.clone(),
        changed_paths: job.changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox,
    };

    // Prior contributions, reconstructed from the record itself: descriptor
    // facts are stamped on every result, so the record is its own manifest.
    let mut engines: Vec<EngineOutput> = Vec::new();
    for (engine_id, results) in group_results(&record) {
        let first = results[0];
        engines.push(EngineOutput {
            descriptor: andon_core::engine::EngineDescriptor {
                engine_id: engine_id.to_string(),
                family: first.family,
                class: first.engine_class,
                version: first.measurement_regime.engine_version().to_string(),
            },
            results: results.into_iter().cloned().collect(),
        });
    }
    let mut failures: Vec<EngineFailure> = job
        .failures
        .iter()
        .map(|(engine_id, reason)| EngineFailure {
            engine_id: engine_id.clone(),
            reason: reason.clone(),
            spilled: false,
        })
        .collect();

    // The deferred engines, now in the foreground.
    for engine_id in &job.spilled {
        let built: Result<Box<dyn andon_core::engine::MeasureEngine>, String> =
            match engine_id.as_str() {
                "static-metrics" => andon_static_metrics::StaticMetricsEngine::for_change(
                    &git,
                    &job.changed,
                    andon_static_metrics::engine_version(),
                )
                .map(|e| Box::new(e) as _)
                .map_err(|e| e.to_string()),
                "clones" => {
                    let (engine, note) = measure::build_clone_engine(&git, &job.changed);
                    if let Some(note) = note {
                        notices.push(note);
                    }
                    engine
                }
                "tamper" => andon_engine_tamper::TamperEngine::for_change(&git, &job.changed)
                    .map(|e| Box::new(e) as _)
                    .map_err(|e| e.to_string()),
                "tests" => TestCommandEngine::from_policy(&job.policy)
                    .map(|e| Box::new(e) as _)
                    .ok_or_else(|| {
                        "the job defers the test command but its own policy snapshot declares \
                         none — the job file is inconsistent"
                            .to_string()
                    }),
                other => Err(format!(
                    "the job names an engine this binary cannot defer: '{other}'"
                )),
            };
        match built {
            Ok(engine) => match run_engine(engine.as_ref(), &ctx) {
                Ok(mut results) => {
                    // These results were produced on the async lane, whichever
                    // lane their engine stamps by default — the fact `wait`
                    // reports and `Freshness` exists to carry. Safe after
                    // sealing: freshness never enters a digest.
                    for result in &mut results {
                        result.freshness.lane = andon_core::schema::enums::Lane::Async;
                    }
                    engines.push(EngineOutput {
                        descriptor: engine.descriptor(),
                        results,
                    })
                }
                Err(e) => failures.push(EngineFailure {
                    engine_id: engine_id.clone(),
                    reason: e.to_string(),
                    spilled: false,
                }),
            },
            Err(reason) => failures.push(EngineFailure {
                engine_id: engine_id.clone(),
                reason,
                spilled: false,
            }),
        }
    }

    // The suite's own words, persisted where a verdict reason can point.
    if let Some(outcome) = suite_output
        .lock()
        .expect("no panics hold this lock")
        .take()
    {
        let path = store::suite_output_path(&git);
        let text = format!(
            "# The last andon test-suite run's output tails ({} bytes kept per stream).\n\
             # exit: {:?}  timed_out: {}  duration_ms: {}\n\
             \n== stdout ==\n{}\n== stderr ==\n{}\n",
            16 * 1024,
            outcome.exit_code,
            outcome.timed_out,
            outcome.duration_ms,
            outcome.stdout_tail,
            outcome.stderr_tail
        );
        match std::fs::write(&path, text) {
            Ok(()) => notices.push(format!(
                "the test command's output is at {}",
                path.display()
            )),
            Err(e) => notices.push(format!(
                "the test command's output could NOT be saved to {}: {e}",
                path.display()
            )),
        }
    }

    let prepared = andon_core::payload::prepare(AssembleRequest {
        tool: measure::tool_identity(),
        record_kind: record.record_kind,
        compare_context: job.compare_context.clone(),
        invocation: record.invocation.clone(),
        reserved: record.reserved.clone(),
        policy: &job.policy,
        registry: &registry,
        engines,
        engine_failures: failures,
        policy_change: job.policy_change.clone(),
        substitution: record.substitution.clone(),
        unreadable_paths: record.unreadable_paths.clone(),
        self_measure: record.self_measure.clone(),
    })
    .map_err(|e| MeasureError::Assembly(e).to_string())?;

    // The same attempt, finished — not a new one. The counter state the
    // measurement recorded is re-used, so completing a measurement can never
    // advance a loop the agent has not taken another turn in.
    let merged = prepared.finish(Advance {
        state: record.verdict.iteration,
        recovered: false,
        contended: false,
    });

    if merged.policy_hash != record.policy_hash {
        // The one internal consistency check that has to hold by construction:
        // both hashes come from the job's policy snapshot. A mismatch means the
        // job and record were never a pair, and a merge would launder that.
        return Err(
            "the merged record's policy_hash does not match the stored record's; the job and \
             the record are not from the same measurement. Re-run `andon measure`."
                .to_string(),
        );
    }

    store::write_last(&git, &merged)?;
    clear(&git);

    // The sandbox closes through the loud path once nothing holds it. Its
    // notices are the operator's: a directory that would not delete is theirs
    // to see, not stderr noise from a destructor.
    drop(ctx);
    if let Some(arc) = recording {
        match Arc::try_unwrap(arc) {
            Ok(recording) => notices.extend(recording.inner.close()),
            Err(_) => notices.push(
                "the sandbox worktree could not be closed through the loud path (a handle \
                 was still held); its cleanup fell back to the best-effort destructor"
                    .to_string(),
            ),
        }
    }

    Ok(Some(Completion {
        record: merged,
        notices,
        ledger_anchor: job.ledger_anchor,
    }))
}

/// Results grouped by engine id, order-preserving within an engine.
fn group_results(
    record: &MeasurementRecord,
) -> Vec<(&str, Vec<&andon_core::schema::payload::MeasurementResult>)> {
    let mut grouped: Vec<(&str, Vec<&andon_core::schema::payload::MeasurementResult>)> = Vec::new();
    for result in &record.results {
        match grouped.iter_mut().find(|(id, _)| *id == result.engine_id) {
            Some((_, results)) => results.push(result),
            None => grouped.push((result.engine_id.as_str(), vec![result])),
        }
    }
    grouped
}
