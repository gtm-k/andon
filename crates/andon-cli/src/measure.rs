//! One measurement, end to end: five engines over one change, assembled into one
//! record.
//!
//! # Where the evidence registry comes from, and why it is not the checkout
//!
//! `payload::prepare` needs a merged registry, and there are two ways to get
//! one: read the `registry/` directory beside the code, or merge the copies the
//! engine crates compile into themselves with `include_str!`.
//!
//! This binary uses the compiled-in copies, and the reason is the one that
//! decides whether the tool works at all outside its own repository. A stranger
//! measuring their own project has no `registry/` directory, and a binary that
//! insisted on one would fail on every repository except Andon's — which is
//! PREMORTEM A1's failure reached by a different road. The compiled-in registry
//! travels with the binary, so `expected_engines` is exactly the set of engines
//! this build ships, by construction rather than by a list somebody maintains.
//!
//! `--registry <dir>` overrides it, for the case where the operator wants to
//! measure under a registry they can see and edit. Taking that option means the
//! binary and the directory can disagree about a claim's tier, which is not
//! hidden: `payload::prepare` collects the disagreement and the verdict carries
//! `evidence-registry-skew`.
//!
//! # An engine that fails is named, never dropped
//!
//! Every engine either contributes results or contributes an
//! [`EngineFailure`], and `payload::prepare` refuses a payload where one does
//! neither. A dropped engine would make "this detector found nothing" and "this
//! detector never ran" the same observation, and the wrong one of those passes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use andon_core::date::Date;
use andon_core::engine::{run_engine, MeasureContext, MeasureEngine};
use andon_core::git::{BlobBatch, ChangedEntry, ChangedSet, Git};
use andon_core::payload::registry_load::{self, LoadedRegistry};
use andon_core::payload::{AssembleRequest, EngineOutput};
use andon_core::policy::Policy;
use andon_core::registry::EngineRegistryFile;
use andon_core::schema::enums::{InvocationSource, MetricClass, RecordKind};
use andon_core::schema::payload::{
    Invocation, MeasurementRecord, MeasurementResult, MetricValue, Reserved, ScopeKind,
    ToolIdentity,
};
use andon_core::selfmeasure::{OverrideReason, SelfMeasureOverride, SelfMeasureProvenance};
use andon_core::verdict::iteration::{Advance, IterationStore};
use andon_core::verdict::policy_change::{self, PolicyChange};
use andon_core::verdict::EngineFailure;

use crate::resolve::{self, Resolution};
use crate::store;

/// Tool name on every record this binary writes.
pub const TOOL_NAME: &str = "andon";

/// What to measure, and under what.
#[derive(Debug, Clone)]
pub struct Request {
    /// Any path inside the repository.
    pub repo: PathBuf,
    /// `--base`, or `None` for the ladder in [`crate::resolve`].
    pub base: Option<String>,
    /// `--head`, defaulting to `HEAD`.
    pub head: Option<String>,
    /// Refuse rather than fall back to the last merged change.
    pub no_fallback: bool,
    /// Measure the last merged change even when there is uncommitted work.
    ///
    /// A dirty tree is otherwise measured as itself. This flag opts out of that
    /// and asks about the committed history instead, which is a different
    /// question about different bytes — so the record announces the
    /// substitution, and the announcement says there is uncommitted work it is
    /// not about.
    pub last_merged: bool,
    /// `--registry <dir>`, or `None` for the compiled-in registry.
    pub registry_dir: Option<PathBuf>,
    /// Apply `policy.self_measure.excluded_paths` — Andon measuring Andon.
    pub self_measure: bool,
    /// Who asked.
    pub source: InvocationSource,
    /// Harness name, when one is calling.
    pub harness: Option<String>,
    /// Model identifier, when the harness discloses one.
    pub model: Option<String>,
    /// Self-report or verifier attestation.
    pub record_kind: RecordKind,
    /// Which copy of `.andon.toml` is in force.
    pub policy_source: PolicySource,
}

/// Where the policy in force is read from.
///
/// The verifier reads it from the **base** commit, so that editing a threshold
/// inside the pull request being measured gains nothing (PLAN B6). The agent
/// side reads the working tree, which is the file the operator can see and edit.
/// Two answers to one question, and which one applies is a property of who is
/// asking — so it is a parameter rather than a rule buried in one caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// `.andon.toml` as it sits in the checkout.
    Worktree,
    /// `.andon.toml` as of a commit, for the verifier.
    Commit(String),
}

impl Default for Request {
    fn default() -> Self {
        Request {
            repo: PathBuf::from("."),
            base: None,
            head: None,
            no_fallback: false,
            last_merged: false,
            registry_dir: None,
            self_measure: false,
            source: InvocationSource::HumanCli,
            harness: None,
            model: None,
            record_kind: RecordKind::SelfReport,
            policy_source: PolicySource::Worktree,
        }
    }
}

/// A finished measurement and everything a surface needs to render it honestly.
#[derive(Debug)]
pub struct Measurement {
    /// The record.
    ///
    /// Three of this struct's fields used to sit beside it — the substitution,
    /// the unreadable paths, and what `[self_measure] excluded_paths` withheld —
    /// and all three are now on the record itself. They were facts about the
    /// measurement that a renderer had to be handed separately, which meant
    /// every renderer reading a record off disk was handed none of them, and
    /// said none of them. What is left here is what genuinely belongs to *this
    /// invocation* rather than to the measurement: how the range was described
    /// and operational notices.
    pub record: MeasurementRecord,
    /// One line naming the range measured.
    pub how: String,
    /// Operational notices a reader needs and the record does not carry:
    /// registry staleness, schedule hygiene, and anything a run did differently
    /// from the ordinary path. Handling that produces no observable signal is a
    /// silent failure for whoever has to account for the result.
    pub notices: Vec<String>,
    /// The branch the iteration counter was keyed on.
    pub branch: String,
    /// How many files the measured change touched, after any exclusions.
    ///
    /// Reported because zero is a real and confusing answer — an empty commit,
    /// or a change consisting only of paths the self-measure policy withholds —
    /// and a reader seeing change-scope zeros deserves to know which it was.
    pub changed_files: usize,
    /// The commit this measurement was taken under, for the ledger to file it
    /// against.
    ///
    /// Captured here rather than asked for again at recording time, and that is
    /// the whole of the fix: `crate::ledger::record` ran `rev-parse HEAD` after
    /// the measurement, so a ref that moved in between — a hook that commits, a
    /// second agent, a rebase next door — filed the note against a commit that
    /// was never underneath the measured bytes.
    ///
    /// `Endpoint::anchor_oid` for the head endpoint: the commit itself where the
    /// head is a commit, and `DirtySnapshot::head_oid` where it is not — read in
    /// the same `status` scan that produced the entries, which is what makes it
    /// transactional with the snapshot rather than merely earlier than the note.
    pub ledger_anchor: String,
}

/// What making the working tree readable cost, and what it could not reach.
#[derive(Debug, Default)]
struct StageFree {
    /// Paths whose content was written to the object database.
    hashed: usize,
    /// Paths still unreadable afterwards.
    unreadable: Vec<String>,
    /// Why, when the attempt failed rather than being unnecessary.
    reason: Option<String>,
}

/// Anything that stopped a measurement before it produced a record.
#[derive(Debug, thiserror::Error)]
pub enum MeasureError {
    /// The range could not be resolved.
    #[error(transparent)]
    Resolve(#[from] resolve::ResolveFailure),
    /// Git refused.
    #[error(transparent)]
    Git(#[from] andon_core::git::GitError),
    /// The registry could not be loaded, so no number may be reported.
    #[error("the evidence registry could not be loaded: {0}")]
    Registry(String),
    /// `.andon.toml` could not be read.
    #[error("policy: {0}")]
    Policy(String),
    /// The payload could not be assembled.
    #[error("assembly: {0}")]
    Assembly(#[from] andon_core::payload::AssemblyError),
    /// The iteration counter could not be read or written.
    #[error("iteration state: {0}")]
    Iteration(String),
}

/// The shipped engine registry files, as this binary compiles them in.
///
/// The roster of a *deployment* rather than a constant list of five: every entry
/// comes from [`crate::shipped::SHIPPED`], whose ids are asserted equal to the
/// `engine =` headers of these same files, so an engine cannot join the binary
/// and leave a gap in `expected_engines`.
fn compiled_registry_files() -> Result<Vec<(String, EngineRegistryFile)>, MeasureError> {
    crate::shipped::SHIPPED
        .iter()
        .map(|engine| {
            (engine.registry_file)()
                .map(|file| {
                    (
                        format!("<compiled-in>/{}.toml", engine.engine_id),
                        file.clone(),
                    )
                })
                .map_err(MeasureError::Registry)
        })
        .collect()
}

/// Load the evidence registry: compiled-in by default, from `dir` on request.
pub fn load_registry(
    dir: Option<&Path>,
    policy: &Policy,
    as_of: Date,
) -> Result<LoadedRegistry, MeasureError> {
    match dir {
        Some(dir) => registry_load::load(dir, &policy.registry, as_of)
            .map_err(|e| MeasureError::Registry(e.to_string())),
        None => {
            let files = compiled_registry_files()?;
            registry_load::load_files(&files, &policy.registry, as_of, "<compiled-in>")
                .map_err(|e| MeasureError::Registry(e.to_string()))
        }
    }
}

/// Measure a change.
pub fn measure(request: &Request) -> Result<Measurement, MeasureError> {
    let git = Git::open(&request.repo)?;
    let resolution = resolve::resolve(
        &git,
        &resolve::Request {
            base: request.base.clone(),
            head: request.head.clone(),
            no_fallback: request.no_fallback,
            last_merged: request.last_merged,
        },
    )?;

    let policy = load_policy(&git, &request.policy_source)?;
    let as_of = Date::today_utc().map_err(|_| {
        MeasureError::Registry(
            "the system clock could not be read, so claim expiry cannot be \
                                evaluated"
                .to_string(),
        )
    })?;
    let registry = load_registry(request.registry_dir.as_deref(), &policy, as_of)?;

    // Self-measurement withholds the fixtures that exist to fire the tamper
    // suite. Declared policy, applied here, and the withheld paths are reported
    // — an exclusion nobody can see is how a dogfood gate stops meaning
    // anything (PREMORTEM S3, docs/self-measure.md).
    let (mut changed, excluded) = if request.self_measure {
        apply_exclusions(&resolution.changed, &policy.self_measure.excluded_paths)
    } else {
        (resolution.changed.clone(), Vec::new())
    };

    // Make the unstaged bytes readable, without touching the index. Only for an
    // uncommitted head: a commit range has nothing on disk to reach for, and
    // writing objects for it would be a side effect with no purpose.
    let stage_free = if resolution.compare_context.head_kind.is_witnessable() {
        StageFree::default()
    } else {
        read_without_staging(&git, &mut changed)
    };

    let ctx = MeasureContext {
        compare_context: resolution.compare_context.clone(),
        policy: policy.clone(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox: None,
    };

    let (engines, engine_failures, mut engine_notes) =
        run_all_engines(&git, &resolution, &changed, &policy, &ctx);

    // What this measurement does and does not cover. Which sentence is true
    // depends on what the head turned out to be, so this asks rather than
    // asserts — the same rule that stopped the fallback claiming a clean tree
    // over a dirty one. An actor can only act on what they can observe.
    if resolution.substitution.is_none() {
        if resolution.compare_context.head_kind.is_witnessable() {
            // A commit head: any uncommitted work is outside these numbers, and
            // a reader looking at a verdict cannot know that unless it is said.
            if !resolution.uncommitted.is_empty() {
                engine_notes.push(format!(
                    "{} path(s) have uncommitted content and are NOT described by this \
                     measurement, which covers committed content only: {}.\n           \
                     This measurement was pinned to a commit, which is why. Re-run without \
                     `--head` (and without `--last-merged`) to measure the working tree \
                     instead — that is a different measurement of different bytes, and it can \
                     reach a different verdict.",
                    resolution.uncommitted.len(),
                    resolution.uncommitted.join(", ")
                ));
            }
        } else {
            // An uncommitted head: the working tree IS what was measured, so the
            // sentence above would be false. What is worth saying here instead
            // is the side effect, and anything the read could not reach.
            if stage_free.hashed > 0 {
                engine_notes.push(format!(
                    "{} unstaged path(s) were read by writing their working-tree content to \
                     this repository's object database as unreferenced blobs, without touching \
                     your index. `git gc` removes them. Where a path declares a `filter` \
                     attribute these are NOT the objects `git add` would create, because the \
                     filter is a program this repository defines and it was not run — the note \
                     below names those paths.",
                    stage_free.hashed
                ));
            }
            if !stage_free.unreadable.is_empty() {
                engine_notes.push(format!(
                    "{} changed path(s) could NOT be read, so nothing below describes them: {}. \
                     {}",
                    stage_free.unreadable.len(),
                    stage_free.unreadable.join(", "),
                    stage_free
                        .reason
                        .as_deref()
                        .unwrap_or("`git add` them and re-run.")
                ));
            }
        }
    }

    // A filter this repository configured is a program this repository wrote,
    // and it did not run — `andon_core::git::command` pins every driver inert on
    // every spawn. Where that changed what was read, say so: an actor can only
    // act on what they can observe, and "these bytes are the raw working-tree
    // bytes, not what your clean filter would have produced" is the kind of
    // thing that changes how a number is read.
    let filtered = git
        .filtered_paths(
            &changed
                .entries
                .iter()
                .map(|e| e.path.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(MeasureError::Git)?;
    if !filtered.is_empty() {
        let drivers: std::collections::BTreeSet<&str> =
            filtered.iter().map(|(_, driver)| driver.as_str()).collect();
        engine_notes.push(format!(
            "{} changed path(s) declare a `filter` attribute ({}), and that filter was NOT run: \
             a filter driver is a program this repository defines, and this is the static lane. \
             Their content was read as the raw working-tree bytes, which is what was written \
             rather than what would be stored: {}.",
            filtered.len(),
            drivers.into_iter().collect::<Vec<_>>().join(", "),
            filtered
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let policy_change = detect_policy_change(&git, &changed).map_err(MeasureError::Policy)?;

    let prepared = andon_core::payload::prepare(AssembleRequest {
        tool: tool_identity(),
        record_kind: request.record_kind,
        compare_context: resolution.compare_context.clone(),
        invocation: Invocation {
            source: request.source,
            harness: request.harness.clone(),
            model: request.model.clone(),
            author: None,
            // Overwritten by the counter in `finish` — the on-disk state is the
            // party that knows which pass this is.
            iteration: 0,
        },
        reserved: Reserved::default(),
        policy: &policy,
        registry: &registry,
        engines,
        engine_failures,
        policy_change,
        // The resolver's and the reader's facts, carried into the one place a
        // record is built. Both used to live only on `Measurement`, which is
        // this process's view and does not survive being written to disk — so
        // `andon report` on the same record announced neither.
        substitution: resolution.substitution.clone(),
        unreadable_paths: stage_free.unreadable.clone(),
        // The third fact that lived for one process. `--self-measure` withheld
        // paths and the terminal named them; the record did not, so the dogfood
        // job's own payload — the artefact somebody reads to find out what the
        // gate covered — said nothing about eighteen files it did not measure.
        self_measure: request
            .self_measure
            .then(|| self_measure_provenance(&policy, &excluded, &resolution)),
    })?;

    let branch = current_branch(&git, &resolution);
    let store = IterationStore::open(store::state_dir(&git))
        .map_err(|e| MeasureError::Iteration(e.to_string()))?;
    let cap = policy.loop_policy.iteration_cap;
    // A verifier reads the counter; it does not take a turn.
    //
    // The counter counts one thing: how many passes an agent has made at this
    // change. A recompute is an observation of that loop from outside it, so
    // advancing here would be the verifier inflating the number it was asked to
    // report — and where the verifier and the agent share a checkout, it would
    // push the agent's *next* measurement into `escalate_to_human` for work the
    // agent never did. Where they do not share one, the number it advanced is a
    // count of nothing on a machine nobody reads.
    //
    // AND NEITHER DOES RE-READING THE SAME CHANGE.
    //
    // The counter counts *attempts at this change*, and the thing that makes an
    // attempt is a change to what is being measured — not a call to the tool.
    // Advancing per invocation counts looking, and looking is what a person does
    // while they decide what to do: five verification runs over one unchanged
    // repository escalated a human to a human, firing the one signal reserved
    // for "an agent has tried enough times, stop trying".
    //
    // Keyed on the measured range rather than on `--source`. A `--source` rule
    // would have been smaller and it has a hole: `human-cli` is the default, so
    // an agent that never passes the flag would silently lose the cap
    // altogether — trading a visible annoyance for an invisible loss of a
    // safety mechanism, which is the wrong direction. The range cannot be
    // forgotten, and for an uncommitted head it is a content hash, so any real
    // edit produces a new one and counts.
    //
    // The comparison itself belongs to the store, not here. This function used
    // to make it by reading the last record it had written, which is
    // unanswerable when two measurements run at once: neither has written one
    // yet, so both believe they are first, and twenty-four readings of one
    // unchanged snapshot escalated a human twenty-one times. The store decides
    // it under the same lock as the write.
    let change = format!(
        "{}..{}",
        resolution.compare_context.base_oid, resolution.compare_context.head_oid
    );
    let advance = match request.record_kind {
        RecordKind::SelfReport => store
            .advance(&branch, cap, prepared.loop_outcome(), &change)
            .map_err(|e| MeasureError::Iteration(e.to_string()))?,
        // `peek` cannot report a restart because it does not perform one. A
        // caller that claimed to have recovered state would be claiming
        // something about a counter it did not write.
        RecordKind::Attestation => Advance {
            state: store.peek(&branch, cap),
            recovered: false,
            contended: false,
        },
    };
    if advance.contended {
        engine_notes.push(
            "another measurement held this repository's loop counter for longer than the wait, \
             so this pass was not counted against the iteration cap. The measurement itself is \
             unaffected — the counter is a loop heuristic, not an input to any number here."
                .to_string(),
        );
    }

    let record = prepared.finish(advance);

    Ok(Measurement {
        record,
        // From the resolved range, which still holds the snapshot the engines
        // read. Nothing between here and the ledger asks git for HEAD again.
        ledger_anchor: resolution.range.head.anchor_oid().to_string(),
        how: resolution.how,
        changed_files: changed.len(),
        notices: engine_notes
            .into_iter()
            .chain(
                registry
                    .notices
                    .iter()
                    .map(|d| format!("registry {}: {}", d.code, d.message)),
            )
            .collect(),
        branch,
    })
}

/// Make unstaged working-tree content readable, without touching the index.
///
/// # What this does
///
/// `git hash-object -w` writes a file's content into the object database and
/// returns its OID. The changed entries for those paths then carry a real blob
/// OID, so every engine reads them through the ordinary `BlobBatch` path and no
/// engine changes at all. One spawn covers every path, so the perf budget is
/// unaffected.
///
/// # Why this does not break P1's blob-OID rule
///
/// The rule is that compared-lane content comes from git blob objects and
/// nothing else, because worktree bytes are checkout-dependent — CRLF here, LF
/// in CI — and a digest over them produces `divergent` on honest work
/// (PREMORTEM Story 1). Three things, each checked rather than assumed:
///
/// 1. **The engines still read blobs.** They are handed an OID and go to the
///    object database, exactly as for committed content. Nothing reads the
///    worktree.
/// 2. **The blob is checkout-normalized.** `hash-object` applies the same clean
///    filters `git add` does, so a CRLF working file becomes an LF blob. The
///    bytes that enter the digest are the bytes that would be committed, not the
///    bytes on this machine's disk. *Verified: the OID this produces is
///    byte-identical to the one `git add` puts in the index for the same file.*
/// 3. **Nothing will ever recompute it anyway.** The record's head is
///    `uncommitted-worktree` and its attestation is `unwitnessed-uncommitted`,
///    so `compare::classify` refuses to compare it before it reads anything
///    else. The false-divergence epidemic needs a verifier comparing digests,
///    and by construction none ever will.
///
/// `git::diff` leaves `dst_oid` empty for these paths and says why: the
/// snapshot's `worktree_oid` "is a content hash computed for keying, not an
/// object in the database, and offering it to the blob reader would name
/// something `cat-file` cannot resolve". That is a mechanical obstacle, and
/// writing the object removes it. The doctrinal sentence beside it — unstaged
/// bytes "live only on disk **by construction**" — states the same premise, and
/// the premise stops holding once the object exists.
///
/// # Why not just tell the caller to `git add`
///
/// Because the caller is usually an agent mid-loop, and `git add` mutates state
/// shared with the human sitting beside it. Requiring a change to the index as
/// the price of being measured is a tool asking its user to stage work they may
/// not want staged. This writes the identical object and leaves the index alone.
///
/// The cost is disclosed rather than hidden: unreferenced loose objects, which
/// is exactly what `git add` followed by `git reset` leaves behind, and which
/// `git gc` collects.
fn read_without_staging(git: &Git, changed: &mut ChangedSet) -> StageFree {
    let pending: Vec<usize> = changed
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.dst_mode.is_some() && !e.is_gitlink() && e.readable_blob().is_none())
        .map(|(i, _)| i)
        .collect();
    if pending.is_empty() {
        return StageFree::default();
    }

    let paths: Vec<String> = pending
        .iter()
        .map(|i| changed.entries[*i].path.clone())
        .collect();
    // One spawn, whatever the size of the change. `--` so a path that looks
    // like an option is still a path.
    let output = git.cmd(["hash-object", "-w", "--"]).args(&paths).text();

    let oids: Vec<String> = match output {
        Ok(text) => text.lines().map(|l| l.trim().to_string()).collect(),
        Err(e) => {
            // A read-only object store, or a file that vanished between the
            // status scan and now. Honest fallback: the paths stay unreadable
            // and the caller is told, including why.
            return StageFree {
                hashed: 0,
                unreadable: paths,
                reason: Some(format!(
                    "their content could not be written to the object database ({e}), so `git \
                     add` them and re-run."
                )),
            };
        }
    };

    // A short reply is a reply about different paths than the ones asked about.
    // Pairing by position across a mismatched length would attach one file's
    // bytes to another file's name, which is worse than not reading either.
    if oids.len() != pending.len() {
        return StageFree {
            hashed: 0,
            unreadable: paths,
            reason: Some(format!(
                "git returned {} object id(s) for {} path(s), so which bytes belong to which \
                 file is not determined; `git add` them and re-run.",
                oids.len(),
                pending.len()
            )),
        };
    }

    for (index, oid) in pending.iter().zip(oids) {
        changed.entries[*index].dst_oid = Some(oid);
    }
    StageFree {
        hashed: pending.len(),
        unreadable: Vec::new(),
        reason: None,
    }
}

/// The clone engine, with a cold retry when another process holds the index.
///
/// # Why a busy lock must not cost a whole engine
///
/// The incremental index is a cache. `IndexLock` serializes writes to it, and a
/// second `andon` in the same checkout — a hook firing while an agent measures,
/// two worktrees sharing a git directory, this suite's own tests — gets
/// `IndexError::Locked` and the constructor fails. Before this, that failure
/// removed the entire clone family from the payload: no duplication numbers, and
/// a record whose completeness dropped to `partial`, because a cache was busy.
///
/// A cold run is the same measurement. `incremental_equivalence` is the property
/// P3 gated the phase on — the index changes how long it takes and never what it
/// says — so retrying without it costs time and nothing else.
///
/// The retry is **narrow and observable**. Only a lock contention takes it: a
/// corrupt or unwritable index is a real problem and stays a real failure. And
/// the caller reports that it happened, because handling that produces no signal
/// is a silent failure for whoever has to explain why a measurement took longer.
fn build_clone_engine(
    git: &Git,
    changed: &ChangedSet,
) -> (Result<Box<dyn MeasureEngine>, String>, Option<String>) {
    use andon_engine_clones::index::IndexError;
    use andon_engine_clones::CloneEngineError;

    let index = store::clones_index(git);
    match andon_engine_clones::ClonesEngine::for_change(git, changed, Some(&index)) {
        Ok(engine) => (Ok(Box::new(engine) as Box<dyn MeasureEngine>), None),
        Err(CloneEngineError::Index(IndexError::Locked { path })) => {
            let cold = andon_engine_clones::ClonesEngine::for_change(git, changed, None)
                .map(|e| Box::new(e) as Box<dyn MeasureEngine>)
                .map_err(|e| e.to_string());
            (
                cold,
                Some(format!(
                    "clones: another Andon process holds the index lock at {path}, so this run \
                     rebuilt the clone index from scratch. The numbers are the same either way; \
                     only the time taken differs."
                )),
            )
        }
        Err(other) => (Err(other.to_string()), None),
    }
}

/// Run every shipped engine, turning each failure into a named absence.
fn run_all_engines(
    git: &Git,
    resolution: &Resolution,
    changed: &ChangedSet,
    policy: &Policy,
    ctx: &MeasureContext,
) -> (Vec<EngineOutput>, Vec<EngineFailure>, Vec<String>) {
    let mut outputs: Vec<EngineOutput> = Vec::new();
    let mut failures: Vec<EngineFailure> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // A closure rather than five copies: an engine whose failure path differed
    // from the others' would be an engine whose absence reads differently, and
    // the reader cannot tell a bespoke message from a bespoke rule.
    let record = |engine_id: &str,
                  built: Result<Box<dyn MeasureEngine>, String>,
                  out: &mut Vec<EngineOutput>,
                  failed: &mut Vec<EngineFailure>| {
        match built {
            Ok(engine) => {
                let descriptor = engine.descriptor();
                match run_engine(engine.as_ref(), ctx) {
                    Ok(results) => out.push(EngineOutput {
                        descriptor,
                        results,
                    }),
                    Err(e) => failed.push(EngineFailure {
                        engine_id: engine_id.to_string(),
                        reason: e.to_string(),
                    }),
                }
            }
            Err(reason) => failed.push(EngineFailure {
                engine_id: engine_id.to_string(),
                reason,
            }),
        }
    };

    record(
        "static-metrics",
        andon_static_metrics::StaticMetricsEngine::for_change(
            git,
            changed,
            andon_static_metrics::engine_version(),
        )
        .map(|e| Box::new(e) as Box<dyn MeasureEngine>)
        .map_err(|e| e.to_string()),
        &mut outputs,
        &mut failures,
    );

    let (clones, clone_note) = build_clone_engine(git, changed);
    if let Some(note) = clone_note {
        notes.push(note);
    }
    record("clones", clones, &mut outputs, &mut failures);

    record(
        "tamper",
        andon_engine_tamper::TamperEngine::for_change(git, changed)
            .map(|e| Box::new(e) as Box<dyn MeasureEngine>)
            .map_err(|e| e.to_string()),
        &mut outputs,
        &mut failures,
    );

    // The process engine's hotspot metric needs a complexity number per path,
    // and the static engine is the only thing in the workspace that has one.
    // Wiring it here is what `process/src/complexity.rs` says the assembly phase
    // owes it; the alternative is every hotspot reporting
    // `unwitnessed: no complexity input for this path`, which is honest and
    // useless.
    let complexity = complexity_from(&outputs);
    let cache = andon_engine_process::cache::HistoryCache::for_repo(git).ok();
    record(
        "process",
        andon_engine_process::ProcessEngine::for_change(
            git,
            &resolution.range,
            changed,
            policy,
            &complexity,
            cache.as_ref(),
        )
        .map(|e| Box::new(e) as Box<dyn MeasureEngine>)
        .map_err(|e| e.to_string()),
        &mut outputs,
        &mut failures,
    );

    // `for_discovery` rather than `for_change`: discovery carries the reports it
    // could not read, and a report that failed to parse becomes a named
    // `unwitnessed` result rather than a silence.
    let discovery = andon_engine_artifacts::engine::discover(git.workdir());
    record(
        "artifacts",
        andon_engine_artifacts::ArtifactsEngine::for_discovery(
            git,
            &resolution.range,
            changed,
            &discovery,
        )
        .map(|e| Box::new(e) as Box<dyn MeasureEngine>)
        .map_err(|e| e.to_string()),
        &mut outputs,
        &mut failures,
    );

    (outputs, failures, notes)
}

/// Per-path complexity for the hotspot metric, from the static engine's results.
///
/// # Why the maximum and not the sum
///
/// A hotspot ranks *where a change is risky*, and the trait it feeds asks only
/// that the number be monotonic in difficulty. Summing a file's functions makes
/// a long file of trivial helpers outrank a short file holding one function
/// nobody can follow — which inverts the signal, because the second file is the
/// dangerous one to edit. The maximum answers "how bad is the worst thing in
/// here", which is the question a reader opening the file is actually asking.
///
/// Cognitive rather than cyclomatic, for the reason the metric exists: cyclomatic
/// counts branches, cognitive counts the nesting that makes them hard to hold in
/// mind, and comprehension is what the ranking is about.
fn complexity_from(outputs: &[EngineOutput]) -> BTreeMap<String, u64> {
    let mut by_path: BTreeMap<String, u64> = BTreeMap::new();
    for output in outputs {
        if output.descriptor.engine_id != "static-metrics" {
            continue;
        }
        for result in &output.results {
            if !result.metric_id.starts_with("static.cognitive-complexity") {
                continue;
            }
            let (Some(path), MetricValue::Count(value)) = (&result.scope.path, &result.value)
            else {
                continue;
            };
            let entry = by_path.entry(path.clone()).or_insert(0);
            *entry = (*entry).max(*value);
        }
    }
    by_path
}

/// The `.andon.toml` edit inside this change, if there is one.
///
/// Read from the two sides' blobs rather than from the working tree: the
/// question is what the change did to policy, and the working tree is neither
/// side of it. A missing base copy means the change *added* the file, which
/// `policy_change::resolve` compares against the conservative defaults — adding
/// a file that turns tamper blocking off is a loosening, and comparing it
/// against nothing would have made it invisible.
fn detect_policy_change(git: &Git, changed: &ChangedSet) -> Result<Option<PolicyChange>, String> {
    let Some(entry) = changed
        .entries
        .iter()
        .find(|e| e.path == ".andon.toml" || e.old_path.as_deref() == Some(".andon.toml"))
    else {
        return Ok(None);
    };

    let mut batch = BlobBatch::open(git).map_err(|e| e.to_string())?;
    let mut read = |oid: Option<&str>| -> Result<Option<String>, String> {
        let Some(oid) = oid.filter(|o| !o.chars().all(|c| c == '0')) else {
            return Ok(None);
        };
        let content = batch.read(oid).map_err(|e| e.to_string())?;
        String::from_utf8(content.into_bytes())
            .map(Some)
            .map_err(|_| ".andon.toml is not UTF-8".to_string())
    };
    let before = read(entry.src_oid.as_deref())?;
    let after = read(entry.dst_oid.as_deref())?;

    let base = policy_change::resolve(before.as_deref()).map_err(|e| e.to_string())?;
    let head = policy_change::resolve(after.as_deref()).map_err(|e| e.to_string())?;
    // No justification: minting a verified one is the verifier's alone, and a
    // self-report carrying one is refused by assembly. P8's ledger is where an
    // unverified justification will come from.
    let change = policy_change::evaluate(&base, &head, None);
    Ok((!change.is_empty()).then_some(change))
}

/// Withhold paths the self-measure policy excludes, and say which.
fn apply_exclusions(changed: &ChangedSet, patterns: &[String]) -> (ChangedSet, Vec<String>) {
    let mut kept: Vec<ChangedEntry> = Vec::new();
    let mut withheld: Vec<String> = Vec::new();
    for entry in &changed.entries {
        if patterns.iter().any(|p| matches_prefix(p, &entry.path)) {
            withheld.push(entry.path.clone());
        } else {
            kept.push(entry.clone());
        }
    }
    (ChangedSet { entries: kept }, withheld)
}

/// Match the `dir/**` shape every shipped exclusion uses.
///
/// Not a glob engine. All five shipped patterns are a literal prefix followed by
/// `/**`, and a pattern this cannot express is refused rather than
/// approximated — an exclusion list whose entries silently match nothing is
/// worse than one that does not parse, because the operator believes the paths
/// are excluded and they are not.
fn matches_prefix(pattern: &str, path: &str) -> bool {
    match pattern.strip_suffix("/**") {
        Some(prefix) => path == prefix || path.starts_with(&format!("{prefix}/")),
        None => path == pattern,
    }
}

/// Read `.andon.toml` from wherever this caller's policy lives.
///
/// Public because every surface needs the same answer. `explain` reports what a
/// tier is allowed to do under the policy in force, and `ledger ack` reports the
/// cap the counter was measured against — both read this file, and a surface
/// that reached for `Policy::default()` instead would print a number the
/// repository does not use.
///
/// Absent means the conservative defaults were in force, which is what the
/// binary would have used and what every repository but this one will hit.
/// A file that exists and cannot be read is surfaced rather than defaulted: a
/// policy the operator believes is in force and is not is the whole reason
/// `Policy` refuses unknown keys.
pub fn load_policy(git: &Git, source: &PolicySource) -> Result<Policy, MeasureError> {
    let text = match source {
        PolicySource::Worktree => {
            let path = git.workdir().join(".andon.toml");
            match std::fs::read_to_string(&path) {
                Ok(text) => Some(text),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(MeasureError::Policy(format!("{}: {e}", path.display()))),
            }
        }
        PolicySource::Commit(oid) => {
            // Presence is asked first, and separately. `git show` on a path a
            // commit does not carry exits 128, which the wrapper reports as a
            // failure — so reading it directly made "this repository has no
            // policy file", which is the ordinary case for every repository but
            // this one, indistinguishable from "git broke". A verifier that
            // refused to attest any project without an `.andon.toml` would refuse
            // nearly all of them, and the error message would name a git command
            // rather than the situation.
            //
            // `cat-file -e` answers exactly the question — does this commit carry
            // this blob — and leaves a real git failure still able to surface as
            // one.
            let spec = format!("{oid}:.andon.toml");
            let present = git
                .cmd(["cat-file", "-e", &spec])
                .succeeds()
                .map_err(|e| MeasureError::Policy(e.to_string()))?;
            if present {
                Some(
                    git.cmd(["show", "--no-textconv", &spec])
                        .text()
                        .map_err(|e| MeasureError::Policy(e.to_string()))?,
                )
            } else {
                None
            }
        }
    };
    match text {
        Some(text) => {
            Policy::from_toml(&text).map_err(|e| MeasureError::Policy(format!("{source:?}: {e}")))
        }
        None => Ok(Policy::default()),
    }
}

/// The branch the iteration counter is keyed on.
///
/// A detached HEAD has no branch name, and keying every detached measurement
/// under one shared name would make an agent's third pass on one commit escalate
/// an unrelated first pass on another. The head OID is the honest key there: it
/// is per-change, which is what the counter is counting.
fn current_branch(git: &Git, resolution: &Resolution) -> String {
    match git
        .cmd(["symbolic-ref", "--quiet", "--short", "HEAD"])
        .succeeds_with_output()
    {
        Ok(Some(name)) if !name.trim().is_empty() => name.trim().to_string(),
        _ => format!("detached:{}", resolution.compare_context.head_oid),
    }
}

/// How this self-measurement was arrived at (PREMORTEM S3,
/// `docs/self-measure.md`).
///
/// # Every field is read, none is asserted
///
/// The binary identity comes from [`tool_identity`], which is the same value
/// the record's `tool` block carries, so the two cannot disagree about which
/// build reached the verdict. The withheld paths are the ones
/// [`apply_exclusions`] actually withheld on this run, not the patterns that
/// withheld them — the patterns are policy and ride in `policy_hash`, and what
/// a reader needs is which files were not measured.
///
/// # The bootstrap override, and where its fields come from
///
/// `docs/self-measure.md`: the rule is that self-measurement runs the last
/// attested release, and until one exists every self-measurement carries the
/// override `bootstrap-no-attested-release`. So the override is present exactly
/// when the policy states the rule and this binary is not an attested release —
/// a condition, read, which is what makes the exception self-expiring rather
/// than a grace period somebody has to remember to end. When policy already
/// says `current-build` there is no rule being excepted and no override.
///
/// `approved_by` is the owner this package declares in its own manifest, which
/// is where this repository records who it belongs to; it is the same name the
/// evidence registry writes in every claim's `owner`. `reference` is the
/// contract the decision is recorded in.
///
/// # `exclusion_drift` is false because there is no baseline
///
/// Drift is defined against the last attested run and there has never been one,
/// which `attested: false` in the same struct says. It is not a claim that the
/// list held still. The renderers read the pair rather than the bool alone.
fn self_measure_provenance(
    policy: &Policy,
    excluded: &[String],
    resolution: &resolve::Resolution,
) -> SelfMeasureProvenance {
    let tool = tool_identity();
    let bootstrap = !tool.attested_release
        && policy.self_measure.binary == andon_core::policy::SelfMeasureBinary::LastAttestedRelease;
    SelfMeasureProvenance {
        measuring_binary_version: tool.version.clone(),
        measuring_binary_oid: tool.build_oid.clone(),
        attested: tool.attested_release,
        override_record: bootstrap.then(|| SelfMeasureOverride {
            reason: OverrideReason::BootstrapNoAttestedRelease,
            justification: format!(
                "`[self_measure] binary` is `last-attested-release` and {} {} is not an \
                 attested release, so this measurement ran the working tree's own build. The \
                 exception names a condition and stops being available the moment the first \
                 attested release exists.",
                tool.name, tool.version
            ),
            reference: "docs/self-measure.md#the-bootstrap-exception".to_string(),
            approved_by: package_owner().to_string(),
            // The commit the override applies to, and overrides do not carry
            // forward. `anchor_oid` rather than `head_oid`: a dirty head's
            // identity is a content hash, which is not a commit for an override
            // to be pinned to.
            head_oid: resolution.range.head.anchor_oid().to_string(),
        }),
        excluded_paths: excluded.to_vec(),
        exclusion_drift: false,
    }
}

/// The owner this package declares, from its own manifest.
///
/// Read rather than written down twice: `Cargo.toml`'s `repository` is where
/// this repository records who it belongs to, and it is the same name the
/// evidence registry writes in every claim's `owner`. A literal here would be a
/// second copy of a fact the manifest already holds, which is how two answers to
/// one question start.
fn package_owner() -> &'static str {
    env!("CARGO_PKG_REPOSITORY")
        .trim_end_matches('/')
        .rsplit('/')
        .nth(1)
        .unwrap_or("unknown")
}

/// Who measured.
///
/// `attested_release` is false and will stay false until a release exists whose
/// own measurement CI attested. Saying `true` here would be the self-measure
/// rule asserting itself (`docs/self-measure.md`), which is the one thing a
/// self-report may not do.
fn tool_identity() -> ToolIdentity {
    ToolIdentity {
        name: TOOL_NAME.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_oid: option_env!("ANDON_BUILD_OID")
            .unwrap_or("unknown")
            .to_string(),
        attested_release: false,
    }
}

/// Results an agent could act on inside this change, worst first.
///
/// The report's ordering, and it is a sort rather than a score: nothing here
/// combines two metrics into one number. Severity, then metric id, so two runs
/// over one change order identically.
pub fn actionable_first(results: &[MeasurementResult]) -> Vec<&MeasurementResult> {
    let mut ordered: Vec<&MeasurementResult> = results.iter().collect();
    ordered.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| {
                actionability_rank(a.metric_class).cmp(&actionability_rank(b.metric_class))
            })
            .then_with(|| a.metric_id.cmp(&b.metric_id))
            .then_with(|| scope_label(a).cmp(&scope_label(b)))
    });
    ordered
}

fn actionability_rank(class: MetricClass) -> u8 {
    match class {
        MetricClass::DiffActionable => 0,
        MetricClass::ContextInformational => 1,
    }
}

/// What a result is about, in one string.
pub fn scope_label(result: &MeasurementResult) -> String {
    let scope = &result.scope;
    match (scope.kind, &scope.path, &scope.symbol) {
        (ScopeKind::Repository, _, _) => "the repository".to_string(),
        (ScopeKind::Change, _, _) => "this change".to_string(),
        (ScopeKind::File, Some(path), _) => path.clone(),
        (ScopeKind::Function, Some(path), Some(symbol)) => match scope.line_span {
            Some(span) => format!("{path}:{} {symbol}", span.start),
            None => format!("{path} {symbol}"),
        },
        (_, Some(path), _) => path.clone(),
        (_, None, _) => "this change".to_string(),
    }
}

/// A metric value as a human reads it.
pub fn value_label(value: &MetricValue) -> String {
    match value {
        MetricValue::Count(n) => n.to_string(),
        MetricValue::Integer(n) => {
            if *n > 0 {
                format!("+{n}")
            } else {
                n.to_string()
            }
        }
        MetricValue::Ratio(r) => format!("{:.4}", r),
        MetricValue::Duration { millis } => format!("{millis} ms"),
        MetricValue::Flag(true) => "fired".to_string(),
        MetricValue::Flag(false) => "did not fire".to_string(),
        MetricValue::Text(text) => text.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_double_star_pattern_matches_the_directory_and_its_contents() {
        assert!(matches_prefix("fixtures/gamed/**", "fixtures/gamed/a.ts"));
        assert!(matches_prefix("fixtures/gamed/**", "fixtures/gamed/x/y.ts"));
        assert!(matches_prefix("fixtures/gamed/**", "fixtures/gamed"));
    }

    #[test]
    fn a_prefix_that_is_not_a_path_boundary_does_not_match() {
        // The bug this pins: `starts_with("fixtures/gamed")` also excludes
        // `fixtures/gamed-honest/`, which is a different directory and one
        // nobody declared.
        assert!(!matches_prefix(
            "fixtures/gamed/**",
            "fixtures/gamed-honest/a.ts"
        ));
    }

    #[test]
    fn a_literal_pattern_matches_only_itself() {
        assert!(matches_prefix(".andon.toml", ".andon.toml"));
        assert!(!matches_prefix(".andon.toml", "docs/.andon.toml"));
    }

    #[test]
    fn the_shipped_exclusions_are_all_expressible() {
        // The refusal-rather-than-approximate claim, checked against the shipped
        // list rather than against an example: a pattern this matcher cannot
        // express would silently exclude nothing.
        for pattern in Policy::default().self_measure.excluded_paths {
            assert!(
                pattern.ends_with("/**"),
                "{pattern} is not the `dir/**` shape this matcher implements"
            );
        }
    }
}
