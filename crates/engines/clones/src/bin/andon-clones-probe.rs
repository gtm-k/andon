//! Measure one change with the clone engine and write the record.
//!
//! ```text
//! andon-clones-probe --repo <PATH> --base <REV> --head <REV> [--index <PATH>] --out <FILE>
//! ```
//!
//! Exit codes: 0 measured, 2 bad usage or an operational failure.
//!
//! # What it is for
//!
//! The standing cross-OS determinism matrix (PLAN B4). The record it writes is a
//! `MeasurementRecord`, which is what `andon-spike compare-records` already
//! reads, so the clone engine joins the matrix without either crate depending on
//! the other — the workflow runs two binaries and compares their output. Coupling
//! an engine crate to the P1.5 spike crate to share a comparison function would
//! be a dependency edge in the wrong direction for a phase that is supposed to be
//! parallel with P2 and P4.
//!
//! # Why a `--base` that is a commit
//!
//! Only commit endpoints produce a `(base_oid, head_oid)` tuple, and only a tuple
//! makes a per-result digest meaningful. A worktree head measures fine and cannot
//! be sealed against anything, so this binary refuses it rather than emitting a
//! record whose digests describe nothing.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::git::{ChangedSet, Git, ResolvedRange, Revision};
use andon_core::parse_health;
use andon_core::policy::Policy;
use andon_core::schema::enums::{InvocationSource, RecordKind, Verdict};
use andon_core::schema::payload::{
    AttestationBlock, Invocation, IterationState, MeasurementRecord, Reserved, ToolIdentity,
    VerdictSummary, SCHEMA_VERSION,
};
use andon_engine_clones::ClonesEngine;

const USAGE: &str = "\
usage: andon-clones-probe --repo <PATH> --base <REV> --head <REV> [--index <PATH>] --out <FILE>
       --base accepts `merge-base:<branch>` or an explicit revision";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("andon-clones-probe: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    let repo = require(&args, "--repo")?;
    let base = require(&args, "--base")?;
    let head = require(&args, "--head")?;
    let out = require(&args, "--out")?;
    let index = value(&args, "--index").map(PathBuf::from);

    let git = Git::open(Path::new(repo)).map_err(|e| e.to_string())?;
    let range = ResolvedRange::resolve(&git, &revision(base), &revision(head))
        .map_err(|e| e.to_string())?;
    let compare_context = range.compare_context().map_err(|e| {
        format!("{e}\nA digest is only meaningful against a (base_oid, head_oid) tuple, so this binary measures commits.")
    })?;
    let changed = ChangedSet::enumerate(&git, &range).map_err(|e| e.to_string())?;

    let engine =
        ClonesEngine::for_change(&git, &changed, index.as_deref()).map_err(|e| e.to_string())?;
    let context = MeasureContext {
        compare_context: compare_context.clone(),
        // The base commit's policy is the verifier's to load; nothing this
        // engine emits is policy-dependent, and `policy_hash` is a record-level
        // field outside every per-result digest.
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox_available: false,
    };
    let results = run_engine(&engine, &context).map_err(|e| e.to_string())?;

    eprintln!(
        "clones: {} changed path(s), index {}, {} result(s), {} clone group(s)",
        changed.len(),
        engine.index_state(),
        results.len(),
        engine.report().groups.len()
    );

    let record = MeasurementRecord {
        // A probe measures a commit range with one engine: nothing substituted,
        // and nothing it was handed went unread.
        substitution: None,
        unreadable_paths: Vec::new(),
        schema_version: SCHEMA_VERSION,
        record_kind: RecordKind::SelfReport,
        tool: ToolIdentity {
            name: "andon-clones-probe".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_oid: String::new(),
            // No attested release of Andon exists yet; the bootstrap exception
            // is stated in the record rather than assumed.
            attested_release: false,
        },
        compare_context,
        invocation: Invocation {
            source: InvocationSource::CiVerifier,
            harness: None,
            model: None,
            author: None,
            iteration: 1,
        },
        reserved: Reserved::default(),
        policy_hash: Policy::default().policy_hash().map_err(|e| e.to_string())?,
        // The weakest of the results', never a standing `complete`: a
        // record that claimed to be complete while carrying a
        // parse-degraded result inside it would put the two halves of
        // the same payload in disagreement, and the record-level field
        // is the one a reader checks first.
        completeness: parse_health::weakest(&results),
        results,
        verdict: VerdictSummary {
            // The probe measures and does not judge: assembling a verdict from
            // engine output is P5a's, and inventing one here would be a second
            // implementation of it for the matrix to disagree with.
            verdict: Verdict::Pass,
            reasons: Vec::new(),
            iteration: IterationState {
                count: 1,
                cap: Policy::default().loop_policy.iteration_cap,
                escalated: false,
            },
        },
        attestation: AttestationBlock::default(),
    };

    let json = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
    std::fs::write(out, format!("{json}\n")).map_err(|e| format!("{out}: {e}"))
}

fn revision(spec: &str) -> Revision {
    match spec.strip_prefix("merge-base:") {
        Some(branch) => Revision::merge_base(branch),
        None => Revision::Rev(spec.to_string()),
    }
}

fn value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let index = args.iter().position(|a| a == name)?;
    args.get(index + 1).map(String::as_str)
}

fn require<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    value(args, name).ok_or_else(|| format!("{name} is required\n{USAGE}"))
}
