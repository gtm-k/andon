//! Measure one change with the tamper suite and write the record.
//!
//! ```text
//! andon-tamper-probe --repo <PATH> --base <REV> --head <REV> --out <FILE>
//! andon-tamper-probe build-fixture --case <DIR> --dest <PATH> [--json <FILE>]
//! ```
//!
//! Exit codes: 0 measured, 2 bad usage or an operational failure.
//!
//! # What it is for
//!
//! The standing cross-OS determinism matrix (PLAN B4, R2-1: *all seven*
//! detectors join it). The record it writes is a `MeasurementRecord`, which
//! `andon-spike compare-records` already reads, so the tamper suite joins the
//! matrix without this crate depending on the P1.5 spike crate.
//!
//! # Why it also builds the fixture
//!
//! The matrix compares per-result digests, and a per-result digest binds
//! `(base_oid, head_oid)`. Building the fixture repository separately on each
//! leg would make the comparison depend on three operating systems producing
//! byte-identical commit OIDs — a second determinism claim nested inside the one
//! under test. So `build-fixture` runs once, on one machine, and the bare
//! repository it produces is what every leg clones. That is the same argument
//! `spike-matrix.yml` makes for its own fixture, and the same conclusion.
//!
//! The commits are made with pinned identity and pinned timestamps so that the
//! OIDs are a function of the committed bytes alone. That is not for the matrix
//! — which ships one build — but so that a maintainer rebuilding the fixture
//! locally gets the same SHAs and can diff a local table against a CI one.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::git::{ChangedSet, Git, ResolvedRange, Revision};
use andon_core::parse_health;
use andon_core::policy::Policy;
use andon_core::schema::enums::{InvocationSource, RecordKind, Verdict};
use andon_core::schema::payload::{
    AttestationBlock, Invocation, IterationState, MeasurementRecord, Reserved, ToolIdentity,
    VerdictSummary, SCHEMA_VERSION,
};
use andon_engine_tamper::detectors;
use andon_engine_tamper::TamperEngine;

const USAGE: &str = "\
usage: andon-tamper-probe --repo <PATH> --base <REV> --head <REV> --out <FILE>
       andon-tamper-probe build-fixture --case <DIR> --dest <PATH> [--json <FILE>]
       --base accepts `merge-base:<branch>` or an explicit revision";

/// Pinned so a rebuilt fixture has the same commit OIDs as the last one.
const FIXTURE_IDENTITY: &[(&str, &str)] = &[
    ("GIT_AUTHOR_NAME", "andon-fixture"),
    ("GIT_AUTHOR_EMAIL", "fixture@andon.invalid"),
    ("GIT_AUTHOR_DATE", "2026-01-01T00:00:00+00:00"),
    ("GIT_COMMITTER_NAME", "andon-fixture"),
    ("GIT_COMMITTER_EMAIL", "fixture@andon.invalid"),
    ("GIT_COMMITTER_DATE", "2026-01-01T00:00:00+00:00"),
];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("andon-tamper-probe: {message}");
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
    if args.first().map(String::as_str) == Some("build-fixture") {
        return build_fixture(&args);
    }

    let repo = require(&args, "--repo")?;
    let base = require(&args, "--base")?;
    let head = require(&args, "--head")?;
    let out = require(&args, "--out")?;

    let git = Git::open(Path::new(repo)).map_err(|e| e.to_string())?;
    let range = ResolvedRange::resolve(&git, &revision(base), &revision(head))
        .map_err(|e| e.to_string())?;
    let compare_context = range.compare_context().map_err(|e| {
        format!("{e}\nA digest is only meaningful against a (base_oid, head_oid) tuple, so this binary measures commits.")
    })?;
    let changed = ChangedSet::enumerate(&git, &range).map_err(|e| e.to_string())?;

    let engine = TamperEngine::for_change(&git, &changed).map_err(|e| e.to_string())?;
    let context = MeasureContext {
        compare_context: compare_context.clone(),
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox_available: false,
    };
    let results = run_engine(&engine, &context).map_err(|e| e.to_string())?;

    // Printed to stderr so a matrix leg's log says which detectors fired
    // without the assertion depending on the log. A leg where nothing fires is
    // a leg comparing seven `false` flags, which is a green matrix that proves
    // the fixture wrong rather than the engine right.
    let fired: Vec<&str> = engine
        .outcomes()
        .iter()
        .filter(|(_, outcome)| outcome.fired)
        .map(|(detector, _)| detectors::signal_name(detector.signal()))
        .collect();
    eprintln!(
        "tamper: {} changed path(s), {} result(s), {} of 7 detectors fired: {}",
        changed.len(),
        results.len(),
        fired.len(),
        if fired.is_empty() {
            "none".to_string()
        } else {
            fired.join(", ")
        }
    );

    let record = MeasurementRecord {
        // A probe measures a commit range with one engine: nothing substituted,
        // and nothing it was handed went unread.
        substitution: None,
        unreadable_paths: Vec::new(),
        self_measure: None,
        schema_version: SCHEMA_VERSION,
        record_kind: RecordKind::SelfReport,
        tool: ToolIdentity {
            name: "andon-tamper-probe".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_oid: String::new(),
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
            // Assembling a verdict from tamper signals is P5a's, under policy
            // the verifier loads from the base commit. A probe that invented one
            // would be a second implementation for the matrix to disagree with.
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

/// Build a two-commit repository from a case directory's `base/` and `head/`
/// trees, and print the SHAs.
fn build_fixture(args: &[String]) -> Result<(), String> {
    let case = PathBuf::from(require(args, "--case")?);
    let dest = PathBuf::from(require(args, "--dest")?);
    if dest.exists() {
        std::fs::remove_dir_all(&dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    std::fs::create_dir_all(&dest).map_err(|e| format!("{}: {e}", dest.display()))?;

    git(&dest, &["init", "--quiet", "--initial-branch=main"])?;
    // Byte-exact working tree on every platform: the fixture's whole purpose is
    // that the committed bytes are the same everywhere, and a checkout filter
    // is the one thing that could make them not be (PREMORTEM T1).
    git(&dest, &["config", "core.autocrlf", "false"])?;
    git(&dest, &["config", "core.eol", "lf"])?;

    copy_tree(&case.join("base"), &dest)?;
    git(&dest, &["add", "-A"])?;
    git(&dest, &["commit", "--quiet", "-m", "base"])?;
    let base = rev_parse(&dest, "HEAD")?;

    clear_tree(&dest)?;
    copy_tree(&case.join("head"), &dest)?;
    git(&dest, &["add", "-A"])?;
    git(&dest, &["commit", "--quiet", "-m", "head"])?;
    let head = rev_parse(&dest, "HEAD")?;

    let json = format!("{{\n  \"base\": \"{base}\",\n  \"head\": \"{head}\"\n}}\n");
    if let Some(path) = value(args, "--json") {
        std::fs::write(path, &json).map_err(|e| format!("{path}: {e}"))?;
    }
    print!("{json}");
    Ok(())
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new("git");
    command.current_dir(dir).args(args);
    for (key, value) in FIXTURE_IDENTITY {
        command.env(key, value);
    }
    // The same hygiene every other git spawn in this workspace uses: a hostile
    // or merely opinionated user config must not reach a fixture's bytes.
    command.env("GIT_CONFIG_NOSYSTEM", "1");
    command.env("LC_ALL", "C");
    let output = command
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn rev_parse(dir: &Path, rev: &str) -> Result<String, String> {
    git(dir, &["rev-parse", rev])
}

/// Copy a tree into the repository, keeping bytes exactly as committed.
fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    if !from.is_dir() {
        return Ok(());
    }
    let mut stack = vec![from.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path.strip_prefix(from).expect("walked from `from`");
            let target = to.join(relative);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            std::fs::copy(&path, &target).map_err(|e| format!("{}: {e}", target.display()))?;
        }
    }
    Ok(())
}

/// Empty the working tree, keeping `.git`, so the head commit is the head tree
/// and not the union of both sides.
fn clear_tree(repo: &Path) -> Result<(), String> {
    for entry in std::fs::read_dir(repo).map_err(|e| format!("{}: {e}", repo.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", repo.display()))?;
        if entry.file_name() == ".git" {
            continue;
        }
        let path = entry.path();
        let result = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        result.map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
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
