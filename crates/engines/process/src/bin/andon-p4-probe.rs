//! `andon-p4-probe` — the process family's cross-OS determinism probe.
//!
//! ```text
//! andon-p4-probe measure --repo PATH --base REV|merge-base:REF --head REV
//!                        [--window DAYS] [--no-cache] [--out FILE]
//! andon-p4-probe compare --leg NAME=FILE [--leg NAME=FILE ...]
//! ```
//!
//! `measure` writes one leg's digest table; `compare` holds several legs against
//! each other by the rule in [`andon_engine_process::probe`] — byte-identical
//! within a measurement regime, visibly skewed across regimes.
//!
//! # Why this is a binary rather than shell in a workflow
//!
//! P4 may not edit `.github/workflows/spike-matrix.yml` this wave — P2 is its
//! single writer (PLAN P1.5 decision (g)) — so the process family's matrix join
//! ships as a documented patch applied after the merge. A patch made of twenty
//! lines of embedded shell is a patch nobody can review and nobody can run
//! locally. The comparison rule lives in the library, is covered by unit tests,
//! and is invoked here; the patch contains only the steps that call it.
//!
//! Output is JSON with sorted keys and no timestamps: the file is meant to be
//! diffed between legs, so nothing in it may vary between two honest runs.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use andon_core::engine::{run_engine, MeasureContext, MeasureEngine};
use andon_core::git::{ChangedSet, Git, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_engine_process::cache::HistoryCache;
use andon_engine_process::complexity::NoComplexity;
use andon_engine_process::engine::ProcessEngine;
use andon_engine_process::probe::{compare_legs, LegReport};

const USAGE: &str = "\
usage: andon-p4-probe measure --repo PATH --base REV|merge-base:REF --head REV
                              [--window DAYS] [--no-cache] [--out FILE]
       andon-p4-probe compare --leg NAME=FILE [--leg NAME=FILE ...]";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("andon-p4-probe: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("measure") => measure(args.collect()).map(|()| ExitCode::SUCCESS),
        Some("compare") => compare(args.collect()),
        Some("-h") | Some("--help") => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => Err(format!("unknown subcommand '{other}'\n{USAGE}")),
        None => Err(format!("a subcommand is required\n{USAGE}")),
    }
}

/// `merge-base:REF` or a plain commit-ish.
fn revision(spec: &str) -> Revision {
    match spec.strip_prefix("merge-base:") {
        Some(with) => Revision::merge_base(with),
        None => Revision::Rev(spec.to_string()),
    }
}

fn measure(args: Vec<String>) -> Result<(), String> {
    let (mut repo, mut base, mut head, mut window, mut out) = (None, None, None, None, None);
    let mut no_cache = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--repo" => repo = Some(PathBuf::from(value("--repo")?)),
            "--base" => base = Some(value("--base")?),
            "--head" => head = Some(value("--head")?),
            "--window" => {
                window = Some(
                    value("--window")?
                        .parse::<u32>()
                        .map_err(|_| "--window needs a whole number of days".to_string())?,
                )
            }
            "--out" => out = Some(PathBuf::from(value("--out")?)),
            "--no-cache" => no_cache = true,
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    let repo = repo.ok_or(format!("--repo is required\n{USAGE}"))?;
    let base = base.ok_or(format!("--base is required\n{USAGE}"))?;
    let head = head.ok_or(format!("--head is required\n{USAGE}"))?;

    let git = Git::open(&repo).map_err(|e| e.to_string())?;
    let mut policy = Policy::default();
    if let Some(days) = window {
        policy.history.window_days = days;
    }

    let range = ResolvedRange::resolve(&git, &revision(&base), &revision(&head))
        .map_err(|e| e.to_string())?;
    let changed = ChangedSet::enumerate(&git, &range).map_err(|e| e.to_string())?;
    let compare_context = range.compare_context().map_err(|e| e.to_string())?;

    let cache = if no_cache {
        None
    } else {
        Some(HistoryCache::for_repo(&git).map_err(|e| e.to_string())?)
    };
    let engine = ProcessEngine::for_change(
        &git,
        &range,
        &changed,
        &policy,
        // No complexity source: the probe measures the process half alone, so
        // every hotspot is an unwitnessed marker — which is itself worth having
        // byte-identical across legs.
        &NoComplexity,
        cache.as_ref(),
    )
    .map_err(|e| e.to_string())?;

    let ctx = MeasureContext {
        compare_context: compare_context.clone(),
        policy,
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox: None,
    };
    let results = run_engine(&engine, &ctx).map_err(|e| e.to_string())?;

    let report = LegReport::new(
        compare_context.base_oid,
        compare_context.head_oid,
        engine.descriptor().version,
        engine.regime(),
        changed.entries.len(),
        engine.is_truncated(),
        &results,
    );
    let text = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    match out {
        Some(path) => write_out(&path, &text),
        None => {
            println!("{text}");
            Ok(())
        }
    }
}

fn compare(args: Vec<String>) -> Result<ExitCode, String> {
    let mut legs: Vec<(String, LegReport)> = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--leg" => {
                let spec = args.next().ok_or("--leg needs NAME=FILE")?;
                let (name, path) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("--leg wants NAME=FILE, got '{spec}'"))?;
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("could not read {path}: {e}"))?;
                let leg: LegReport = serde_json::from_str(&text)
                    .map_err(|e| format!("{path} is not a probe report: {e}"))?;
                legs.push((name.to_string(), leg));
            }
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }

    let comparison = compare_legs(&legs);
    println!("legs: {}", legs.len());
    for (regime, names) in &comparison.groups {
        println!(
            "  regime {} :: {}",
            &regime[..8.min(regime.len())],
            names.join(", ")
        );
    }
    for skew in &comparison.skews {
        println!("  skew   {skew}");
    }
    if comparison.skews.is_empty() && comparison.groups.len() == 1 {
        println!("  every leg shares one regime: the strong form of the assertion applies.");
    } else {
        println!(
            "  legs in different regimes are NOT digest-compared. That is PREMORTEM S4: a\n  \
             version difference is `unwitnessed-version-skew`, never `divergent`."
        );
    }

    if comparison.passed() {
        println!("PASS: every regime group is byte-identical.");
        return Ok(ExitCode::SUCCESS);
    }
    for failure in &comparison.failures {
        eprintln!("FAIL: {failure}");
    }
    Ok(ExitCode::FAILURE)
}

fn write_out(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, format!("{text}\n"))
        .map_err(|e| format!("could not write {}: {e}", path.display()))
}
