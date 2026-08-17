//! `andon-registry-lint` — the build-failing evidence gate.
//!
//! Ships in P0 and is required green from P2 onward (PLAN R2-2). It is a
//! separate binary from the measurement tool on purpose: it has to run in CI
//! before most of the engines it polices exist, and it must not need any of them
//! to be buildable.
//!
//! ```text
//! andon-registry-lint [OPTIONS] <REGISTRY_DIR>
//!
//!   --as-of <YYYY-MM-DD>  Date to evaluate expiries against (default: today, UTC)
//!   --policy <PATH>       Policy file supplying the claim budget and stagger limit
//!   --quiet               Print only failures
//!
//! Exit codes: 0 clean (notices allowed), 1 lint failed, 2 bad usage or I/O.
//! ```
//!
//! Expired claims are notices, not failures. Halting the release train because a
//! citation aged is the failure mode PREMORTEM S2 describes — the claim demotes
//! to a visible `evidence: stale` instead, and the build stays green.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use andon_core::date::Date;
use andon_core::policy::{Policy, RegistryPolicy};
use andon_core::registry::{lint, parse_file, DiagnosticSeverity, EngineRegistryFile};

const USAGE: &str = "\
usage: andon-registry-lint [--as-of YYYY-MM-DD] [--policy PATH] [--quiet] <REGISTRY_DIR>";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("andon-registry-lint: {message}");
            ExitCode::from(2)
        }
    }
}

struct Args {
    registry_dir: PathBuf,
    as_of: Date,
    policy_path: Option<PathBuf>,
    quiet: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut registry_dir = None;
    let mut as_of = None;
    let mut policy_path = None;
    let mut quiet = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--as-of" => {
                let raw = args.next().ok_or("--as-of needs a YYYY-MM-DD value")?;
                as_of = Some(raw.parse::<Date>().map_err(|e| e.to_string())?);
            }
            "--policy" => {
                policy_path = Some(PathBuf::from(args.next().ok_or("--policy needs a path")?));
            }
            "--quiet" => quiet = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'\n{USAGE}"));
            }
            other => {
                if registry_dir.replace(PathBuf::from(other)).is_some() {
                    return Err(format!("expected one registry directory\n{USAGE}"));
                }
            }
        }
    }

    Ok(Args {
        registry_dir: registry_dir.ok_or_else(|| format!("missing registry directory\n{USAGE}"))?,
        // Tests always pass --as-of: a lint whose verdict depends on the day it
        // runs cannot be asserted on. CI deliberately does not — staleness
        // notices should appear as claims age, and since they never fail the
        // build, letting the real date reach CI is how expiry becomes visible.
        as_of: as_of.unwrap_or_else(Date::today_utc),
        policy_path,
        quiet,
    })
}

fn run() -> Result<ExitCode, String> {
    let args = parse_args()?;

    let registry_policy = load_registry_policy(args.policy_path.as_deref())?;
    let files = load_registry_files(&args.registry_dir)?;

    if files.is_empty() && !args.quiet {
        // The P0 state: the registry exists, no engine has shipped a metric yet.
        // Say so rather than printing a silent success that looks like a pass
        // over content that was never there.
        println!(
            "registry {}: no engine registry files yet; nothing to check",
            args.registry_dir.display()
        );
    }

    let (_registry, report) = lint(&files, &registry_policy, args.as_of);

    for diagnostic in &report.diagnostics {
        let label = match diagnostic.severity {
            DiagnosticSeverity::Error => "error",
            DiagnosticSeverity::Notice => "notice",
        };
        if diagnostic.severity == DiagnosticSeverity::Error || !args.quiet {
            eprintln!(
                "{label}[{}] {}: {}",
                diagnostic.code, diagnostic.location, diagnostic.message
            );
        }
    }

    if report.failed() {
        let count = report.errors().count();
        eprintln!(
            "registry lint failed: {count} error(s) across {} claim(s) and {} metric(s)",
            report.claim_count, report.metric_count
        );
        return Ok(ExitCode::from(1));
    }

    if !args.quiet {
        println!(
            "registry lint clean: {} claim(s), {} metric(s), budget {} (as of {})",
            report.claim_count, report.metric_count, registry_policy.claim_budget, args.as_of
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn load_registry_policy(path: Option<&Path>) -> Result<RegistryPolicy, String> {
    let Some(path) = path else {
        return Ok(RegistryPolicy::default());
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read policy {}: {e}", path.display()))?;
    let policy =
        Policy::from_toml(&text).map_err(|e| format!("invalid policy {}: {e}", path.display()))?;
    Ok(policy.registry)
}

fn load_registry_files(dir: &Path) -> Result<Vec<(String, EngineRegistryFile)>, String> {
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }

    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    // Sorted so diagnostics come out in the same order everywhere, which matters
    // when CI output is the only thing a contributor can see.
    paths.sort();

    let mut files = Vec::new();
    for path in paths {
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let parsed = parse_file(&label, &text).map_err(|e| e.to_string())?;
        files.push((label, parsed));
    }
    Ok(files)
}
