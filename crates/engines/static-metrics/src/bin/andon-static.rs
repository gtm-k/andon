//! `andon-static` — the P2 harness as a command line.
//!
//! Three jobs, none of them the product CLI (which arrives at P5b):
//!
//! ```text
//! andon-static measure --repo <PATH> --base <REV> --head <REV> [--out <FILE>] [--quiet]
//! andon-static fixture --manifest <FILE> --dest <DIR> [--json <FILE>]
//! andon-static corpus plan  [--manifest <FILE>]
//! andon-static corpus check [--manifest <FILE>] --root <DIR>
//!                           [--baseline <FILE>] [--write-baseline <FILE>]
//!                           [--run-ref <URL>]
//!
//! Exit codes: 0 success, 1 the answer was negative (a budget was exceeded),
//! 2 bad usage or an operational failure.
//! ```
//!
//! The records `measure` writes are compared across matrix legs by
//! `andon-spike compare-records`, which reads a `MeasurementRecord` and cares
//! nothing about which engine produced it. There is no `compare` subcommand here
//! for that reason: a second cross-leg comparison would be a second set of
//! failure messages to keep honest.
//!
//! The flag parser is hand-rolled, for the reason `andon-spike`'s and
//! `andon-registry-lint`'s are: this workspace's supply-chain gate is
//! `cargo deny check licenses bans sources`, and a dependency admitted for
//! argument parsing is a dependency the verifier has to be trusted with.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use andon_core::git::{Git, Revision};
use andon_static_metrics::{corpus, fixture, record};

const USAGE: &str = "\
usage: andon-static <measure|fixture|corpus> [OPTIONS]
       measure --repo <PATH> --base <REV> --head <REV> [--out <FILE>] [--quiet]
       fixture --manifest <FILE> --dest <DIR> [--json <FILE>]
       corpus plan  [--manifest <FILE>]
       corpus check [--manifest <FILE>] --root <DIR> [--baseline <FILE>]
                    [--write-baseline <FILE>] [--run-ref <URL>]";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("andon-static: {message}");
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, Default)]
struct Flags {
    values: Vec<(String, String)>,
    switches: Vec<String>,
    positional: Vec<String>,
}

impl Flags {
    fn parse(args: impl Iterator<Item = String>, switch_names: &[&str]) -> Result<Self, String> {
        let mut flags = Flags::default();
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            if let Some(name) = arg.strip_prefix("--") {
                if switch_names.contains(&name) {
                    flags.switches.push(name.to_string());
                } else if let Some((name, value)) = name.split_once('=') {
                    flags.values.push((name.to_string(), value.to_string()));
                } else {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("--{name} needs a value"))?;
                    flags.values.push((name.to_string(), value));
                }
            } else {
                flags.positional.push(arg);
            }
        }
        Ok(flags)
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn require(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn on(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }
}

const SWITCHES: &[&str] = &["quiet", "help"];

fn run() -> Result<ExitCode, String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(|| USAGE.to_string())?;
    if command == "--help" || command == "-h" {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    let flags = Flags::parse(args.collect::<Vec<_>>().into_iter(), SWITCHES)?;
    match command.as_str() {
        "measure" => cmd_measure(&flags),
        "fixture" => cmd_fixture(&flags),
        "corpus" => cmd_corpus(&flags),
        other => Err(format!("unknown command '{other}'\n{USAGE}")),
    }
}

/// `--base merge-base:<branch>` or an explicit revision, the same spelling
/// `andon-spike` accepts.
fn base_revision(spec: &str) -> Revision {
    match spec.split_once(':') {
        Some(("merge-base", branch)) => Revision::merge_base(branch),
        _ => Revision::Rev(spec.to_string()),
    }
}

fn cmd_measure(flags: &Flags) -> Result<ExitCode, String> {
    let git = Git::open(Path::new(flags.get("repo").unwrap_or("."))).map_err(|e| e.to_string())?;
    let version = flags
        .get("engine-version")
        .map(str::to_string)
        .unwrap_or_else(|| andon_static_metrics::engine_version().to_string());
    let record = record::measure(
        &git,
        &base_revision(flags.require("base")?),
        &Revision::Rev(flags.require("head")?.to_string()),
        &version,
    )
    .map_err(|e| e.to_string())?;

    if let Some(out) = flags.get("out") {
        record::write(Path::new(out), &record).map_err(|e| e.to_string())?;
    }
    if !flags.on("quiet") {
        println!(
            "measured {}..{}: {} result(s), {} file(s) unmeasured, completeness {:?}, engine {version}",
            &record.compare_context.base_oid[..12],
            &record.compare_context.head_oid[..12],
            record.results.len(),
            unmeasured_count(&record),
            record.completeness,
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// The `static.unmeasured-files` value, for the one-line summary.
fn unmeasured_count(record: &andon_core::schema::payload::MeasurementRecord) -> String {
    record
        .results
        .iter()
        .find(|r| r.metric_id == andon_static_metrics::metrics::METRIC_UNMEASURED_FILES)
        .map(|r| format!("{:?}", r.value))
        .unwrap_or_else(|| "?".to_string())
}

fn cmd_fixture(flags: &Flags) -> Result<ExitCode, String> {
    let manifest_path = flags
        .get("manifest")
        .map(PathBuf::from)
        .unwrap_or_else(fixture::matrix_manifest_path);
    let manifest = fixture::load(&manifest_path).map_err(|e| e.to_string())?;
    let prepared =
        fixture::build(&manifest, Path::new(flags.require("dest")?)).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&prepared).map_err(|e| e.to_string())?;
    if let Some(out) = flags.get("json") {
        std::fs::write(out, format!("{json}\n")).map_err(|e| e.to_string())?;
    }
    println!("{json}");
    Ok(ExitCode::SUCCESS)
}

fn cmd_corpus(flags: &Flags) -> Result<ExitCode, String> {
    let action = flags
        .positional
        .first()
        .ok_or("corpus needs `plan` or `check`")?
        .clone();
    let manifest_path = flags
        .get("manifest")
        .map(PathBuf::from)
        .unwrap_or_else(corpus::manifest_path);
    let manifest = corpus::load(&manifest_path).map_err(|e| e.to_string())?;

    match action.as_str() {
        // Tab-separated so the workflow's fetch loop reads it with `read` and
        // never parses TOML in bash.
        "plan" => {
            for repo in &manifest.repos {
                println!("{}\t{}\t{}", repo.name, repo.url, repo.rev);
            }
            Ok(ExitCode::SUCCESS)
        }
        "check" => {
            let root = PathBuf::from(flags.require("root")?);
            let report = corpus::run(&manifest, &root).map_err(|e| e.to_string())?;

            println!(
                "{:<12} {:>7} {:>9} {:>9} {:>9} {:>11} {:>13} {:>11}",
                "language",
                "files",
                "degraded",
                "error",
                "missing",
                "nodes",
                "degraded/file",
                "error/node"
            );
            for language in &report.languages {
                println!(
                    "{:<12} {:>7} {:>9} {:>9} {:>9} {:>11} {:>13.5} {:>11.7}",
                    language.name,
                    language.files,
                    language.degraded_files,
                    language.error_nodes,
                    language.missing_nodes,
                    language.total_nodes,
                    language.degraded_file_ratio(),
                    language.error_node_ratio(),
                );
                if language.unreadable_files > 0 {
                    println!(
                        "  {} file(s) were not readable as {} source",
                        language.unreadable_files, language.name
                    );
                }
            }

            // Named, not only counted. A rate says the grammar is slipping; the
            // paths say whether it is one exotic file or a language feature the
            // pin predates — the difference between raising a budget and
            // bumping a grammar.
            if report.degraded.is_empty() {
                println!(
                    "
no file in the corpus degraded the parse"
                );
            } else {
                println!(
                    "
degraded files ({}):",
                    report.degraded.len()
                );
                for file in &report.degraded {
                    println!(
                        "  {:<10} {:<12} {} ERROR, {} MISSING  {}",
                        file.repo, file.language, file.error_nodes, file.missing_nodes, file.path
                    );
                }
            }

            // The recorded baseline, when one is offered: a delta a human can
            // read, never a gate. The gate is the budget; the baseline's job is
            // to make a grammar bump's effect visible.
            if let Some(path) = flags.get("baseline") {
                let baseline = corpus::load_baseline(Path::new(path)).map_err(|e| e.to_string())?;
                println!("\nagainst the baseline recorded {}:", baseline.recorded_at);
                if baseline.regime != andon_static_metrics::engine::regime_stamp() {
                    println!(
                        "  REGIME MOVED since the baseline was taken — the numbers above are \
                         the ones to record.\n    baseline: {:?}\n    now:      {:?}",
                        baseline.regime,
                        andon_static_metrics::engine::regime_stamp()
                    );
                }
                for language in &report.languages {
                    match baseline.languages.iter().find(|l| l.name == language.name) {
                        Some(before) if before == language => {
                            println!("  {:<12} unchanged", language.name)
                        }
                        Some(before) => println!(
                            "  {:<12} files {} -> {}, degraded {} -> {}, error nodes {} -> {}",
                            language.name,
                            before.files,
                            language.files,
                            before.degraded_files,
                            language.degraded_files,
                            before.error_nodes,
                            language.error_nodes
                        ),
                        None => println!("  {:<12} new since the baseline", language.name),
                    }
                }
            }

            if let Some(path) = flags.get("write-baseline") {
                let baseline = report.to_baseline(
                    &andon_core::date::Date::today_utc()
                        .map_err(|e| e.to_string())?
                        .to_string(),
                    flags.get("run-ref").unwrap_or("local run"),
                );
                let text = toml::to_string_pretty(&baseline).map_err(|e| e.to_string())?;
                std::fs::write(path, text).map_err(|e| e.to_string())?;
                println!("\nwrote a fresh baseline to {path}");
            }

            if report.within_budget() {
                println!("\nevery language is within its ex ante budget");
                return Ok(ExitCode::SUCCESS);
            }
            eprintln!("\nparse-health budget EXCEEDED:");
            for problem in &report.problems {
                eprintln!("  {problem}");
            }
            Ok(ExitCode::from(1))
        }
        other => Err(format!("unknown corpus action '{other}'")),
    }
}
