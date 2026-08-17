//! `andon-spike` — the P1.5 kernel as a command line.
//!
//! Everything the composite action does, it does by calling this binary. The
//! action is YAML around these subcommands and nothing else, so the fixture
//! suite exercising them in-process and the action exercising them in a workflow
//! are testing one implementation.
//!
//! ```text
//! andon-spike measure  --repo <PATH> --head <REV> [--base <SPEC>] [--out <FILE>]
//!                      [--no-note] [--engine-version <V>]
//! andon-spike verify   --repo <PATH> --head <SHA> --trusted-branch <REF>
//!                      [--fork-tier] [--no-attest] [--out <FILE>]
//! andon-spike scenario prepare --manifest <FILE> --dest <DIR> [--json <FILE>]
//! andon-spike scenario check   --manifest <FILE> --repo <DIR>
//! andon-spike digests --record <FILE>
//! andon-spike compare-records --leg <LABEL>=<FILE> --leg <LABEL>=<FILE> [...]
//! andon-spike notes <list|copy|fetch|merge|push> --repo <PATH> [...]
//!
//! --base defaults to merge-base against the trusted branch:
//!        --base merge-base:origin/main   the fork point (the andon default)
//!        --base <REV>                    an explicit commit
//!
//! Exit codes: 0 success, 1 the answer was negative (a scenario failed its
//! expectation, legs disagreed), 2 bad usage or an operational failure.
//! ```
//!
//! # Why `verify` exits 0 on `divergent`
//!
//! A divergence is a successful verification: the tool did its job and found
//! tampering. Turning it into a non-zero exit would make the CI *step* red for
//! the same reason a crash does, and a workflow could not tell "Andon found
//! something" from "Andon fell over". The attestation value is the answer, and
//! it is written to `GITHUB_OUTPUT` for the workflow to map onto a check
//! conclusion — which is PLAN P9's acceptance criterion, not this phase's.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use andon_core::git::{Git, Revision};
use andon_core::schema::enums::{InvocationSource, RecordKind};
use andon_ledger_min::measure::measure;
use andon_ledger_min::notes::{Notes, ATTEST_REF, MEASURE_REF};
use andon_ledger_min::records;
use andon_ledger_min::scenario;
use andon_ledger_min::spike;
use andon_ledger_min::verify::{attest, verify, VerifyRequest};

const USAGE: &str = "\
usage: andon-spike <measure|verify|scenario|digests|compare-records|notes> [OPTIONS]
       run `andon-spike <command> --help` for the options of one command";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("andon-spike: {message}");
            ExitCode::from(2)
        }
    }
}

/// A tiny flag parser. Hand-rolled for the same reason `andon-registry-lint`'s
/// is: this workspace's supply-chain gate is `cargo deny check licenses bans
/// sources`, and a dependency admitted for argument parsing is a dependency the
/// verifier has to be trusted with.
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

    fn all(&self, name: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    fn require(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn on(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    fn path(&self, name: &str, default: &str) -> PathBuf {
        PathBuf::from(self.get(name).unwrap_or(default))
    }
}

const SWITCHES: &[&str] = &["no-note", "no-attest", "fork-tier", "help", "quiet"];

fn run() -> Result<ExitCode, String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(|| USAGE.to_string())?;
    let rest: Vec<String> = args.collect();
    if command == "--help" || command == "-h" {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    let flags = Flags::parse(rest.into_iter(), SWITCHES)?;
    match command.as_str() {
        "measure" => cmd_measure(&flags),
        "verify" => cmd_verify(&flags),
        "scenario" => cmd_scenario(&flags),
        "digests" => cmd_digests(&flags),
        "compare-records" => cmd_compare_records(&flags),
        "notes" => cmd_notes(&flags),
        other => Err(format!("unknown command '{other}'\n{USAGE}")),
    }
}

fn open(flags: &Flags) -> Result<Git, String> {
    Git::open(&flags.path("repo", ".")).map_err(|e| e.to_string())
}

/// `--base merge-base:<branch>` or an explicit revision.
fn base_revision(spec: Option<&str>) -> Revision {
    match spec {
        Some(spec) => match spec.split_once(':') {
            Some(("merge-base", branch)) => Revision::merge_base(branch),
            _ => Revision::Rev(spec.to_string()),
        },
        // The andon default: the fork point, not wherever the trusted branch has
        // since advanced to. Main advancing must not move what was measured
        // (PLAN R2-5 moving-main).
        None => Revision::merge_base("origin/main"),
    }
}

fn cmd_measure(flags: &Flags) -> Result<ExitCode, String> {
    let git = open(flags)?;
    let head = flags.get("head").unwrap_or("HEAD").to_string();
    let version = flags
        .get("engine-version")
        .map(str::to_string)
        .unwrap_or_else(spike::engine_version);
    let (record, _range) = measure(
        &git,
        &base_revision(flags.get("base")),
        &Revision::Rev(head),
        RecordKind::SelfReport,
        InvocationSource::Hook,
        &version,
    )
    .map_err(|e| e.to_string())?;

    if !flags.on("no-note") {
        Notes::new(&git, flags.get("notes-ref").unwrap_or(MEASURE_REF))
            .append(&record.compare_context.head_oid, &record)
            .map_err(|e| e.to_string())?;
    }
    if let Some(out) = flags.get("out") {
        records::write(Path::new(out), &record).map_err(|e| e.to_string())?;
    }
    if !flags.on("quiet") {
        println!(
            "measured {}..{}: {} result(s), engine {}",
            &record.compare_context.base_oid[..12],
            &record.compare_context.head_oid[..12],
            record.results.len(),
            version
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(flags: &Flags) -> Result<ExitCode, String> {
    let git = open(flags)?;
    let request = VerifyRequest {
        head: flags.require("head")?.to_string(),
        trusted_branch: flags.require("trusted-branch")?.to_string(),
        fork_tier: flags.on("fork-tier"),
    };
    let outcome = if flags.on("no-attest") {
        verify(&git, &request)
    } else {
        attest(&git, &request)
    }
    .map_err(|e| e.to_string())?;

    let value = serde_json::to_string(&outcome.attestation)
        .map_err(|e| e.to_string())?
        .trim_matches('"')
        .to_string();
    println!(
        "attestation: {value}  (base {} resolved by the verifier, {} self-report(s))",
        &outcome.trusted_base_oid[..12],
        outcome.self_reports
    );
    if let Some(compare) = &outcome.attest_record.attestation.compare {
        println!(
            "  matched={} mismatched={:?} unpaired={:?} flag-disagreements={:?}",
            compare.matched.len(),
            compare.mismatched,
            compare.unpaired,
            compare.flag_disagreements
        );
    }
    for signal in &outcome.attest_record.attestation.tamper_signals {
        println!("  tamper signal: {signal:?}");
    }
    if let Some(out) = flags.get("out") {
        records::write(Path::new(out), &outcome.attest_record).map_err(|e| e.to_string())?;
    }
    // The workflow maps this onto a check conclusion. Six values, one line, no
    // parsing of prose (PLAN P9's mapping criterion consumes exactly this).
    if let Ok(path) = std::env::var("GITHUB_OUTPUT") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        writeln!(file, "attestation={value}").map_err(|e| e.to_string())?;
    }
    // Zero even on `divergent`: finding tampering is this command succeeding.
    Ok(ExitCode::SUCCESS)
}

fn cmd_scenario(flags: &Flags) -> Result<ExitCode, String> {
    let action = flags
        .positional
        .first()
        .ok_or("scenario needs `prepare` or `check`")?
        .clone();
    let manifest_path = PathBuf::from(flags.require("manifest")?);
    let manifest = scenario::load(&manifest_path).map_err(|e| e.to_string())?;

    match action.as_str() {
        "prepare" => {
            let dest = PathBuf::from(flags.require("dest")?);
            let prepared =
                scenario::prepare(&manifest, &dest, &scenario::PrepareOptions::default())
                    .map_err(|e| e.to_string())?;
            let json = serde_json::to_string_pretty(&prepared).map_err(|e| e.to_string())?;
            if let Some(out) = flags.get("json") {
                std::fs::write(out, format!("{json}\n")).map_err(|e| e.to_string())?;
            }
            println!("{json}");
            Ok(ExitCode::SUCCESS)
        }
        "check" => {
            let git = Git::open(&flags.path("repo", ".")).map_err(|e| e.to_string())?;
            let head = git
                .cmd(["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"])
                .text()
                .map_err(|e| e.to_string())?
                .trim()
                .to_string();
            let attested = Notes::attest(&git).read(&head).map_err(|e| e.to_string())?;
            let [record] = attested.as_slice() else {
                return Err(format!(
                    "expected exactly one attestation on {head}, found {}",
                    attested.len()
                ));
            };
            let problems = scenario::check(&manifest, record);
            if problems.is_empty() {
                println!(
                    "{}: {:?} as expected",
                    manifest.name, record.attestation.value
                );
                Ok(ExitCode::SUCCESS)
            } else {
                for problem in &problems {
                    eprintln!("{}: {problem}", manifest.name);
                }
                Ok(ExitCode::from(1))
            }
        }
        other => Err(format!("unknown scenario action '{other}'")),
    }
}

/// Print one record's per-result digests, sorted.
///
/// The cheap half of the matrix. `compare-records` needs two legs and a runner
/// that has both; this prints one leg's answer in a stable form that a human can
/// diff against another leg's log — which is how the Windows and Linux legs get
/// cross-checked before anyone spends a macOS minute on the full sweep.
fn cmd_digests(flags: &Flags) -> Result<ExitCode, String> {
    let record = records::read(Path::new(flags.require("record")?)).map_err(|e| e.to_string())?;
    println!(
        "tuple {}..{}",
        record.compare_context.base_oid, record.compare_context.head_oid
    );
    for row in records::digest_rows(&record).map_err(|e| e.to_string())? {
        let flag = if row.deterministic { "d" } else { "-" };
        println!("{} {flag} {} {}", row.digest, row.metric_id, row.scope);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_compare_records(flags: &Flags) -> Result<ExitCode, String> {
    let mut legs = Vec::new();
    for spec in flags.all("leg") {
        let (label, path) = spec
            .split_once('=')
            .ok_or_else(|| format!("--leg wants <label>=<path>, got '{spec}'"))?;
        let record = records::read(Path::new(path)).map_err(|e| e.to_string())?;
        legs.push((label.to_string(), record));
    }
    let compared = records::compare(&legs).map_err(|e| e.to_string())?;

    println!("legs: {}", compared.legs.join(", "));
    for row in &compared.rows {
        let mark = if row.agreed { "ok  " } else { "DIFF" };
        let digest = row
            .digests
            .iter()
            .flatten()
            .next()
            .map(|d| d[..16].to_string())
            .unwrap_or_else(|| "<absent>".to_string());
        println!("{mark} {digest}  {}  {}", row.metric_id, row.scope);
    }
    if compared.agreed() {
        println!(
            "\n{} result(s) byte-identical across {} leg(s)",
            compared.rows.len(),
            compared.legs.len()
        );
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!("\ncross-leg digest comparison FAILED:");
    for problem in &compared.problems {
        eprintln!("  {problem}");
    }
    Ok(ExitCode::from(1))
}

fn cmd_notes(flags: &Flags) -> Result<ExitCode, String> {
    let action = flags
        .positional
        .first()
        .ok_or("notes needs list|copy|fetch|merge|push")?
        .clone();
    let git = open(flags)?;
    // `--ref measure` / `--ref attest` as shorthands, because a workflow author
    // typing the full ref by hand is a workflow author who will eventually type
    // `refs/notes/andon-measures`.
    let notes_ref = match flags.get("ref") {
        None | Some("measure") => MEASURE_REF,
        Some("attest") => ATTEST_REF,
        Some(other) => other,
    };
    let notes = Notes::new(&git, notes_ref);
    match action.as_str() {
        "list" => {
            for commit in notes.annotated_commits().map_err(|e| e.to_string())? {
                println!("{commit}");
            }
        }
        "copy" => {
            notes
                .copy(flags.require("from")?, flags.require("to")?)
                .map_err(|e| e.to_string())?;
        }
        "fetch" => {
            let found = notes
                .fetch(flags.get("remote").unwrap_or("origin"))
                .map_err(|e| e.to_string())?;
            println!("fetched: {found}");
        }
        "merge" => {
            let merged = notes.merge_tracking().map_err(|e| e.to_string())?;
            println!("merged: {merged}");
        }
        "push" => {
            let attempts = flags
                .get("attempts")
                .map(str::parse::<u32>)
                .transpose()
                .map_err(|e| e.to_string())?
                .unwrap_or(3);
            let used = notes
                .push_with_retry(flags.get("remote").unwrap_or("origin"), attempts)
                .map_err(|e| e.to_string())?;
            println!("pushed on attempt {used}");
        }
        other => return Err(format!("unknown notes action '{other}'")),
    }
    Ok(ExitCode::SUCCESS)
}
