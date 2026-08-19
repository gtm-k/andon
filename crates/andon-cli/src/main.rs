//! `andon` — the command line.
//!
//! Six subcommands over one measurement: `measure`, `wait`, `report`, `explain`,
//! `ledger`, `attest-stub`.
//!
//! # Exit codes are part of the contract
//!
//! A hook, a CI job, and a pre-commit gate all decide what to do next from the
//! exit code, so it carries the verdict rather than merely "the process did not
//! crash":
//!
//! | code | meaning |
//! |---|---|
//! | 0 | `pass` or `advise` — the line keeps moving |
//! | 2 | `block` — the line stops |
//! | 3 | `escalate_to_human` — the loop is over; a human decides |
//! | 1 | the tool could not do its job (bad usage, unreadable repository, or a changed path it could not read) |
//!
//! The distinction between 1 and 2 is the one that matters. A gate that could
//! not tell "Andon found something" from "Andon fell over" would be a gate whose
//! red check means nothing, and a team that cannot read a red check turns it off
//! — which is how a measurement tool stops measuring (PREMORTEM A4).
//!
//! **A `pass` requires that the change was actually read.** If any changed path
//! could not be read, the exit is 1 whatever the verdict says — the report is
//! still printed in full, and the note names the paths. The reason is the
//! project's own rule about absences: the honest shape for an unmeasured thing
//! is not the shape of a clean measurement, and an agent keys on the exit code,
//! so a caveat that lives only in prose is invisible to the actor who needs it.
//!
//! This is rare by design. An ordinary uncommitted working tree is read without
//! staging (`measure::read_without_staging`), so it does not reach this.
//!
//! `--exit-zero` turns every verdict into a 0 for the caller who wants the
//! report without the gate.

#![warn(clippy::all)]

use std::process::ExitCode;

use andon_core::git::Git;
use andon_core::policy::Policy;
use andon_core::schema::enums::{InvocationSource, Verdict};
use andon_core::schema::payload::MeasurementRecord;

use andon_cli::args::Flags;
use andon_cli::render::terminal::{Colour, Detail};
use andon_cli::{attest, explain, lanes, ledger, measure, render, store};

const USAGE: &str = "\
andon — measurement that carries its evidence.

  andon measure       measure a change and reach a verdict
  andon report        render the last measurement again, or one from a file
  andon explain       the claim a number stands on, and what it does not predict
  andon wait          what the async lane still owes this measurement
  andon ledger        measurements recorded in the commit
  andon attest-stub   recompute a change as the verifier would, and compare

Run `andon <command> --help` for one command's options.

Exit codes: 0 pass or advise · 2 block · 3 escalate to human · 1 the tool failed.";

const MEASURE_USAGE: &str = "\
andon measure [OPTIONS]

  --repo <PATH>        any path inside the repository (default: .)
  --base <REV>         base revision, or merge-base:<ref>
                       (default: the fork point against this repository's own
                        upstream, falling back to the last merged change)
  --head <REV>         head revision. Omitting it is NOT the same as passing
                       HEAD: with uncommitted work in the tree, the default
                       head is that working tree, and `--head HEAD` asks for
                       the commit instead — a different measurement, which can
                       reach a different verdict
  --no-fallback        refuse rather than measure the last merged change
  --last-merged        measure the last merged change even when the tree is
                       dirty, instead of measuring the working tree
  --registry <DIR>     load the evidence registry from a directory instead of
                       the copy compiled into this binary
  --self-measure       apply [self_measure] excluded_paths from .andon.toml
  --source <WHO>       hook | agent-initiated | human-cli (default: human-cli)
  --harness <NAME>     harness that invoked this, for the ledger
  --model <ID>         model identifier, for the ledger
  --json               print the record as canonical JSON instead of a report
  --profile <NAME>     print a bounded view instead of the full record.
                       `agent-mode` is the token-budgeted projection for an agent
                       (PREMORTEM A2), sized from [agent] in .andon.toml
  --html <FILE>        also write a self-contained HTML report
  --record             append the record to refs/notes/andon-measure
  --full               print every result, including absences and INFO findings
  --no-color           never emit ANSI escapes
  --exit-zero          always exit 0, whatever the verdict";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("andon: {message}");
            ExitCode::from(1)
        }
    }
}

const SWITCHES: &[&str] = &[
    "help",
    "json",
    "record",
    "full",
    "no-color",
    "no-fallback",
    "last-merged",
    "self-measure",
    "exit-zero",
    "list",
    "fork-tier",
];

fn run() -> Result<ExitCode, String> {
    let mut argv = std::env::args().skip(1);
    let Some(command) = argv.next() else {
        println!("{USAGE}");
        return Ok(ExitCode::from(1));
    };
    if command == "--help" || command == "-h" || command == "help" {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    if command == "--version" {
        println!("andon {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }

    let flags = Flags::parse(argv, SWITCHES)?;
    match command.as_str() {
        "measure" => cmd_measure(&flags),
        "report" => cmd_report(&flags),
        "explain" => cmd_explain(&flags),
        "wait" => cmd_wait(&flags),
        "ledger" => cmd_ledger(&flags),
        "attest-stub" => cmd_attest(&flags),
        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
}

fn colour(flags: &Flags) -> Colour {
    if flags.on("no-color") {
        Colour::Off
    } else {
        Colour::detect()
    }
}

fn detail(flags: &Flags) -> Detail {
    if flags.on("full") {
        Detail::Full
    } else {
        Detail::Normal
    }
}

/// The exit code a verdict earns.
fn code_for(verdict: Verdict, exit_zero: bool) -> ExitCode {
    if exit_zero {
        return ExitCode::SUCCESS;
    }
    match verdict {
        Verdict::Pass | Verdict::Advise => ExitCode::SUCCESS,
        Verdict::Block => ExitCode::from(2),
        Verdict::EscalateToHuman => ExitCode::from(3),
    }
}

fn cmd_measure(flags: &Flags) -> Result<ExitCode, String> {
    if flags.on("help") {
        println!("{MEASURE_USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    flags.reject_unknown(&[
        "repo", "base", "head", "registry", "source", "harness", "model", "html", "profile",
    ])?;

    let request = measure::Request {
        repo: flags.path("repo", "."),
        base: flags.get("base").map(str::to_string),
        head: flags.get("head").map(str::to_string),
        no_fallback: flags.on("no-fallback"),
        last_merged: flags.on("last-merged"),
        registry_dir: flags.get("registry").map(std::path::PathBuf::from),
        self_measure: flags.on("self-measure"),
        source: source_of(flags.get("source"))?,
        harness: flags.get("harness").map(str::to_string),
        model: flags.get("model").map(str::to_string),
        ..measure::Request::default()
    };

    let measurement = measure::measure(&request).map_err(|e| e.to_string())?;
    let git = Git::open(&request.repo).map_err(|e| e.to_string())?;

    // The measurement is the thing the caller asked for; the saved copy is a
    // convenience for `report`, `explain` and `wait`. So the answer is delivered
    // first and the copy is best effort — a transient filesystem failure must
    // not throw away a measurement that has already been computed, and it must
    // not be silent either, because the next `andon report` will read a stale
    // record and say nothing about it.
    let saved = store::write_last(&git, &measurement.record);

    if let Some(name) = flags.get("profile") {
        println!(
            "{}",
            render::profile(&measurement.record, name, &request.repo)?
        );
    } else if flags.on("json") {
        println!(
            "{}",
            andon_core::canonical::to_canonical_string(&measurement.record)
                .map_err(|e| e.to_string())?
        );
    } else {
        print!(
            "{}",
            render::terminal::render(&measurement, colour(flags), detail(flags))
        );
    }

    if let Some(path) = flags.get("html") {
        let html = render::html::render(&measurement);
        std::fs::write(path, html).map_err(|e| format!("{path}: {e}"))?;
        if !flags.on("json") {
            println!(" report written to {path}\n");
        }
    }

    if flags.on("record") {
        let note = ledger::record(&git, &measurement.record, &measurement.ledger_anchor)?;
        if !flags.on("json") {
            println!(" {note}\n");
        }
    }

    if let Err(e) = saved {
        eprintln!(
            "andon: the measurement above was not saved for `andon report`: {e}\n       \
             The record itself is unaffected; re-run `andon measure` to store it."
        );
    }

    Ok(code_for_record(&measurement.record, flags.on("exit-zero")))
}

/// The exit code a record earns, verdict and coverage together.
///
/// A verdict about less than the caller asked about does not get a clean exit —
/// see the module docs. It is a function of the *record* rather than of the run
/// because it has to be the same answer everywhere: `measure` exited 1 over
/// unreadable paths and then `report`, `--json`, the HTML report and the agent
/// profile read the saved record and all exited 0, so the one thing an agent
/// can act on survived for exactly one process. The fact is durable now, and so
/// is the code it produces.
fn code_for_record(record: &MeasurementRecord, exit_zero: bool) -> ExitCode {
    if exit_zero {
        return ExitCode::SUCCESS;
    }
    if covers_less_than_asked(record) {
        return ExitCode::from(1);
    }
    code_for(record.verdict.verdict, false)
}

/// Whether this record describes less than the change it was asked about.
///
/// One predicate rather than the field read at each surface, because the surfaces
/// disagreed the last time it was: `measure`, `report`, `wait`, `--json`, the
/// HTML report and the agent profile were taught the rule and `ledger show` was
/// not, so the one command whose whole job is to re-serve a record months later
/// answered 0 while printing `NOT READ` on the line above. The verdict now says
/// so too (`verdict::reason::CHANGE_NOT_READ`), and this is why the exit code
/// stays 1 rather than following the verdict to 0: `advise` keeps the line
/// moving, and a change nobody read must not.
fn covers_less_than_asked(record: &MeasurementRecord) -> bool {
    !record.unreadable_paths.is_empty()
}

fn cmd_report(flags: &Flags) -> Result<ExitCode, String> {
    if flags.on("help") {
        println!(
            "andon report [--repo <PATH>] [--input <FILE>] [--html <FILE>] [--json] [--full]\n\
             andon report --profile agent-mode\n\n  \
             Renders the last measurement taken in this checkout, or a record from a file."
        );
        return Ok(ExitCode::SUCCESS);
    }
    flags.reject_unknown(&["repo", "input", "html", "profile"])?;

    let record = match flags.get("input") {
        Some(path) => store::read_record(std::path::Path::new(path))?,
        None => {
            let git = Git::open(&flags.path("repo", ".")).map_err(|e| e.to_string())?;
            store::read_last(&git)?
        }
    };

    if let Some(name) = flags.get("profile") {
        println!(
            "{}",
            render::profile(&record, name, &flags.path("repo", "."))?
        );
        return Ok(code_for_record(&record, flags.on("exit-zero")));
    }
    if flags.on("json") {
        println!(
            "{}",
            andon_core::canonical::to_canonical_string(&record).map_err(|e| e.to_string())?
        );
    } else {
        print!(
            "{}",
            render::terminal::render_record(&record, colour(flags), detail(flags))
        );
    }

    if let Some(path) = flags.get("html") {
        std::fs::write(path, render::html::render_record(&record))
            .map_err(|e| format!("{path}: {e}"))?;
        if !flags.on("json") {
            println!(" report written to {path}\n");
        }
    }

    Ok(code_for_record(&record, flags.on("exit-zero")))
}

fn cmd_explain(flags: &Flags) -> Result<ExitCode, String> {
    if flags.on("help") {
        println!(
            "andon explain <METRIC-ID|CLAIM-ID> [--repo <PATH>] [--registry <DIR>]\n\
             andon explain --list\n\n  \
             Prints the claim a number stands on: its tier, citation, population, effect, \
             re-review date,\n  and — the field this tool exists for — what the number does \
             NOT predict."
        );
        return Ok(ExitCode::SUCCESS);
    }
    flags.reject_unknown(&["repo", "registry"])?;

    if flags.on("list") {
        print!("{}", explain::list());
        return Ok(ExitCode::SUCCESS);
    }
    let Some(query) = flags.first() else {
        return Err(
            "name a metric or a claim: `andon explain static.sloc`, or `andon explain --list`"
                .to_string(),
        );
    };

    // Policy shapes what a claim's tier is allowed to do, so it is loaded even
    // when no measurement is taken. Outside a repository the conservative
    // defaults apply, which is what the binary would have used anyway — but
    // inside one, a `.andon.toml` that exists and cannot be read is surfaced
    // rather than defaulted. `measure` treats that condition as an error, and
    // two surfaces answering one question differently is how an operator ends
    // up reading a ceiling computed under a policy that is not theirs.
    let git = Git::open(&flags.path("repo", ".")).ok();
    let policy = match &git {
        Some(git) => measure::load_policy(git, &measure::PolicySource::Worktree)
            .map_err(|e| e.to_string())?,
        None => Policy::default(),
    };

    let as_of = andon_core::date::Date::today_utc()
        .map_err(|_| "the system clock could not be read".to_string())?;
    let registry = measure::load_registry(
        flags.get("registry").map(std::path::Path::new),
        &policy,
        as_of,
    )
    .map_err(|e| e.to_string())?;

    let subject = explain::subject_of(query)?;
    let record = git.as_ref().and_then(|git| store::read_last(git).ok());
    print!(
        "{}",
        explain::explain(&subject, &policy, &registry, record.as_ref())?
    );
    println!();
    Ok(ExitCode::SUCCESS)
}

fn cmd_wait(flags: &Flags) -> Result<ExitCode, String> {
    if flags.on("help") {
        println!(
            "andon wait [--repo <PATH>] [--input <FILE>]\n\n  \
             Reports what the async lane still owes the last measurement."
        );
        return Ok(ExitCode::SUCCESS);
    }
    flags.reject_unknown(&["repo", "input"])?;
    let record = match flags.get("input") {
        Some(path) => store::read_record(std::path::Path::new(path))?,
        None => {
            let git = Git::open(&flags.path("repo", ".")).map_err(|e| e.to_string())?;
            store::read_last(&git)?
        }
    };
    print!("{}", lanes::wait(&record));
    Ok(code_for_record(&record, flags.on("exit-zero")))
}

fn cmd_ledger(flags: &Flags) -> Result<ExitCode, String> {
    if flags.on("help") || flags.first().is_none() {
        println!(
            "andon ledger <list|show|ack> [--repo <PATH>]\n\n  \
             list              every commit carrying a measurement record\n  \
             show [<COMMIT>]   the records recorded against one commit (default: HEAD)\n  \
             ack [--branch B]  clear the loop counter after a human has looked at an escalation"
        );
        return Ok(ExitCode::SUCCESS);
    }
    flags.reject_unknown(&["repo", "branch"])?;
    let git = Git::open(&flags.path("repo", ".")).map_err(|e| e.to_string())?;

    match flags.first().unwrap_or("list") {
        "list" => print!("{}", ledger::list(&git)?),
        "show" => {
            let commit = flags
                .positional()
                .get(1)
                .map(String::as_str)
                .unwrap_or("HEAD");
            let records = ledger::show(&git, commit)?;
            if records.is_empty() {
                println!("\n  No record is recorded against {commit}.\n");
            }
            for record in &records {
                print!(
                    "{}",
                    render::terminal::render_record(record, colour(flags), detail(flags))
                );
            }
            // The coverage rule, and only the coverage rule. `show` is a query
            // over what is already filed, so it does not turn a historical
            // `block` into an exit 2 — a gate keyed on the newest of several
            // records against one commit is P8's question about the ledger, not
            // an answer this command may invent. What it must not do is serve a
            // record whose change was never read and call that a clean run,
            // which is what it did.
            if records.iter().any(covers_less_than_asked) && !flags.on("exit-zero") {
                return Ok(ExitCode::from(1));
            }
        }
        // The cap comes from the policy in force, never from the default. An
        // acknowledgement reporting "of a cap of 3" in a repository whose
        // `.andon.toml` says five would be a sentence stating a number it did
        // not read — the defect class this phase inherited three instances of.
        "ack" => {
            let policy = measure::load_policy(&git, &measure::PolicySource::Worktree)
                .map_err(|e| e.to_string())?;
            print!("\n{}\n", ledger::ack(&git, flags.get("branch"), &policy)?);
        }
        other => return Err(format!("unknown ledger command '{other}'")),
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_attest(flags: &Flags) -> Result<ExitCode, String> {
    if flags.on("help") {
        println!(
            "andon attest-stub --head <SHA> [--repo <PATH>] [--trusted-branch <REF>] \
             [--fork-tier]\n\n  \
             Recomputes a change the way the verifier would, reads the self-report from\n  \
             refs/notes/andon-measure, and classifies the pair. A stub: P9 builds the verifier,\n  \
             and the output says what this did not check."
        );
        return Ok(ExitCode::SUCCESS);
    }
    flags.reject_unknown(&["repo", "head", "trusted-branch"])?;
    let head = flags
        .get("head")
        .ok_or_else(|| "--head is required: the SHA under examination".to_string())?;
    let attested = attest::attest(&attest::Request {
        repo: flags.path("repo", "."),
        head: head.to_string(),
        trusted_branch: flags
            .get("trusted-branch")
            .unwrap_or("origin/main")
            .to_string(),
        fork_tier: flags.on("fork-tier"),
    })?;
    print!("{}", attest::render(&attested));
    // Zero on `divergent`, deliberately, and for the reason `andon-spike verify`
    // gives: a divergence is a *successful* verification. Turning it into a
    // non-zero exit would make the step red for the same reason a crash does,
    // and a workflow could not tell "Andon found something" from "Andon fell
    // over". The attestation value is the answer.
    Ok(ExitCode::SUCCESS)
}

fn source_of(spec: Option<&str>) -> Result<InvocationSource, String> {
    match spec {
        None | Some("human-cli") => Ok(InvocationSource::HumanCli),
        Some("hook") => Ok(InvocationSource::Hook),
        Some("agent-initiated") => Ok(InvocationSource::AgentInitiated),
        // `ci-verifier` is deliberately absent: it is what a verifier record
        // says, and a self-report that could claim it would be a record calling
        // itself trusted.
        Some(other) => Err(format!(
            "unknown --source '{other}'; one of hook, agent-initiated, human-cli"
        )),
    }
}
