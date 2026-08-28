//! `andon` — the command line.
//!
//! The subcommands are the ones `USAGE` lists — enumerated there, and only
//! there.
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
//!
//! # A reader that stops reading is not a failure
//!
//! Every byte this binary puts on stdout goes through one fallible writer, and
//! a `BrokenPipe` from it — `head` took what it wanted, `grep -m1` matched, an
//! agent truncated its read — is a quiet exit 0 at the top level rather than a
//! panic in whichever `println!` came next. Windows reports a closed pipe the
//! same way, as an error on the write rather than as a signal, so this is one
//! rule on every platform and not a Unix `SIGPIPE` reset. Any other refusal
//! from stdout — a full disk behind a redirect — is a failure, said on stderr
//! with exit 1. The library commands that have something to print return it
//! (`init`, `hook`, `demo`, `doctor`) rather than printing it, so that this
//! rule has one place to live.
//!
//! The rule is uniform: a closed pipe exits 0 whatever the run would otherwise
//! have exited — a `block` that was going to exit 2, and the no-argument
//! `USAGE` page that ordinarily exits 1. The reader left before the verdict or
//! the usage error could reach them, and there is nobody left to fail for; the
//! exit code is a message, and a message needs a reader. stderr is written as
//! a run goes: it is the operator's channel, and the notices on it are about
//! the run, not the pipe.

#![warn(clippy::all)]

use std::io::{self, Write};
use std::process::ExitCode;

use andon_core::git::Git;
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
  andon wait          run anything the async lane still owes, and report it
  andon ledger        the recorded measurements: list, stats, sync, migrate
  andon attest-stub   recompute a change as the verifier would, and compare
  andon init          install a gate-shaped hook for a harness, removably
  andon hook          what an installed hook runs (see `andon init`)
  andon demo          watch a forged self-report get caught, locally, in a minute
  andon doctor        write the redacted self-report bundle a false-positive issue needs

Run `andon <command> --help` for one command's options.

Exit codes: 0 pass or advise · 2 block · 3 escalate to human · 1 the tool failed.";

const MEASURE_USAGE: &str = "\
andon measure [OPTIONS]

  --repo <PATH>        any path inside the repository (default: .)
  --base <REV>         base revision, or merge-base:<ref>
                       (default: the fork point against this repository's own
                        upstream. Where this repository offers no fork point --
                        a branch named neither main nor master, no remote, or a
                        manual-fetch checkout -- the base is the commit your
                        working tree sits on; and with nothing in flight, the
                        last merged change. The report says which was used)
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

/// Why a run stopped short of an exit code.
enum Failure {
    /// The tool could not do its job. Said on stderr; exit 1.
    Message(String),
    /// stdout refused a write. What that means depends on why — see
    /// [`stdout_failed`].
    Stdout(io::Error),
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Failure::Message(message)
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        Failure::Message(message.to_string())
    }
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Failure::Stdout(error)
    }
}

/// A run's result: the exit code it earned, or why it has none.
type Outcome = Result<ExitCode, Failure>;

fn main() -> ExitCode {
    let mut out = io::stdout();
    let code = match run(&mut out) {
        Ok(code) => code,
        Err(Failure::Message(message)) => {
            eprintln!("andon: {message}");
            ExitCode::from(1)
        }
        Err(Failure::Stdout(error)) => return stdout_failed(&error),
    };
    // stdout is line-buffered, so a final partial line is still in the buffer
    // here. Flushed explicitly rather than left to the runtime's exit, which
    // flushes too but discards the error — and the one thing this binary must
    // not do is drop bytes it was asked for and exit as if it had written them.
    match out.flush() {
        Ok(()) => code,
        Err(error) => stdout_failed(&error),
    }
}

/// The exit when stdout refused a write.
///
/// A closed pipe is the reader's decision, not a failure of this tool: `head`
/// read what it wanted, or an agent truncated its read. The process exits 0
/// and says nothing — a message would go to a stderr the same pager may have
/// closed, and a non-zero exit would fail a pipeline for having been read.
/// Everything else stdout can refuse is a real failure and is reported as one.
fn stdout_failed(error: &io::Error) -> ExitCode {
    if error.kind() == io::ErrorKind::BrokenPipe {
        ExitCode::SUCCESS
    } else {
        eprintln!("andon: stdout: {error}");
        ExitCode::from(1)
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
    "claude",
    "cursor",
    "ci",
    "remove",
    "distribution",
    "across-regimes",
    "check",
    "keep",
];

fn run(out: &mut dyn Write) -> Outcome {
    let mut argv = std::env::args().skip(1);
    let Some(command) = argv.next() else {
        writeln!(out, "{USAGE}")?;
        return Ok(ExitCode::from(1));
    };
    if command == "--help" || command == "-h" || command == "help" {
        writeln!(out, "{USAGE}")?;
        return Ok(ExitCode::SUCCESS);
    }
    if command == "--version" {
        writeln!(out, "andon {}", env!("CARGO_PKG_VERSION"))?;
        return Ok(ExitCode::SUCCESS);
    }

    let flags = Flags::parse(argv, SWITCHES)?;
    match command.as_str() {
        "measure" => cmd_measure(out, &flags),
        "report" => cmd_report(out, &flags),
        "explain" => cmd_explain(out, &flags),
        "wait" => cmd_wait(out, &flags),
        "ledger" => cmd_ledger(out, &flags),
        "attest-stub" => cmd_attest(out, &flags),
        "init" => {
            write!(out, "{}", andon_cli::init::cmd_init(&flags)?)?;
            writeln!(out)?;
            Ok(ExitCode::SUCCESS)
        }
        "hook" => {
            let hook = andon_cli::init::hook::cmd_hook(&flags)?;
            write!(out, "{}", hook.stdout)?;
            Ok(ExitCode::from(hook.code))
        }
        "demo" => {
            write!(out, "{}", andon_cli::demo::cmd_demo(&flags)?)?;
            Ok(ExitCode::SUCCESS)
        }
        "doctor" => {
            writeln!(out, "{}", andon_cli::doctor::cmd_doctor(&flags)?)?;
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command '{other}'\n\n{USAGE}").into()),
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

fn cmd_measure(out: &mut dyn Write, flags: &Flags) -> Outcome {
    if flags.on("help") {
        writeln!(out, "{MEASURE_USAGE}")?;
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
        writeln!(
            out,
            "{}",
            render::profile(&measurement.record, name, &request.repo)?
        )?;
    } else if flags.on("json") {
        writeln!(
            out,
            "{}",
            andon_core::canonical::to_canonical_string(&measurement.record)
                .map_err(|e| e.to_string())?
        )?;
        say_if_verdict_contradicted(&measurement.record);
    } else {
        write!(
            out,
            "{}",
            render::terminal::render(&measurement, colour(flags), detail(flags))
        )?;
    }

    if let Some(path) = flags.get("html") {
        let html = render::html::render(&measurement);
        std::fs::write(path, html).map_err(|e| format!("{path}: {e}"))?;
        say(out, flags, &format!(" report written to {path}\n"))?;
    }

    if flags.on("record") {
        let note = ledger::record(&git, &measurement.record, &measurement.ledger_anchor)?;
        say(out, flags, &format!(" {note}\n"))?;
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

/// Whether stdout is a machine surface on this run.
///
/// `--json` and `--profile` both make stdout a document a parser reads to the
/// end. Anything else the run has to say goes to stderr.
fn stdout_is_machine_readable(flags: &Flags) -> bool {
    flags.on("json") || flags.get("profile").is_some()
}

/// An operational line for whoever is running this — never into a parser.
///
/// `--profile agent-mode` was clean JSON only when used alone. Combined with
/// `--record` or `--html` it appended " report written to ..." or the ledger
/// note to stdout, and the agent-facing surface stopped parsing at a measured
/// byte offset — on the one surface PREMORTEM A2 exists for.
///
/// The line is moved rather than dropped. "Was the note written?" is a question
/// the operator can only answer from what the tool says, and a machine surface
/// that silently stopped reporting its own side effects would be trading one
/// actor's problem for another's.
fn say(out: &mut dyn Write, flags: &Flags, line: &str) -> io::Result<()> {
    if stdout_is_machine_readable(flags) {
        eprintln!("{}", line.trim_end());
        Ok(())
    } else {
        writeln!(out, "{line}")
    }
}

/// Say on stderr what the JSON surface cannot say in its own bytes.
///
/// `--json` re-serves the record exactly as it was sealed, which is the point of
/// it: the bytes are evidence, and a tool that quietly rewrote a stored verdict
/// on the way out would be doing the thing the trust boundary exists to prevent.
/// So the label goes beside the bytes rather than into them — stdout stays a
/// parseable record, stderr carries the sentence, and the exit code is already
/// 1 through `covers_less_than_asked`.
///
/// The agent profile does not need this: it is a computed projection rather than
/// the sealed record, so it carries `verdict_invalid` structurally, which is the
/// right shape for the one surface built for a reader that does not read prose.
fn say_if_verdict_contradicted(record: &MeasurementRecord) {
    if andon_core::verdict::stored_verdict_is_contradicted(record) {
        eprintln!(
            "andon: {}",
            andon_core::verdict::contradiction_label(record)
        );
    }
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

fn cmd_report(out: &mut dyn Write, flags: &Flags) -> Outcome {
    if flags.on("help") {
        writeln!(
            out,
            "andon report [--repo <PATH>] [--input <FILE>] [--html <FILE>] [--json] [--full]\n\
             andon report --profile agent-mode\n\n  \
             Renders the last measurement taken in this checkout, or a record from a file."
        )?;
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
        writeln!(
            out,
            "{}",
            render::profile(&record, name, &flags.path("repo", "."))?
        )?;
    } else if flags.on("json") {
        writeln!(
            out,
            "{}",
            andon_core::canonical::to_canonical_string(&record).map_err(|e| e.to_string())?
        )?;
        say_if_verdict_contradicted(&record);
    } else {
        write!(
            out,
            "{}",
            render::terminal::render_record(&record, colour(flags), detail(flags))
        )?;
    }

    // Below the rendering rather than inside it, so `--profile` no longer
    // returns before it: `report --profile agent-mode --html <file>` exited 0,
    // wrote no file, and said nothing about either.
    if let Some(path) = flags.get("html") {
        std::fs::write(path, render::html::render_record(&record))
            .map_err(|e| format!("{path}: {e}"))?;
        say(out, flags, &format!(" report written to {path}\n"))?;
    }

    Ok(code_for_record(&record, flags.on("exit-zero")))
}

fn cmd_explain(out: &mut dyn Write, flags: &Flags) -> Outcome {
    if flags.on("help") {
        writeln!(
            out,
            "andon explain <METRIC-ID|CLAIM-ID> [--repo <PATH>] [--registry <DIR>]\n\
             andon explain --list\n\n  \
             Prints the claim a number stands on: its tier, citation, population, effect, \
             re-review date,\n  and — the field this tool exists for — what the number does \
             NOT predict."
        )?;
        return Ok(ExitCode::SUCCESS);
    }
    flags.reject_unknown(&["repo", "registry"])?;

    if flags.on("list") {
        write!(out, "{}", explain::list())?;
        return Ok(ExitCode::SUCCESS);
    }
    let Some(query) = flags.first() else {
        return Err(
            "name a metric or a claim: `andon explain static.sloc`, or `andon explain --list`"
                .into(),
        );
    };

    // One body with the MCP server's `explain_finding` (`explain::run`), so the
    // two surfaces cannot answer one question differently.
    let explained = explain::run(
        &flags.path("repo", "."),
        flags.get("registry").map(std::path::Path::new),
        query,
    )?;
    // stderr for the terminal reader, so the explanation on stdout stays
    // pipeable. The MCP surface appends the same notice as its own block.
    if let Some(notice) = &explained.notice {
        eprintln!("explain: {notice}");
    }
    write!(out, "{}", explained.answer)?;
    writeln!(out)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_wait(out: &mut dyn Write, flags: &Flags) -> Outcome {
    if flags.on("help") {
        writeln!(
            out,
            "andon wait [--repo <PATH>] [--input <FILE>] [--record]\n\n  \
             Completes the last measurement — work the fast lane deferred to the async lane\n  \
             (the user test command, or engines spilled at the cold cap) is executed HERE,\n  \
             in the foreground, and merged into the record — then reports what the lane\n  \
             still owes. --record appends the merged record to refs/notes/andon-measure.\n  \
             With --input the record is only rendered: a file is not this checkout's\n  \
             measurement, and there is no job of it to run."
        )?;
        return Ok(ExitCode::SUCCESS);
    }
    flags.reject_unknown(&["repo", "input"])?;
    // Whether a job actually ran HERE travels with the record, because nothing
    // in the record distinguishes a job that ran and died from one that never
    // existed: a timeout emits no result at all. `wait` used to infer it from an
    // empty async lane and told the reader no work had been deferred, one line
    // under the notice naming the log file that proved otherwise.
    let (record, job_ran) = match flags.get("input") {
        // A record read from a file: this invocation ran nothing.
        Some(path) => (store::read_record(std::path::Path::new(path))?, false),
        None => {
            let repo = flags.path("repo", ".");
            // Execute anything pending before rendering, so the report below
            // is about the completed measurement rather than a stale half.
            let completed = andon_cli::jobs::complete(&repo)?;
            let git = Git::open(&repo).map_err(|e| e.to_string())?;
            match completed {
                None => (store::read_last(&git)?, false),
                Some(completion) => {
                    for notice in &completion.notices {
                        eprintln!("andon: {notice}");
                    }
                    if flags.on("record") {
                        let note =
                            ledger::record(&git, &completion.record, &completion.ledger_anchor)?;
                        eprintln!("andon: {note}");
                    }
                    (completion.record, true)
                }
            }
        }
    };
    write!(out, "{}", lanes::wait(&record, job_ran))?;
    Ok(code_for_record(&record, flags.on("exit-zero")))
}

const LEDGER_USAGE: &str = "\
andon ledger <list|show|ack|stats|sync|migrate|trailer> [--repo <PATH>]

  list              every commit carrying a measurement record
  show [<COMMIT>]   the records recorded against one commit (default: HEAD)
  ack [--branch B]  clear the loop counter after a human has looked at an escalation
  trailer [<COMMIT>]  one Andon-Measure-Digest trailer line per record on the
                    commit (default: HEAD), ready for a commit message. A
                    trailer travels where notes refs do not — a fork PR — and
                    the verifier compares against the digest alone
  stats             the ledger as a dataset. Single-repo local analytics for this
                    repository's maintainer — not a fleet dashboard.
    --by <DIM>          slice by one dimension with a verdict breakdown; the
                        dimensions are source, harness, model, author, iteration
    --filter <D>=<V>    keep only records where dimension D has value V
    --distribution      per-metric value distributions, grouped by measurement
                        regime, with the threshold-clustering warning. Values
                        measured under different regimes are never pooled unless
                        --across-regimes is passed, and the pooled view stays
                        labeled as mixed
    --check             exit 2 when any clustering warning fires, so a CI job
                        goes red on the finding rather than on a log grep
    --ref <NAME>        which ledger to read: measure (default) or attest
  fp-window         the S6 false-positive budget, measured (PLAN P9b): changes,
                    MED+ rate with the cognitive/cyclomatic split (P2 rider),
                    escalation rate, policy hashes, and the policy-in-force diff
                    against the conservative defaults (round-1 B8). Reports the
                    quantities; the P10b entry gate does the comparing
    --since <STAMP>     window start, YYYY-MM-DDTHH:MM:SSZ, inclusive (required)
    --until <STAMP>     window end, same shape (default: now)
  sync              fetch both ledger refs, merge with cat_sort_uniq, and push —
                    retrying with backoff. Exhausted retries fail red: the
                    records stay safe locally and the failure says what to do
    --remote <NAME>     the remote to sync with (default: origin)
    --attempts <N>      push attempts per ref before failing loudly (default: 3)
  migrate           carry records from a pre-squash head onto the landed commit
    --from <REV>        the branch head that was squash-merged
    --to <REV>          the commit the squash landed (e.g. the new main tip)";

fn cmd_ledger(out: &mut dyn Write, flags: &Flags) -> Outcome {
    if flags.on("help") || flags.first().is_none() {
        writeln!(out, "{LEDGER_USAGE}")?;
        return Ok(ExitCode::SUCCESS);
    }
    flags.reject_unknown(&[
        "repo", "branch", "by", "filter", "ref", "remote", "attempts", "from", "to", "since",
        "until",
    ])?;
    let git = Git::open(&flags.path("repo", ".")).map_err(|e| e.to_string())?;

    match flags.first().unwrap_or("list") {
        "list" => write!(out, "{}", ledger::list(&git)?)?,
        "show" => {
            let commit = flags
                .positional()
                .get(1)
                .map(String::as_str)
                .unwrap_or("HEAD");
            let records = ledger::show(&git, commit)?;
            if records.is_empty() {
                writeln!(out, "\n  No record is recorded against {commit}.\n")?;
            }
            for record in &records {
                write!(
                    out,
                    "{}",
                    render::terminal::render_record(record, colour(flags), detail(flags))
                )?;
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
            write!(
                out,
                "\n{}\n",
                ledger::ack(&git, flags.get("branch"), &policy)?
            )?;
        }
        "stats" => {
            let by = match flags.get("by") {
                None => None,
                Some(name) => {
                    Some(andon_ledger::stats::Dimension::parse(name).ok_or_else(|| {
                        format!(
                            "'{name}' is not a ledger dimension; the dimensions are source, \
                             harness, model, author, iteration"
                        )
                    })?)
                }
            };
            let filter = flags
                .get("filter")
                .map(andon_ledger::stats::Filter::parse)
                .transpose()?;
            let request = ledger::StatsRequest {
                notes_ref: ledger::ref_named(flags.get("ref").unwrap_or("measure"))?.to_string(),
                distribution: flags.on("distribution") || flags.on("check"),
                across_regimes: flags.on("across-regimes"),
                by,
                filter,
            };
            let (report, clustered) = ledger::stats_report(&git, &request)?;
            write!(out, "{report}")?;
            // `--check` keys the exit on the finding: 2 is the "the line
            // stops" code, and a clustering signature is a stop-and-look
            // signal for a human, distinguishable from 1 (the tool fell over).
            if clustered && flags.on("check") {
                return Ok(ExitCode::from(2));
            }
        }
        "fp-window" => {
            let since = flags.get("since").ok_or(
                "fp-window needs --since <STAMP>, the ledgered window start \
                 (YYYY-MM-DDTHH:MM:SSZ)",
            )?;
            write!(
                out,
                "{}",
                ledger::fp_report(&git, since, flags.get("until"))?
            )?;
        }
        "sync" => {
            let attempts = match flags.get("attempts") {
                None => 3,
                Some(text) => text.parse::<u32>().map_err(|_| {
                    format!("--attempts wants a number of push attempts, not '{text}'")
                })?,
            };
            write!(
                out,
                "\n{}\n",
                ledger::sync(&git, flags.get("remote").unwrap_or("origin"), attempts)?
            )?;
        }
        "migrate" => {
            let from = flags
                .get("from")
                .ok_or("migrate needs --from <REV>, the branch head that was squash-merged")?;
            let to = flags
                .get("to")
                .ok_or("migrate needs --to <REV>, the commit the squash landed")?;
            write!(out, "\n{}\n", ledger::migrate(&git, from, to)?)?;
        }
        "trailer" => {
            let commit = flags
                .positional()
                .get(1)
                .map(String::as_str)
                .unwrap_or("HEAD");
            // Bare trailer lines on stdout, no framing: the output's job is to
            // be appended to a commit message, by a person or by `--trailer`.
            write!(out, "{}", ledger::trailer(&git, commit)?)?;
        }
        other => return Err(format!("unknown ledger command '{other}'\n\n{LEDGER_USAGE}").into()),
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_attest(out: &mut dyn Write, flags: &Flags) -> Outcome {
    if flags.on("help") {
        writeln!(
            out,
            "andon attest-stub --head <SHA> [--repo <PATH>] [--trusted-branch <REF>] \
             [--fork-tier]\n\n  \
             Recomputes a change the way the verifier would, reads the self-report from\n  \
             refs/notes/andon-measure, and classifies the pair. A stub: P9 builds the verifier,\n  \
             and the output says what this did not check."
        )?;
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
    write!(out, "{}", attest::render(&attested))?;
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
