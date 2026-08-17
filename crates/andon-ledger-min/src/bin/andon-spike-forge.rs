//! `andon-spike-forge` — the adversary.
//!
//! A deliberately forging agent binary. It reads a self-report out of
//! `refs/notes/andon-measure`, rewrites it to say something that is not true,
//! **re-seals every per-result digest so the record is internally consistent**,
//! and writes it back.
//!
//! # Why this is a separate executable
//!
//! The threat PRE-DECISIONS names is "agent-attached measurements are
//! self-reported until CI attests" — that is, an agent whose numbers cannot be
//! taken on trust because the agent controls the binary that produced them. A
//! fixture that staged that threat with a `--lie` flag on the honest binary
//! would be testing a code path that does not exist in the wild, and would put
//! forging capability inside the tool whose product is not forging.
//!
//! So every line of forging logic is in this file, compiled only into this
//! binary. `crates/andon-ledger-min/tests/binary_separation.rs` fails the build
//! if any of it leaks into the library, which is what `andon-spike` links.
//!
//! # Why it re-seals
//!
//! A forger that changed a number and left the digest describing the old one
//! would be caught by arithmetic, not by the trust model. Re-sealing produces
//! exactly what a competent attacker produces: a record that is self-consistent,
//! correctly formatted, and false. The only thing that catches it is an
//! independent recompute — which is the claim P1.5 exists to test.
//!
//! ```text
//! andon-spike-forge --repo <PATH> --commit <SHA> --op <OP> [--base-oid <OID>] [--ref <REF>]
//!
//!   --op inflate-metric       every count is one higher than measured
//!   --op flip-deterministic   every count is forged AND every `deterministic`
//!                             flag is set to false, buying the whole record an
//!                             opt-out from the compare for the price of a
//!                             boolean the digest does not cover (E4)
//!   --op flip-one-deterministic
//!                             the same dodge on exactly ONE result, with every
//!                             other result left honest — the shape a competent
//!                             attacker ships, because the record still carries
//!                             genuine matching pairs
//!   --op fabricate-base       the claimed base becomes --base-oid: measure
//!                             against a base where the numbers look good, then
//!                             claim a different one (R2-4 base-fabrication)
//!
//! Exit codes: 0 forged, 1 nothing to forge, 2 bad usage or I/O.
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use andon_core::git::Git;
use andon_core::schema::payload::{MeasurementRecord, MetricValue};
use andon_ledger_min::notes::{Notes, MEASURE_REF};

const USAGE: &str = "\
usage: andon-spike-forge --repo <PATH> --commit <SHA> --op \
<inflate-metric|flip-deterministic|flip-one-deterministic|fabricate-base> \
[--base-oid <OID>] [--ref <REF>]";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("andon-spike-forge: {message}");
            ExitCode::from(2)
        }
    }
}

struct Args {
    repo: PathBuf,
    commit: String,
    op: String,
    base_oid: Option<String>,
    notes_ref: String,
}

fn parse_args() -> Result<Args, String> {
    let mut repo = None;
    let mut commit = None;
    let mut op = None;
    let mut base_oid = None;
    let mut notes_ref = MEASURE_REF.to_string();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--repo" => repo = Some(PathBuf::from(value("--repo")?)),
            "--commit" => commit = Some(value("--commit")?),
            "--op" => op = Some(value("--op")?),
            "--base-oid" => base_oid = Some(value("--base-oid")?),
            "--ref" => notes_ref = value("--ref")?,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unexpected argument '{other}'\n{USAGE}")),
        }
    }

    Ok(Args {
        repo: repo.ok_or_else(|| format!("--repo is required\n{USAGE}"))?,
        commit: commit.ok_or_else(|| format!("--commit is required\n{USAGE}"))?,
        op: op.ok_or_else(|| format!("--op is required\n{USAGE}"))?,
        base_oid,
        notes_ref,
    })
}

fn run() -> Result<ExitCode, String> {
    let args = parse_args()?;
    let git = Git::open(&args.repo).map_err(|e| e.to_string())?;
    let notes = Notes::new(&git, args.notes_ref.clone());

    let mut records = notes.read(&args.commit).map_err(|e| e.to_string())?;
    if records.is_empty() {
        eprintln!(
            "nothing to forge: {} carries no record on {}",
            args.commit, args.notes_ref
        );
        return Ok(ExitCode::from(1));
    }

    for record in &mut records {
        match args.op.as_str() {
            "inflate-metric" => inflate(record),
            "flip-deterministic" => {
                // Both halves, because the flag alone leaves an honest number
                // behind it and the whole point of the dodge is to hide a
                // dishonest one. `compare.rs`'s PROBE8 pins the same shape at
                // the unit level; this is it through real git.
                inflate(record);
                for result in &mut record.results {
                    result.deterministic = false;
                }
            }
            "flip-one-deterministic" => {
                // The subtler shape, and the one a competent attacker actually
                // ships: every other result stays honest, so the record carries
                // genuine matching pairs and the compare has plenty to show.
                // The forged number hides in the single result that claims to be
                // outside the compare set. `compare.rs`'s PROBE9 pins it at the
                // unit level; this is it through real git.
                let Some(target) = pick_one(record) else {
                    return Err("the record has no results to flip".to_string());
                };
                let result = &mut record.results[target];
                result.deterministic = false;
                result.value = inflate_value(&result.value);
            }
            "fabricate-base" => {
                let oid = args
                    .base_oid
                    .clone()
                    .ok_or("--op fabricate-base needs --base-oid")?;
                record.compare_context.base_oid = oid;
            }
            other => return Err(format!("unknown --op '{other}'\n{USAGE}")),
        }
        reseal(record)?;
    }

    notes
        .write(&args.commit, &records)
        .map_err(|e| e.to_string())?;
    println!(
        "forged {} record(s) on {} ({})",
        records.len(),
        args.commit,
        args.op
    );
    Ok(ExitCode::SUCCESS)
}

/// Every count one higher than what was measured.
///
/// A small lie on purpose. A wildly wrong number would be caught by anything;
/// off-by-one is what a plausible attacker ships, and it is invisible to
/// everything except a recompute.
fn inflate(record: &mut MeasurementRecord) {
    for result in &mut record.results {
        result.value = inflate_value(&result.value);
    }
}

fn inflate_value(value: &MetricValue) -> MetricValue {
    match value {
        MetricValue::Count(n) => MetricValue::Count(n.saturating_add(1)),
        MetricValue::Integer(n) => MetricValue::Integer(n.saturating_add(1)),
        MetricValue::Duration { millis } => MetricValue::Duration {
            millis: millis.saturating_add(1),
        },
        MetricValue::Ratio(r) => MetricValue::Ratio(r + 0.000_001),
        MetricValue::Flag(b) => MetricValue::Flag(!b),
        MetricValue::Text(t) => MetricValue::Text(format!("{t}!")),
    }
}

/// Index of the one result a single-result attack targets.
///
/// Chosen by sorted `(metric_id, canonical scope)` rather than by position, so
/// the fixture attacks the same result on every platform and a failure names the
/// same metric wherever it is reproduced.
fn pick_one(record: &MeasurementRecord) -> Option<usize> {
    record
        .results
        .iter()
        .enumerate()
        .min_by_key(|(_, result)| {
            (
                result.metric_id.clone(),
                andon_core::canonical::to_canonical_string(&result.scope).unwrap_or_default(),
            )
        })
        .map(|(index, _)| index)
}

/// Re-seal every result against the record's (possibly forged) tuple.
///
/// This is the step that makes the forgery competent rather than clumsy.
fn reseal(record: &mut MeasurementRecord) -> Result<(), String> {
    let ctx = record.compare_context.clone();
    for result in &mut record.results {
        result.seal(&ctx).map_err(|e| e.to_string())?;
    }
    Ok(())
}
