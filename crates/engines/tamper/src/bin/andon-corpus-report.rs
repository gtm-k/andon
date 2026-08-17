//! Measure the tamper suite against the frozen corpus, and print the table.
//!
//! ```text
//! andon-corpus-report [--repo <PATH>] [--check-floors] [--check-freeze] [--markdown]
//! andon-corpus-report freeze --frozen <DATE> --refresh-due <DATE> [--repo <PATH>]
//! ```
//!
//! Exit codes: 0 the report was produced (and any requested check passed), 1 a
//! check failed, 2 bad usage or an operational failure.
//!
//! # Why the freeze is a separate verb
//!
//! PLAN.md P3 requires corpus v1 to be frozen and reviewed **before** the
//! precision and recall floors are measured against it — the test and its
//! subject must not be authored in one motion. `freeze` writes what the corpus
//! *is*; the report reads it back and refuses to describe a corpus that has
//! moved since. The ordering is visible in the commit history, which is the
//! point: a freeze that could be re-run to match a disappointing measurement
//! would not be a freeze.
//!
//! The argument parser is hand-rolled for the same reason `andon-spike`'s is:
//! this workspace's supply-chain gate is `cargo deny check licenses bans
//! sources`, and a dependency admitted for argument parsing is a dependency the
//! verifier has to be trusted with.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use andon_engine_tamper::corpus::{self, FreezeMarker, Report, PRECISION_FLOOR, RECALL_FLOOR};
use andon_engine_tamper::detectors;

const USAGE: &str = "\
usage: andon-corpus-report [--repo <PATH>] [--check-floors] [--check-freeze] [--markdown]
       andon-corpus-report freeze --frozen <DATE> --refresh-due <DATE> [--repo <PATH>]";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("andon-corpus-report: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    let repo = value(&args, "--repo")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    if args.first().map(String::as_str) == Some("freeze") {
        return freeze(&repo, &args);
    }

    let cases = corpus::load(&repo).map_err(|e| e.to_string())?;
    if cases.is_empty() {
        return Err(format!(
            "no corpus cases found under {}",
            repo.join(corpus::ADVERSARIAL_DIR).display()
        ));
    }

    let marker = if args.iter().any(|a| a == "--check-freeze") {
        Some(corpus::verify_freeze(&repo)?)
    } else {
        corpus::verify_freeze(&repo).ok()
    };

    let report = corpus::measure(&cases);
    if args.iter().any(|a| a == "--markdown") {
        print!("{}", markdown(&report, marker.as_ref()));
    } else {
        print!("{}", plain(&report, marker.as_ref()));
    }

    if args.iter().any(|a| a == "--check-floors") {
        let below = report.below_floor();
        if !below.is_empty() {
            eprintln!(
                "\nFLOORS NOT MET: {}\n\
                 The floors are ex ante (PLAN.md P3, round-1 B9) — precision >= {PRECISION_FLOOR:.2}, \
                 recall >= {RECALL_FLOOR:.2}.\n\
                 A detector below one of them fails the phase. Fix the detector; the corpus is \
                 frozen and is not the variable.",
                below
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return Ok(ExitCode::from(1));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn freeze(repo: &Path, args: &[String]) -> Result<ExitCode, String> {
    let frozen = value(args, "--frozen").ok_or("freeze needs --frozen <DATE>")?;
    let refresh_due = value(args, "--refresh-due").ok_or("freeze needs --refresh-due <DATE>")?;
    let cases = corpus::load(repo).map_err(|e| e.to_string())?;
    let marker = FreezeMarker {
        version: 1,
        frozen: frozen.to_string(),
        refresh_due: refresh_due.to_string(),
        digest: corpus::content_digest(repo).map_err(|e| e.to_string())?,
        adversarial_cases: cases
            .iter()
            .filter(|c| c.family == corpus::Family::Adversarial)
            .count(),
        honest_cases: cases
            .iter()
            .filter(|c| c.family == corpus::Family::Honest)
            .count(),
    };
    let path = corpus::freeze_marker_path(repo);
    let body = format!(
        "# Corpus v1 — the freeze marker.\n\
         #\n\
         # PLAN.md P3: the corpus is frozen and ensemble-reviewed BEFORE the precision and\n\
         # recall floors are measured against it, so that the test and its subject are not\n\
         # authored in one motion. This file records what was frozen.\n\
         #\n\
         # `digest` is a SHA-256 over every case file and manifest in both corpora, sorted by\n\
         # path. `andon-corpus-report --check-freeze` recomputes it and refuses to publish a\n\
         # report describing a corpus that has moved. Editing a case after the freeze is not a\n\
         # lint failure to be waved through: it invalidates the published numbers, and the\n\
         # order is always re-freeze then re-measure, never the reverse.\n\
         #\n\
         # `refresh_due` is the quarterly refresh of PREMORTEM S1, checked by the scheduled\n\
         # `corpus-refresh` workflow. An adversarial corpus that never changes becomes the\n\
         # evasion training set for whoever reads it.\n\
         #\n\
         # Generated by `andon-corpus-report freeze`. Do not hand-edit the digest.\n\
         \n\
         version = {}\n\
         frozen = \"{}\"\n\
         refresh_due = \"{}\"\n\
         digest = \"{}\"\n\
         adversarial_cases = {}\n\
         honest_cases = {}\n",
        marker.version,
        marker.frozen,
        marker.refresh_due,
        marker.digest,
        marker.adversarial_cases,
        marker.honest_cases
    );
    std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
    println!(
        "froze {} adversarial and {} should-pass cases at {}\n  {}",
        marker.adversarial_cases,
        marker.honest_cases,
        marker.digest,
        path.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let index = args.iter().position(|a| a == name)?;
    args.get(index + 1).map(String::as_str)
}

fn ratio(value: Option<f64>) -> String {
    value
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "—".to_string())
}

fn header(report: &Report, marker: Option<&FreezeMarker>) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "corpus v1 — {} adversarial cases, {} should-pass cases\n",
        report.adversarial_cases, report.honest_cases
    ));
    match marker {
        Some(marker) => out.push_str(&format!(
            "frozen {} (refresh due {}), digest {}\n",
            marker.frozen,
            marker.refresh_due,
            &marker.digest[..16]
        )),
        None => out.push_str("NOT VERIFIED AGAINST A FREEZE MARKER\n"),
    }
    out.push_str(&format!(
        "floors, set ex ante: precision >= {PRECISION_FLOOR:.2}, recall >= {RECALL_FLOOR:.2}\n"
    ));
    out
}

fn plain(report: &Report, marker: Option<&FreezeMarker>) -> String {
    let mut out = header(report, marker);
    out.push('\n');
    out.push_str("detector                    TP  FN  FP  TN   precision  recall   cross-fires\n");
    for detector in detectors::all() {
        let name = detectors::signal_name(detector.signal());
        let score = &report.scores[name];
        out.push_str(&format!(
            "{:<26}  {:>2}  {:>2}  {:>2}  {:>2}   {:>9}  {:>6}   {:>11}{}\n",
            name,
            score.true_positives,
            score.false_negatives,
            score.false_positives,
            score.true_negatives,
            ratio(score.precision()),
            ratio(score.recall()),
            score.cross_fires,
            if score.meets_floors() {
                ""
            } else {
                "  BELOW FLOOR"
            }
        ));
    }
    for detector in detectors::all() {
        let name = detectors::signal_name(detector.signal());
        let score = &report.scores[name];
        if !score.missed.is_empty() {
            out.push_str(&format!("\n{name} missed: {}\n", score.missed.join(", ")));
        }
        if !score.fired_on_honest.is_empty() {
            out.push_str(&format!(
                "{name} fired on should-pass: {}\n",
                score.fired_on_honest.join(", ")
            ));
        }
    }
    out
}

fn markdown(report: &Report, marker: Option<&FreezeMarker>) -> String {
    let mut out = String::new();
    for line in header(report, marker).lines() {
        out.push_str(&format!("{line}\n"));
    }
    out.push_str("\n| detector | TP | FN | FP | TN | precision | recall | cross-fires |\n");
    out.push_str("|---|---:|---:|---:|---:|---:|---:|---:|\n");
    for detector in detectors::all() {
        let name = detectors::signal_name(detector.signal());
        let score = &report.scores[name];
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} |\n",
            name,
            score.true_positives,
            score.false_negatives,
            score.false_positives,
            score.true_negatives,
            ratio(score.precision()),
            ratio(score.recall()),
            score.cross_fires,
        ));
    }
    out
}
