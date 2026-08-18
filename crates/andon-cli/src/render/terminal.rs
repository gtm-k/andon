//! The terminal render.
//!
//! Written for the reader who has thirty seconds: the verdict word, what it
//! means, what drove it, and then the findings worst-first with their evidence
//! attached. Everything below the fold is still there for the reader who has
//! five minutes.
//!
//! Colour is an accent and never a carrier. Every severity is spelled as a word
//! and marked with a shape, so the render is identical in meaning through a pipe,
//! in a CI log, on a monochrome terminal, and to a reader who cannot distinguish
//! red from green. `NO_COLOR` and a non-terminal stdout both turn the accent off.

use std::fmt::Write as _;

use andon_core::schema::enums::{Completeness, Severity, Verdict};
use andon_core::schema::payload::{MeasurementRecord, MeasurementResult};

use crate::measure::{scope_label, value_label, Measurement};
use crate::render::{
    absences, attestation_line, completeness_note, findings, severity_mark, severity_word,
    verdict_meaning, verdict_word,
};

/// Whether to emit ANSI escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Colour {
    /// Emit escapes.
    On,
    /// Emit none.
    Off,
}

impl Colour {
    /// The honest default: colour only when a person is looking at a terminal
    /// and has not asked for it to stop.
    pub fn detect() -> Self {
        use std::io::IsTerminal;
        let suppressed = std::env::var_os("NO_COLOR").is_some()
            || std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false);
        if !suppressed && std::io::stdout().is_terminal() {
            Colour::On
        } else {
            Colour::Off
        }
    }

    fn paint(self, code: &str, text: &str) -> String {
        match self {
            Colour::On => format!("\x1b[{code}m{text}\x1b[0m"),
            Colour::Off => text.to_string(),
        }
    }

    fn dim(self, text: &str) -> String {
        self.paint("2", text)
    }

    fn bold(self, text: &str) -> String {
        self.paint("1", text)
    }

    fn severity(self, severity: Severity, text: &str) -> String {
        let code = match severity {
            Severity::Info => "2",
            Severity::Low => "36",
            Severity::Medium => "33",
            Severity::High => "31",
            Severity::Critical => "1;31",
        };
        self.paint(code, text)
    }

    fn verdict(self, verdict: Verdict, text: &str) -> String {
        let code = match verdict {
            Verdict::Pass => "1;32",
            Verdict::Advise => "1;36",
            Verdict::Block => "1;31",
            Verdict::EscalateToHuman => "1;35",
        };
        self.paint(code, text)
    }
}

/// How much of the record to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Verdict, reasons, and the findings that reached above the floor.
    Normal,
    /// Every result, including the informational ones and every absence.
    Full,
}

/// Render a fresh measurement.
pub fn render(measurement: &Measurement, colour: Colour, detail: Detail) -> String {
    let mut out = String::new();
    header(&mut out, measurement, colour);
    body(
        &mut out,
        &measurement.record,
        colour,
        detail,
        Some(&measurement.branch),
    );
    out
}

/// Render a record read back from disk, with no measurement context around it.
pub fn render_record(record: &MeasurementRecord, colour: Colour, detail: Detail) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n {}  {}",
        colour.verdict(record.verdict.verdict, verdict_word(record.verdict.verdict)),
        colour.dim(verdict_meaning(record.verdict.verdict))
    );
    let _ = writeln!(
        out,
        " {}",
        colour.dim(&format!(
            "change   {} → {} ({})",
            crate::resolve::short(&record.compare_context.base_oid),
            crate::resolve::short(&record.compare_context.head_oid),
            record.compare_context.base_resolution
        ))
    );
    body(&mut out, record, colour, detail, None);
    out
}

fn header(out: &mut String, measurement: &Measurement, colour: Colour) {
    let record = &measurement.record;
    let verdict = record.verdict.verdict;
    let _ = writeln!(
        out,
        "\n {}  {}",
        colour.verdict(verdict, verdict_word(verdict)),
        colour.dim(verdict_meaning(verdict))
    );

    let engines: std::collections::BTreeSet<&str> = record
        .results
        .iter()
        .map(|r| r.engine_id.as_str())
        .collect();
    let _ = writeln!(
        out,
        " {}",
        colour.dim(&format!("change   {}", measurement.how))
    );
    let _ = writeln!(
        out,
        " {}",
        colour.dim(&format!(
            "reading  {} file(s) changed · {} engine(s) · {} result(s) · record {}",
            measurement.changed_files,
            engines.len(),
            record.results.len(),
            format!("{:?}", record.completeness).to_lowercase()
        ))
    );
    if measurement.changed_files == 0 {
        // Zero changed files with change-scope numbers beside it reads like a
        // broken measurement unless it is named. It is not broken: an empty
        // commit is a real commit, and every engine still reports what it found,
        // which is nothing.
        let _ = writeln!(
            out,
            " {}",
            colour.dim(
                "         this change touches no files, so every change-scope number below is a \
                 measurement of nothing rather than a failure to measure"
            )
        );
    }
    let _ = writeln!(
        out,
        " {}",
        colour.dim(&format!(
            "trust    {}",
            attestation_line(record.attestation.value)
        ))
    );

    // The substitution, said before anything else that could be mistaken for a
    // measurement of the working change. PREMORTEM A1: a fallback that is not
    // announced is a report about something other than what was asked for.
    if let Some(substitution) = &measurement.substitution {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            " {} {}",
            colour.bold("NOTE"),
            colour.bold("nothing was in flight, so this is not your working change")
        );
        let _ = writeln!(out, "   asked for  {}", substitution.asked_for);
        let _ = writeln!(out, "   measured   {}", substitution.measured);
        let _ = writeln!(out, "   {}", colour.dim(&substitution.because));
    }

    if !measurement.excluded.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            " {} {} path(s) withheld by [self_measure] excluded_paths: {}",
            colour.bold("EXCLUDED"),
            measurement.excluded.len(),
            measurement.excluded.join(", ")
        );
    }

    for notice in &measurement.notices {
        let _ = writeln!(out, " {} {notice}", colour.dim("note    "));
    }
}

fn body(
    out: &mut String,
    record: &MeasurementRecord,
    colour: Colour,
    detail: Detail,
    branch: Option<&str>,
) {
    reasons(out, record, colour);
    finding_list(out, record, colour, detail);
    absence_list(out, record, colour, detail);
    iteration(out, record, colour, branch);
    footer(out, colour);
}

fn reasons(out: &mut String, record: &MeasurementRecord, colour: Colour) {
    if record.verdict.reasons.is_empty() {
        return;
    }
    let _ = writeln!(out, "\n {}", colour.bold("WHY"));
    for reason in &record.verdict.reasons {
        let _ = writeln!(
            out,
            "  {} {}  {}",
            colour.severity(reason.severity, severity_mark(reason.severity)),
            colour.severity(reason.severity, &pad(&reason.code, 24)),
            reason.message
        );
        if !reason.metric_ids.is_empty() {
            let _ = writeln!(
                out,
                "     {}",
                colour.dim(&format!("↳ {}", reason.metric_ids.join(", ")))
            );
        }
    }
}

fn finding_list(out: &mut String, record: &MeasurementRecord, colour: Colour, detail: Detail) {
    let all = findings(record);
    let shown: Vec<&&MeasurementResult> = all
        .iter()
        .filter(|r| detail == Detail::Full || r.severity > Severity::Info)
        .collect();
    if shown.is_empty() {
        let _ = writeln!(
            out,
            "\n {}",
            colour.dim(&format!(
                "No finding rose above the advisory floor. {} measured number(s) are in the \
                 record; `andon report --full` prints them.",
                all.len()
            ))
        );
        return;
    }

    let _ = writeln!(
        out,
        "\n {} {}",
        colour.bold("FINDINGS"),
        colour.dim("(worst first; a sort, not a score — nothing here is added up)")
    );
    for result in &shown {
        finding(out, result, colour);
    }
    if detail == Detail::Normal && shown.len() < all.len() {
        let _ = writeln!(
            out,
            " {}",
            colour.dim(&format!(
                "  … and {} more at INFO. `andon report --full` prints them.",
                all.len() - shown.len()
            ))
        );
    }
}

fn finding(out: &mut String, result: &MeasurementResult, colour: Colour) {
    let _ = writeln!(
        out,
        "  {} {}  {}  {}",
        colour.severity(result.severity, severity_mark(result.severity)),
        colour.severity(result.severity, &pad(severity_word(result.severity), 4)),
        colour.bold(&result.metric_id),
        colour.dim(&scope_label(result))
    );

    let delta = result
        .delta
        .as_ref()
        .map(|d| format!("  (Δ {})", value_label(d)))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "       {}{delta}",
        colour.bold(&value_label(&result.value))
    );

    // The evidence, attached to the number rather than to a footnote. Tier and
    // citation say why to believe it; the `does_not_predict` line says what it
    // is not evidence for, and it is the field this whole project is about.
    let _ = writeln!(
        out,
        "       {}",
        colour.dim(&format!(
            "evidence  tier {:?}{} · {}",
            result.evidence.tier,
            if result.evidence.stale {
                " · STALE (past its re-review date)"
            } else {
                ""
            },
            result.evidence.citation
        ))
    );
    if let Some(line) = result.evidence.does_not_predict.first() {
        let _ = writeln!(
            out,
            "       {}",
            colour.dim(&format!("does not predict  {line}"))
        );
    }
    if result.completeness != Completeness::Complete {
        let _ = writeln!(
            out,
            "       {}",
            colour.dim(&format!(
                "{}: {}",
                format!("{:?}", result.completeness).to_lowercase(),
                completeness_note(result.completeness)
            ))
        );
    }
}

fn absence_list(out: &mut String, record: &MeasurementRecord, colour: Colour, detail: Detail) {
    let absent = absences(record);
    if absent.is_empty() {
        return;
    }
    if detail == Detail::Normal {
        let _ = writeln!(
            out,
            "\n {} {}",
            colour.bold("NOT MEASURED"),
            colour.dim(&format!(
                "{} result(s) have no number, and say why. `andon report --full` names each.",
                absent.len()
            ))
        );
        return;
    }
    let _ = writeln!(
        out,
        "\n {} {}",
        colour.bold("NOT MEASURED"),
        colour.dim("(an absence, never a zero)")
    );
    for result in absent {
        let _ = writeln!(
            out,
            "  {}  {}",
            colour.bold(&result.metric_id),
            colour.dim(&scope_label(result))
        );
        let _ = writeln!(out, "       {}", value_label(&result.value));
    }
}

fn iteration(out: &mut String, record: &MeasurementRecord, colour: Colour, branch: Option<&str>) {
    let state = record.verdict.iteration;
    if state.count == 0 && !state.escalated {
        return;
    }
    // The counter is per branch, so the branch is part of the fact. Without it a
    // reader cannot tell which loop the count belongs to, which is the whole
    // reason the counter is keyed that way rather than kept per repository.
    let _ = writeln!(
        out,
        "\n {}",
        colour.dim(&format!(
            "loop     pass {} of a cap of {}{}{}",
            state.count,
            state.cap,
            branch.map(|b| format!(" on {b}")).unwrap_or_default(),
            if state.escalated {
                " — the cap has fired; `andon ledger ack` clears it once a human has looked"
            } else {
                ""
            }
        ))
    );
}

fn footer(out: &mut String, colour: Colour) {
    let _ = writeln!(
        out,
        "\n {}\n",
        colour
            .dim("Every number above stands on a claim you can read: `andon explain <metric-id>`.")
    );
}

fn pad(text: &str, width: usize) -> String {
    let mut padded = text.to_string();
    while padded.chars().count() < width {
        padded.push(' ');
    }
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colour_off_emits_no_escapes() {
        let painted = Colour::Off.severity(Severity::Critical, "CRIT");
        assert_eq!(painted, "CRIT");
        assert!(!painted.contains('\u{1b}'));
    }

    #[test]
    fn every_severity_is_distinguishable_without_colour() {
        // The accessibility rule, checked rather than asserted in prose: two
        // bands that share both a word and a shape would be indistinguishable
        // to a reader who cannot see the colour.
        let bands = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for band in bands {
            assert!(
                seen.insert((severity_word(band), severity_mark(band))),
                "{band:?} shares its word and shape with another band"
            );
        }
    }

    #[test]
    fn padding_never_truncates() {
        assert_eq!(pad("abc", 5), "abc  ");
        assert_eq!(pad("abcdefg", 3), "abcdefg");
    }
}
