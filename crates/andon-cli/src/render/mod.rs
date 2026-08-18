//! Turning a record into something an actor can act on.
//!
//! Two surfaces, one shape. The terminal render is what the agent's human sees
//! in the loop; the HTML report is what gets attached to a review, emailed, or
//! read three weeks later by somebody who was not there. They present the same
//! facts in the same order, and the ordering is a sort — severity, then
//! actionability, then metric id — never a score. PRE-DECISIONS non-goal 1 bars
//! a composite figure *forever*, and a report header is exactly where one would
//! arrive: "health: 72" is the single most tempting thing to put at the top of a
//! page like this, it would be read as the product's answer, and it is the
//! anti-Goodhart position the whole tool exists to hold.
//!
//! # Three rules both renderers obey
//!
//! 1. **An absence is rendered as an absence.** A result the engines could not
//!    witness carries its own reason string (`unwitnessed: no coverage report
//!    found`) and appears under a heading that says so. Rendering it as a zero
//!    would be the report telling the reader something the measurement does not
//!    know.
//! 2. **Every number carries its evidence.** Tier, citation, and the
//!    `does_not_predict` lines travel with the number rather than living in a
//!    footnote, because the question a reader has is "why should I believe this,
//!    and what does it not tell me" and the answer has to be next to the number.
//! 3. **Nothing is restated in prose that could be read from the record.**
//!    Thresholds, tiers, completeness values, and policy settings are
//!    interpolated from the loaded structures. A sentence that reads the field
//!    it describes cannot drift from it, and this project has now shipped the
//!    opposite mistake three times in one phase (DEFERRED-APPROVALS E21).

pub mod html;
pub mod terminal;

use andon_core::schema::enums::{Attestation, Completeness, Severity, Verdict};
use andon_core::schema::payload::{MeasurementRecord, MeasurementResult};

/// The four words, spelled as an actor reads them.
pub fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Pass => "PASS",
        Verdict::Advise => "ADVISE",
        Verdict::Block => "BLOCK",
        Verdict::EscalateToHuman => "ESCALATE TO HUMAN",
    }
}

/// What the verdict tells the actor to do, in one sentence.
pub fn verdict_meaning(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Pass => "nothing above the advisory floor. The line keeps moving.",
        Verdict::Advise => "findings worth reading that do not stop the line.",
        Verdict::Block => "the line stops. Something here has to be dealt with before this lands.",
        Verdict::EscalateToHuman => {
            "the loop has been round enough times. A human decides from here; the agent should \
             stop trying."
        }
    }
}

/// Severity as a word, so the band is legible without colour.
pub fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MED",
        Severity::High => "HIGH",
        Severity::Critical => "CRIT",
    }
}

/// Severity as a shape, so the band survives greyscale printing and colour
/// blindness. Accessibility is not decoration: colour alone is never the
/// carrier of a fact in this project.
pub fn severity_mark(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "·",
        Severity::Low => "-",
        Severity::Medium => "=",
        Severity::High => "!",
        Severity::Critical => "!!",
    }
}

/// What a completeness value means for the number beside it.
pub fn completeness_note(completeness: Completeness) -> &'static str {
    match completeness {
        Completeness::Complete => "everything this engine set out to measure was measured",
        Completeness::Partial => "some of what was set out to be measured was not",
        Completeness::ParseDegraded => {
            "the parser could not read part of the input, so this number is a lower bound and \
             cannot reach the blocking band"
        }
        Completeness::Unwitnessed => {
            "the inputs this needs did not exist, so there is no number — not a zero"
        }
    }
}

/// How much trust the record has earned, in the reader's terms.
pub fn attestation_line(attestation: Attestation) -> &'static str {
    match attestation {
        Attestation::Confirmed => {
            "CI recomputed this change independently and every compared digest matched"
        }
        Attestation::ConfirmedStatic => {
            "CI recomputed this from an unprivileged job with no self-report to compare against — \
             a pass, and the weaker one"
        }
        Attestation::Divergent => {
            "CI recomputed this change and the numbers disagree, or a tamper signal fired"
        }
        Attestation::Unwitnessed => {
            "self-reported. No CI recompute has witnessed it, so nothing here counts as attested \
             evidence yet"
        }
        Attestation::UnwitnessedVersionSkew => {
            "the two sides ran different engine or tool versions, so their numbers were never \
             comparable. Not an accusation"
        }
        Attestation::UnwitnessedBaseMismatch => {
            "the base this was measured against is not the one CI trusts — a stale base or a \
             rebase. Not an accusation, and not a pass"
        }
    }
}

/// Whether a result is an absence rather than a measurement.
///
/// Keyed on the record's own completeness field rather than on the shape of the
/// value, so an engine that starts reporting absences differently cannot make
/// one look like a number here.
pub fn is_absence(result: &MeasurementResult) -> bool {
    result.completeness == Completeness::Unwitnessed
}

/// Results that carry a number, worst first.
pub fn findings(record: &MeasurementRecord) -> Vec<&MeasurementResult> {
    crate::measure::actionable_first(&record.results)
        .into_iter()
        .filter(|r| !is_absence(r))
        .collect()
}

/// Results that carry an absence, with the reason each names.
pub fn absences(record: &MeasurementRecord) -> Vec<&MeasurementResult> {
    let mut ordered: Vec<&MeasurementResult> =
        record.results.iter().filter(|r| is_absence(r)).collect();
    ordered.sort_by(|a, b| {
        a.metric_id
            .cmp(&b.metric_id)
            .then_with(|| crate::measure::scope_label(a).cmp(&crate::measure::scope_label(b)))
    });
    ordered
}

/// Tamper results whose flag fired.
pub fn fired_flags(record: &MeasurementRecord) -> Vec<&MeasurementResult> {
    let mut fired: Vec<&MeasurementResult> = record
        .results
        .iter()
        .filter(|r| andon_core::verdict::severity::fired_signal(r).is_some())
        .collect();
    fired.sort_by(|a, b| a.metric_id.cmp(&b.metric_id));
    fired
}
