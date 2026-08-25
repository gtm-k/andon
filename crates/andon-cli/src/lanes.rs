//! The async lane's report: what a record came back with, and what it was
//! still owed.
//!
//! # Where the waiting actually happens
//!
//! Not here. The lane is deferred execution: `measure` leaves a job file
//! (`crate::jobs`) and `andon wait` **executes** it in the foreground before
//! rendering — so by the time this module sees a record, anything that was
//! owed has either been merged in (`lane: async` results below) or failed
//! loudly on the way. This module renders; it does not pretend to wait, it
//! does not sleep for effect, and it does not report a completed async job
//! that never ran — the whole thesis of this tool is that a measurement never
//! claims more than it did.
//!
//! **The lane is not the only thing a measurement can be waiting on.** This said
//! "today the answer is nothing" and printed it unconditionally, including over
//! an escalation — where the answer is a person, and where this same command
//! exited 3 to say so. A sentence and an exit code disagreeing is worst in the
//! one command somebody runs to find out whether they can move on.
//!
//! The answer is derived from the record rather than hardcoded: a result stamped
//! `lane: async` would be reported as outstanding the day one exists, without an
//! edit here. A sentence that reads the field it describes cannot drift from it.

use std::fmt::Write as _;

use andon_core::schema::enums::{Completeness, Lane, Verdict};
use andon_core::schema::payload::MeasurementRecord;

/// What the async lane owes this record.
pub fn wait(record: &MeasurementRecord) -> String {
    let mut out = String::new();
    let async_results: Vec<&_> = record
        .results
        .iter()
        .filter(|r| r.freshness.lane == Lane::Async)
        .collect();

    let _ = writeln!(
        out,
        "\n  change   {}",
        crate::resolve::change_line(&record.compare_context)
    );
    // How much trust the record has earned, from the one function that answers
    // that question for every surface.
    //
    // This was the last surface not calling it. `wait` learned to label an
    // uncommitted head and stopped there, so terminal `report`, the read-back
    // report, the HTML report and `attest-stub` all told a reader that no CI
    // recompute of this record is possible — *not now and not later* — and `wait`
    // said nothing at all about it. Three surfaces agreeing and a fourth silent
    // is a cross-surface disagreement, not a disclosure: a reader who reaches for
    // `wait` to ask what is still outstanding is asking exactly the question
    // whose answer is "nothing, and nothing ever can be".
    let _ = writeln!(
        out,
        "  trust    {}",
        crate::render::attestation_line(record.attestation.value)
    );

    // `wait` is a rendering of the record, so it carries what every rendering of
    // the record has to carry. It named neither of these, which is half of why
    // `report` and `wait` disagreed with the measurement that produced them —
    // one line each rather than the terminal render's block, because this
    // command's subject is the lanes and a reader is here to ask about those.
    if let Some(substitution) = &record.substitution {
        let _ = writeln!(
            out,
            "  NOTE     these numbers are not about your working change — {}",
            substitution.measured
        );
    }
    if !record.unreadable_paths.is_empty() {
        let _ = writeln!(
            out,
            "  NOT READ {} changed path(s) could not be read, so nothing here describes them: {}",
            record.unreadable_paths.len(),
            record.unreadable_paths.join(", ")
        );
    }

    if let Some(provenance) = &record.self_measure {
        let _ = writeln!(
            out,
            "  SELF     Andon measuring itself; {} changed path(s) withheld by [self_measure] \
             excluded_paths",
            provenance.excluded_paths.len()
        );
    }

    if async_results.is_empty() {
        let _ = writeln!(
            out,
            "  lanes    every one of the {} result(s) in this record came from the fast lane.",
            record.results.len()
        );
        // THE ASYNC LANE IS NOT THE ONLY THING A MEASUREMENT CAN BE WAITING ON.
        //
        // `wait` answers "what does this measurement still owe?", and on an
        // escalation the answer is a person. It printed "Nothing is
        // outstanding." and exited 3 — the code whose documented meaning is
        // *the loop is over; a human decides* — so the sentence and the exit
        // code disagreed, in the one command somebody runs to find out whether
        // they can move on.
        //
        // The exit code is right and the sentence was wrong, so the sentence
        // changed. `ledger ack` is what clears it, and it is named here because
        // an escalation with no stated way out is the dead end PREMORTEM A4
        // describes.
        if record.verdict.iteration.escalated || record.verdict.verdict == Verdict::EscalateToHuman
        {
            let _ = writeln!(
                out,
                "\n  A HUMAN IS OUTSTANDING. This measurement escalated on pass {} of a cap of \
                 {}, which means the agent must stop trying and somebody has to look. Nothing \
                 else is: every result in this record came from the fast lane.\n  \
                 `andon ledger ack` records that a human looked, and clears the counter.",
                record.verdict.iteration.count, record.verdict.iteration.cap
            );
        } else if let Some(unanswered) = record
            .verdict
            .reasons
            .iter()
            .find(|r| r.code == "engine-unavailable" || r.code == "measurement-incomplete")
        {
            // AN EMPTY ASYNC LANE IS NOT PROOF THAT NOTHING WAS DEFERRED.
            //
            // This is the escalation bug above, a second time. Deferred work
            // that RAN and produced no result — a test command killed at its
            // timeout is the ordinary case — leaves `async_results` empty,
            // because a timeout is an unanswered question and deliberately
            // emits no `tests.*` result. Counting results therefore reported
            // "no deferred work was pending" directly beneath the line naming
            // the log file that proves one was, in the one command somebody
            // runs to find out whether they can move on.
            //
            // The record already carries the honest answer as a reason. Read it
            // rather than inferring from a count: the count cannot distinguish
            // "nothing was deferred" from "something was deferred and died".
            let _ = writeln!(
                out,
                "\n  DEFERRED WORK RAN AND ANSWERED NOTHING. This command completed a job that \
                 produced no result, so the async lane is empty for a reason that is not \
                 absence:\n    {}  {}\n  That is an unanswered question, not a passing test. \
                 The verdict above was reached WITHOUT the answer.",
                unanswered.code, unanswered.message
            );
        } else {
            let _ = writeln!(
                out,
                "\n  Nothing is outstanding. Every result in this record came from the fast \
                 lane, and no deferred work was pending: a measurement that spills to the \
                 async lane — the user test command, or engines past the cold cap — is \
                 completed by this same command, and its results arrive stamped `lane: async`."
            );
        }
    } else {
        let _ = writeln!(
            out,
            "  lanes    {} of {} result(s) came from the async lane.",
            async_results.len(),
            record.results.len()
        );
        for result in async_results {
            let _ = writeln!(
                out,
                "    {:<44} {}",
                result.metric_id,
                format!("{:?}", result.completeness).to_lowercase()
            );
        }
    }

    // A partial record is the fast lane having hit its cold cap, which is the
    // condition the async lane exists to absorb. Worth saying here even with no
    // lane to wait for, because it is why the record is short.
    if record.completeness == Completeness::Partial {
        let _ = writeln!(
            out,
            "\n  This record is partial: some of what was set out to be measured was not. The \
             results say which."
        );
    }
    let _ = writeln!(out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use andon_core::testing::{sample_compare_context, sample_result};

    fn record(results: Vec<andon_core::schema::payload::MeasurementResult>) -> MeasurementRecord {
        MeasurementRecord {
            substitution: None,
            unreadable_paths: Vec::new(),
            self_measure: None,
            schema_version: andon_core::schema::payload::SCHEMA_VERSION,
            record_kind: andon_core::schema::enums::RecordKind::SelfReport,
            tool: andon_core::schema::payload::ToolIdentity {
                name: "andon".into(),
                version: "0.1.0".into(),
                build_oid: "0".repeat(40),
                attested_release: false,
            },
            compare_context: sample_compare_context(),
            invocation: andon_core::schema::payload::Invocation {
                source: andon_core::schema::enums::InvocationSource::HumanCli,
                harness: None,
                model: None,
                author: None,
                iteration: 0,
            },
            reserved: Default::default(),
            policy_hash: "0".repeat(64),
            completeness: Completeness::Complete,
            verdict: andon_core::schema::payload::VerdictSummary {
                verdict: andon_core::schema::enums::Verdict::Pass,
                reasons: Vec::new(),
                iteration: andon_core::schema::payload::IterationState {
                    count: 0,
                    cap: 3,
                    escalated: false,
                },
            },
            attestation: Default::default(),
            results,
        }
    }

    #[test]
    fn a_fast_only_record_reports_nothing_outstanding() {
        let text = wait(&record(vec![sample_result()]));
        assert!(text.contains("Nothing is outstanding"), "{text}");
    }

    #[test]
    fn deferred_work_that_died_is_not_reported_as_nothing_deferred() {
        // A test command killed at its timeout emits no `tests.*` result at all
        // — a timeout is an unanswered question, never a test failure — so the
        // async lane is empty and a result count cannot tell that apart from a
        // measurement where nothing was ever deferred. It reported the second,
        // one line under the log file proving the first.
        //
        // Fixtured from the reason the record actually carries, not from a flag
        // this test invents: `engine-unavailable` is what a timed-out lane
        // records, so a record without one is genuinely fast-only and the test
        // above still holds.
        let mut r = record(vec![sample_result()]);
        r.verdict
            .reasons
            .push(andon_core::schema::payload::VerdictReason {
                code: "engine-unavailable".to_string(),
                severity: andon_core::schema::enums::Severity::Low,
                message: "the declared test command was killed at its timeout".to_string(),
                metric_ids: Vec::new(),
            });

        let text = wait(&r);
        assert!(
            !text.contains("no deferred work was pending"),
            "a job ran and died; the report must not call that nothing deferred: {text}"
        );
        assert!(
            text.contains("DEFERRED WORK RAN AND ANSWERED NOTHING"),
            "{text}"
        );
        assert!(
            text.contains("the declared test command was killed at its timeout"),
            "the reason's own message is the honest account and must be quoted: {text}"
        );
    }

    #[test]
    fn an_escalation_is_outstanding_and_the_sentence_says_so() {
        // The command printed "Nothing is outstanding." and exited 3 — the code
        // whose documented meaning is *the loop is over; a human decides*. The
        // sentence and the exit code disagreed, in the one command somebody runs
        // to find out whether they can move on.
        //
        // The exit code was right, so the sentence changed. And an escalation
        // with no stated way out is the dead end PREMORTEM A4 describes, so the
        // command that clears it is named.
        let mut record = record(vec![sample_result()]);
        record.verdict.verdict = andon_core::schema::enums::Verdict::EscalateToHuman;
        record.verdict.iteration = andon_core::schema::payload::IterationState {
            count: 4,
            cap: 3,
            escalated: true,
        };
        let text = wait(&record);
        assert!(
            !text.contains("Nothing is outstanding"),
            "an escalation was reported as nothing outstanding:\n{text}"
        );
        assert!(text.contains("pass 4 of a cap of 3"), "{text}");
        assert!(
            text.contains("ledger ack"),
            "the escalation is reported with no way out of it:\n{text}"
        );
    }

    #[test]
    fn an_ordinary_record_still_reports_nothing_outstanding() {
        // The other half: the new sentence must not fire on the records it is
        // not about.
        let text = wait(&record(vec![sample_result()]));
        assert!(text.contains("Nothing is outstanding"), "{text}");
        assert!(!text.contains("A HUMAN IS OUTSTANDING"), "{text}");
    }

    #[test]
    fn an_async_result_would_be_reported_without_editing_this_file() {
        // The claim in the module documentation, checked: the answer is read off
        // `freshness.lane` rather than from a constant that says "no lane yet".
        let mut result = sample_result();
        result.freshness.lane = Lane::Async;
        let text = wait(&record(vec![result]));
        assert!(!text.contains("Nothing is outstanding"), "{text}");
        assert!(text.contains("async lane"), "{text}");
    }
}
