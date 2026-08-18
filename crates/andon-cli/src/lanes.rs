//! `andon wait` — the async lane, and what it honestly is today.
//!
//! # Why this command exists before the lane does
//!
//! The measurement contract splits into a fast lane (sub-second static diff) and
//! an async lane (mutation runs, full test suites) with per-result freshness, and
//! `wait` is how a caller blocks until the slow half arrives. **P7 builds the
//! async lane.** This build has only the fast one, and every result it produces
//! is stamped `lane: fast`.
//!
//! So `wait` reads the last record and reports what is actually outstanding,
//! which today is nothing. It does not pretend to wait, it does not sleep for
//! effect, and it does not report a completed async job that never ran — the
//! whole thesis of this tool is that a measurement never claims more than it
//! did, and a subcommand that faked a lane would be the first thing to break it.
//!
//! The answer is derived from the record rather than hardcoded: a result stamped
//! `lane: async` would be reported as outstanding the day one exists, without an
//! edit here. A sentence that reads the field it describes cannot drift from it.

use std::fmt::Write as _;

use andon_core::schema::enums::{Completeness, Lane};
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
        "\n  change   {} → {}",
        crate::resolve::short(&record.compare_context.base_oid),
        crate::resolve::short(&record.compare_context.head_oid)
    );

    if async_results.is_empty() {
        let _ = writeln!(
            out,
            "  lanes    every one of the {} result(s) in this record came from the fast lane.",
            record.results.len()
        );
        let _ = writeln!(
            out,
            "\n  Nothing is outstanding. This build ships no async lane: mutation runs and full \
             test suites execute repository code, which needs the sandbox, and the sandbox is \
             not in this binary. When it is, results from it will be stamped `lane: async` and \
             this command will report them."
        );
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
