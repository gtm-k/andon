//! The proof that a truncated history cannot become a tamper accusation.
//!
//! # What is being proved, and why it needs proving
//!
//! `ResultDigestInput` covers `value` **and** `completeness`. So if the agent
//! and the verifier both emitted a per-file `process.churn-commits` result and
//! one of them had a shallow clone, the pair would be:
//!
//! ```text
//! agent:    Count(4)          / complete
//! verifier: Text(unwitnessed) / unwitnessed
//! ```
//!
//! Same `(metric_id, scope)`, different digest — and `andon_core::compare` maps
//! a mismatch to `divergent`, the first-class tamper outcome. `actions/checkout`
//! clones at depth 1 by default, so that is not an exotic configuration; it is
//! the default one, and it would make the process family accuse every honest
//! pull request of gaming. PREMORTEM Story 1, arriving through P4.
//!
//! The engine's emission rule closes it: a truncated window produces
//! **change-scoped** markers and no per-file results, so the two sides have
//! nothing paired and `compare` withholds the pass instead of making an
//! accusation. These tests run the real `classify` over records built by the
//! real engine, in both directions, so the rule cannot quietly stop working.
//!
//! The last test is the other half of the argument: a *forged* number still
//! reaches `divergent`. A design that made every disagreement gentle would have
//! solved the false-accusation problem by disabling the detector.

mod common;

use andon_core::compare::{classify, BaseRelation, CompareInputs};
use andon_core::engine::{run_engine, MeasureContext};
use andon_core::git::{ChangedSet, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_core::schema::enums::{Attestation, RecordKind};
use andon_core::schema::payload::{MeasurementRecord, MeasurementResult, MetricValue};
use andon_core::testing::{sample_compare_context, sample_record};
use andon_engine_process::complexity::NoComplexity;
use andon_engine_process::engine::{ProcessEngine, METRIC_CHURN_COMMITS};
use andon_engine_process::HistoryWindow;
use common::TestRepo;

/// A three-commit repository and the range from its second commit to its third.
fn measured_results(repo: &TestRepo, truncate: bool) -> Vec<MeasurementResult> {
    let git = repo.git();
    let base = repo.rev_parse("HEAD~1");
    let head = repo.rev_parse("HEAD");
    let range = ResolvedRange::resolve(git, &Revision::Rev(base), &Revision::Rev(head.clone()))
        .expect("both endpoints are commits");
    let changed = ChangedSet::enumerate(git, &range).expect("enumerating the change");

    let mut window =
        HistoryWindow::read(git, &head, Policy::default().history.window_days).expect("history");
    // Staging truncation on the window rather than by making a shallow clone
    // keeps the two sides of this test byte-comparable: everything else about
    // them is identical, so the classification difference can only come from the
    // property under test. `history_semantics.rs` proves that a real
    // `--depth 1` clone sets this same flag.
    window.truncated = truncate;

    let engine = ProcessEngine::from_window(&window, &changed, &NoComplexity);
    let ctx = MeasureContext {
        // The sample context, so both records carry the same tuple and the
        // compare reaches its digest step rather than stopping at step 1.
        compare_context: sample_compare_context(),
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox: None,
    };
    run_engine(&engine, &ctx).expect("the engine measures")
}

fn record(kind: RecordKind, results: Vec<MeasurementResult>) -> MeasurementRecord {
    let mut record = sample_record();
    record.record_kind = kind;
    record.results = results;
    record
}

fn equal_tuple() -> CompareInputs {
    CompareInputs {
        base_relation: BaseRelation::Equal,
        head_equal: true,
        fork_tier: false,
    }
}

fn fixture(name: &str) -> TestRepo {
    let repo = TestRepo::new(name);
    repo.write("src/a.ts", b"one\n");
    repo.commit_as("alice", 0, "first");
    repo.write("src/a.ts", b"one\ntwo\n");
    repo.commit_as("bob", 30, "second");
    repo.write("src/a.ts", b"one\ntwo\nthree\n");
    repo.commit_as("alice", 60, "third");
    repo
}

#[test]
fn two_complete_sides_confirm() {
    // The baseline. Without it, a test that says "not divergent" could be
    // passing because nothing ever confirms.
    let repo = fixture("both-complete");
    let agent = record(RecordKind::SelfReport, measured_results(&repo, false));
    let verifier = record(RecordKind::Attestation, measured_results(&repo, false));
    assert_eq!(
        classify(Some(&agent), &verifier, equal_tuple()).attestation,
        Attestation::Confirmed
    );
}

#[test]
fn a_shallow_verifier_meeting_a_complete_agent_does_not_accuse() {
    // The default `actions/checkout` case. This is the one that would have made
    // the process family unusable.
    let repo = fixture("shallow-verifier");
    let agent = record(RecordKind::SelfReport, measured_results(&repo, false));
    let verifier = record(RecordKind::Attestation, measured_results(&repo, true));
    let classification = classify(Some(&agent), &verifier, equal_tuple());
    assert_ne!(
        classification.attestation,
        Attestation::Divergent,
        "a truncated verifier must never accuse an honest agent of tampering"
    );
    assert_eq!(classification.attestation, Attestation::Unwitnessed);
    assert!(classification.tamper_signals.is_empty());
    let compare = classification.compare.expect("a compare was attempted");
    assert!(
        compare.mismatched.is_empty(),
        "nothing should have been compared: {:?}",
        compare.mismatched
    );
}

#[test]
fn a_shallow_agent_meeting_a_complete_verifier_does_not_get_accused_either() {
    // The mirror image: a developer measuring inside a shallow clone. The
    // asymmetry has two directions and only one of them is the CI default, so
    // only one of them would have been noticed.
    let repo = fixture("shallow-agent");
    let agent = record(RecordKind::SelfReport, measured_results(&repo, true));
    let verifier = record(RecordKind::Attestation, measured_results(&repo, false));
    let classification = classify(Some(&agent), &verifier, equal_tuple());
    assert_ne!(classification.attestation, Attestation::Divergent);
    assert_eq!(classification.attestation, Attestation::Unwitnessed);
    assert!(classification.tamper_signals.is_empty());
}

#[test]
fn two_truncated_sides_agree_with_each_other() {
    // Both shallow: the markers pair, the digests match, and the record is
    // confirmed — on markers that say plainly that nothing was measured. That is
    // the right answer: the two sides did the same thing and got the same
    // result, and what they measured is disclosed in every result's
    // `completeness`.
    let repo = fixture("both-shallow");
    let agent = record(RecordKind::SelfReport, measured_results(&repo, true));
    let verifier = record(RecordKind::Attestation, measured_results(&repo, true));
    assert_eq!(
        classify(Some(&agent), &verifier, equal_tuple()).attestation,
        Attestation::Confirmed
    );
}

#[test]
fn a_forged_number_still_reaches_divergent() {
    // The detector is not disabled. One churn count is edited and re-sealed —
    // exactly what a self-report that wanted a friendlier number would do — and
    // the compare catches it.
    let repo = fixture("forged");
    let mut forged = measured_results(&repo, false);
    let target = forged
        .iter_mut()
        .find(|r| r.metric_id == METRIC_CHURN_COMMITS)
        .expect("the fixture produces churn results");
    target.value = MetricValue::Count(0);
    target
        .seal(&sample_compare_context())
        .expect("re-sealing the forged value");

    let agent = record(RecordKind::SelfReport, forged);
    let verifier = record(RecordKind::Attestation, measured_results(&repo, false));
    let classification = classify(Some(&agent), &verifier, equal_tuple());
    assert_eq!(classification.attestation, Attestation::Divergent);
    assert_eq!(
        classification
            .compare
            .expect("a compare was attempted")
            .mismatched,
        vec![METRIC_CHURN_COMMITS.to_string()]
    );
}
