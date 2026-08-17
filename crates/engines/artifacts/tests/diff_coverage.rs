//! The artifacts engine against a real repository and a real report.
//!
//! The unit tests cover the two parsers and the hunk reader in isolation. What
//! is proved here is the attribution: that the lines a change touched, the lines
//! a coverage tool reported, and the gap between them line up on real `git diff`
//! output — and that every way of having no answer produces an absence rather
//! than a zero.

use std::path::{Path, PathBuf};

use andon_core::engine::{run_engine, MeasureContext, MeasureEngine};
use andon_core::git::{ChangedSet, Git, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_core::registry::Registry;
use andon_core::schema::enums::{Completeness, EngineFamily};
use andon_core::schema::payload::{MeasurementResult, MetricValue, ScopeKind};
use andon_engine_artifacts::engine::*;
use andon_engine_artifacts::report::CoverageReport;

/// A repository with one file, changed once. Lines 4 and 5 are the change.
struct Fixture {
    path: PathBuf,
    git: Git,
    base: String,
    head: String,
}

fn fixture(name: &str) -> Fixture {
    let path = std::env::temp_dir().join(format!(
        "andon-p4-artifacts-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("fixture directory");

    let bootstrap = Git::open(Path::new(".")).expect("the workspace is a git repository");
    bootstrap
        .cmd(["init", "--quiet", "--initial-branch=main"])
        .arg(&path)
        .output()
        .expect("git init");
    let git = Git::open(&path).expect("a repository");
    git.cmd(["config", "user.name", "Fixture"])
        .output()
        .expect("name");
    git.cmd(["config", "user.email", "f@andon.invalid"])
        .output()
        .expect("email");

    let commit = |message: &str| -> String {
        git.cmd(["add", "--all", "."]).output().expect("add");
        git.cmd(["commit", "--quiet", "-m", message])
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "f@andon.invalid")
            .env("GIT_AUTHOR_DATE", "1735689600 +0000")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "f@andon.invalid")
            .env("GIT_COMMITTER_DATE", "1735689600 +0000")
            .output()
            .expect("commit");
        git.cmd(["rev-parse", "HEAD"])
            .text()
            .expect("rev-parse")
            .trim()
            .to_string()
    };

    std::fs::create_dir_all(path.join("src")).expect("src");
    std::fs::write(path.join("src/a.ts"), b"one\ntwo\nthree\n").expect("write");
    let base = commit("base");
    std::fs::write(path.join("src/a.ts"), b"one\ntwo\nthree\nfour\nfive\n").expect("write");
    let head = commit("head");

    Fixture {
        path: git.workdir().to_path_buf(),
        git,
        base,
        head,
    }
}

fn measure(fixture: &Fixture, reports: &[CoverageReport]) -> Vec<MeasurementResult> {
    let range = ResolvedRange::resolve(
        &fixture.git,
        &Revision::Rev(fixture.base.clone()),
        &Revision::Rev(fixture.head.clone()),
    )
    .expect("both endpoints are commits");
    let changed = ChangedSet::enumerate(&fixture.git, &range).expect("enumerating");
    let engine = ArtifactsEngine::for_change(&fixture.git, &range, &changed, reports)
        .expect("the hunk diff runs");
    let ctx = MeasureContext {
        compare_context: range.compare_context().expect("a commit range"),
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox_available: false,
    };
    run_engine(&engine, &ctx).expect("the engine measures")
}

#[test]
fn only_the_changed_lines_a_report_calls_unexecuted_are_counted() {
    let fixture = fixture("gap");
    // Line 4 was added and never executed; line 5 was added and executed; line 1
    // is untouched by the change and uncovered, which must not be counted.
    let lcov = "SF:src/a.ts\nDA:1,0\nDA:4,0\nDA:5,2\nend_of_record\n";
    let report = CoverageReport::parse("lcov.info", lcov.as_bytes()).expect("parses");

    let results = measure(&fixture, &[report]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].completeness, Completeness::Complete);
    assert_eq!(
        results[0].value,
        MetricValue::Count(1),
        "one changed line is uncovered; the uncovered untouched line is not this \
         change's business"
    );
}

#[test]
fn a_changed_line_the_report_never_mentions_is_not_a_gap() {
    // Coverage tools omit blank lines, comments, and declarations. Counting
    // those as uncovered would make every reformat look like a testing failure.
    let fixture = fixture("unmentioned");
    let lcov = "SF:src/a.ts\nDA:1,1\nend_of_record\n";
    let report = CoverageReport::parse("lcov.info", lcov.as_bytes()).expect("parses");
    let results = measure(&fixture, &[report]);
    assert_eq!(results[0].value, MetricValue::Count(0));
}

#[test]
fn no_report_at_all_is_one_change_scoped_absence() {
    let fixture = fixture("no-report");
    let results = measure(&fixture, &[]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].scope.kind, ScopeKind::Change);
    assert_eq!(results[0].completeness, Completeness::Unwitnessed);
    assert_eq!(
        results[0].value,
        MetricValue::Text(REASON_NO_REPORT.to_string())
    );
}

#[test]
fn a_file_outside_the_report_is_an_absence_and_not_a_zero() {
    let fixture = fixture("not-in-report");
    let lcov = "SF:src/elsewhere.ts\nDA:1,1\nend_of_record\n";
    let report = CoverageReport::parse("lcov.info", lcov.as_bytes()).expect("parses");
    let results = measure(&fixture, &[report]);
    assert_eq!(results[0].completeness, Completeness::Unwitnessed);
    assert_eq!(
        results[0].value,
        MetricValue::Text(REASON_NOT_IN_REPORT.to_string()),
        "a file the report does not cover has no coverage figure, and zero gaps \
         would read as fully covered"
    );
}

#[test]
fn a_degraded_report_says_so_on_every_result_it_produced() {
    let fixture = fixture("degraded");
    // A `DA` record before any `SF` — the document parses, and part of it was
    // skipped.
    let lcov = "DA:9,0\nSF:src/a.ts\nDA:4,0\nend_of_record\n";
    let report = CoverageReport::parse("lcov.info", lcov.as_bytes()).expect("parses");
    assert!(report.degraded);
    let results = measure(&fixture, &[report]);
    assert_eq!(results[0].completeness, Completeness::ParseDegraded);
    assert_eq!(results[0].value, MetricValue::Count(1));
}

#[test]
fn a_cobertura_report_produces_the_same_finding_as_an_lcov_one() {
    let fixture = fixture("cobertura");
    let xml = r#"<coverage><packages><package><classes>
        <class filename="src/a.ts"><lines>
          <line number="4" hits="0"/>
          <line number="5" hits="1"/>
        </lines></class>
      </classes></package></packages></coverage>"#;
    let report = CoverageReport::parse("coverage.xml", xml.as_bytes()).expect("parses");
    let results = measure(&fixture, &[report]);
    assert_eq!(results[0].value, MetricValue::Count(1));
}

#[test]
fn discovery_reads_a_report_from_a_known_path_and_nowhere_else() {
    let fixture = fixture("discovery");
    std::fs::write(
        fixture.path.join("lcov.info"),
        "SF:src/a.ts\nDA:4,0\nend_of_record\n",
    )
    .expect("write report");
    // A report somewhere the candidate list does not name must not be picked up:
    // a walk would find fixtures and vendored trees and attach a stranger's
    // numbers to this change.
    std::fs::create_dir_all(fixture.path.join("vendor/other")).expect("dir");
    std::fs::write(
        fixture.path.join("vendor/other/lcov.info"),
        "SF:src/a.ts\nDA:5,0\nend_of_record\n",
    )
    .expect("write decoy");

    let discovery = discover(&fixture.path);
    assert_eq!(discovery.reports.len(), 1);
    assert!(discovery.problems.is_empty());

    let results = measure(&fixture, &discovery.reports);
    assert_eq!(results[0].value, MetricValue::Count(1));
}

#[test]
fn a_malformed_report_is_carried_as_a_problem_rather_than_dropped() {
    // Present and unreadable is a different situation from absent, and an
    // operator who cannot tell them apart cannot fix either.
    let fixture = fixture("malformed");
    std::fs::write(fixture.path.join("coverage.xml"), b"<coverage><classes>")
        .expect("write report");
    let discovery = discover(&fixture.path);
    assert!(discovery.reports.is_empty());
    assert_eq!(discovery.problems.len(), 1);
}

#[test]
fn every_result_is_excluded_from_the_digest_compare_set() {
    // The property that makes the whole family safe to have: a coverage report
    // is an untracked build output, so no verifier can reproduce one and none of
    // these numbers may be digest-compared.
    let fixture = fixture("deterministic-flag");
    let lcov = "SF:src/a.ts\nDA:4,0\nend_of_record\n";
    let report = CoverageReport::parse("lcov.info", lcov.as_bytes()).expect("parses");
    for result in measure(&fixture, &[report]) {
        assert!(
            !result.deterministic,
            "{} must not be compared",
            result.metric_id
        );
        assert_eq!(result.family, EngineFamily::Artifacts);
    }
}

#[test]
fn the_engine_and_its_registry_file_do_not_drift() {
    let engine = ArtifactsEngine::from_lines(
        &Default::default(),
        &ChangedSet {
            entries: Vec::new(),
        },
        &[],
    );
    Registry::check_engine(
        registry_file().expect("the compiled registry parses"),
        &engine,
    )
    .unwrap_or_else(|problems| panic!("registry drift: {problems:#?}"));
    assert_eq!(engine.descriptor().family, EngineFamily::Artifacts);
}

#[test]
fn the_regime_lists_every_parser_this_build_carries() {
    // A regime that varied with the input would make two runs of one binary look
    // like two binaries.
    let engine = ArtifactsEngine::from_lines(
        &Default::default(),
        &ChangedSet {
            entries: Vec::new(),
        },
        &[],
    );
    match engine.regime() {
        andon_core::schema::regime::MeasurementRegime::Artifacts {
            parser_versions, ..
        } => {
            assert_eq!(parser_versions.len(), 3);
            for format in ["lcov", "cobertura", "coverage.py-xml"] {
                assert!(parser_versions.contains_key(format), "{format} is missing");
            }
        }
        other => panic!("the artifacts engine must report an artifacts regime, got {other:?}"),
    }
}

#[test]
fn a_report_that_exists_and_cannot_be_read_says_so_rather_than_saying_nothing() {
    // "You have no coverage report" and "your coverage.xml is malformed" ask
    // different things of whoever reads the payload, and only one of them is
    // something they can act on. `discover` carries its failures; this is the
    // constructor that puts them where an actor can see them.
    let fixture = fixture("unreadable-surfaced");
    std::fs::write(fixture.path.join("coverage.xml"), b"<coverage><classes>")
        .expect("write report");
    let discovery = discover(&fixture.path);
    assert!(discovery.reports.is_empty());
    assert_eq!(discovery.problems.len(), 1);

    let range = ResolvedRange::resolve(
        &fixture.git,
        &Revision::Rev(fixture.base.clone()),
        &Revision::Rev(fixture.head.clone()),
    )
    .expect("both endpoints are commits");
    let changed = ChangedSet::enumerate(&fixture.git, &range).expect("enumerating");
    let engine = ArtifactsEngine::for_discovery(&fixture.git, &range, &changed, &discovery)
        .expect("the hunk diff runs");
    let ctx = MeasureContext {
        compare_context: range.compare_context().expect("a commit range"),
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox_available: false,
    };
    let results = run_engine(&engine, &ctx).expect("the engine measures");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].completeness, Completeness::Unwitnessed);
    assert_eq!(
        results[0].value,
        MetricValue::Text(REASON_REPORT_UNREADABLE.to_string()),
        "a broken report must not be reported as an absent one"
    );
}

#[test]
fn every_unwitnessed_value_comes_from_the_closed_reason_set() {
    let fixture = fixture("closed-reasons");
    let lcov = "SF:src/elsewhere.ts\nDA:1,1\nend_of_record\n";
    let report = CoverageReport::parse("lcov.info", lcov.as_bytes()).expect("parses");
    let mut seen = 0;
    for results in [measure(&fixture, &[]), measure(&fixture, &[report])] {
        for result in results {
            if result.completeness != Completeness::Unwitnessed {
                continue;
            }
            seen += 1;
            match &result.value {
                MetricValue::Text(reason) => assert!(
                    UNWITNESSED_REASONS.contains(&reason.as_str()),
                    "unwitnessed reasons must come from the closed set, got {reason:?}"
                ),
                other => panic!("an unwitnessed result carried a number: {other:?}"),
            }
        }
    }
    assert!(seen >= 2, "the fixture must produce unwitnessed results");
}

#[test]
fn a_broken_report_beside_a_working_one_is_still_reported() {
    // The case that was invisible: `lcov.info` answers the question, so the
    // engine had a report and said nothing about the `coverage.xml` it could not
    // read. Somebody's coverage step is failing, and the working file next to it
    // is exactly what keeps that quiet.
    let fixture = fixture("broken-beside-working");
    std::fs::write(
        fixture.path.join("lcov.info"),
        "SF:src/a.ts\nDA:4,0\nend_of_record\n",
    )
    .expect("write good report");
    std::fs::write(fixture.path.join("coverage.xml"), b"<coverage><classes>")
        .expect("write broken report");

    let discovery = discover(&fixture.path);
    assert_eq!(discovery.reports.len(), 1, "the good report was read");
    assert_eq!(discovery.problems.len(), 1, "the broken one was refused");

    let range = ResolvedRange::resolve(
        &fixture.git,
        &Revision::Rev(fixture.base.clone()),
        &Revision::Rev(fixture.head.clone()),
    )
    .expect("both endpoints are commits");
    let changed = ChangedSet::enumerate(&fixture.git, &range).expect("enumerating");
    let engine = ArtifactsEngine::for_discovery(&fixture.git, &range, &changed, &discovery)
        .expect("the hunk diff runs");
    let ctx = MeasureContext {
        compare_context: range.compare_context().expect("a commit range"),
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox_available: false,
    };
    let results = run_engine(&engine, &ctx).expect("the engine measures");

    // The real finding from the readable report survives.
    let gap = results
        .iter()
        .find(|r| r.scope.kind == ScopeKind::File)
        .expect("the working report still produced its finding");
    assert_eq!(gap.value, MetricValue::Count(1));

    // And the broken one is named, by path, in its own note.
    let note = results
        .iter()
        .find(|r| r.scope.kind == ScopeKind::Change)
        .expect("the broken report must be reported");
    assert_eq!(note.completeness, Completeness::Unwitnessed);
    assert_eq!(
        note.value,
        MetricValue::Text(REASON_REPORT_UNREADABLE.to_string())
    );
    assert_eq!(
        note.scope.path.as_deref(),
        Some("coverage.xml"),
        "an operator has to be told which file is broken"
    );

    // And "no coverage report found" is never said when one was found.
    assert!(!results
        .iter()
        .any(|r| r.value == MetricValue::Text(REASON_NO_REPORT.to_string())));
}
