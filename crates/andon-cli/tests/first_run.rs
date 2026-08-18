//! The stranger's first command.
//!
//! # The failure this file exists to prevent
//!
//! PREMORTEM A1, rated **fatal**: *"the stranger's very first command on a clean
//! checkout returned nothing (base == head → empty diff → empty report)"*. It is
//! an acceptance criterion of this phase and not a nicety, because the person
//! who hits it is the person deciding whether to keep the tool.
//!
//! Prose cannot hold that. What holds it is a test that runs the real binary
//! against a repository built the way a stranger's is — no `origin`, no branch
//! called `main` on a remote, nothing in flight — and asserts that what comes
//! back is non-empty, carries evidence, and **says** it is the last merged change
//! rather than quietly substituting one.
//!
//! Every test here drives `andon` as a subprocess. A library-level test would
//! leave the wiring between `main` and the pipeline unexercised, and the wiring
//! is where a first-run path breaks.

mod common;

use std::path::Path;
use std::process::Command;

use andon_core::git::Git;
use andon_core::schema::payload::MeasurementRecord;

const EXE: &str = env!("CARGO_BIN_EXE_andon");

/// A repository like the one a stranger clones: history, no remote, clean tree.
fn stranger_repo() -> common::Built {
    let dir = common::golden_root().join("honest-change");
    let case = common::read_case(&dir);
    common::build(&dir, &case)
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(EXE).args(args).output().expect("andon runs")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn measure_json(repo: &Path, extra: &[&str]) -> (MeasurementRecord, std::process::Output) {
    let mut args = vec!["measure", "--repo", repo.to_str().expect("utf-8"), "--json"];
    args.extend_from_slice(extra);
    let output = run(&args);
    let record: MeasurementRecord = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}\nstdout: {}\nstderr: {}",
            stdout(&output),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (record, output)
}

#[test]
fn the_first_command_on_a_clean_checkout_returns_a_real_measurement() {
    // The A1 case itself. No arguments beyond the repository: no base, no head,
    // no configuration, nothing in flight.
    let repo = stranger_repo();
    let (record, _) = measure_json(repo.path(), &[]);

    assert!(
        !record.results.is_empty(),
        "the first command produced an empty record, which is PREMORTEM A1"
    );
    let engines: std::collections::BTreeSet<&str> = record
        .results
        .iter()
        .map(|r| r.engine_id.as_str())
        .collect();
    assert_eq!(
        engines.len(),
        5,
        "a first measurement that ran fewer than every shipped engine: {engines:?}"
    );
    assert_ne!(
        record.compare_context.base_oid, record.compare_context.head_oid,
        "base == head is the empty-diff shape A1 describes"
    );
    // Evidence-carrying, which is the other half of the criterion: a non-empty
    // report of bare numbers would satisfy "non-empty" and fail the product.
    for result in &record.results {
        assert!(
            !result.evidence.claim_id.is_empty(),
            "{} reached a record with no claim behind it",
            result.metric_id
        );
        assert!(
            !result.evidence.does_not_predict.is_empty(),
            "{} carries no statement of what it does not predict",
            result.metric_id
        );
    }
}

#[test]
fn the_substitution_is_announced_in_the_record_and_in_the_render() {
    // Silently measuring something other than what was asked for is worse than
    // returning nothing: the reader believes the numbers describe their working
    // change. So the substitution has to survive being serialized, not merely be
    // printed once.
    let repo = stranger_repo();
    let (record, _) = measure_json(repo.path(), &[]);
    assert_eq!(
        record.compare_context.base_resolution, "no-diff-fallback:last-merged-change",
        "the record does not say the base was substituted"
    );

    let rendered = stdout(&run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
    ]));
    assert!(
        rendered.contains("not your working change"),
        "the terminal render does not announce the substitution:\n{rendered}"
    );
    assert!(
        rendered.contains("last merged change"),
        "the terminal render does not say what was measured instead:\n{rendered}"
    );
}

#[test]
fn the_html_report_announces_the_substitution_too() {
    // A report is the artefact that outlives the terminal. It is read by
    // somebody who never saw the command, so it carries the caveat or the caveat
    // does not exist for them.
    let repo = stranger_repo();
    let out = repo.path().join("report.html");
    let output = run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
        "--html",
        out.to_str().expect("utf-8"),
    ]);
    assert!(out.exists(), "no report written: {output:?}");
    let html = std::fs::read_to_string(&out).expect("the report reads back");
    assert!(
        html.contains("This is not your working change"),
        "{html:.400}"
    );
    assert!(html.contains("<!doctype html>"));
    // Self-contained: a report that fetches anything is a report that renders as
    // unstyled text on the machine it matters on.
    for external in ["http://", "https://", "<script", "<link", "@import", "url("] {
        assert!(
            !html.contains(external),
            "the report reaches outside itself via `{external}`"
        );
    }
}

#[test]
fn refusing_the_fallback_is_a_legible_refusal_rather_than_an_empty_report() {
    // The other honest answer. A caller who does not want a substitution gets a
    // refusal that names the situation — never a report of nothing dressed as a
    // measurement.
    let repo = stranger_repo();
    let output = run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-fallback",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no earlier state") || stderr.contains("single commit"),
        "{stderr}"
    );
}

#[test]
fn a_repository_with_one_commit_refuses_and_says_what_to_do() {
    // The one honest dead end: nothing to compare against, and no arrangement of
    // arguments that invents one. The refusal has to name the situation and the
    // way out, because the person reading it has run one command and has no
    // model of the tool yet.
    let temp = tempfile::tempdir().expect("a temporary directory");
    let bootstrap = Git::open(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("a repository");
    bootstrap
        .cmd([
            "init",
            "--quiet",
            "--initial-branch=main",
            "--object-format=sha1",
        ])
        .arg(temp.path())
        .output()
        .expect("git init");
    let git = Git::open(temp.path()).expect("the fixture is a repository");
    git.cmd(["config", "user.name", common::FIXTURE_NAME])
        .output()
        .expect("config");
    git.cmd(["config", "user.email", common::FIXTURE_EMAIL])
        .output()
        .expect("config");
    std::fs::write(temp.path().join("a.ts"), b"export const a = 1;\n").expect("write");
    git.cmd(["add", "--all", "."]).output().expect("add");
    git.cmd(["commit", "--quiet", "-m", "root"])
        .env("GIT_AUTHOR_NAME", common::FIXTURE_NAME)
        .env("GIT_AUTHOR_EMAIL", common::FIXTURE_EMAIL)
        .env("GIT_AUTHOR_DATE", common::FIXTURE_DATE)
        .env("GIT_COMMITTER_NAME", common::FIXTURE_NAME)
        .env("GIT_COMMITTER_EMAIL", common::FIXTURE_EMAIL)
        .env("GIT_COMMITTER_DATE", common::FIXTURE_DATE)
        .output()
        .expect("commit");

    let output = run(&["measure", "--repo", temp.path().to_str().expect("utf-8")]);
    assert!(
        !output.status.success(),
        "a root commit measured against what?"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("single commit"), "{stderr}");
    assert!(
        stderr.contains("--base"),
        "the refusal does not say how to proceed:\n{stderr}"
    );
}

#[test]
fn the_exit_code_carries_the_verdict() {
    // A gate that cannot tell "Andon found something" from "Andon fell over" is
    // a gate whose red check means nothing, and a red check that means nothing
    // gets turned off.
    let honest = common::golden_root().join("honest-change");
    let gamed = common::golden_root().join("gamed-change");
    let honest_repo = common::build(&honest, &common::read_case(&honest));
    let gamed_repo = common::build(&gamed, &common::read_case(&gamed));

    let pass = run(&[
        "measure",
        "--repo",
        honest_repo.path().to_str().expect("utf-8"),
        "--base",
        &honest_repo.base_oid,
        "--head",
        &honest_repo.head_oid,
        "--no-color",
    ]);
    assert_eq!(pass.status.code(), Some(0), "an honest change exits 0");

    let block = run(&[
        "measure",
        "--repo",
        gamed_repo.path().to_str().expect("utf-8"),
        "--base",
        &gamed_repo.base_oid,
        "--head",
        &gamed_repo.head_oid,
        "--no-color",
    ]);
    assert_eq!(
        block.status.code(),
        Some(2),
        "a blocking verdict must not share an exit code with a tool failure"
    );

    // And the escape hatch for a caller who wants the report without the gate.
    let quiet = run(&[
        "measure",
        "--repo",
        gamed_repo.path().to_str().expect("utf-8"),
        "--base",
        &gamed_repo.base_oid,
        "--head",
        &gamed_repo.head_oid,
        "--no-color",
        "--exit-zero",
    ]);
    assert_eq!(quiet.status.code(), Some(0));

    // A tool failure is 1, and distinct from both.
    let broken = run(&["measure", "--repo", "/no/such/repository/anywhere"]);
    assert_eq!(broken.status.code(), Some(1));
}

#[test]
fn an_absence_is_never_rendered_as_a_zero() {
    // The product's own rule, checked over a real render rather than asserted in
    // a doc comment. Every result the engines could not witness carries its
    // reason string, and that string reaches the reader.
    let repo = stranger_repo();
    let rendered = stdout(&run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
        "--full",
    ]));
    let (record, _) = measure_json(repo.path(), &[]);
    let absences: Vec<&_> = record
        .results
        .iter()
        .filter(|r| r.completeness == andon_core::schema::enums::Completeness::Unwitnessed)
        .collect();
    assert!(
        !absences.is_empty(),
        "this fixture has no absence to check; the assertion would be vacuous"
    );
    assert!(rendered.contains("NOT MEASURED"), "{rendered}");
    for result in absences {
        if let andon_core::schema::payload::MetricValue::Text(reason) = &result.value {
            assert!(
                rendered.contains(reason.as_str()),
                "the reason for {} never reached the reader: {reason}",
                result.metric_id
            );
        }
    }
}

#[test]
fn nothing_the_tool_prints_is_a_composite_score() {
    // Non-goal 1, and the hardest thing to hold in a report: a header figure is
    // the single most tempting thing to add. This is a smoke test, not a proof —
    // it catches the vocabulary, and review catches the rest.
    let repo = stranger_repo();
    let out = repo.path().join("report.html");
    let rendered = stdout(&run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
        "--full",
        "--html",
        out.to_str().expect("utf-8"),
    ]));
    let html = std::fs::read_to_string(&out).expect("the report reads back");
    for banned in ["health score", "quality score", "overall score", "grade:"] {
        assert!(!rendered.to_lowercase().contains(banned), "{banned}");
        assert!(!html.to_lowercase().contains(banned), "{banned}");
    }
    // And the report says so out loud, where a reader would go looking for one.
    assert!(html.contains("there is no score in this tool"));
}

#[test]
fn explain_works_before_any_measurement_has_been_taken() {
    // The evidence surface cannot depend on a record: a reader evaluating the
    // tool asks "what does this number mean" before they have run it on
    // anything, and an answer of "measure something first" is the tool refusing
    // to state its own claims.
    let temp = tempfile::tempdir().expect("a temporary directory");
    let output = run(&[
        "explain",
        "static.sloc",
        "--repo",
        temp.path().to_str().expect("utf-8"),
    ]);
    let text = stdout(&output);
    assert!(output.status.success(), "{output:?}");
    assert!(text.contains("does NOT tell you"), "{text}");
    assert!(text.contains("tier"), "{text}");
}

#[test]
fn report_before_measure_says_what_to_run() {
    let repo = stranger_repo();
    let output = run(&["report", "--repo", repo.path().to_str().expect("utf-8")]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("andon measure"), "{stderr}");
}

#[test]
fn the_tool_writes_nothing_into_the_working_tree() {
    // A tool invited to look at somebody's repository does not leave state in
    // it. Everything goes under the git directory, which is ignored by
    // construction and goes away with the clone.
    let repo = stranger_repo();
    let before = tracked_status(repo.path());
    let _ = run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
    ]);
    let after = tracked_status(repo.path());
    assert_eq!(before, after, "the measurement dirtied the working tree");
}

fn tracked_status(repo: &Path) -> String {
    let git = Git::open(repo).expect("a repository");
    git.cmd(["status", "--porcelain"])
        .text()
        .expect("git status")
}
