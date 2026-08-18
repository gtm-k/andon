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
    // Asserted on the structure the substitution has, not on its wording. The
    // headline is prose that improves — it did, once, to stop claiming a clean
    // tree over a dirty one — and a test that pinned the sentence would have
    // reddened on the fix rather than on a regression.
    assert!(
        rendered.contains("asked for") && rendered.contains("measured"),
        "the terminal render does not announce what was asked for and what was measured \
         instead:\n{rendered}"
    );
    assert!(
        rendered.contains("last merged change"),
        "the terminal render does not say what was measured instead:\n{rendered}"
    );
    assert!(
        rendered.contains("working change"),
        "the terminal render does not say the numbers are not about the working \
         change:\n{rendered}"
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
fn two_measurements_racing_in_one_checkout_both_produce_a_record() {
    // Not an exotic case. P6's whole point is a gate-shaped hook, so a hook
    // firing while an agent measures — or a person running the command beside
    // their editor, or two worktrees on one git directory — is the arrangement
    // the design creates on purpose.
    //
    // This found two real defects, and it is here so they cannot come back. A
    // busy clone-index lock removed the entire clone family from the payload and
    // dropped record completeness to `partial` because a *cache* was in use; and
    // both writers used one fixed temporary filename for the saved record, so on
    // Windows the second rename failed and took the whole measurement with it.
    // Both presented as an intermittent test failure, which is the shape a
    // concurrency defect wears until somebody looks.
    let repo = stranger_repo();
    let path = repo.path().to_str().expect("utf-8").to_string();

    let spawn = || {
        Command::new(EXE)
            .args(["measure", "--repo", &path, "--json", "--exit-zero"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("andon starts")
    };
    let first = spawn();
    let second = spawn();
    let outputs = [
        first.wait_with_output().expect("andon finishes"),
        second.wait_with_output().expect("andon finishes"),
    ];

    for (n, output) in outputs.iter().enumerate() {
        let record: MeasurementRecord =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
                panic!(
                    "racing measurement {n} produced no usable record: {e}\nstderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        let engines: std::collections::BTreeSet<&str> = record
            .results
            .iter()
            .map(|r| r.engine_id.as_str())
            .collect();
        assert_eq!(
            engines.len(),
            5,
            "racing measurement {n} lost an engine to contention over derived state: {engines:?}"
        );
    }
}

#[test]
fn a_verification_reads_the_loop_counter_and_does_not_take_a_turn() {
    // The counter counts one thing: how many passes an agent has made at this
    // change. `attest-stub` recomputes the same change from outside that loop,
    // and it used to advance the counter on the way through — so a verifier
    // sharing a checkout with an agent inflated the agent's number, and enough
    // verifications pushed the agent's next measurement into
    // `escalate_to_human` for work the agent never did.
    // The gamed fixture, deliberately: the counter advances only on a run with
    // something an agent could act on, so the honest case correctly leaves it at
    // zero and would make this assertion vacuous.
    let dir = common::golden_root().join("gamed-change");
    let repo = common::build(&dir, &common::read_case(&dir));
    let path = repo.path().to_str().expect("utf-8").to_string();

    // Three measurements, so the counter holds a number worth preserving.
    for _ in 0..3 {
        let _ = run(&[
            "measure",
            "--repo",
            &path,
            "--base",
            &repo.base_oid,
            "--head",
            &repo.head_oid,
            "--json",
            "--exit-zero",
        ]);
    }
    let before = loop_state(repo.path());
    assert!(
        before.values().any(|count| *count > 0),
        "the counter never advanced, so this assertion would be vacuous: {before:?}"
    );

    let output = run(&[
        "attest-stub",
        "--repo",
        &path,
        "--head",
        &repo.head_oid,
        "--trusted-branch",
        "main",
    ]);
    assert!(
        output.status.success(),
        "attest-stub failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        before,
        loop_state(repo.path()),
        "a verification moved the agent's loop counter"
    );
}

/// The per-branch counts, read from the tool's own state file.
fn loop_state(repo: &Path) -> std::collections::BTreeMap<String, u32> {
    let git = Git::open(repo).expect("a repository");
    let path = git
        .facts()
        .git_dir
        .join("andon")
        .join("iteration-state.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Default::default();
    };
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid state");
    value["branches"]
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0) as u32))
                .collect()
        })
        .unwrap_or_default()
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

/// A repository with a change written and not committed — the state an agent is
/// in for most of its loop.
fn dirty_repo() -> common::Built {
    let repo = stranger_repo();
    std::fs::write(
        repo.path().join("src").join("greet.ts"),
        b"export function greet(n: string): string {\n  return n;\n}\n",
    )
    .expect("write");
    repo
}

#[test]
fn uncommitted_work_is_refused_and_never_reported_as_a_pass() {
    // The worst available answer, and the one this replaced: measure the last
    // merged change instead, print PASS, exit 0. The caller reads a verdict
    // about bytes that are not the ones they asked about, and a hook keyed on
    // the exit code lets the change through.
    //
    // The capability itself is blocked upstream — `andon_core::git::resolve`
    // refuses to build a `CompareContext` from a dirty endpoint, and every
    // result is sealed against one — so the honest answer available to this
    // crate is a refusal that names the limitation.
    let repo = dirty_repo();
    let output = run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(1),
        "uncommitted work must not produce a verdict exit code; a hook cannot tell a verdict \
         about other bytes from a verdict about these ones.\nstdout: {}\nstderr: {stderr}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("PASS"),
        "a pass was reported over unmeasured uncommitted work"
    );
    // The refusal names what it is about, and what actually works.
    assert!(stderr.contains("src/greet.ts"), "{stderr}");
    assert!(stderr.contains("commit the change"), "{stderr}");
    assert!(stderr.contains("--last-merged"), "{stderr}");
    // And it does not send the reader down a path that cannot work: staging
    // leaves an index endpoint, which is dirty too and errors identically.
    assert!(
        !stderr.contains("git add"),
        "the refusal suggests staging, which does not help: {stderr}"
    );
}

#[test]
fn staging_the_change_does_not_turn_the_refusal_into_a_measurement() {
    // Pinned because it is the first thing a reader tries, and because a future
    // edit reaching for `Revision::Index` would look like it worked — an index
    // endpoint is a dirty endpoint and `compare_context` refuses it the same way.
    let repo = dirty_repo();
    let git = Git::open(repo.path()).expect("a repository");
    git.cmd(["add", "--all", "."]).output().expect("git add");
    let output = run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Staging does not change this"));
}

#[test]
fn the_opt_in_fallback_says_the_tree_is_dirty_rather_than_claiming_it_is_clean() {
    // `--last-merged` is how a caller says they meant the last merged change.
    // What it must not do is repeat the sentence the clean path uses: "nothing
    // is in flight in this checkout" is false here, and it is false about the
    // one thing the reader can check in a single command.
    let repo = dirty_repo();
    let rendered = stdout(&run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
        "--last-merged",
        "--exit-zero",
    ]));
    assert!(
        !rendered.contains("nothing is in flight"),
        "the report asserts a clean tree over a dirty one:\n{rendered}"
    );
    assert!(rendered.contains("there IS uncommitted work"), "{rendered}");
    assert!(rendered.contains("src/greet.ts"), "{rendered}");
}

#[test]
fn a_clean_checkout_still_falls_back_and_still_says_the_tree_was_clean() {
    // The other half of the same rule, and PREMORTEM A1's path: the refusal must
    // not have swallowed the first-run experience. A clean tree falls back, and
    // the sentence it prints is true.
    let repo = stranger_repo();
    let rendered = stdout(&run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
    ]));
    assert!(rendered.contains("nothing is in flight"), "{rendered}");
    assert!(
        !rendered.contains("there IS uncommitted work"),
        "{rendered}"
    );
}

#[test]
fn the_agent_profile_is_bounded_by_the_policy_the_repository_declares() {
    // PREMORTEM A2: a payload that blows an agent's context is one way to earn
    // "installed and never invoked". The bounded projection has existed in
    // `andon-core` since P0 and nothing called it, so the only machine-readable
    // surface was the full record — measured at 572 KB on this repository,
    // against a declared budget of 6000 bytes.
    let repo = stranger_repo();
    let path = repo.path().to_str().expect("utf-8").to_string();

    let full = run(&["measure", "--repo", &path, "--json", "--exit-zero"]);
    let profile = run(&[
        "measure",
        "--repo",
        &path,
        "--profile",
        "agent-mode",
        "--exit-zero",
    ]);
    assert!(
        profile.status.success(),
        "{}",
        String::from_utf8_lossy(&profile.stderr)
    );

    let policy = andon_core::policy::Policy::default();
    let budget = (policy.agent.profile_token_budget * policy.agent.bytes_per_token) as usize;
    let view: serde_json::Value =
        serde_json::from_slice(&profile.stdout).expect("the profile is JSON");

    // The bound, read from policy rather than restated as a number here.
    assert!(
        profile.stdout.len() <= budget + 1,
        "the agent profile is {} bytes against a declared budget of {budget}",
        profile.stdout.len()
    );
    assert!(
        profile.stdout.len() < full.stdout.len(),
        "the profile is not smaller than the record it projects"
    );
    assert_eq!(view["profile"], "agent-mode");
    // A projection that dropped findings says so; one that did not must not
    // claim it did.
    let shown = view["findings"].as_array().expect("findings").len();
    let total = view["total_findings"].as_u64().expect("a total") as usize;
    assert_eq!(
        view["truncated"].as_bool().expect("a flag"),
        shown < total,
        "the truncation flag disagrees with what was kept ({shown} of {total})"
    );
    // Evidence is referenced, not inlined: the repetition that made the full
    // record large is exactly what this view removes.
    for finding in view["findings"].as_array().expect("findings") {
        assert!(finding["claim_id"].is_string());
        assert!(
            finding.get("does_not_predict").is_none(),
            "the profile inlines the evidence block it exists to reference"
        );
    }
}

#[test]
fn an_unknown_profile_name_is_refused_rather_than_ignored() {
    let repo = stranger_repo();
    let output = run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--profile",
        "small",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("agent-mode"));
}

#[test]
fn uncommitted_work_is_disclosed_even_when_committed_changes_were_measured() {
    // The narrower version of the same gap, and the one that survives the
    // refusal: on a branch with commits ahead of its fork point, those commits
    // are measured — correctly — and an agent that has since edited the tree has
    // work these numbers do not describe. The refusal never fires here, because
    // there *was* something to measure. Silence would leave the reader unable to
    // see the one fact that changes how they read the verdict.
    let repo = stranger_repo();
    let git = Git::open(repo.path()).expect("a repository");
    // A branch point, so the ladder finds committed work ahead of it.
    git.cmd(["branch", "base-point", &repo.base_oid])
        .output()
        .expect("branch");
    std::fs::write(
        repo.path().join("src").join("late.ts"),
        b"export const late = 1;
",
    )
    .expect("write");

    let rendered = stdout(&run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--base",
        &repo.base_oid,
        "--no-color",
        "--exit-zero",
    ]));
    assert!(
        rendered.contains("uncommitted content"),
        "a measurement of committed work said nothing about the uncommitted work beside          it:
{rendered}"
    );
    assert!(rendered.contains("src/late.ts"), "{rendered}");
}
