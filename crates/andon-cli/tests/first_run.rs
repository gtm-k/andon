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
fn uncommitted_work_is_measured_rather_than_stepped_around() {
    // What this replaced, and why the replacement is the point.
    //
    // This test used to assert a *refusal*. That was the honest answer while the
    // schema had no way to say "measured against an uncommitted tree" — the
    // alternative on offer was measuring the last merged change and printing
    // PASS, which tells the caller a verdict about bytes that are not the ones
    // they asked about. The mini-G2 ruling took the other road: the schema grew
    // the representation, so the refusal is no longer the best available answer
    // and this asserts the capability instead.
    let repo = stranger_repo();
    // Deliberately NOT staged. Requiring `git add` before a tool will look at
    // your work makes being measured cost a mutation of state shared with
    // whoever else is in the repository.
    std::fs::write(repo.path().join("src").join("greet.ts"), COMPLEX_TS).expect("write");

    let output = run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
    ]);
    let rendered = stdout(&output);
    assert!(
        !rendered.contains("last merged change"),
        "uncommitted work was stepped around rather than measured:\n{rendered}"
    );
    assert!(
        rendered.contains("uncommitted working tree"),
        "the header does not say what was measured:\n{rendered}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "a complex function staged and uncommitted did not stop the line:\n{rendered}"
    );
}

#[test]
fn unstaged_bytes_are_read_without_touching_the_index() {
    // The residual this closed, and the reason it was worth closing rather than
    // disclosing. Engines read blobs, and an edit that exists only on disk has
    // none — so the honest interim behaviour was to say so and tell the caller
    // to `git add`. But the caller is usually an agent mid-loop, and `git add`
    // mutates state shared with the human beside it: being measured should not
    // cost you a staged change you did not ask for.
    //
    // `git hash-object -w` writes the identical object `git add` would write and
    // leaves the index alone. Verified here on both counts.
    let repo = stranger_repo();
    let git = Git::open(repo.path()).expect("a repository");
    std::fs::write(repo.path().join("src").join("greet.ts"), COMPLEX_TS).expect("write");

    let before = porcelain(&git);
    let output = run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
    ]);
    let rendered = stdout(&output);

    // Read, and acted on.
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unstaged complex function did not stop the line:\n{rendered}"
    );
    assert!(
        rendered.contains("static.cognitive-complexity"),
        "the unstaged bytes were not measured:\n{rendered}"
    );

    // The index is exactly where it was: the path is still unstaged, and
    // nothing is staged that was not staged before.
    assert_eq!(
        before,
        porcelain(&git),
        "measuring mutated the index; ` M` becoming `M ` is the change this avoids"
    );
    assert!(
        git.cmd(["diff", "--cached", "--name-only"])
            .text()
            .expect("git diff --cached")
            .trim()
            .is_empty(),
        "something was staged"
    );

    // And the side effect is disclosed rather than done quietly.
    assert!(
        rendered.contains("object database"),
        "writing objects into the caller's repository was not disclosed:\n{rendered}"
    );
}

/// `git status --porcelain`, for comparing index state before and after.
fn porcelain(git: &Git) -> String {
    git.cmd(["status", "--porcelain"])
        .text()
        .expect("git status")
}

#[test]
fn a_change_that_could_not_be_read_never_exits_clean() {
    // The fallback, and the rule behind it: the honest shape for an unmeasured
    // thing is not the shape of a clean measurement. An agent keys on the exit
    // code, so a caveat that lives only in prose is invisible to the actor who
    // needs it.
    //
    // Driven through a read-only object store, which is the real way this
    // happens — measuring a repository you do not own.
    let repo = stranger_repo();
    std::fs::write(repo.path().join("src").join("greet.ts"), COMPLEX_TS).expect("write");

    let objects = repo.path().join(".git").join("objects");
    let mut perms = std::fs::metadata(&objects)
        .expect("objects dir")
        .permissions();
    perms.set_readonly(true);
    if std::fs::set_permissions(&objects, perms).is_err() {
        eprintln!("skipped: cannot make the object store read-only here");
        return;
    }

    let output = run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
    ]);
    let rendered = stdout(&output);

    // Restore before asserting, so a failure does not leave an unremovable
    // temporary directory behind.
    let mut perms = std::fs::metadata(&objects)
        .expect("objects dir")
        .permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    let _ = std::fs::set_permissions(&objects, perms);

    if output.status.code() == Some(2) {
        // Windows honours the read-only bit on directories inconsistently; if
        // the write succeeded anyway the fallback was not exercised and there is
        // nothing here to assert.
        eprintln!("skipped: the object write succeeded despite the read-only bit");
        return;
    }
    assert_eq!(
        output.status.code(),
        Some(1),
        "a change that could not be read exited as though it had been \
         measured:\n{rendered}"
    );
    assert!(
        rendered.contains("could NOT be read"),
        "the unreadable paths were not named:\n{rendered}"
    );
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

    // `--head HEAD` pins a commit head, which is the case this note is for: the
    // caller asked about two commits, and their uncommitted edits are outside
    // the answer. Without it the head would be the working tree and the note
    // would be false — which is the whole reason it reads `head_kind`.
    let rendered = stdout(&run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--base",
        &repo.base_oid,
        "--head",
        "HEAD",
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

#[test]
fn a_measurement_of_uncommitted_work_reaches_a_verdict_end_to_end() {
    // THE POSITIVE CONTROL, in the shape P5a learned the hard way.
    //
    // Every other guard around this feature asserts a bad state is unreachable:
    // no synthesized tuple, no accusation, no false claim of a clean tree. A
    // suite made only of prohibitions passes most easily on a tool that does
    // nothing — which is how the MED+ dead band and the confirmation gate both
    // shipped behind hundreds of green tests. So this one asserts the good state
    // is reachable: a change written and staged but not committed is measured by
    // the real binary, on a real repository, and comes back with a verdict that
    // stops the line.
    let repo = stranger_repo();
    let git = Git::open(repo.path()).expect("a repository");
    // A function nobody could test in fifteen cases, written and staged and not
    // committed — the state an agent is in for most of its loop.
    std::fs::write(repo.path().join("src").join("classify.ts"), COMPLEX_TS).expect("write");
    git.cmd(["add", "--all", "."]).output().expect("git add");

    let (record, output) = measure_json(repo.path(), &["--exit-zero"]);

    // It measured the working tree, and says so in the record rather than only
    // on screen.
    use andon_core::schema::payload::HeadKind;
    assert_eq!(
        record.compare_context.head_kind,
        HeadKind::UncommittedWorktree,
        "the head was not the working tree, so this asserts nothing about uncommitted work"
    );
    assert!(!record.compare_context.head_kind.is_witnessable());

    // Every engine still ran. A capability that quietly lost a family would pass
    // a verdict assertion on its own.
    let engines: std::collections::BTreeSet<&str> = record
        .results
        .iter()
        .map(|r| r.engine_id.as_str())
        .collect();
    assert_eq!(engines.len(), 5, "{engines:?}");

    // The uncommitted bytes were actually read — the point of the whole thing.
    // Without this the test would pass over a record full of "could not read"
    // markers, which is exactly the half-built state this feature passed through.
    let complexity: Vec<&_> = record
        .results
        .iter()
        .filter(|r| r.metric_id.starts_with("static.cognitive-complexity"))
        .filter(|r| r.scope.path.as_deref() == Some("src/classify.ts"))
        .collect();
    assert!(
        !complexity.is_empty(),
        "no complexity was measured on the uncommitted file; the engines saw the path but not \
         its bytes"
    );

    // And it reached a verdict that acts. `--exit-zero` was passed so the
    // process code cannot mask a panic, so the verdict is read from the record.
    assert_eq!(
        record.verdict.verdict,
        andon_core::schema::enums::Verdict::Block,
        "a function this complex, staged and uncommitted, did not stop the line: {:?}",
        record.verdict.reasons
    );
    assert!(output.status.success(), "--exit-zero was passed");

    // The trust half is honest and specific: permanently unwitnessable, and not
    // collapsed into the generic value that means "not yet".
    assert_eq!(
        record.attestation.value,
        andon_core::schema::enums::Attestation::UnwitnessedUncommitted
    );
    assert!(!record.attestation.value.counts_downstream());
}

/// A function nobody could test in fifteen cases.
const COMPLEX_TS: &[u8] = br#"
export function classify(a: number, b: number, c: number): string {
  if (a > 0) {
    if (b > 0) {
      if (c > 0) { return "aaa"; }
      return "aab";
    }
    if (c > 0) { return "aba"; }
    return "abb";
  }
  if (b > 0) {
    if (c > 0) { return "baa"; }
    return "bab";
  }
  if (c > 0) {
    if (a < -10) { return "bba"; }
    return "bbb";
  }
  if (a > 1000) { return "big-a"; }
  if (b > 1000) { return "big-b"; }
  if (c > 1000) { return "big-c"; }
  if (a > 2000) { return "huge-a"; }
  if (a < -100 && b < -100) { return "ccc"; }
  return "none";
}
"#;

#[test]
fn an_uncommitted_head_is_never_confused_with_a_commit() {
    // The no-synthesis rule, checked on the wire rather than in a doc comment.
    // A record whose `head_oid` held HEAD's commit OID would pass a verifier's
    // tuple check while describing bytes that were never committed — the R2-4
    // laundering path, and false `divergent` on honest work from the other side.
    let repo = stranger_repo();
    let git = Git::open(repo.path()).expect("a repository");
    std::fs::write(
        repo.path().join("src").join("extra.ts"),
        b"export const e = 1;\n",
    )
    .expect("write");
    git.cmd(["add", "--all", "."]).output().expect("git add");

    let (record, _) = measure_json(repo.path(), &["--exit-zero"]);
    let head_commit = git
        .cmd(["rev-parse", "HEAD"])
        .text()
        .expect("rev-parse")
        .trim()
        .to_string();
    assert_ne!(
        record.compare_context.head_oid, head_commit,
        "the record wrote HEAD's commit OID as the head of an uncommitted measurement"
    );
    assert_ne!(
        record.compare_context.head_oid,
        record.compare_context.base_oid
    );
}

#[test]
fn re_reading_the_same_change_is_not_another_attempt_at_it() {
    // The counter counts attempts at *this change*, and what makes an attempt is
    // a change to what is being measured — not a call to the tool. Advancing per
    // invocation counts looking, and looking is what a person does while they
    // decide what to do: five verification runs over one unchanged repository
    // escalated a human to a human, firing the one signal reserved for "an agent
    // has tried enough times, stop trying".
    //
    // Driven exactly as an agent drives it: a dirty tree, no pinned range.
    let repo = stranger_repo();
    let git = Git::open(repo.path()).expect("a repository");
    let path = repo.path().to_str().expect("utf-8").to_string();
    std::fs::write(repo.path().join("src").join("greet.ts"), COMPLEX_TS).expect("write");
    git.cmd(["add", "--all", "."]).output().expect("git add");

    for _ in 0..5 {
        let _ = run(&["measure", "--repo", &path, "--json", "--exit-zero"]);
    }
    let counts = loop_state(repo.path());
    let highest = counts.values().copied().max().unwrap_or(0);
    assert_eq!(
        highest, 1,
        "five readings of one unchanged change counted as {highest} attempts: {counts:?}"
    );

    // The control: a real edit is a real attempt, or the counter has simply
    // stopped counting and this test would pass over a cap that no longer fires.
    let mut edited = COMPLEX_TS.to_vec();
    edited.extend_from_slice(
        b"
export const another = 1;
",
    );
    std::fs::write(repo.path().join("src").join("greet.ts"), &edited).expect("write");
    git.cmd(["add", "--all", "."]).output().expect("git add");
    let _ = run(&["measure", "--repo", &path, "--json", "--exit-zero"]);

    let after = loop_state(repo.path());
    assert!(
        after.values().copied().max().unwrap_or(0) > highest,
        "an actual edit did not count as an attempt: {after:?}"
    );
}

#[test]
fn fixing_the_finding_clears_the_budget_on_a_real_repository() {
    // THE OTHER HALF OF THE COUNTER, and the one that was dead in production.
    //
    // A counter that advances and never resets makes escalation guaranteed
    // rather than earned: on any branch living longer than a few attempts the
    // agent is sent to a human whatever it does, including getting it right.
    // That is PREMORTEM S6 — the anti-grinding mechanism inverting into the
    // flood it exists to prevent.
    //
    // The reset was gated on record completeness being `complete`, and record
    // completeness is the weakest of the results. Engines emit `unwitnessed`
    // for honest absences — no coverage report here, no history for a file this
    // change added — so on an ordinary healthy repository the gate never opened.
    // Asserted end to end, on a real repository, through the real binary,
    // because that is the only place the roll-up is real.
    let repo = stranger_repo();
    let git = Git::open(repo.path()).expect("a repository");
    let path = repo.path().to_str().expect("utf-8").to_string();
    let measure = || run(&["measure", "--repo", &path, "--json", "--exit-zero"]);

    // Three attempts at a finding, each a genuine edit so each one counts.
    for n in 0..3u8 {
        let mut source = COMPLEX_TS.to_vec();
        source.extend_from_slice(format!("\n// attempt {n}\n").as_bytes());
        std::fs::write(repo.path().join("src").join("greet.ts"), &source).expect("write");
        git.cmd(["add", "--all", "."]).output().expect("git add");
        let _ = measure();
    }
    let climbing = loop_state(repo.path());
    assert!(
        climbing.values().copied().max().unwrap_or(0) >= 3,
        "three genuine attempts did not accumulate: {climbing:?}"
    );

    // Now fix it, the way an agent actually fixes a complexity finding: the
    // branching goes, and part of it moves into a new file. Nothing is left to
    // act on — and the new file has no history for the process family to read
    // and no entry in the coverage report, so both answer `unwitnessed`. That is
    // the ordinary shape of a healthy repository, and it is exactly the state
    // that used to hold the budget open for ever.
    std::fs::write(
        repo.path().join("src").join("greet.ts"),
        b"import { polite } from \"./polite\";\n\nexport function greet(name: string): string {\n  return polite(name);\n}\n",
    )
    .expect("write");
    std::fs::write(
        repo.path().join("src").join("polite.ts"),
        b"export function polite(name: string): string {\n  return `hello, ${name}`;\n}\n",
    )
    .expect("write");
    git.cmd(["add", "--all", "."]).output().expect("git add");

    let output = measure();
    let record: MeasurementRecord = serde_json::from_slice(&output.stdout).expect("a record");
    assert_eq!(
        record.verdict.verdict,
        andon_core::schema::enums::Verdict::Pass,
        "the fix did not reach a pass: {:?}",
        record.verdict.reasons
    );
    // The premise: this really is the state that used to block the reset. If a
    // future engine change made these records `complete`, this test would still
    // pass while asserting nothing about the defect it was written for.
    assert_ne!(
        record.completeness,
        andon_core::schema::enums::Completeness::Complete,
        "this repository no longer reproduces the condition the reset was dead under"
    );
    assert_eq!(
        record.verdict.iteration.count, 0,
        "the loop was fixed and the counter did not clear, so the next attempt starts \
         part-way to an escalation nobody earned"
    );
    assert!(!record.verdict.iteration.escalated);
}

#[test]
fn a_renamed_path_is_named_as_the_file_it_became() {
    // `git status --porcelain` reports a rename as `R  old -> new`, and a naive
    // read of the line yields "old.ts -> new.ts" as though it were one path —
    // a string that names nothing in the repository, printed in a message whose
    // entire job is to say which files were not measured.
    let repo = stranger_repo();
    let git = Git::open(repo.path()).expect("a repository");
    git.cmd(["mv", "src/greet.ts", "src/hello.ts"])
        .output()
        .expect("git mv");

    // A pinned commit range, so the head is a commit and the rename sits beside
    // it as uncommitted work — which is the case this disclosure is for.
    let rendered = stdout(&run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--base",
        &repo.base_oid,
        "--head",
        "HEAD",
        "--no-color",
        "--exit-zero",
    ]));
    if !rendered.contains("uncommitted content") {
        // The disclosure only appears on a commit head with uncommitted work
        // beside it; if the fixture stops producing that, say so rather than
        // asserting nothing.
        panic!("the disclosure this checks did not appear:\n{rendered}");
    }
    assert!(
        !rendered.contains(" -> "),
        "a rename was reported as one path with an arrow in it:\n{rendered}"
    );
    assert!(rendered.contains("src/hello.ts"), "{rendered}");
}

/// Raw git, deliberately outside `Git::cmd`'s hygiene.
///
/// Every other git call in this file goes through the pinned wrapper, which is
/// the point of the wrapper. This one must not: it is the positive control that
/// proves the canary below can fire at all, and it can only prove that by being
/// the unpinned git an ordinary tool would have run.
fn unpinned_git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("git runs")
}

#[test]
fn a_repository_defined_filter_is_never_executed() {
    // A `filter` attribute plus a `filter.<name>.clean` command is a program the
    // repository defines, and git runs it whenever it reads that file's
    // working-tree content — `status` does it for an in-place edit that leaves
    // the size alone, `hash-object -w` does it always. Both are on the path of
    // an ordinary `andon measure`, and both were running it: a planted filter
    // created a working-tree file, updated a ref, and staged its own side effect
    // while `andon` exited 0 and printed `pass`.
    //
    // PRE-DECISIONS separates the code-executing checks from the safe static
    // lane. This is the assertion that the line holds.
    let repo = stranger_repo();
    let root = repo.path();
    let canary_ref = "refs/heads/andon-filter-canary";
    // Everything the filter would touch, expressed as git operations so the
    // command needs nothing but git on the PATH.
    let clean = format!("git update-ref {canary_ref} HEAD && git add --all .");

    unpinned_git(root, &["config", "filter.evil.clean", &clean]);
    unpinned_git(root, &["config", "filter.evil.smudge", "cat"]);
    std::fs::write(root.join(".gitattributes"), "*.ts filter=evil\n").expect("write attributes");
    unpinned_git(root, &["add", ".gitattributes"]);
    unpinned_git(root, &["commit", "-m", "attributes"]);

    let fired = |what: &str| {
        let out = unpinned_git(root, &["rev-parse", "--verify", "--quiet", what]);
        out.status.success()
    };
    let clear = || {
        unpinned_git(root, &["update-ref", "-d", canary_ref]);
    };

    // An in-place edit that keeps the size and moves the mtime: the shape that
    // makes git read content through the filter rather than deciding from stat
    // data alone.
    let edited = root.join("src").join("greet.ts");
    let before = std::fs::read_to_string(&edited).expect("read");
    let after = before.replace("hello, stranger", "HELLO, STRANGER");
    assert_ne!(
        before, after,
        "the fixture changed shape; nothing was edited"
    );
    std::fs::write(&edited, after).expect("write");

    // THE POSITIVE CONTROL. Without it this test passes on a machine where the
    // filter could never have run — a missing shell, a git that ignores the
    // driver — and asserts nothing at all.
    clear();
    unpinned_git(root, &["status", "--porcelain"]);
    assert!(
        fired(canary_ref),
        "the canary never fired under an unpinned git, so this test cannot tell a filter that \
         was stopped from one that was never reachable"
    );

    // Now the tool. Same repository, same edit, same filter. The unstage comes
    // first and the canary is cleared last: `git reset` reads content too, and
    // clearing before it would leave the control's own firing in place to be
    // read as the tool's.
    unpinned_git(root, &["reset", "--quiet"]);
    let entries_before = unpinned_git(root, &["ls-files", "--stage"]).stdout;
    clear();
    let output = run(&[
        "measure",
        "--repo",
        root.to_str().expect("utf-8"),
        "--no-color",
        "--exit-zero",
    ]);
    let entries_after = unpinned_git(root, &["ls-files", "--stage"]).stdout;

    assert!(
        !fired(canary_ref),
        "a repository-defined filter executed inside `andon measure`:\n{}",
        stdout(&output)
    );
    assert_eq!(
        entries_before, entries_after,
        "the measurement staged something; the filter's `git add` reached the index"
    );

    // And the disclosure, because a filter that silently did not run leaves the
    // reader believing they are looking at the bytes git would store.
    let rendered = stdout(&output);
    assert!(
        rendered.contains("filter"),
        "the filter was neutralized and nothing said so:\n{rendered}"
    );
}
