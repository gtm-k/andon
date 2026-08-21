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

/// The full OID `HEAD` names right now.
fn head_of(git: &Git) -> String {
    git.cmd(["rev-parse", "HEAD"])
        .text()
        .expect("rev-parse")
        .trim()
        .to_string()
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
    //
    // And the situation it names has to be the one the repository is in. This
    // fixture has four commits; the refusal used to tell it it had one, because
    // `--no-fallback` reached for the root-commit dead end without ever asking
    // whether `HEAD~1` existed. The way out it printed — "commit something" —
    // was advice for a repository nobody was holding.
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
        stderr.contains("no working change"),
        "the refusal does not say what is actually true of this repository:\n{stderr}"
    );
    assert!(
        !stderr.contains("single commit"),
        "a repository with history was told it has a single commit:\n{stderr}"
    );
    // The way out, which is the half a refusal exists for.
    assert!(stderr.contains("--base"), "{stderr}");
}

#[test]
fn a_shallow_clone_is_told_to_fetch_rather_than_to_commit() {
    // PREMORTEM A1, on the standard CI checkout. `actions/checkout` defaults to
    // `fetch-depth: 1`, so the boundary commit of a truncated history is what a
    // great many first commands run against — and the refusal told them "this
    // repository has a single commit ... Commit something", which is false
    // about the repository and sends the reader away from `git fetch
    // --unshallow`, the one command that fixes it.
    //
    // `git.facts().shallow` was already read for exactly this purpose by
    // `ResolveError::NoMergeBase`. This is that reading, one dead end over.
    let repo = stranger_repo();
    let temp = tempfile::tempdir().expect("a temporary directory");
    let shallow = temp.path().join("shallow");
    let bootstrap = Git::open(repo.path()).expect("a repository");
    let url = format!(
        "file://{}",
        repo.path().to_str().expect("utf-8").replace('\\', "/")
    );
    bootstrap
        .cmd(["clone", "--quiet", "--depth", "1", &url])
        .arg(&shallow)
        .output()
        .expect("the shallow clone happens; without it this test asserts nothing");
    assert!(
        Git::open(&shallow)
            .expect("the clone is a repository")
            .facts()
            .shallow,
        "the clone is not shallow, so this test asserts nothing"
    );

    // No flags at all: the default path, which is what makes this A1 rather
    // than a corner reachable only by asking for it.
    let output = run(&[
        "measure",
        "--repo",
        shallow.to_str().expect("utf-8"),
        "--no-color",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("shallow") && stderr.contains("--unshallow"),
        "a shallow clone was not told the history was truncated, or not told how to fix \
         it:\n{stderr}"
    );
    assert!(
        !stderr.contains("single commit") && !stderr.contains("Commit something"),
        "a shallow clone was told to commit something:\n{stderr}"
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
    // A branch carries its count and the change that count is about, since the
    // pair is what lets two concurrent measurements agree on whether a change
    // has already been counted. Only the count is this helper's business.
    value["branches"]
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v["count"].as_u64().unwrap_or(0) as u32))
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

#[test]
fn a_half_finished_operation_says_so_on_the_default_path() {
    // The detector for this is complete and correct in
    // `andon_core::git::resolve` and fires at the top of every resolution. The
    // default path could not reach it: the base ladder took `Ok(range)` or
    // `continue`, so every typed error — including this one — was swallowed as
    // "that candidate does not apply", the ladder exhausted, and what got
    // printed instead was a refusal about uncommitted work claiming this build
    // measures committed content only, plus a suggestion of `--last-merged`
    // that the next command refuses with the error thrown away here.
    //
    // A true statement discarded and a false one printed in its place.
    let repo = stranger_repo();
    let root = repo.path();
    let git = Git::open(root).expect("a repository");

    // A conflicting merge, which is the state an agent lands in most often.
    let base = git
        .cmd(["rev-parse", "HEAD"])
        .text()
        .expect("rev-parse")
        .trim()
        .to_string();
    git.cmd(["checkout", "--quiet", "-b", "side", &base])
        .output()
        .expect("branch");
    std::fs::write(root.join("src").join("greet.ts"), b"export const x = 1;\n").expect("write");
    git.cmd(["commit", "--quiet", "--all", "-m", "side"])
        .output()
        .expect("commit");
    git.cmd(["checkout", "--quiet", "-"])
        .output()
        .expect("checkout back");
    std::fs::write(root.join("src").join("greet.ts"), b"export const x = 2;\n").expect("write");
    git.cmd(["commit", "--quiet", "--all", "-m", "ours"])
        .output()
        .expect("commit");
    // Expected to fail: the conflict is the fixture.
    let _ = git.cmd(["merge", "--quiet", "side"]).output();
    assert!(
        git.facts().git_dir.join("MERGE_HEAD").exists(),
        "the merge did not conflict, so this test asserts nothing"
    );

    // No flags: the path a person or an agent is actually on.
    let stderr =
        |output: &std::process::Output| String::from_utf8_lossy(&output.stderr).into_owned();
    let default = run(&[
        "measure",
        "--repo",
        root.to_str().expect("utf-8"),
        "--no-color",
    ]);
    let said = stderr(&default);
    assert!(
        said.contains("merge is in progress"),
        "the default path did not name the half-finished operation:\n{said}"
    );
    assert!(
        !said.contains("measures committed content only"),
        "the refusal claimed this build cannot measure uncommitted content, which this same \
         binary does:\n{said}"
    );
    // The remedy has to be one that works. `--last-merged` was suggested and
    // refuses; the only true advice is to finish or abort.
    assert!(
        said.contains("--abort"),
        "no remedy that works was offered:\n{said}"
    );

    // And the suggestion that used to be made is not made, because it does not
    // work — which the same binary proves in the next two lines.
    let last_merged = run(&[
        "measure",
        "--repo",
        root.to_str().expect("utf-8"),
        "--last-merged",
        "--no-color",
    ]);
    assert!(
        stderr(&last_merged).contains("merge is in progress"),
        "`--last-merged` was still offered as a way out of a state it refuses"
    );
    assert!(!said.contains("--last-merged"), "{said}");
}

#[test]
fn a_half_finished_operation_says_so_where_the_ladder_finds_no_candidate() {
    // THE SAME DEAD END, on the path the ladder cannot reach.
    //
    // Propagating the typed error out of the ladder fixed the repositories where
    // a base candidate exists. Where none does — a `trunk` branch, no remote,
    // which is every checkout five minutes after `git init` — the loop body never
    // runs, `ResolvedRange::resolve` is never called, nothing asks whether an
    // operation is half-finished, and the fall-through prints the generic
    // uncommitted-work refusal recommending `--last-merged`. Which the next
    // command refuses with the typed error. Reproduced exactly that way before
    // this test existed.
    //
    // Whether the question gets asked must not depend on which refs happen to
    // exist, so it is asked of the repository before any of them are consulted.
    let repo = stranger_repo();
    let root = repo.path();
    let path = root.to_str().expect("utf-8").to_string();
    let git = Git::open(root).expect("a repository");

    // No name in `BASE_CANDIDATES`, and no remote to supply one.
    git.cmd(["branch", "--move", "trunk"])
        .output()
        .expect("rename the branch");

    // A conflicting cherry-pick, which is the state a rebase-heavy agent lands in.
    let base = head_of(&git);
    git.cmd(["checkout", "--quiet", "-b", "side", &base])
        .output()
        .expect("branch");
    std::fs::write(root.join("src").join("greet.ts"), b"export const x = 1;\n").expect("write");
    git.cmd(["commit", "--quiet", "--all", "-m", "side"])
        .output()
        .expect("commit");
    git.cmd(["checkout", "--quiet", "trunk"])
        .output()
        .expect("checkout back");
    std::fs::write(root.join("src").join("greet.ts"), b"export const x = 2;\n").expect("write");
    git.cmd(["commit", "--quiet", "--all", "-m", "ours"])
        .output()
        .expect("commit");
    // Expected to fail: the conflict is the fixture.
    let _ = git.cmd(["cherry-pick", "side"]).output();
    assert!(
        git.facts().git_dir.join("CHERRY_PICK_HEAD").exists(),
        "the cherry-pick did not conflict, so this test asserts nothing"
    );

    // The premise: no base candidate resolves, so the ladder cannot be what asks.
    for candidate in [
        "@{upstream}",
        "origin/HEAD",
        "origin/main",
        "origin/master",
        "upstream/main",
        "main",
        "master",
    ] {
        // An error and a quiet nothing both mean "this repository does not have
        // it": `@{upstream}` exits 128 with no upstream configured, the rest exit
        // 1 with no output.
        assert!(
            !matches!(
                git.cmd(["rev-parse", "--verify", "--quiet", candidate])
                    .succeeds_with_output(),
                Ok(Some(_))
            ),
            "{candidate} resolves here, so this test is the ladder path again"
        );
    }

    let stderr =
        |output: &std::process::Output| String::from_utf8_lossy(&output.stderr).into_owned();
    for flags in [
        vec!["measure", "--repo", &path, "--no-color"],
        vec!["measure", "--repo", &path, "--no-color", "--last-merged"],
        vec!["measure", "--repo", &path, "--no-color", "--no-fallback"],
    ] {
        let named = flags.join(" ");
        let said = stderr(&run(&flags));
        assert!(
            said.contains("cherry-pick is in progress"),
            "`{named}` did not name the half-finished operation:\n{said}"
        );
        // The remedy has to be one that works, and the dead-end suggestion must
        // not be made — the same binary refuses it two lines up.
        assert!(said.contains("--abort"), "no remedy that works:\n{said}");
        assert!(
            !said.contains("--last-merged"),
            "`{named}` offered a way out of a state it refuses:\n{said}"
        );
        assert!(
            !said.contains("uncommitted work here"),
            "`{named}` described conflict markers as an ordinary dirty tree:\n{said}"
        );
    }
}

/// The complex function these tests write when they need one that measures.
const NESTED_TS: &str = r#"
export function classify(a: number, b: number, c: number): string {
  if (a > 0) {
    if (b > 0) {
      if (c > 0) { return "all"; }
      for (let i = 0; i < a; i++) { if (i % 2 === 0) { return "even"; } }
      return "ab";
    }
    while (a > b) { a -= 1; if (a === c) { break; } }
    return "a";
  }
  switch (b) {
    case 1: return "one";
    case 2: return c > 0 ? "two" : "neither";
    default: return b > c ? "big" : "small";
  }
}
"#;

#[test]
fn a_dirty_measurement_can_be_recorded_and_does_not_launder_onto_the_commit() {
    // `--record` on a dirty tree passed `compare_context.head_oid` to `git notes
    // append`. For `head_kind: uncommitted-worktree` that is a 64-hex content
    // hash and not an object, so git answered `failed to resolve ... as a valid
    // ref` and the process exited 1 AFTER printing a full report — exit 1 means
    // "the tool could not do its job", so the verdict was masked by the failure
    // to file it, and `refs/notes/andon-measure` was empty after every dirty
    // measurement. E22 requires a dirty record to have a working ledger.
    let repo = stranger_repo();
    let root = repo.path();
    let git = Git::open(root).expect("a repository");
    std::fs::write(root.join("src").join("classify.ts"), NESTED_TS).expect("write");

    let anchor = git
        .cmd(["rev-parse", "HEAD"])
        .text()
        .expect("rev-parse")
        .trim()
        .to_string();

    let recorded = run(&[
        "measure",
        "--repo",
        root.to_str().expect("utf-8"),
        "--record",
        "--no-color",
        "--exit-zero",
    ]);
    assert!(
        recorded.status.success(),
        "recording a dirty measurement failed: {}",
        String::from_utf8_lossy(&recorded.stderr)
    );

    // The note exists, and it hangs on the commit the work sits on.
    let shown = stdout(&run(&[
        "ledger",
        "show",
        &anchor,
        "--repo",
        root.to_str().expect("utf-8"),
        "--no-color",
    ]));
    assert!(
        !shown.contains("No record is recorded"),
        "nothing was filed against the anchor commit:\n{shown}"
    );

    // The anchor is an attachment point and not an identity: the record still
    // says the head was a working tree.
    let records = andon_cli::ledger::show(&git, &anchor).expect("the note reads back");
    assert_eq!(records.len(), 1, "{records:?}");
    use andon_core::schema::payload::HeadKind;
    assert_eq!(
        records[0].compare_context.head_kind,
        HeadKind::UncommittedWorktree,
        "the record anchored to a commit forgot that it was about a working tree"
    );
    assert_ne!(
        records[0].compare_context.head_oid, anchor,
        "the snapshot identity was replaced by the anchor, which is the laundering path R2-4 \
         exists to close"
    );

    // THE LAUNDERING QUESTION, which nobody could reach before because the write
    // failed first: commit the work, and ask whether the measurement has become
    // a statement about the new commit.
    git.cmd(["add", "--all", "."]).output().expect("add");
    git.cmd(["commit", "--quiet", "-m", "committed"])
        .output()
        .expect("commit");
    let after = git
        .cmd(["rev-parse", "HEAD"])
        .text()
        .expect("rev-parse")
        .trim()
        .to_string();
    assert_ne!(after, anchor, "the commit did not happen");
    assert!(
        andon_cli::ledger::show(&git, &after)
            .expect("the ledger reads")
            .is_empty(),
        "the dirty measurement became a record about the commit that eventually contained the \
         work — an unwitnessable measurement wearing a witnessable commit's name"
    );
    assert_eq!(
        andon_cli::ledger::show(&git, &anchor)
            .expect("the ledger reads")
            .len(),
        1,
        "the record moved rather than staying where it was filed"
    );

    // And the verifier's own entry point reads it rather than falling over.
    let attested = run(&[
        "attest-stub",
        "--repo",
        root.to_str().expect("utf-8"),
        "--head",
        &anchor,
        "--trusted-branch",
        &repo.base_oid,
        "--no-color",
    ]);
    assert!(
        attested.status.success(),
        "attest-stub could not read a ledger holding a dirty record: {}",
        String::from_utf8_lossy(&attested.stderr)
    );
}

#[test]
fn a_dirty_record_is_filed_against_the_commit_it_was_measured_under() {
    // THE DEFECT. `ledger::record` asked `rev-parse HEAD` for the anchor *after*
    // the measurement, so anything that moved the ref in between — a hook that
    // commits, a second agent, a rebase in the next terminal — filed the note
    // against a commit that was never underneath the measured bytes. Measured at
    // the time: a snapshot taken under `c664569` recorded against `376f2d9`, a
    // commit with a different tree.
    //
    // The attachment point is the only durable record of what a dirty
    // measurement was taken from: `head_oid` is the snapshot's content hash and
    // `base_oid` is the fork point, so neither says which commit the working tree
    // sat on. Filing it against the wrong one is a false statement about what the
    // numbers describe, printed out loud by the note this command prints.
    //
    // Driven through the library rather than the binary, because the window is
    // inside one process: the CLI takes the snapshot and files the note without
    // returning, and a subprocess test cannot get between them. The interleave
    // here is the same window with the timing taken out of it.
    let repo = stranger_repo();
    let root = repo.path();
    let git = Git::open(root).expect("a repository");
    std::fs::write(root.join("src").join("classify.ts"), NESTED_TS).expect("write");

    let measured_under = head_of(&git);
    let measurement = andon_cli::measure::measure(&andon_cli::measure::Request {
        repo: root.to_path_buf(),
        ..Default::default()
    })
    .expect("the dirty tree measures");
    use andon_core::schema::payload::HeadKind;
    assert_eq!(
        measurement.record.compare_context.head_kind,
        HeadKind::UncommittedWorktree,
        "the fixture did not produce a dirty head, so this test asserts nothing"
    );
    assert_eq!(
        measurement.ledger_anchor, measured_under,
        "the measurement did not capture the commit it was taken under"
    );

    // The race window: HEAD moves to a commit with a different tree, after the
    // snapshot and before the note. `src/classify.ts` stays dirty throughout, so
    // the record still describes bytes that sat on `measured_under`.
    std::fs::write(root.join("unrelated.md"), "a concurrent commit\n").expect("write");
    git.cmd(["add", "--", "unrelated.md"])
        .output()
        .expect("add");
    git.cmd(["commit", "--quiet", "-m", "concurrent"])
        .output()
        .expect("commit");
    let moved_to = head_of(&git);
    assert_ne!(moved_to, measured_under, "HEAD did not move");

    let note = andon_cli::ledger::record(&git, &measurement.record, &measurement.ledger_anchor)
        .expect("the note is filed");

    assert_eq!(
        andon_cli::ledger::show(&git, &measured_under)
            .expect("the ledger reads")
            .len(),
        1,
        "the record was not filed against the commit it was measured under; the note said: {note}"
    );
    assert!(
        andon_cli::ledger::show(&git, &moved_to)
            .expect("the ledger reads")
            .is_empty(),
        "the record was filed against a commit that was never underneath the measured bytes"
    );
    // And the sentence the operator reads names the commit it actually used.
    assert!(
        note.contains(&measured_under[..12]) && !note.contains(&moved_to[..12]),
        "the note described an anchor it did not use: {note}"
    );
}

#[test]
fn a_dirty_record_reads_as_uncommitted_on_every_surface() {
    // `andon report` and `andon wait` rendered a dirty record as
    // `base → e35229f4072e (merge-base)` — the working tree's content hash cut
    // to twelve characters, which is exactly the shape of a commit OID — with
    // no trust line and no uncommitted labelling. The record's own `head_kind`
    // said `uncommitted-worktree` the whole time; these renderers did not read
    // it, so two shipped renderings of one record disagreed.
    //
    // The schema's defence for carrying a content hash in `head_oid` is that
    // "nothing downstream will mistake it for one, because this field says not
    // to". That is a claim about readers, and this is the test that the readers
    // hold up their end.
    let repo = stranger_repo();
    let root = repo.path();
    let path = root.to_str().expect("utf-8").to_string();
    std::fs::write(root.join("src").join("classify.ts"), NESTED_TS).expect("write");

    let (record, _) = measure_json(root, &["--exit-zero"]);
    use andon_core::schema::payload::HeadKind;
    assert_eq!(
        record.compare_context.head_kind,
        HeadKind::UncommittedWorktree,
        "the fixture did not produce a dirty head, so this test asserts nothing"
    );
    let head_short: String = record.compare_context.head_oid.chars().take(12).collect();

    // The trust sentence, read from the one function every surface renders it
    // from, so a reworded line cannot make this test stop checking anything.
    let trust = andon_cli::render::attestation_line(record.attestation.value);
    assert!(
        trust.contains("no CI recompute is possible"),
        "the fixture is not the unwitnessed-uncommitted case: {trust}"
    );

    // Asserted inside the loop rather than beside it. It used to be checked once,
    // for `report`, after the loop — so `wait` was taught the change line and the
    // exit code and not this, and three surfaces said a recompute of this record
    // is impossible while the fourth said nothing. A per-surface claim checked on
    // one surface is how the next surface goes missing.
    let html = repo.path().join("dirty.html");
    let html_arg = html.to_str().expect("utf-8").to_string();
    let _ = run(&["report", "--repo", &path, "--html", &html_arg]);
    for (name, rendered) in [
        (
            "report".to_string(),
            stdout(&run(&["report", "--repo", &path, "--no-color"])),
        ),
        (
            "wait".to_string(),
            stdout(&run(&["wait", "--repo", &path, "--no-color"])),
        ),
        (
            "report --html".to_string(),
            std::fs::read_to_string(&html).expect("the HTML report reads back"),
        ),
    ] {
        assert!(
            rendered.contains("uncommitted working tree"),
            "`andon {name}` did not say the head was a working tree:\n{rendered}"
        );
        assert!(
            rendered.contains("no CI recompute is possible"),
            "`andon {name}` carried no trust line, so it disagrees with the surfaces that \
             do about whether CI can ever witness this record:\n{rendered}"
        );
        // Abbreviation is what made a snapshot hash look like a commit OID, and
        // only the terminal surfaces abbreviate. The HTML prints the whole
        // sixty-four characters, which no commit OID has, in a row whose headline
        // three lines up already says the head is a working tree.
        if name != "report --html" {
            assert!(
                !rendered.contains(&head_short),
                "`andon {name}` printed the snapshot hash abbreviated like a commit OID \
                 ({head_short}):\n{rendered}"
            );
        }
    }
}

#[test]
fn the_substitution_survives_being_written_and_read_back() {
    // `cli::resolve`'s own documentation says the substitution "must appear in
    // every rendering of the record — the reason it is a value rather than a
    // log line". It was not a field on the record, so it could not: it lived on
    // the CLI's in-process `Measurement`, which does not survive being written
    // to disk. `andon report` on a substituted measurement printed a page of
    // numbers with nothing saying they were about a different change from the
    // one asked for — on a committed record too, so it was systematic.
    let repo = stranger_repo();
    let path = repo.path().to_str().expect("utf-8").to_string();

    let (record, _) = measure_json(repo.path(), &[]);
    let substitution = record
        .substitution
        .as_ref()
        .expect("the clean fixture takes the fallback, so the record carries a substitution");
    assert!(!substitution.measured.is_empty());

    let reported = stdout(&run(&["report", "--repo", &path, "--no-color"]));
    assert!(
        reported.contains("asked for") && reported.contains("measured"),
        "the read-back render did not announce the substitution:\n{reported}"
    );

    // The artefact that outlives the terminal, on the read-back path — which
    // passed `None` for the substitution and so never rendered the panel.
    let out = repo.path().join("read-back.html");
    let _ = run(&[
        "report",
        "--repo",
        &path,
        "--html",
        out.to_str().expect("utf-8"),
    ]);
    let html = std::fs::read_to_string(&out).expect("the report reads back");
    assert!(
        html.contains("This is not your working change"),
        "the read-back HTML report lost the substitution"
    );

    // The agent surface too. An agent acting on a fallback verdict without
    // knowing it is a fallback is PREMORTEM A1 through the one view built for
    // agents.
    let profile = stdout(&run(&[
        "report",
        "--repo",
        &path,
        "--profile",
        "agent-mode",
    ]));
    let parsed: serde_json::Value = serde_json::from_str(&profile).expect("valid profile");
    assert!(
        parsed["measured_instead"].is_string(),
        "the agent profile did not carry the substitution: {profile}"
    );
}

#[test]
fn an_unreadable_path_survives_into_every_later_reading_of_the_record() {
    // `measure` printed PASS, named the unreadable path, and exited 1 — and then
    // saved a normal PASS record. `report`, `--json`, the HTML report and the
    // agent profile all read it back, exited 0, and lost the fact. A verdict
    // about less than the caller asked about had a clean exit everywhere except
    // the terminal that produced it, and `main`'s own contract says a pass
    // requires that the change was actually read.
    //
    // Driven through `--input` rather than by breaking a repository's object
    // database: what is under test is that the record carries the fact and every
    // surface honours it, and a record is the input to all four of them.
    let repo = stranger_repo();
    let (mut record, _) = measure_json(repo.path(), &[]);
    assert!(
        record.unreadable_paths.is_empty(),
        "an ordinary measurement reported unreadable paths"
    );
    record.unreadable_paths = vec!["src/unreachable.ts".to_string()];

    let saved = repo.path().join("with-unreadable.json");
    std::fs::write(
        &saved,
        andon_core::canonical::to_canonical_string(&record).expect("serializes"),
    )
    .expect("writes");
    let input = saved.to_str().expect("utf-8").to_string();

    for surface in [
        vec!["report", "--input", &input, "--no-color"],
        vec!["wait", "--input", &input, "--no-color"],
    ] {
        let name = surface[0].to_string();
        let output = run(&surface);
        assert_eq!(
            output.status.code(),
            Some(1),
            "`andon {name}` gave a clean exit over a record whose change was not fully read"
        );
    }

    let reported = stdout(&run(&["report", "--input", &input, "--no-color"]));
    assert!(
        reported.contains("src/unreachable.ts"),
        "the read-back render did not name the path nothing described:\n{reported}"
    );

    let out = repo.path().join("unreadable.html");
    let _ = run(&[
        "report",
        "--input",
        &input,
        "--html",
        out.to_str().expect("utf-8"),
    ]);
    let html = std::fs::read_to_string(&out).expect("the report reads back");
    assert!(
        html.contains("src/unreachable.ts"),
        "the HTML report lost it"
    );

    // The agent sees a count rather than the paths: this view has a byte budget,
    // and what an agent needs is "this verdict covers less than you asked
    // about".
    let profile = stdout(&run(&[
        "report",
        "--input",
        &input,
        "--profile",
        "agent-mode",
    ]));
    let parsed: serde_json::Value = serde_json::from_str(&profile).expect("valid profile");
    assert_eq!(parsed["unread_paths"], 1, "{profile}");
    assert_eq!(
        parsed["head_kind"], "commit",
        "the agent profile does not say what its head_oid is: {profile}"
    );
}

/// Write a dirty change whose bytes cannot reach the object database.
///
/// This is what a read-only object store does to `measure::read_without_staging`,
/// and it is the only way to reach the assembly path: the verdict is reached
/// while the record is being built, so a record doctored afterwards — which is
/// how [`an_unreadable_path_survives_into_every_later_reading_of_the_record`]
/// drives the renderers — cannot exercise it at all.
///
/// `git hash-object -w` writes `.git/objects/<xx>/<rest>`, so a regular file
/// where that two-character directory belongs makes the write fail and leaves
/// every read in the repository working, which is the shape of the real failure.
/// The content is padded until its hash lands on a prefix this repository holds
/// no objects under, so blocking it cannot take a real object down with it.
fn write_an_unwritable_change(git: &Git, path: &Path) {
    let objects = git.facts().git_dir.join("objects");
    for padding in 0..64 {
        std::fs::write(path, format!("{NESTED_TS}\n// {padding}\n")).expect("write");
        let oid = git
            .cmd(["hash-object", "--"])
            .args([path])
            .text()
            .expect("git hashes a working-tree file");
        let dir = objects.join(&oid.trim()[..2]);
        if dir.exists() {
            continue;
        }
        std::fs::write(&dir, b"not a directory").expect("the objects directory is writable");
        // The premise, checked rather than assumed: writing fails and reading
        // does not. A test that silently lost its fault injection would pass by
        // measuring an ordinary change.
        assert!(
            git.cmd(["hash-object", "-w", "--"])
                .args([path])
                .text()
                .is_err(),
            "the object store still accepts writes, so nothing here is unreadable"
        );
        assert!(
            std::fs::read_to_string(path).is_ok(),
            "the file is readable"
        );
        return;
    }
    panic!("no free hash prefix in 64 tries");
}

#[test]
fn a_change_that_could_not_be_read_is_never_recorded_as_a_pass() {
    // THE DEFECT. `unreadable_paths` became durable and every renderer learned
    // to print it, and the verdict still never asked: a measurement whose change
    // could not be read reached `pass`, was **saved** as `pass`, and `ledger
    // show` re-served it with the headline `PASS` printed three lines above the
    // list of paths it had not read. `main`'s exit-code table already said a pass
    // requires that the change was actually read; the record did not.
    //
    // Carrying a fact is not the same as acting on it. This is the test that the
    // verdict acts on it, and that the one surface which re-serves a record from
    // the commit answers the same way as the six that read it from disk.
    let repo = stranger_repo();
    let root = repo.path();
    let path = root.to_str().expect("utf-8").to_string();
    let git = Git::open(root).expect("a repository");
    write_an_unwritable_change(&git, &root.join("src").join("classify.ts"));

    let measured = run(&["measure", "--repo", &path, "--no-color", "--record"]);
    let rendered = stdout(&measured);
    assert_eq!(
        measured.status.code(),
        Some(1),
        "a change that could not be read did not earn the tool-could-not-look exit:\n{rendered}"
    );

    let record: MeasurementRecord = andon_cli::store::read_last(&git).expect("a record was saved");
    assert_eq!(
        record.unreadable_paths,
        vec!["src/classify.ts".to_string()],
        "the fault injection did not produce an unreadable path, so this test asserts nothing"
    );

    // The verdict itself, in the record that outlives this process.
    use andon_core::schema::enums::Verdict;
    assert_ne!(
        record.verdict.verdict,
        Verdict::Pass,
        "a measurement that could not read {:?} was saved as a pass",
        record.unreadable_paths
    );
    // `advise` and not `block`: nothing was found, because nothing was read, and
    // exit 2 is reserved for "this change has something to deal with". The
    // exit-code table's own distinction between 1 and 2.
    assert_eq!(record.verdict.verdict, Verdict::Advise);
    assert!(
        record
            .verdict
            .reasons
            .iter()
            .any(|r| r.code == andon_core::verdict::reason::CHANGE_NOT_READ
                && r.message.contains("src/classify.ts")),
        "the verdict does not say why it is not a pass: {:?}",
        record.verdict.reasons
    );
    assert!(
        !rendered.contains("The line keeps moving"),
        "the headline still told the reader to carry on:\n{rendered}"
    );

    // And the same record, re-served from the commit it was filed against.
    let shown = run(&["ledger", "show", "--repo", &path, "--no-color"]);
    let served = stdout(&shown);
    assert!(
        served.contains("NOT READ") && served.contains("src/classify.ts"),
        "`ledger show` did not name what the record could not read:\n{served}"
    );
    assert!(
        !served.contains("PASS"),
        "`ledger show` printed PASS above the list of what was never read:\n{served}"
    );
    assert_eq!(
        shown.status.code(),
        Some(1),
        "`ledger show` gave a clean exit over a record whose change was not read:\n{served}"
    );
    // `--exit-zero` still means what it says on every surface.
    assert_eq!(
        run(&[
            "ledger",
            "show",
            "--repo",
            &path,
            "--no-color",
            "--exit-zero"
        ])
        .status
        .code(),
        Some(0),
        "`--exit-zero` did not reach `ledger show`"
    );
}

#[test]
fn a_filter_driver_that_cannot_be_neutralized_is_refused() {
    // The fail-closed half of the filter defence, and the only branch of it
    // that refuses rather than proceeds.
    //
    // Neutralization works by pinning `filter.<name>.clean` and friends empty
    // with `-c`, which outranks every config file. A driver whose *name*
    // contains `=` cannot be written as a `-c` key at all — git parses the key
    // at the first `=` and sets something else — so the pin would silently miss
    // and the program would run on the next `status`. Git accepts such a name
    // (`[filter "a=b"]` is a legal subsection), so this is reachable rather
    // than theoretical.
    //
    // Without this test the refusal is code nobody has run, which is the state
    // this whole round was called to fix.
    let repo = stranger_repo();
    let root = repo.path();

    unpinned_git(
        root,
        &[
            "config",
            "filter.a=b.clean",
            "git update-ref refs/heads/unneutralizable HEAD",
        ],
    );
    // The name really is what this test thinks it is.
    let listed = unpinned_git(root, &["config", "--get-regexp", "^filter\\."]);
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("filter.a=b.clean"),
        "git did not keep the driver name this test is about, so it asserts nothing"
    );

    let output = run(&[
        "measure",
        "--repo",
        root.to_str().expect("utf-8"),
        "--no-color",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a filter driver that cannot be pinned inert was measured anyway:\n{stderr}"
    );
    assert!(
        stderr.contains("a=b") && stderr.contains("neutralize"),
        "the refusal does not name the driver or say why it refused:\n{stderr}"
    );
    // And it says what to do, because the reader has run one command.
    assert!(stderr.contains("unset"), "{stderr}");
}

/// A scratch repository on a named branch, with one commit and a dirty tree.
///
/// Deliberately not `stranger_repo()`: this is `git init` an hour ago, which is
/// the checkout the head rung exists for and the one the base ladder finds
/// nothing in.
fn scratch_on_branch(branch: &str) -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("a temporary directory");
    let bootstrap = Git::open(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("a repository");
    bootstrap
        .cmd([
            "init",
            "--quiet",
            &format!("--initial-branch={branch}"),
            "--object-format=sha1",
        ])
        .arg(temp.path())
        .output()
        .expect("git init");
    let git = Git::open(temp.path()).expect("the fixture is a repository");
    for (key, value) in [
        ("user.name", common::FIXTURE_NAME),
        ("user.email", common::FIXTURE_EMAIL),
        ("core.autocrlf", "false"),
        ("core.eol", "lf"),
    ] {
        git.cmd(["config", key, value]).output().expect("config");
    }
    std::fs::write(
        temp.path().join("src.ts"),
        b"export function a(x: number) {\n  return x;\n}\n",
    )
    .expect("write");
    git.cmd(["add", "--all", "."]).output().expect("add");
    commit_fixture(&git, "root");
    // The change in flight: the state the product exists for.
    std::fs::write(
        temp.path().join("src.ts"),
        b"export function a(x: number) {\n  if (x > 0) {\n    if (x > 1) {\n      if (x > 2) {\n\
          return 1;\n      }\n    }\n  }\n  return x;\n}\n",
    )
    .expect("write");
    temp
}

/// Commit whatever is staged at the fixture identity, so a scratch repository
/// built here is as reproducible as one built from `fixtures/golden`.
fn commit_fixture(git: &Git, message: &str) {
    git.cmd(["commit", "--quiet", "--all", "-m", message])
        .env("GIT_AUTHOR_NAME", common::FIXTURE_NAME)
        .env("GIT_AUTHOR_EMAIL", common::FIXTURE_EMAIL)
        .env("GIT_AUTHOR_DATE", common::FIXTURE_DATE)
        .env("GIT_COMMITTER_NAME", common::FIXTURE_NAME)
        .env("GIT_COMMITTER_EMAIL", common::FIXTURE_EMAIL)
        .env("GIT_COMMITTER_DATE", common::FIXTURE_DATE)
        .output()
        .expect("git commit");
}

/// Every metric and value in a record, keyed so two records can be compared
/// without their OIDs, which differ by construction.
fn value_map(record: &MeasurementRecord) -> std::collections::BTreeMap<String, String> {
    record
        .results
        .iter()
        .map(|r| {
            (
                format!("{}|{:?}", r.metric_id, r.scope),
                format!("{:?}", r.value),
            )
        })
        .collect()
}

#[test]
fn the_branch_name_does_not_decide_whether_the_tool_works() {
    // THE BLOCKER. A controlled A/B with exactly one variable.
    //
    // `develop`, `dev` and `trunk` were refused — exit 1, a message about
    // uncommitted work — while `main` and `master` measured the same bytes in
    // the same repository, and `git branch --move trunk main` flipped the
    // outcome. The cause was structural rather than a missing candidate name:
    // the worktree head was only consumed inside the `BASE_CANDIDATES` loop, so
    // where no candidate resolves the loop body never ran and control fell
    // through to a refusal. The clean path had `last_merged_change` as its A1
    // rung; the dirty path had no rung at all.
    //
    // Widening `BASE_CANDIDATES` would not have fixed it. `develop` is not the
    // only name a branch can have, and the manual-fetch checkout below has no
    // candidate under any name.
    let mut values: Vec<(String, std::collections::BTreeMap<String, String>)> = Vec::new();
    for branch in ["develop", "dev", "trunk", "main", "master"] {
        let repo = scratch_on_branch(branch);
        let (record, output) = measure_json(repo.path(), &[]);
        assert_ne!(
            output.status.code(),
            Some(1),
            "a repository whose branch is `{branch}` could not be measured at all:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !record.results.is_empty(),
            "`{branch}` produced an empty record"
        );
        assert_eq!(
            record.compare_context.head_kind,
            andon_core::schema::payload::HeadKind::UncommittedWorktree,
            "`{branch}` did not measure the working tree, which is the whole point"
        );
        values.push((branch.to_string(), value_map(&record)));
    }
    // Same bytes, so the same numbers. A rung that measured *something* while
    // measuring a different change would pass the exit-code assertion above and
    // still be the silent substitution this module exists to prevent.
    let (first_name, first) = values[0].clone();
    for (branch, map) in &values[1..] {
        assert_eq!(
            &first, map,
            "`{first_name}` and `{branch}` measured the same bytes and disagreed"
        );
    }
}

#[test]
fn the_record_says_the_base_was_the_commit_the_tree_sits_on() {
    // The rung's disclosure half. The change measured is the working change, so
    // this is not a `Substitution` — but *how the base was arrived at* is a fact
    // about the record, and a reader months later has to be able to tell "HEAD
    // because I asked" from "HEAD because this repository offered no fork
    // point". The terminal header says it too, from the same value.
    let repo = scratch_on_branch("develop");
    let (record, _) = measure_json(repo.path(), &[]);
    assert_eq!(
        record.compare_context.base_resolution, "no-branch-point:head",
        "the record does not say how the base was arrived at"
    );
    assert!(
        record.substitution.is_none(),
        "the working change was measured, so nothing was substituted for it"
    );

    let rendered = stdout(&run(&[
        "measure",
        "--repo",
        repo.path().to_str().expect("utf-8"),
        "--no-color",
    ]));
    assert!(
        rendered.contains("no branch point found"),
        "the header does not say the base was arrived at without a fork point:\n{rendered}"
    );

    // A named base still says it was named, so the new value cannot swallow the
    // ordinary one.
    let (explicit, _) = measure_json(repo.path(), &["--base", "HEAD"]);
    assert_eq!(explicit.compare_context.base_resolution, "head");
}

#[test]
fn the_manual_fetch_checkout_is_measured() {
    // The same blocker with a remote attached, which is what makes it a CI
    // failure rather than a scratch-repo artefact: `git init -b develop`, add a
    // remote, fetch, `reset --hard`. `origin/HEAD` is kept unset (see below)
    // and the branch tracks nothing, so no candidate resolves — while a plain
    // `git clone` of the same upstream measures, because clone sets both.
    let upstream = scratch_on_branch("develop");
    let upstream_git = Git::open(upstream.path()).expect("a repository");
    commit_fixture(&upstream_git, "second");
    let url = format!(
        "file://{}",
        upstream.path().to_str().expect("utf-8").replace('\\', "/")
    );

    let temp = tempfile::tempdir().expect("a temporary directory");
    let bootstrap = Git::open(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("a repository");
    bootstrap
        .cmd([
            "init",
            "--quiet",
            "--initial-branch=develop",
            "--object-format=sha1",
        ])
        .arg(temp.path())
        .output()
        .expect("git init");
    let git = Git::open(temp.path()).expect("a repository");
    for (key, value) in [
        ("user.name", common::FIXTURE_NAME),
        ("user.email", common::FIXTURE_EMAIL),
        ("core.autocrlf", "false"),
        ("core.eol", "lf"),
    ] {
        git.cmd(["config", key, value]).output().expect("config");
    }
    git.cmd(["remote", "add", "origin", &url])
        .output()
        .expect("remote add");
    git.cmd(["fetch", "--quiet", "origin"])
        .output()
        .expect("fetch");
    // The premise is constructed here, not inherited from the runner: git 2.48
    // made `fetch` create `origin/HEAD` when it is missing, so whether the ref
    // exists after the line above is decided by whichever git the environment
    // ships. Deleting it builds the checkout this test describes — the shape
    // older gits and refspec-driven CI fetches leave behind — under the test's
    // own control. `set-head --delete` exits 0 whether or not the ref exists,
    // so this holds on both sides of 2.48.
    git.cmd(["remote", "set-head", "origin", "--delete"])
        .output()
        .expect("unset origin/HEAD");
    git.cmd(["reset", "--quiet", "--hard", "origin/develop"])
        .output()
        .expect("reset");

    // The premise, established above rather than assumed: neither of the two
    // candidates a clone would have set exists. Still asserted, as the
    // tripwire — a hit here means the setup lost control of the premise again.
    for candidate in ["origin/HEAD", "@{upstream}"] {
        let resolved = git
            .cmd(["rev-parse", "--verify", "--quiet", candidate])
            .succeeds_with_output();
        assert!(
            !matches!(resolved, Ok(Some(_))),
            "{candidate} resolves, so this test is not the checkout it describes"
        );
    }

    std::fs::write(
        temp.path().join("src.ts"),
        b"export function a(x: number) {\n  if (x > 0) {\n    if (x > 1) {\n      return 1;\n\
          }\n  }\n  return x;\n}\n",
    )
    .expect("write");

    let (record, output) = measure_json(temp.path(), &[]);
    assert_ne!(
        output.status.code(),
        Some(1),
        "the manual-fetch CI checkout could not be measured:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        record.compare_context.base_resolution, "no-branch-point:head",
        "the record does not say how the base was arrived at"
    );
}

#[test]
fn a_repository_with_no_commit_is_told_something_true_about_itself() {
    // The refusal that survives the rung, and the message class this phase has
    // blocked on three times. What it used to say — "a bare repository with no
    // worktree to resolve, or a snapshot git reported and then could not diff" —
    // was two alternatives, both asserted without being checked, and both false
    // here: `--is-bare-repository` is `false` and `--show-toplevel` resolves.
    // Its two remedies both failed as well: `--last-merged` refuses with the
    // typed error, and "commit the change, then re-run" leaves a one-commit
    // repository whose next `andon measure` refuses again.
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
    let git = Git::open(temp.path()).expect("a repository");
    for (key, value) in [
        ("user.name", common::FIXTURE_NAME),
        ("user.email", common::FIXTURE_EMAIL),
    ] {
        git.cmd(["config", key, value]).output().expect("config");
    }
    std::fs::write(temp.path().join("a.ts"), b"export const a = 1;\n").expect("write");

    let path = temp.path().to_str().expect("utf-8").to_string();
    let output = run(&["measure", "--repo", &path, "--no-color"]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("no commit yet"),
        "the refusal does not name the state the repository is in:\n{stderr}"
    );
    assert!(
        !stderr.contains("bare"),
        "the refusal still calls a non-bare repository bare:\n{stderr}"
    );
    assert!(
        !stderr.contains("--last-merged"),
        "the refusal still offers a flag that refuses here too:\n{stderr}"
    );

    // The remedy is followed, and it has to end in a measurement. The pair it
    // replaced did not.
    git.cmd(["add", "--all", "."]).output().expect("add");
    commit_fixture(&git, "first");
    std::fs::write(
        temp.path().join("a.ts"),
        b"export const a = 1;\nexport const b = 2;\n",
    )
    .expect("write");
    let after = run(&["measure", "--repo", &path, "--no-color"]);
    assert_ne!(
        after.status.code(),
        Some(1),
        "the remedy the refusal names does not end in a measurement:\n{}",
        String::from_utf8_lossy(&after.stderr)
    );
}

#[test]
fn a_record_whose_stored_verdict_contradicts_it_is_labelled_on_every_surface() {
    // The legacy record. A schema-v2 payload sealed before a change nobody read
    // was a reason not to pass: `unreadable_paths` naming what was not read and
    // `verdict: pass` beside it, which the current `evaluate` cannot produce and
    // which is still on disk and still in `refs/notes/andon-measure`.
    //
    // Three options were open — reject it, migrate it, or label it — and this is
    // label. Not recompute: a verdict is a function of the policy, registry and
    // iteration state in force when it was reached, none of which a reader has
    // months later, and printing a newly computed word in the old one's place
    // would make two renderings of one record disagree. Not reject: `ledger
    // show` exists to re-serve records months later. Not migrate: the bytes are
    // sealed, and rewriting a stored verdict in place is the shape of the
    // laundering path the trust boundary exists to keep shut.
    let repo = stranger_repo();
    let (mut record, _) = measure_json(repo.path(), &[]);
    record.unreadable_paths = vec!["src/work.ts".to_string()];
    record.verdict.verdict = andon_core::schema::enums::Verdict::Pass;
    record
        .verdict
        .reasons
        .retain(|r| r.code != andon_core::verdict::reason::CHANGE_NOT_READ);

    let saved = repo.path().join("legacy.json");
    std::fs::write(
        &saved,
        andon_core::canonical::to_canonical_string(&record).expect("serializes"),
    )
    .expect("writes");
    let input = saved.to_str().expect("utf-8").to_string();

    // The terminal render, which `report` and `ledger show` both reach through
    // one function.
    let reported = stdout(&run(&["report", "--input", &input, "--no-color"]));
    assert!(
        reported.contains("INVALID"),
        "the read-back render still headlines a verdict the record contradicts:\n{reported}"
    );
    assert!(
        !reported.starts_with("\n PASS"),
        "PASS is still the headline, which is what a reader with thirty seconds takes \
         away:\n{reported}"
    );
    // The stored word is still shown. Labelling it invalid is not hiding it —
    // the record is evidence, and a reader has to be able to see what it says.
    assert!(
        reported.contains("stored   PASS"),
        "the label withheld the word the record actually stores:\n{reported}"
    );

    // The HTML page, which outlives the terminal and is the one most likely to
    // be read by somebody deciding whether the change was safe.
    let out = repo.path().join("legacy.html");
    let _ = run(&[
        "report",
        "--input",
        &input,
        "--html",
        out.to_str().expect("utf-8"),
    ]);
    let html = std::fs::read_to_string(&out).expect("the report reads back");
    assert!(
        html.contains("lamp-word\">INVALID"),
        "the HTML lamp is still lit for a verdict the record contradicts"
    );
    assert!(
        html.contains("<title>Andon · INVALID"),
        "the browser tab contradicts the page's own headline"
    );

    // The agent surface carries it structurally, because it is the one written
    // for a reader that does not read prose.
    let profile = stdout(&run(&[
        "report",
        "--input",
        &input,
        "--profile",
        "agent-mode",
    ]));
    let parsed: serde_json::Value = serde_json::from_str(&profile).expect("valid profile");
    assert_eq!(parsed["verdict_invalid"], true, "{profile}");
    assert_eq!(parsed["verdict"], "pass", "{profile}");

    // `--json` re-serves the sealed bytes exactly, because they are evidence.
    // The label goes beside them on stderr; the exit code was already 1.
    let json = run(&["report", "--input", &input, "--json"]);
    let served: MeasurementRecord =
        serde_json::from_slice(&json.stdout).expect("the bytes are still a record");
    assert_eq!(
        served.verdict.verdict,
        andon_core::schema::enums::Verdict::Pass,
        "the stored verdict was rewritten on the way out, which is a migration"
    );
    assert_eq!(served.unreadable_paths, record.unreadable_paths);
    let said = String::from_utf8_lossy(&json.stderr);
    assert!(
        said.contains("stores `pass`"),
        "the machine surface served a contradicted record with nothing said about it:\n{said}"
    );
    assert_eq!(json.status.code(), Some(1), "{said}");
}

#[test]
fn an_ordinary_record_still_gets_the_verdict_word_it_earned() {
    // The other half of a label: it must not fire on the records it is not
    // about. A rule that reddens honest work is uninstalled faster than one that
    // misses something.
    let repo = stranger_repo();
    let (record, _) = measure_json(repo.path(), &[]);
    assert!(record.unreadable_paths.is_empty());

    let saved = repo.path().join("ordinary.json");
    std::fs::write(
        &saved,
        andon_core::canonical::to_canonical_string(&record).expect("serializes"),
    )
    .expect("writes");
    let input = saved.to_str().expect("utf-8").to_string();

    let reported = stdout(&run(&["report", "--input", &input, "--no-color"]));
    assert!(
        !reported.contains("INVALID"),
        "an honest record was labelled invalid:\n{reported}"
    );
    let profile = stdout(&run(&[
        "report",
        "--input",
        &input,
        "--profile",
        "agent-mode",
    ]));
    let parsed: serde_json::Value = serde_json::from_str(&profile).expect("valid profile");
    assert_eq!(parsed["verdict_invalid"], false, "{profile}");

    // And a record that carries unread paths *and* the verdict they earned is
    // not contradicted either: the label is about the contradiction, not about
    // the field.
    let mut consistent = record.clone();
    consistent.unreadable_paths = vec!["src/work.ts".to_string()];
    consistent.verdict.verdict = andon_core::schema::enums::Verdict::Advise;
    let saved = repo.path().join("consistent.json");
    std::fs::write(
        &saved,
        andon_core::canonical::to_canonical_string(&consistent).expect("serializes"),
    )
    .expect("writes");
    let reported = stdout(&run(&[
        "report",
        "--input",
        saved.to_str().expect("utf-8"),
        "--no-color",
    ]));
    assert!(
        !reported.contains("INVALID"),
        "a record whose verdict matches its own fields was labelled invalid:\n{reported}"
    );
}

#[test]
fn the_machine_surface_stays_machine_readable_beside_every_other_flag() {
    // `--profile agent-mode` was clean JSON only when used alone. Combined with
    // `--record` or `--html` it appended " report written to ..." or the ledger
    // note to stdout, so the agent-facing surface stopped parsing at a measured
    // byte offset — on the one surface PREMORTEM A2 exists for. And `report
    // --profile agent-mode --html <file>` returned before the write, exiting 0
    // with no file and nothing said.
    //
    // The lines are moved to stderr rather than dropped: "was the note written?"
    // is a question the operator can only answer from what the tool says.
    let repo = dirty_repo();
    let root = repo.path().to_str().expect("utf-8").to_string();
    let html = repo.path().join("agent.html");
    let html_arg = html.to_str().expect("utf-8").to_string();

    let output = run(&[
        "measure",
        "--repo",
        &root,
        "--profile",
        "agent-mode",
        "--html",
        &html_arg,
        "--record",
        "--no-color",
    ]);
    let out = stdout(&output);
    serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
        panic!("agent-mode stdout is not parseable JSON: {e}\n{out}");
    });
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("report written to"),
        "the HTML write was not reported anywhere, so the operator cannot tell it happened:\n\
         {said}"
    );
    assert!(
        said.contains("refs/notes/andon-measure"),
        "the ledger note was not reported anywhere:\n{said}"
    );
    assert!(html.is_file(), "the HTML report was not written");

    // `report`, where the profile used to return before the write.
    let second = repo.path().join("agent-report.html");
    let second_arg = second.to_str().expect("utf-8").to_string();
    let output = run(&[
        "report",
        "--repo",
        &root,
        "--profile",
        "agent-mode",
        "--html",
        &second_arg,
    ]);
    let out = stdout(&output);
    serde_json::from_str::<serde_json::Value>(&out)
        .unwrap_or_else(|e| panic!("report --profile stdout is not parseable JSON: {e}\n{out}"));
    assert!(
        second.is_file(),
        "`report --profile agent-mode --html` returned without writing the file"
    );

    // The human path is unchanged: the line still lands where a person is
    // looking.
    let third = repo.path().join("human.html");
    let printed = stdout(&run(&[
        "measure",
        "--repo",
        &root,
        "--html",
        third.to_str().expect("utf-8"),
        "--no-color",
    ]));
    assert!(
        printed.contains("report written to"),
        "the operational line was moved off the human surface too:\n{printed}"
    );
}

#[test]
fn a_root_commit_in_a_repository_full_of_them_is_not_called_the_only_one() {
    // "This repository has a single commit" is a statement about the
    // repository, and the head with no parent is not always the only commit in
    // one. Two ways to reach the refusal in a three-commit repository — pinning
    // `--head <root>`, and a detached checkout of the root — and both were told
    // the repository had one commit while `git rev-list --count HEAD` on the
    // branch beside them said three.
    //
    // The count is read now, so the sentence says what was found rather than
    // asserting something the reader can disprove in one command.
    let repo = scratch_on_branch("main");
    let path = repo.path().to_str().expect("utf-8").to_string();
    let git = Git::open(repo.path()).expect("a repository");
    // A history to be wrong about.
    commit_fixture(&git, "second");
    std::fs::write(repo.path().join("src.ts"), b"export const c = 3;\n").expect("write");
    commit_fixture(&git, "third");
    let root = git
        .cmd(["rev-list", "--max-parents=0", "HEAD"])
        .text()
        .expect("rev-list")
        .trim()
        .to_string();
    let count = git
        .cmd(["rev-list", "--count", "HEAD"])
        .text()
        .expect("rev-list")
        .trim()
        .to_string();
    assert_eq!(
        count, "3",
        "the fixture is not the repository this test is about"
    );

    for args in [
        vec!["measure", "--repo", &path, "--head", &root, "--no-color"],
        vec!["measure", "--repo", &path, "--no-color"],
    ] {
        // The second shape needs the detached checkout; the first does not.
        if args.len() == 4 {
            git.cmd(["checkout", "--quiet", &root])
                .output()
                .expect("detach");
        }
        let output = run(&args);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(
            !stderr.contains("single commit"),
            "a three-commit repository was told it has one:\n{stderr}"
        );
        assert!(
            stderr.contains("root commit"),
            "the refusal does not name what is actually true of the head:\n{stderr}"
        );
        assert!(
            !stderr.contains("Commit something"),
            "a repository with three commits was told to commit something:\n{stderr}"
        );
    }
    git.cmd(["checkout", "--quiet", "main"])
        .output()
        .expect("reattach");
}

#[test]
fn the_provenance_panel_says_what_its_head_value_is() {
    // The schema's defence for carrying a content hash in `head_oid` is that
    // "nothing downstream will mistake it for one, because this field says not
    // to" — a claim about readers, true only where a reader reads the field. The
    // HTML provenance panel, which is the artefact somebody opens three weeks
    // later to find out what was measured, printed the bare value in a row
    // labelled `Head`. A sixty-four-character hex string under that label reads
    // as a commit to anyone who has ever seen one.
    let repo = dirty_repo();
    let root = repo.path().to_str().expect("utf-8").to_string();
    // Outside the repository: an HTML report written into the working tree is
    // itself an uncommitted path, and the next measurement of the same tree
    // would key a different snapshot.
    let out = tempfile::tempdir().expect("a temporary directory");
    let dirty_html = out.path().join("dirty.html");
    let _ = run(&[
        "measure",
        "--repo",
        &root,
        "--html",
        dirty_html.to_str().expect("utf-8"),
        "--no-color",
    ]);
    let html = std::fs::read_to_string(&dirty_html).expect("the report reads back");
    let (record, _) = measure_json(repo.path(), &[]);
    assert_eq!(
        record.compare_context.head_kind,
        andon_core::schema::payload::HeadKind::UncommittedWorktree,
        "this fixture is not the dirty measurement the test is about"
    );
    let row = html
        .split("<dt>Head</dt>")
        .nth(1)
        .and_then(|rest| rest.split("</dd>").next())
        .expect("the provenance panel has a Head row");
    assert!(
        row.contains(&record.compare_context.head_oid),
        "the panel no longer carries the value at all: {row}"
    );
    assert!(
        row.contains("not a commit"),
        "the panel prints a content hash in a row labelled Head and does not say so: {row}"
    );

    // A commit head still says it is one, so the label is read rather than
    // pinned to the dirty case.
    let committed = out.path().join("committed.html");
    let _ = run(&[
        "measure",
        "--repo",
        &root,
        "--base",
        "HEAD~1",
        "--head",
        "HEAD",
        "--html",
        committed.to_str().expect("utf-8"),
        "--no-color",
    ]);
    let html = std::fs::read_to_string(&committed).expect("the report reads back");
    let row = html
        .split("<dt>Head</dt>")
        .nth(1)
        .and_then(|rest| rest.split("</dd>").next())
        .expect("the provenance panel has a Head row");
    assert!(
        row.contains("a commit") && !row.contains("not a commit"),
        "a commit head is not described as one: {row}"
    );
}
