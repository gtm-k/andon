//! The sandbox's behaviour, observed rather than claimed, on all three OS legs.
//!
//! Every test here runs on Linux, macOS and Windows through the ordinary
//! `cargo test --workspace` (the P1 pattern: Linux on push, the full matrix at
//! phase gates via `workflow_dispatch`). The mechanisms differ per OS — job
//! objects against process groups — so the tests assert the *observable*
//! contract: what crossed the environment boundary, and whether a process
//! survived. Process death is observed through a heartbeat file, because a
//! stopped heartbeat needs no process-inspection API on any OS.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use andon_core::engine::{run_engine, ExecSpec, MeasureContext, SandboxExec};
use andon_core::git::Git;
use andon_core::policy::Policy;
use andon_core::schema::enums::{Completeness, EngineClass, Lane, Severity};
use andon_core::schema::payload::{CompareContext, HeadKind, MetricValue};
use andon_sandbox::{OverlayEntry, Sandbox, TestCommandEngine};

const PROBE: &str = env!("CARGO_BIN_EXE_andon-sandbox-probe");

/// A path as one shell word, on either platform's shell.
fn q(path: impl AsRef<Path>) -> String {
    format!("\"{}\"", path.as_ref().display())
}

/// A repository with one commit: `committed.txt` and `doomed.txt`.
fn scratch_repo() -> (tempfile::TempDir, Git, String) {
    let temp = tempfile::tempdir().expect("a temporary directory");
    let bootstrap = Git::open(Path::new(env!("CARGO_MANIFEST_DIR")))
        .expect("the workspace is a git repository");
    bootstrap
        .cmd(["init", "--quiet", "--initial-branch=main"])
        .arg(temp.path())
        .output()
        .expect("git init");
    let git = Git::open(temp.path()).expect("the new repository opens");
    for (key, value) in [
        ("user.name", "Andon Test"),
        ("user.email", "test@andon.invalid"),
        ("core.autocrlf", "false"),
    ] {
        git.cmd(["config", key, value]).output().expect("config");
    }
    std::fs::write(temp.path().join("committed.txt"), b"committed\n").expect("write");
    std::fs::write(temp.path().join("doomed.txt"), b"doomed\n").expect("write");
    git.cmd(["add", "--all", "."]).output().expect("add");
    git.cmd(["commit", "--quiet", "-m", "base"])
        .output()
        .expect("commit");
    let head = git
        .cmd(["rev-parse", "HEAD"])
        .text()
        .expect("rev-parse")
        .trim()
        .to_string();
    (temp, git, head)
}

fn spec(command: String, timeout_ms: u32) -> ExecSpec {
    ExecSpec {
        command,
        timeout_ms,
        env_allow: Vec::new(),
        memory_limit_mb: None,
    }
}

/// Wait until a heartbeat file stops growing, and return its final size.
///
/// "Stops" means one full second with no growth — twenty missed beats. The
/// loop bounds the wait so a genuinely immortal process fails the test rather
/// than hanging it.
fn quiesced_size(path: &Path) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(15);
    let size = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let mut last = size(path);
    let mut stable_since = Instant::now();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        let now = size(path);
        if now != last {
            last = now;
            stable_since = Instant::now();
        } else if stable_since.elapsed() >= Duration::from_secs(1) {
            return last;
        }
    }
    panic!("the heartbeat at {} never stopped", path.display());
}

#[test]
fn the_worktree_is_the_snapshot_and_the_operators_tree_is_untouched() {
    let (temp, git, head) = scratch_repo();

    // The measured change, as blobs: `overlay.txt` added, `doomed.txt` deleted.
    // The blob enters the object database the way `read_without_staging` puts
    // dirty content there — `hash-object -w` — and the staging file is deleted
    // before the sandbox enters, so the bytes can only have come from the blob.
    let staging = temp.path().join("overlay-staging.txt");
    std::fs::write(&staging, b"overlay content\n").expect("write");
    let blob = git
        .cmd(["hash-object", "-w", "--"])
        .arg(staging.to_str().expect("utf-8 temp path"))
        .text()
        .expect("hash-object")
        .trim()
        .to_string();
    std::fs::remove_file(&staging).expect("remove staging");
    let overlay = [
        OverlayEntry {
            path: "overlay.txt".to_string(),
            blob_oid: Some(blob),
            executable: false,
        },
        OverlayEntry {
            path: "doomed.txt".to_string(),
            blob_oid: None,
            executable: false,
        },
    ];

    let sandbox = Sandbox::enter(&git, &head, &overlay).expect("the sandbox enters");
    let workdir = sandbox.workdir().to_path_buf();

    assert_eq!(
        std::fs::read(workdir.join("committed.txt")).expect("committed.txt"),
        b"committed\n",
        "the anchor commit's content is there"
    );
    assert_eq!(
        std::fs::read(workdir.join("overlay.txt")).expect("overlay.txt"),
        b"overlay content\n",
        "the overlay blob is there"
    );
    assert!(
        !workdir.join("doomed.txt").exists(),
        "the deletion is applied"
    );

    // The operator's tree: exactly as committed, no overlay applied to it.
    assert!(temp.path().join("doomed.txt").exists());
    assert!(!temp.path().join("overlay.txt").exists());

    let notices = sandbox.close();
    assert!(
        notices.is_empty(),
        "cleanup had something to say: {notices:?}"
    );
    assert!(!workdir.exists(), "the worktree directory is gone");
    let registrations = git
        .cmd(["worktree", "list", "--porcelain"])
        .text()
        .expect("worktree list");
    assert_eq!(
        registrations.matches("worktree ").count(),
        1,
        "only the main worktree remains registered: {registrations}"
    );
}

#[test]
fn the_environment_is_default_deny_with_a_policy_extension() {
    // Set process-global variables with names nothing else uses; the sandbox
    // must pass one through only because policy names it.
    std::env::set_var("ANDON_SB_SECRET", "must-not-cross");
    std::env::set_var("ANDON_SB_ALLOWED", "may-cross");

    let (_temp, git, head) = scratch_repo();
    let sandbox = Sandbox::enter(&git, &head, &[]).expect("enters");
    let dump = sandbox.workdir().join("env.txt");

    let mut run_spec = spec(format!("{} env-dump {}", q(PROBE), q(&dump)), 30_000);
    run_spec.env_allow = vec!["ANDON_SB_ALLOWED".to_string()];
    let outcome = sandbox.run(&run_spec).expect("the probe runs");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "stderr: {}",
        outcome.stderr_tail
    );

    let names: Vec<String> = std::fs::read_to_string(&dump)
        .expect("the dump was written")
        .lines()
        .map(|l| l.trim().to_ascii_uppercase())
        .collect();

    assert!(
        names.contains(&"PATH".to_string()),
        "PATH crosses: {names:?}"
    );
    assert!(
        names.contains(&"ANDON_SANDBOX".to_string()),
        "the sandbox marks itself"
    );
    assert!(
        names.contains(&"ANDON_SB_ALLOWED".to_string()),
        "the policy extension crosses"
    );
    assert!(
        !names.contains(&"ANDON_SB_SECRET".to_string()),
        "an unlisted variable NEVER crosses"
    );

    sandbox.close();
}

#[test]
fn the_timeout_kills_the_child_and_its_children() {
    let (_temp, git, head) = scratch_repo();
    let sandbox = Sandbox::enter(&git, &head, &[]).expect("enters");
    let heartbeat = sandbox.workdir().join("hb.txt");

    let started = Instant::now();
    let outcome = sandbox
        .run(&spec(
            format!("{} spawn-orphan {}", q(PROBE), q(&heartbeat)),
            700,
        ))
        .expect("the run returns");

    assert!(outcome.timed_out, "the cap fired");
    assert_eq!(
        outcome.exit_code, None,
        "a killed command reports no exit code — the kill's code is not the suite's"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the kill happened near the cap, not at the test harness timeout"
    );

    // The grandchild was spawned by the child, not by the sandbox. Its
    // heartbeat stopping is the process-tree claim, observed.
    let final_size = quiesced_size(&heartbeat);
    std::thread::sleep(Duration::from_millis(500));
    let after = std::fs::metadata(&heartbeat).map(|m| m.len()).unwrap_or(0);
    assert_eq!(after, final_size, "the grandchild is dead, not slow");

    sandbox.close();
}

#[test]
fn a_finished_command_leaves_no_stragglers_behind() {
    let (_temp, git, head) = scratch_repo();
    let sandbox = Sandbox::enter(&git, &head, &[]).expect("enters");
    let heartbeat = sandbox.workdir().join("hb.txt");

    let outcome = sandbox
        .run(&spec(
            format!("{} orphan-and-exit {}", q(PROBE), q(&heartbeat)),
            30_000,
        ))
        .expect("the run returns");
    assert!(!outcome.timed_out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "stderr: {}",
        outcome.stderr_tail
    );

    // The command passed; the daemon it left must still be dead — the sweep
    // runs on every exit, not only on timeout.
    let final_size = quiesced_size(&heartbeat);
    std::thread::sleep(Duration::from_millis(500));
    let after = std::fs::metadata(&heartbeat).map(|m| m.len()).unwrap_or(0);
    assert_eq!(after, final_size, "the straggler outlived the measurement");

    sandbox.close();
}

#[test]
fn exit_codes_and_output_tails_come_back_verbatim() {
    let (_temp, git, head) = scratch_repo();
    let sandbox = Sandbox::enter(&git, &head, &[]).expect("enters");

    let failing = sandbox
        .run(&spec(format!("{} exit 3", q(PROBE)), 30_000))
        .expect("runs");
    assert_eq!(failing.exit_code, Some(3));
    assert!(!failing.timed_out);

    let talking = sandbox
        .run(&spec(format!("{} say hello-tail", q(PROBE)), 30_000))
        .expect("runs");
    assert!(talking.stdout_tail.contains("hello-tail"), "{talking:?}");
    assert!(
        talking.stderr_tail.contains("err:hello-tail"),
        "{talking:?}"
    );

    sandbox.close();
}

// ---------------------------------------------------------------- the engine

/// The policy that turns the lane on, pointing the suite at the probe.
fn lane_policy(command: &str) -> Policy {
    let mut policy = Policy::default();
    policy.sandbox.enabled = true;
    policy.sandbox.test_command = Some(command.to_string());
    policy
}

fn engine_context(policy: Policy, sandbox: Option<Arc<dyn SandboxExec>>) -> MeasureContext {
    MeasureContext {
        compare_context: CompareContext {
            base_oid: "1".repeat(40),
            head_oid: "2".repeat(40),
            head_kind: HeadKind::Commit,
            git_version: "git version 2.51.0".to_string(),
            base_resolution: "explicit".to_string(),
        },
        policy,
        changed_paths: Vec::new(),
        sandbox,
    }
}

#[test]
fn a_passing_suite_reports_no_failure_on_the_async_lane() {
    let (_temp, git, head) = scratch_repo();
    let command = format!("{} exit 0", q(PROBE));
    let policy = lane_policy(&command);
    let engine = TestCommandEngine::from_policy(&policy).expect("the policy declares the engine");
    let sandbox = Sandbox::enter(&git, &head, &[]).expect("enters");

    let results = run_engine(&engine, &engine_context(policy, Some(Arc::new(sandbox))))
        .expect("the suite ran");

    assert_eq!(results.len(), 2, "the flag and the sentence");
    let flag = &results[0];
    assert_eq!(flag.metric_id, "tests.suite-failure");
    assert_eq!(flag.value, MetricValue::Flag(false));
    assert_eq!(flag.severity, Severity::Info, "a pass ranks as nothing");
    assert_eq!(flag.engine_class, EngineClass::CodeExec);
    assert_eq!(flag.completeness, Completeness::Complete);
    assert!(!flag.digest.is_empty(), "run_engine sealed it");
    for result in &results {
        assert_eq!(
            result.freshness.lane,
            Lane::Async,
            "every suite result rides the async lane"
        );
    }
    let sentence = &results[1];
    assert!(
        matches!(&sentence.value, MetricValue::Text(text) if text.contains("exited 0")),
        "{:?}",
        sentence.value
    );
    // The payload half of the disclosure, in the regime of every result.
    let regime = andon_core::canonical::to_canonical_string(&flag.measurement_regime)
        .expect("the regime serializes");
    assert!(
        regime.contains("\"sandbox\":\"no-net-isolation\""),
        "the payload carries the isolation disclosure: {regime}"
    );
    assert!(
        regime.contains("exit 0"),
        "the regime names the command it ran: {regime}"
    );
}

#[test]
fn a_failing_suite_fires_the_flag_and_the_default_policy_stops_the_line() {
    let (_temp, git, head) = scratch_repo();
    let command = format!("{} exit 3", q(PROBE));
    let policy = lane_policy(&command);
    let engine = TestCommandEngine::from_policy(&policy).expect("declared");
    let sandbox = Sandbox::enter(&git, &head, &[]).expect("enters");
    let ctx = engine_context(policy, Some(Arc::new(sandbox)));

    let results = run_engine(&engine, &ctx).expect("the suite ran; failing is an answer");
    let flag = &results[0];
    assert_eq!(flag.value, MetricValue::Flag(true));
    assert_eq!(
        flag.severity,
        Severity::Critical,
        "the declared ladder, before assembly's tier cap"
    );

    let verdict_ctx = andon_core::verdict::VerdictContext {
        policy: &ctx.policy,
        policy_change: None,
        engine_failures: &[],
        stale_claim_ids: &[],
        iteration_state_recovered: false,
        completeness: Completeness::Complete,
        registry_skew: &[],
        unreadable_paths: &[],
    };
    assert!(
        andon_core::verdict::severity::stops_the_line(flag, &verdict_ctx),
        "block_on_test_failure reads the flag"
    );
    let sentence = &results[1];
    assert!(
        matches!(&sentence.value, MetricValue::Text(text) if text.contains("exited 3")),
        "{:?}",
        sentence.value
    );
}

#[test]
fn a_timeout_is_an_unanswered_question_and_never_a_failure() {
    let (_temp, git, head) = scratch_repo();
    let command = format!("{} spawn-orphan hb-timeout.txt", q(PROBE));
    let mut policy = lane_policy(&command);
    policy.sandbox.test_timeout_ms = 500;
    let engine = TestCommandEngine::from_policy(&policy).expect("declared");
    let sandbox = Sandbox::enter(&git, &head, &[]).expect("enters");

    let error = run_engine(&engine, &engine_context(policy, Some(Arc::new(sandbox))))
        .expect_err("a timeout is not a result");
    let message = error.to_string();
    assert!(message.contains("500 ms"), "{message}");
    assert!(
        message.contains("never a test failure"),
        "the refusal states the rule: {message}"
    );
}

#[test]
fn without_a_sandbox_the_engine_is_refused_at_the_boundary() {
    let policy = lane_policy("true");
    let engine = TestCommandEngine::from_policy(&policy).expect("declared");
    let error = run_engine(&engine, &engine_context(policy, None))
        .expect_err("code-exec without a sandbox");
    assert!(
        matches!(
            error,
            andon_core::engine::EngineError::SandboxRequired { ref engine_id }
                if engine_id == "tests"
        ),
        "{error:?}"
    );
}

#[test]
fn the_policy_is_the_feature_flag_in_both_directions() {
    let mut policy = Policy::default();
    assert!(
        TestCommandEngine::from_policy(&policy).is_none(),
        "defaults ship no engine"
    );
    policy.sandbox.test_command = Some("true".to_string());
    assert!(
        TestCommandEngine::from_policy(&policy).is_none(),
        "a command without the flag is still off"
    );
    policy.sandbox.enabled = true;
    assert!(TestCommandEngine::from_policy(&policy).is_some());
    policy.sandbox.test_command = None;
    assert!(
        TestCommandEngine::from_policy(&policy).is_none(),
        "the flag without a command has nothing to run"
    );
}

#[test]
fn the_compiled_registry_declares_exactly_what_the_engine_emits() {
    let file = andon_sandbox::engine::registry_file().expect("the registry parses");
    let declared: Vec<&str> = file.metrics.iter().map(|m| m.metric_id.as_str()).collect();
    assert_eq!(
        declared,
        vec!["tests.suite-failure", "tests.suite-outcome"],
        "the registry file and this test agree on the emission set"
    );
    assert!(
        file.metrics.iter().all(|m| !m.deterministic),
        "nothing a test suite produces is byte-reproducible, so nothing enters \
         the digest compare set"
    );
    let ladders = andon_sandbox::engine::severity_ladders();
    for metric in &file.metrics {
        assert!(
            ladders.contains_key(&metric.metric_id),
            "{} declares no ladder",
            metric.metric_id
        );
    }
}

#[test]
fn a_declared_command_does_not_spill_while_the_lane_is_disabled() {
    // P7's F4, pinned at last. The behaviour was correct all along and was
    // verified by hand twice — once at P7's review, once at the 2026-08-25
    // re-verdict — and nothing in the suite defended it, so a regression would
    // have been silent both times.
    //
    // `enabled` is the rollback path for the only v1 code-exec surface. A
    // repository that declares a `test_command` and then turns the lane off is
    // saying "do not run my code", and the switch has to win over the
    // declaration rather than merely reorder it: a `false` that still spilled
    // would execute a command an operator had explicitly disabled, which is the
    // failure this flag exists to make impossible.
    //
    // Asserted through `from_policy` because that is the seam where the lane is
    // decided — no engine, no job, nothing to spill. Testing further downstream
    // would pin the consequence rather than the rule.
    let mut policy = lane_policy("this command must never run");
    policy.sandbox.enabled = false;

    assert!(
        TestCommandEngine::from_policy(&policy).is_none(),
        "the lane is disabled, so a declared test_command must produce no engine"
    );

    // The other half, so the test cannot pass because the command went missing:
    // the identical policy with the switch back on DOES produce one. Without
    // this, an unrelated change that stopped reading `test_command` at all would
    // leave the assertion above green and meaningless.
    policy.sandbox.enabled = true;
    assert!(
        TestCommandEngine::from_policy(&policy).is_some(),
        "the same declaration with the lane enabled must still produce an engine"
    );
}
