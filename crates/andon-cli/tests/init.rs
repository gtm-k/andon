//! `andon init` and `andon hook`, driven as the binary a harness drives.
//!
//! The installer's promises are behavioural — additive, idempotent, removable,
//! refusing what it does not own — and each is held here by doing the thing to
//! a real repository and reading what is on disk afterwards. The hook's gate
//! contract (0 keep going, 2 stop the line, silent when nothing is in flight)
//! is held by running the real `andon hook` the way Claude Code would,
//! including the JSON payload on stdin.

mod common;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use andon_core::git::Git;

const EXE: &str = env!("CARGO_BIN_EXE_andon");

fn run_in(repo: &Path, args: &[&str]) -> Output {
    Command::new(EXE)
        .args(args)
        .arg("--repo")
        .arg(repo)
        .output()
        .expect("andon runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A repository with one commit and a clean tree.
fn scratch() -> tempfile::TempDir {
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
        ("core.autocrlf", "false"),
        ("core.eol", "lf"),
    ] {
        git.cmd(["config", key, value]).output().expect("config");
    }
    std::fs::write(
        temp.path().join("src.ts"),
        "export function a(x: number) {\n  return x;\n}\n",
    )
    .expect("write");
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
    temp
}

/// A change whose cognitive complexity crosses the declared Medium rung.
const TANGLED: &str = concat!(
    "export function classify(x: number): number {\n",
    "  let out = 0;\n",
    "  if (x > 0) {\n",
    "    if (x > 1) {\n",
    "      if (x > 2) {\n",
    "        if (x > 3) {\n",
    "          if (x > 4) {\n",
    "            if (x > 5) {\n",
    "              out = 6;\n",
    "            } else {\n",
    "              out = 5;\n",
    "            }\n",
    "          }\n",
    "        }\n",
    "      }\n",
    "    }\n",
    "  }\n",
    "  if (x < 0 && x > -10) {\n",
    "    out = -1;\n",
    "  }\n",
    "  return out;\n",
    "}\n",
);

#[test]
fn claude_install_is_additive_idempotent_and_removable() {
    let repo = scratch();
    // Somebody else's configuration is already there.
    let settings = repo.path().join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(
        &settings,
        r#"{"model": "opus", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "somebody-elses-hook"}]}]}}"#,
    )
    .unwrap();

    let installed = run_in(repo.path(), &["init", "--claude"]);
    assert!(installed.status.success(), "{}", stderr(&installed));
    let report = stdout(&installed);
    assert!(report.contains("wrote"), "{report}");
    assert!(
        report.contains("--remove"),
        "an installer must say how to undo itself: {report}"
    );

    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(
        written["model"], "opus",
        "a key the installer does not own must survive the merge"
    );
    let stop = written["hooks"]["Stop"].as_array().unwrap();
    assert_eq!(stop.len(), 2, "additive: theirs and ours");
    assert_eq!(
        stop[0]["hooks"][0]["command"], "somebody-elses-hook",
        "the foreign hook survives, first"
    );
    assert_eq!(stop[1]["hooks"][0]["command"], "andon hook claude-stop");

    let mcp: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(repo.path().join(".mcp.json")).unwrap())
            .unwrap();
    assert_eq!(mcp["mcpServers"]["andon"]["command"], "andon-mcp");

    // Idempotent: a second install writes nothing new.
    let again = run_in(repo.path(), &["init", "--claude"]);
    assert!(stdout(&again).contains("unchanged"), "{}", stdout(&again));
    let after_again: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(after_again["hooks"]["Stop"].as_array().unwrap().len(), 2);

    // Removal takes exactly ours and leaves exactly theirs.
    let removed = run_in(repo.path(), &["init", "--claude", "--remove"]);
    assert!(removed.status.success(), "{}", stderr(&removed));
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(after["model"], "opus");
    let stop = after["hooks"]["Stop"].as_array().unwrap();
    assert_eq!(stop.len(), 1);
    assert_eq!(stop[0]["hooks"][0]["command"], "somebody-elses-hook");
    assert!(
        !repo.path().join(".mcp.json").exists()
            || !std::fs::read_to_string(repo.path().join(".mcp.json"))
                .unwrap()
                .contains("andon"),
        "the MCP registration is gone"
    );
}

/// The command strings the two Stop-hook variants install.
const PLAIN_HOOK: &str = "andon hook claude-stop";
const SELF_MEASURE_HOOK: &str = "andon hook claude-stop --self-measure";

/// The one andon command in the Stop hooks of `.claude/settings.json`.
fn installed_stop_command(repo: &Path) -> String {
    let settings: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo.join(".claude").join("settings.json")).unwrap(),
    )
    .unwrap();
    let ours: Vec<&str> = settings["hooks"]["Stop"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|entry| entry["hooks"].as_array().unwrap())
        .filter_map(|h| h["command"].as_str())
        .filter(|c| c.starts_with("andon "))
        .collect();
    assert_eq!(ours.len(), 1, "exactly one andon Stop hook: {ours:?}");
    ours[0].to_string()
}

#[test]
fn a_variant_change_rewrites_the_installed_stop_hook() {
    let repo = scratch();
    // A foreign Stop hook shares the settings file and must survive untouched.
    let settings = repo.path().join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(
        &settings,
        r#"{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "somebody-elses-hook"}]}]}}"#,
    )
    .unwrap();
    let installed = run_in(repo.path(), &["init", "--claude"]);
    assert!(installed.status.success(), "{}", stderr(&installed));
    assert_eq!(installed_stop_command(repo.path()), PLAIN_HOOK);

    // plain -> self-measure: the flag changed, so "unchanged" would be a
    // report about a repository whose requested gate is not installed.
    let raised = run_in(repo.path(), &["init", "--claude", "--self-measure"]);
    assert!(raised.status.success(), "{}", stderr(&raised));
    let report = stdout(&raised);
    assert!(
        !report.contains("already runs"),
        "a variant change must not be reported as unchanged: {report}"
    );
    assert!(
        report.contains(SELF_MEASURE_HOOK) && report.contains(&format!("it ran `{PLAIN_HOOK}`")),
        "the report must name what it installed and what that replaced: {report}"
    );
    assert_eq!(installed_stop_command(repo.path()), SELF_MEASURE_HOOK);

    // Same variant again: now it really is unchanged.
    let again = run_in(repo.path(), &["init", "--claude", "--self-measure"]);
    assert!(again.status.success(), "{}", stderr(&again));
    assert!(
        stdout(&again).contains(&format!("already runs `{SELF_MEASURE_HOOK}`"))
            && stdout(&again).contains("unchanged"),
        "{}",
        stdout(&again)
    );
    assert_eq!(installed_stop_command(repo.path()), SELF_MEASURE_HOOK);

    // self-measure -> plain: the rewrite works in both directions.
    let lowered = run_in(repo.path(), &["init", "--claude"]);
    assert!(lowered.status.success(), "{}", stderr(&lowered));
    assert!(
        stdout(&lowered).contains(&format!("it ran `{SELF_MEASURE_HOOK}`")),
        "{}",
        stdout(&lowered)
    );
    assert_eq!(installed_stop_command(repo.path()), PLAIN_HOOK);

    // The foreign hook rode through every rewrite untouched.
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    let stop = after["hooks"]["Stop"].as_array().unwrap();
    assert_eq!(stop.len(), 2, "theirs and ours: {stop:?}");
    assert_eq!(stop[0]["hooks"][0]["command"], "somebody-elses-hook");
}

#[test]
fn an_unparseable_settings_file_is_refused_never_clobbered() {
    let repo = scratch();
    let settings = repo.path().join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(&settings, "{ not json").unwrap();

    let output = run_in(repo.path(), &["init", "--claude"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not valid JSON"),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        std::fs::read_to_string(&settings).unwrap(),
        "{ not json",
        "the broken file must be exactly as the installer found it"
    );
}

#[test]
fn cursor_installs_the_gate_where_git_says_hooks_live() {
    let repo = scratch();
    let installed = run_in(repo.path(), &["init", "--cursor"]);
    assert!(installed.status.success(), "{}", stderr(&installed));

    let hook = repo.path().join(".git").join("hooks").join("pre-commit");
    let script = std::fs::read_to_string(&hook).expect("the gate exists");
    assert!(script.contains("exec andon hook pre-commit"), "{script}");
    assert!(script.starts_with("#!/bin/sh"), "a hook needs a shebang");

    let rules = repo.path().join(".cursor").join("rules").join("andon.mdc");
    let rules_text = std::fs::read_to_string(&rules).expect("the rules file exists");
    assert!(
        rules_text.contains("discoverability only"),
        "the rules file must say it is not the gate: {rules_text}"
    );

    let removed = run_in(repo.path(), &["init", "--cursor", "--remove"]);
    assert!(removed.status.success(), "{}", stderr(&removed));
    assert!(!hook.exists());
    assert!(!rules.exists());
}

#[test]
fn a_foreign_pre_commit_hook_is_refused_with_the_line_to_add() {
    let repo = scratch();
    let hook = repo.path().join(".git").join("hooks").join("pre-commit");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, "#!/bin/sh\nmake lint\n").unwrap();

    let output = run_in(repo.path(), &["init", "--cursor"]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(
        message.contains("andon hook pre-commit"),
        "the refusal must hand over the exact line to add: {message}"
    );
    assert_eq!(
        std::fs::read_to_string(&hook).unwrap(),
        "#!/bin/sh\nmake lint\n",
        "somebody else's hook must be exactly as the installer found it"
    );
}

#[test]
fn init_ci_prints_the_committed_recipe() {
    let repo = scratch();
    let output = run_in(repo.path(), &["init", "--ci"]);
    assert!(output.status.success());
    let recipe = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("docs")
            .join("ci-recipe.md"),
    )
    .expect("the recipe is committed");
    assert_eq!(
        stdout(&output).trim_end(),
        recipe.trim_end(),
        "the printed recipe is the committed document, byte for byte"
    );
}

/// Run `andon hook claude-stop` the way Claude Code runs it: JSON on stdin.
fn run_stop_hook(repo: &Path) -> Output {
    let mut child = Command::new(EXE)
        .args(["hook", "claude-stop", "--repo"])
        .arg(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("andon runs");
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(br#"{"hook_event_name": "Stop", "stop_hook_active": false}"#)
        .expect("stdin written");
    child.wait_with_output().expect("hook finishes")
}

#[test]
fn the_stop_hook_gate_blocks_fixes_and_passes() {
    let repo = scratch();

    // Nothing in flight: silence, exit 0. A chat-only session never hears
    // from the gate.
    let quiet = run_stop_hook(repo.path());
    assert_eq!(quiet.status.code(), Some(0), "{}", stderr(&quiet));
    assert!(stdout(&quiet).is_empty(), "{}", stdout(&quiet));
    assert!(stderr(&quiet).is_empty(), "{}", stderr(&quiet));

    // A tangled change in flight: exit 2 blocks the stop, and stderr — the
    // stream Claude Code feeds back to the agent — carries the profile with
    // an actionable location.
    std::fs::write(repo.path().join("src.ts"), TANGLED).unwrap();
    let blocked = run_stop_hook(repo.path());
    assert_eq!(blocked.status.code(), Some(2), "{}", stderr(&blocked));
    let fed_back = stderr(&blocked);
    assert!(fed_back.contains("BLOCK"), "{fed_back}");
    let profile_line = fed_back
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("the agent profile rides on stderr");
    let profile: serde_json::Value = serde_json::from_str(profile_line).expect("parseable");
    assert_eq!(profile["profile"], "agent-mode");
    assert_eq!(profile["verdict"], "block");
    assert!(
        profile["findings"].as_array().unwrap().iter().any(|f| {
            f["scope"]
                .as_str()
                .is_some_and(|s| s.starts_with("src.ts:1-") && s.ends_with(":classify"))
        }),
        "the finding is located to path, span, and symbol: {profile}"
    );

    // The fix: exit 0, and the transcript line says what was measured.
    std::fs::write(
        repo.path().join("src.ts"),
        "export function classify(x: number): number {\n  return x > 0 ? 1 : 0;\n}\n// fixed\n",
    )
    .unwrap();
    let passed = run_stop_hook(repo.path());
    assert_eq!(passed.status.code(), Some(0), "{}", stderr(&passed));
    assert!(stdout(&passed).contains("PASS"), "{}", stdout(&passed));
}
