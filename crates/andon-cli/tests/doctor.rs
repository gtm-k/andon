//! `andon doctor`, driven as a person about to file a false-positive issue
//! drives it (PLAN P10a-adoption; round-1 5.2, the S6 disconnection
//! replacement).
//!
//! Every test runs the real binary and reads the file it wrote, because the
//! requirement is about what leaves the machine. The bundle is pasted into a
//! PUBLIC issue, so the property under test is what it must NOT contain, and
//! that is a property of the bytes on disk rather than of a library type.
//!
//! # The sentinels
//!
//! The scratch repository is built to leak. Its source carries a marker
//! string, its head commit's message is a marker, and its author is a marker —
//! each a thing the bundle must never carry. None of them is a symbol name,
//! because a symbol is the one thing the bundle carries on purpose: a
//! false-positive report without `src.ts:classify` is a report about nothing.
//! The redaction test asserts both halves — the location is there, the
//! sentinels and the temporary directory's path are not — so it cannot pass on
//! an empty bundle.
//!
//! # Paths are checked on parsed strings, in both separator forms
//!
//! A raw `contains` over the file text cannot catch a leaked Windows path: JSON
//! escapes the backslashes, so `C:\Users\...` would sit on disk as
//! `C:\\Users\\...` and the assertion would pass over the very failure it
//! exists for. The check walks every string value of the parsed document and
//! asks for the temporary directory in the form git reports it and the form
//! the OS does.

mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Output};

use andon_core::git::Git;
use andon_core::policy::Policy;
use serde_json::Value;

const EXE: &str = env!("CARGO_BIN_EXE_andon");

/// The file `andon doctor` writes into the current directory.
const BUNDLE: &str = "andon-doctor.json";

/// A string in the source. Inside a string literal, so it is content and not a
/// symbol.
const CODE_SENTINEL: &str = "SECRET_SENTINEL_9f3a";
/// The head commit's message.
const MESSAGE_SENTINEL: &str = "SECRET_COMMIT_MESSAGE_7b2c";
/// The author of every commit.
const AUTHOR_SENTINEL: &str = "Sentinel Author 5d1e";
/// The author's email.
const EMAIL_SENTINEL: &str = "sentinel-5d1e@andon.invalid";

/// The P6 convergence shape — cognitive complexity past the Medium rung — with
/// the code sentinel inside it, so the one function the bundle will name by
/// symbol is also the one whose body must not appear.
const TANGLED: &str = concat!(
    "export function classify(x: number): number {\n",
    "  const marker = 'SECRET_SENTINEL_9f3a';\n",
    "  let out = marker.length;\n",
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

/// A policy that loosens one gate against the conservative defaults, in the
/// root `.andon.toml`'s own shape.
const LOOSENED_POLICY: &str = "schema_version = 1\n\n[severity]\nblock_on_tamper = false\n";

/// A repository with a root commit and one committed change that crosses the
/// Medium rung, authored and described by the sentinels. `policy` is written
/// as `.andon.toml` before the root commit when given.
fn scratch(policy: Option<&str>) -> (tempfile::TempDir, String, String) {
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
        ("user.name", AUTHOR_SENTINEL),
        ("user.email", EMAIL_SENTINEL),
        ("core.autocrlf", "false"),
    ] {
        git.cmd(["config", key, value]).output().expect("config");
    }

    let commit = |message: &str| {
        git.cmd(["add", "--all", "."]).output().expect("add");
        git.cmd(["commit", "--quiet", "-m", message])
            .env("GIT_AUTHOR_NAME", AUTHOR_SENTINEL)
            .env("GIT_AUTHOR_EMAIL", EMAIL_SENTINEL)
            .env("GIT_AUTHOR_DATE", common::FIXTURE_DATE)
            .env("GIT_COMMITTER_NAME", AUTHOR_SENTINEL)
            .env("GIT_COMMITTER_EMAIL", EMAIL_SENTINEL)
            .env("GIT_COMMITTER_DATE", common::FIXTURE_DATE)
            .output()
            .expect("commit");
        git.cmd(["rev-parse", "HEAD"])
            .text()
            .expect("rev-parse")
            .trim()
            .to_string()
    };

    if let Some(text) = policy {
        std::fs::write(temp.path().join(".andon.toml"), text).expect("write policy");
    }
    std::fs::write(
        temp.path().join("src.ts"),
        "export function a(x: number) {\n  return x;\n}\n",
    )
    .expect("write");
    let base = commit("root");

    std::fs::write(temp.path().join("src.ts"), TANGLED).expect("write");
    let head = commit(MESSAGE_SENTINEL);
    (temp, base, head)
}

/// [`scratch`], measured and recorded through the real binary — the state a
/// person filing a false-positive report is in.
fn measured_scratch(policy: Option<&str>) -> tempfile::TempDir {
    let (temp, base, head) = scratch(policy);
    let measured = run_in(
        temp.path(),
        &[
            "measure",
            "--base",
            &base,
            "--head",
            &head,
            "--record",
            "--exit-zero",
        ],
    );
    assert!(
        measured.status.success(),
        "measure --record failed: {}",
        String::from_utf8_lossy(&measured.stderr)
    );
    temp
}

fn run_in(repo: &Path, args: &[&str]) -> Output {
    Command::new(EXE)
        .args(args)
        .arg("--repo")
        .arg(repo)
        .current_dir(repo)
        .output()
        .expect("andon runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Run `andon doctor` in `repo` — given the repository's ABSOLUTE path, the
/// harder case, because a path the tool was handed is a path it could echo —
/// and return the confirmation line and the parsed bundle.
fn doctor(repo: &Path) -> (String, String, Value) {
    let output = run_in(repo, &["doctor"]);
    assert!(
        output.status.success(),
        "doctor failed: exit {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(repo.join(BUNDLE)).unwrap_or_else(|e| {
        panic!("doctor did not write {BUNDLE} into the current directory: {e}")
    });
    // `from_str` refuses trailing content, so this is also the "one document"
    // assertion: two concatenated objects, or a report printed after the JSON,
    // fail here.
    let value: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{BUNDLE} is not one JSON document: {e}\n{text}"));
    (stdout(&output), text, value)
}

/// Every string value in a JSON document, wherever it sits.
fn strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
        Value::Object(map) => map.values().for_each(|v| strings(v, out)),
        _ => {}
    }
}

#[test]
fn the_bundle_is_one_json_document_with_the_declared_keys() {
    let repo = measured_scratch(None);
    let (said, _, bundle) = doctor(repo.path());

    // The confirmation names the file, so the person knows what to paste.
    assert!(said.contains(BUNDLE), "{said}");

    let keys: BTreeSet<&str> = bundle
        .as_object()
        .expect("the bundle is a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    let declared: BTreeSet<&str> = [
        "schema_version",
        "bundle",
        "redaction",
        "redactions",
        "andon_version",
        "rule_pack_version",
        "platform",
        "git_version",
        "repository",
        "policy",
        "regimes",
        "last_measurement",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, declared);

    // The two constants are the workspace's own, read off the crates that
    // declare them rather than restated here.
    assert_eq!(bundle["andon_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        bundle["rule_pack_version"],
        andon_engine_tamper::syntax::RULE_PACK_VERSION
    );
    assert_eq!(bundle["platform"]["os"], std::env::consts::OS);
    assert_eq!(bundle["platform"]["arch"], std::env::consts::ARCH);
    assert!(
        bundle["git_version"]
            .as_str()
            .is_some_and(|v| v.starts_with("git version")),
        "{}",
        bundle["git_version"]
    );

    // The repository is named by its basename and nothing longer.
    let basename = repo
        .path()
        .file_name()
        .expect("the temp dir has a name")
        .to_string_lossy()
        .into_owned();
    assert_eq!(bundle["repository"], basename);

    // The measurement half carries what a triage needs, and the two fields the
    // agent profile computes are there by their own names.
    let last = &bundle["last_measurement"];
    assert!(last.is_object(), "{last}");
    for key in [
        "verdict",
        "reasons",
        "finding_count",
        "findings",
        "policy_hash",
        "agent_profile",
    ] {
        assert!(
            last.get(key).is_some(),
            "last_measurement lacks {key}: {last}"
        );
    }
    assert!(last["agent_profile"]["truncated"].is_boolean());
    assert!(last["agent_profile"]["total_reasons"].is_u64());
    assert_eq!(
        last["finding_count"].as_u64(),
        Some(last["findings"].as_array().expect("findings").len() as u64)
    );
    assert!(
        last["reasons"]
            .as_array()
            .expect("reasons")
            .iter()
            .all(|r| r["code"].is_string() && r["message"].is_string()),
        "{}",
        last["reasons"]
    );
}

#[test]
fn nothing_from_the_repository_but_paths_and_symbols_reaches_the_bundle() {
    let repo = measured_scratch(None);
    let (_, text, bundle) = doctor(repo.path());
    let mut values = Vec::new();
    strings(&bundle, &mut values);

    // The half that must be there, so an empty bundle cannot pass this test:
    // the finding's location, path and symbol.
    let findings = bundle["last_measurement"]["findings"]
        .as_array()
        .expect("findings");
    assert!(
        !findings.is_empty(),
        "the change crosses the Medium rung; nothing fired: {bundle}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f["path"] == "src.ts" && f["symbol"] == "classify"),
        "no finding names src.ts:classify: {findings:?}"
    );

    // The half that must not be: content, message, author.
    for sentinel in [
        CODE_SENTINEL,
        MESSAGE_SENTINEL,
        AUTHOR_SENTINEL,
        EMAIL_SENTINEL,
    ] {
        assert!(!text.contains(sentinel), "{sentinel} leaked:\n{text}");
    }

    // No absolute path, in either separator form, in any string value. The
    // form git reports (`toplevel`, forward slashes on every OS) and the form
    // the OS handed the test are both asked for, and so are their mirrors.
    let toplevel = Git::open(repo.path())
        .expect("a repository")
        .facts()
        .toplevel
        .display()
        .to_string();
    let native = repo.path().display().to_string();
    let forms: BTreeSet<String> = [&toplevel, &native]
        .into_iter()
        .flat_map(|p| [p.clone(), p.replace('\\', "/"), p.replace('/', "\\")])
        .collect();
    for value in &values {
        for form in &forms {
            assert!(
                !value.contains(form.as_str()),
                "an absolute path leaked into the bundle: {value}"
            );
        }
    }
}

#[test]
fn the_regimes_are_the_ones_fp_window_reports_for_the_same_repo() {
    let repo = measured_scratch(None);

    // What `ledger fp-window` prints for the one recorded change: one label per
    // regime, each with its record count.
    let fp = run_in(
        repo.path(),
        &["ledger", "fp-window", "--since", "2020-01-01T00:00:00Z"],
    );
    let report = stdout(&fp);
    assert!(fp.status.success(), "{report}");
    let line = report
        .lines()
        .map(str::trim_start)
        .find(|l| l.starts_with("regimes"))
        .unwrap_or_else(|| panic!("fp-window printed no regimes line:\n{report}"));
    let rest = line.strip_prefix("regimes").expect("prefix").trim();
    assert!(
        !rest.starts_with("none"),
        "the window holds the recorded change, so regimes cannot be empty: {line}"
    );
    let expected: BTreeSet<String> = rest
        .split(" · ")
        .map(|part| {
            part.rsplit_once(" (")
                .unwrap_or_else(|| panic!("no record count on '{part}'"))
                .0
                .to_string()
        })
        .collect();
    assert!(!expected.is_empty());

    let (_, _, bundle) = doctor(repo.path());
    let regimes = bundle["regimes"].as_array().expect("regimes");
    let got: BTreeSet<String> = regimes
        .iter()
        .map(|r| r["label"].as_str().expect("a label").to_string())
        .collect();
    assert_eq!(got, expected, "\nfp-window:\n{report}\ndoctor:\n{bundle}");

    // One regime per family, carried as the regime's own family rather than
    // parsed out of the label.
    let families: BTreeSet<&str> = regimes
        .iter()
        .map(|r| r["family"].as_str().expect("a family"))
        .collect();
    assert_eq!(families.len(), regimes.len(), "{regimes:?}");
}

#[test]
fn the_policy_diff_is_the_one_fp_window_reports() {
    let repo = measured_scratch(Some(LOOSENED_POLICY));

    let fp = run_in(
        repo.path(),
        &["ledger", "fp-window", "--since", "2020-01-01T00:00:00Z"],
    );
    let report = stdout(&fp);
    assert!(fp.status.success(), "{report}");
    // Each delta is printed on its own line as `field: before -> after (direction)`.
    let expected: Vec<String> = report
        .lines()
        .map(str::trim)
        .filter(|l| {
            l.contains(": ") && l.contains(" -> ") && l.ends_with(')') && !l.starts_with("->")
        })
        .map(str::to_string)
        .collect();
    assert_eq!(
        expected,
        vec!["severity.block_on_tamper: true -> false (loosens)".to_string()],
        "{report}"
    );

    let (_, _, bundle) = doctor(repo.path());
    let got: Vec<String> = bundle["policy"]["diff_vs_defaults"]
        .as_array()
        .expect("diff_vs_defaults")
        .iter()
        .map(|d| d.as_str().expect("a described delta").to_string())
        .collect();
    assert_eq!(got, expected);
    assert_eq!(bundle["policy"]["loosenings"], 1);

    // The hash is of the policy in force, the one a fresh measurement would
    // stamp — derived from the same text through the same digest.
    let in_force = Policy::from_toml(LOOSENED_POLICY).expect("the fixture policy parses");
    assert_eq!(
        bundle["policy"]["hash"],
        in_force.policy_hash().expect("hashes")
    );
    // And the record was measured under that same policy.
    assert_eq!(
        bundle["last_measurement"]["policy_hash"],
        bundle["policy"]["hash"]
    );
}

#[test]
fn no_prior_measurement_still_yields_a_bundle_with_last_measurement_null() {
    let (repo, _, _) = scratch(None);
    let (said, _, bundle) = doctor(repo.path());
    assert!(said.contains(BUNDLE), "{said}");

    assert!(bundle["last_measurement"].is_null(), "{bundle}");
    // Regimes are read off the last measurement's results; with none, there is
    // nothing to read and the list says so by being empty rather than by
    // guessing what a measurement would have stamped.
    assert_eq!(bundle["regimes"], Value::Array(Vec::new()));
    // No `.andon.toml`: the conservative defaults are in force, and the hash
    // is theirs.
    assert_eq!(
        bundle["policy"]["hash"],
        Policy::default().policy_hash().expect("hashes")
    );
    assert_eq!(
        bundle["policy"]["diff_vs_defaults"],
        Value::Array(Vec::new())
    );
    assert_eq!(bundle["policy"]["loosenings"], 0);
    assert_eq!(
        bundle["rule_pack_version"],
        andon_engine_tamper::syntax::RULE_PACK_VERSION
    );
}
