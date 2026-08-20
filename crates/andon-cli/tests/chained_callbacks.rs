//! `andon measure` on a repository that contains a method chain.
//!
//! # The failure this file exists to prevent
//!
//! Reported against the binary, on a real repository: a vendored bundle with two
//! anonymous functions on one line ended the command with exit 1 and no
//! measurement at all. Two callbacks in one chain produced one scope, one scope
//! produced two identical pairing keys, and `payload::prepare` refuses a payload
//! whose pairing key names two results. The refusal is right; the collision was
//! manufactured out of ordinary code, and every repository containing
//! `.map().filter()` was unmeasurable.
//!
//! Exit 1 is the code for "the tool could not do its job", which is what makes
//! this a subprocess test rather than a library one: an engine-level assertion
//! about symbols would have passed throughout, and the thing a user met was the
//! exit code.
//!
//! The repository is built here rather than under `fixtures/golden`: the golden
//! corpus is frozen, and a case whose only purpose is to reach a refusal does not
//! belong in the reference payloads.

use std::path::Path;
use std::process::Command;

use andon_core::git::Git;
use andon_core::schema::payload::{MeasurementRecord, ScopeKind};

const EXE: &str = env!("CARGO_BIN_EXE_andon");

/// The shapes the defect was reported on, in the languages it was reported in.
const CHAINS: &[(&str, &str)] = &[
    (
        "src/chain.ts",
        "export const out = xs.map(x => x * 2).filter(x => x > 0);\n",
    ),
    (
        "src/promise.js",
        "fetch(u).then(r => r.json()).catch(e => log(e));\n",
    ),
    (
        "src/jquery.js",
        "$(\".a\").on(\"click\", function () { hide(); }).on(\"blur\", function () { hide(); });\n",
    ),
    (
        "src/lambdas.py",
        "xs = list(map(lambda x: x + 1, filter(lambda x: x > 0, ys)))\n",
    ),
    // The reported file's own shape: many anonymous functions on one line, as a
    // minifier writes them.
    (
        "vendor/bundle.min.js",
        "var f=[function(a){return a},function(b){return b},function(c){return c}];\n",
    ),
];

/// A repository holding a base commit and the chain files, staged.
///
/// Every git call goes through `Git::cmd` for the reason the golden builder does
/// it: a repository built with a bare `git` inherits whichever `core.autocrlf`
/// the machine carries, and this suite would then pass or fail per developer.
fn chain_repo() -> (tempfile::TempDir, String) {
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
        ("core.eol", "lf"),
    ] {
        git.cmd(["config", key, value])
            .output()
            .unwrap_or_else(|e| panic!("config {key}: {e}"));
    }

    std::fs::write(temp.path().join("README.md"), b"base\n").expect("write");
    git.cmd(["add", "--all", "."]).output().expect("git add");
    git.cmd(["commit", "--quiet", "-m", "base"])
        .output()
        .expect("git commit");
    let base = git
        .cmd(["rev-parse", "HEAD"])
        .text()
        .expect("rev-parse")
        .trim()
        .to_string();

    for (path, source) in CHAINS {
        let full = temp.path().join(path);
        std::fs::create_dir_all(full.parent().expect("a parent")).expect("create parent");
        std::fs::write(full, source.as_bytes()).expect("write");
    }
    git.cmd(["add", "--all", "."]).output().expect("git add");

    (temp, base)
}

#[test]
fn a_repository_full_of_method_chains_measures_rather_than_failing() {
    let (repo, base) = chain_repo();
    let output = Command::new(EXE)
        .args([
            "measure",
            "--repo",
            repo.path().to_str().expect("utf-8"),
            "--base",
            &base,
            "--json",
        ])
        .output()
        .expect("andon runs");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    // 1 is "the tool could not do its job". A verdict of `block` is 2 and is not
    // this test's business — what is, is that the tool answered at all.
    assert_ne!(
        output.status.code(),
        Some(1),
        "the tool failed instead of measuring:\n{stderr}"
    );
    assert!(
        !stderr.contains("pairing key"),
        "assembly refused an ordinary method chain:\n{stderr}"
    );

    let record: MeasurementRecord =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}\nstderr: {stderr}"));

    // Every chain file is measured, and both of its callbacks are there. A fix
    // that dropped one site would also have stopped the abort, and would have
    // replaced a loud refusal with a quiet undercount.
    for (path, _) in CHAINS {
        let symbols: Vec<&str> = record
            .results
            .iter()
            .filter(|r| r.scope.kind == ScopeKind::Function)
            .filter(|r| r.scope.path.as_deref() == Some(path))
            .filter(|r| r.metric_id == "static.sloc")
            .filter_map(|r| r.scope.symbol.as_deref())
            .collect();
        assert!(symbols.len() >= 2, "{path}: {symbols:?}");
        let distinct: std::collections::BTreeSet<&str> = symbols.iter().copied().collect();
        assert_eq!(distinct.len(), symbols.len(), "{path}: {symbols:?}");
    }
}
