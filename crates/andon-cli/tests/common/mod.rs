//! Building the golden fixture repositories from committed data.
//!
//! # Why the repositories are built rather than committed
//!
//! A golden set needs frozen fixture repositories, and a git repository cannot
//! be committed inside a git repository. The alternative to a bundle — which is
//! opaque in a diff and version-sensitive — is to commit the *inputs* and build
//! the repository deterministically, which is what happens here.
//!
//! Deterministic means byte-for-byte reproducible commit OIDs, and that is a
//! requirement rather than a nicety: `base_oid` and `head_oid` are inside
//! `ResultDigestInput`, so every per-result digest in the reference payload is a
//! function of them. Author, committer, both dates, the message, and the tree
//! are all fixed here, and the object format is pinned to SHA-1 so that a
//! developer whose global git config sets `init.defaultObjectFormat = sha256`
//! gets the same OIDs as CI rather than a wall of red.
//!
//! Every git invocation goes through `Git::cmd`, so the fixture is built by the
//! same hygienic spawn path the code under test uses — a fixture built with the
//! ambient environment would inherit whatever `core.autocrlf` the machine
//! carries, and the digests this suite exists to pin would be pinned to that
//! machine.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use andon_core::git::Git;

/// Fixed identity for every fixture commit.
pub const FIXTURE_NAME: &str = "Andon Golden";
/// Fixed email for every fixture commit.
pub const FIXTURE_EMAIL: &str = "golden@andon.invalid";
/// Fixed timestamp: 2026-01-01T00:00:00Z, in git's `<epoch> <offset>` form.
pub const FIXTURE_DATE: &str = "1767225600 +0000";

/// One step of a fixture repository: write these files, remove those, commit.
#[derive(Debug, serde::Deserialize)]
pub struct Step {
    /// Directory under `steps/` holding the files this step writes.
    pub id: String,
    /// Commit message. Part of the OID, so it is committed data.
    pub message: String,
    /// Repository-relative paths this step deletes.
    #[serde(default)]
    pub remove: Vec<String>,
}

/// A golden case as committed data.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// Case schema version.
    pub schema_version: u32,
    /// Case name; matches the directory.
    pub name: String,
    /// What this case is for, in a sentence a reviewer can check.
    pub description: String,
    /// Step id measured as the base.
    pub base: String,
    /// Step id measured as the head.
    pub head: String,
    /// Ordered steps.
    #[serde(rename = "step")]
    pub steps: Vec<Step>,
}

/// A built fixture repository.
pub struct Built {
    /// Where it lives. Held so the temporary directory outlives the handle.
    pub dir: tempfile::TempDir,
    /// Base commit OID.
    pub base_oid: String,
    /// Head commit OID.
    pub head_oid: String,
}

impl Built {
    /// The working tree root.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

/// The `fixtures/golden` directory, resolved from this crate rather than from
/// the current working directory.
pub fn golden_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("golden")
}

/// Every case directory, sorted.
pub fn cases() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(golden_root())
        .expect("fixtures/golden exists")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.join("case.toml").is_file())
        .collect();
    dirs.sort();
    dirs
}

/// Read a case definition.
pub fn read_case(dir: &Path) -> Case {
    let text = std::fs::read_to_string(dir.join("case.toml"))
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    toml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
}

/// Build a case into a fresh temporary repository.
pub fn build(dir: &Path, case: &Case) -> Built {
    let temp = tempfile::tempdir().expect("a temporary directory");
    // `Git::open` needs a repository, so the very first invocation cannot come
    // from a handle onto the fixture. The workspace's own repository lends one,
    // resolved from the manifest directory rather than from the current working
    // directory, which a test runner does not promise.
    let bootstrap = Git::open(Path::new(env!("CARGO_MANIFEST_DIR")))
        .expect("the workspace is a git repository");
    bootstrap
        .cmd([
            "init",
            "--quiet",
            "--initial-branch=main",
            // Pinned so a machine whose global config prefers SHA-256 still
            // produces the OIDs the reference payloads were recorded against.
            "--object-format=sha1",
        ])
        .arg(temp.path())
        .output()
        .expect("git init");

    let git = Git::open(temp.path()).expect("the fixture is a git repository");
    git.cmd(["config", "user.name", FIXTURE_NAME])
        .output()
        .expect("config user.name");
    git.cmd(["config", "user.email", FIXTURE_EMAIL])
        .output()
        .expect("config user.email");
    // The bytes this repository commits must not depend on whose machine built
    // it. `GIT_CONFIG_NOSYSTEM` keeps `/etc/gitconfig` out, but the *global*
    // config still reaches `git add` — and `core.autocrlf` there decides whether
    // a CRLF working-tree file becomes a CRLF blob or an LF one. Two answers,
    // two blobs, two commit OIDs, and every reference digest is a function of
    // the OIDs. Pinned here rather than assumed, so a contributor whose global
    // config says `true` records the same fixture as CI does.
    for (key, value) in [("core.autocrlf", "false"), ("core.eol", "lf")] {
        git.cmd(["config", key, value])
            .output()
            .unwrap_or_else(|e| panic!("config {key}: {e}"));
    }

    let mut base_oid = String::new();
    let mut head_oid = String::new();
    for step in &case.steps {
        let source = dir.join("steps").join(&step.id);
        if source.is_dir() {
            copy_tree(&source, git.workdir());
        }
        for path in &step.remove {
            let full = git.workdir().join(path);
            if full.exists() {
                std::fs::remove_file(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()));
            }
        }
        git.cmd(["add", "--all", "."]).output().expect("git add");
        let oid = commit(&git, &step.message);
        if step.id == case.base {
            base_oid = oid.clone();
        }
        if step.id == case.head {
            head_oid = oid;
        }
    }
    assert!(!base_oid.is_empty(), "{}: no step matches base", case.name);
    assert!(!head_oid.is_empty(), "{}: no step matches head", case.name);

    Built {
        dir: temp,
        base_oid,
        head_oid,
    }
}

/// Commit whatever is staged, at the fixed identity and timestamp.
fn commit(git: &Git, message: &str) -> String {
    git.cmd(["commit", "--quiet", "--allow-empty", "-m", message])
        .env("GIT_AUTHOR_NAME", FIXTURE_NAME)
        .env("GIT_AUTHOR_EMAIL", FIXTURE_EMAIL)
        .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
        .env("GIT_COMMITTER_NAME", FIXTURE_NAME)
        .env("GIT_COMMITTER_EMAIL", FIXTURE_EMAIL)
        .env("GIT_COMMITTER_DATE", FIXTURE_DATE)
        .output()
        .expect("git commit");
    git.cmd(["rev-parse", "HEAD"])
        .text()
        .expect("rev-parse")
        .trim()
        .to_string()
}

/// Copy a step's tree over the working tree, byte for byte.
///
/// Bytes go down exactly as they are in the fixture — no newline translation —
/// because a fixture whose line endings depend on the checkout is a fixture that
/// pins its digests to one machine's `core.autocrlf`.
fn copy_tree(source: &Path, dest: &Path) {
    for entry in std::fs::read_dir(source).expect("a step directory") {
        let entry = entry.expect("a directory entry");
        let target = dest.join(entry.file_name());
        if entry.path().is_dir() {
            std::fs::create_dir_all(&target).expect("directory");
            copy_tree(&entry.path(), &target);
        } else {
            let bytes = std::fs::read(entry.path()).expect("fixture bytes");
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).expect("parent directory");
            }
            std::fs::write(&target, bytes).expect("write fixture file");
        }
    }
}
