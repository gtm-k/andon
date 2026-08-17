//! The cross-OS matrix fixture, built from committed bytes.
//!
//! # Why P2 builds its own instead of reusing the spike's
//!
//! P1.5's `scenario` module builds fixtures too, and its manifests are richer:
//! they stage attacks, run the spike's measurement, and — the part that matters
//! — commit **what the verifier must conclude**, which the scenario suite then
//! checks. Its own documentation explains why that matters: an expectation
//! written beside the assertion is a test that can be quietly relaxed while
//! still looking green.
//!
//! A P2 matrix fixture has no attestation expectation to commit. Reusing that
//! manifest format would mean writing a `verify.expect` value that nothing ever
//! checks — a committed claim with no verification behind it, which is the exact
//! anti-pattern the format was designed against. So this is a smaller builder
//! for a smaller job: commits, bytes, and the one expectation P2 *does* have, the
//! result count, which `tests/matrix_fixture.rs` checks on every run.
//!
//! # The bytes are the point
//!
//! The fixture carries LF files, CRLF files, a file with both, a file that ends
//! without a terminator, a CJK path, and a file that does not parse. It carries
//! **no** `.gitattributes`, so a matrix leg cloning it gets whatever its
//! runner's git does to the working tree — CRLF everywhere on a default Windows
//! install, which is PREMORTEM Story 1's setup reproduced on purpose. The
//! compared lane reads blobs, so the digests must agree anyway.
//!
//! The deliberately-broken file is load-bearing rather than decorative:
//! `completeness: parse-degraded` is **inside** the per-result digest input, so
//! the matrix does not merely show that clean files agree — it shows that three
//! operating systems agree about which file was degraded and by how much.
//!
//! CJK rather than accented Latin, for the reason `scenario.rs` records: macOS
//! normalizes filenames to NFD, so a path containing `ü` would decompose on one
//! leg and not the others — a digest mismatch on a fixture nobody tampered with.
//! CJK code points have no decomposed form.
//!
//! Construction is pinned. Every git invocation goes through
//! [`andon_core::git::Git::cmd`], which forces `core.autocrlf=false`, and author
//! identity and timestamps are fixed — so the same manifest produces the same
//! commit OIDs on every platform, and a failing matrix leg is reproducible from
//! the fixture name alone.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use andon_core::git::{Git, GitError};
use serde::{Deserialize, Serialize};

/// Fixed identity and clock for fixture commits. Same values and same reasoning
/// as the spike's scenario builder: everything that feeds a commit OID is
/// stated.
const FIXTURE_NAME: &str = "Andon Fixture";
const FIXTURE_EMAIL: &str = "fixture@andon.invalid";
const FIXTURE_EPOCH: i64 = 1_767_225_600;

/// A fixture could not be read or built.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// The manifest is not valid TOML for this schema.
    #[error("{path}: {source}")]
    Manifest {
        /// Manifest that failed to parse.
        path: String,
        /// The parse failure.
        #[source]
        source: toml::de::Error,
    },
    /// Well-formed TOML that is still not a buildable fixture.
    #[error("{path}: {detail}")]
    Invalid {
        /// Manifest at fault.
        path: String,
        /// What is wrong with it.
        detail: String,
    },
    /// Filesystem work failed.
    #[error("{detail}: {source}")]
    Io {
        /// What was being attempted.
        detail: String,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// A git command failed.
    #[error(transparent)]
    Git(#[from] GitError),
}

/// One fixture, as committed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Manifest schema version. Only `1` is accepted.
    pub schema_version: u32,
    /// Fixture id, matching its file name.
    pub name: String,
    /// Why this fixture exists, and what a change to it would mean.
    pub rationale: String,
    /// Branch the commits land on.
    pub branch: String,
    /// How many results the static engine must produce over `base..head`.
    ///
    /// A floor stated in the manifest rather than read off whatever the run
    /// produced. Four legs that each measured nothing agree perfectly about
    /// nothing, and every digest assertion would be vacuously true.
    pub expect_result_count: usize,
    /// Ordered commits. The first is the base, the last is the head.
    #[serde(rename = "commit")]
    pub commits: Vec<Commit>,
}

/// One commit in a fixture.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    /// Label the resulting commit is known by.
    pub label: String,
    /// Commit message.
    pub message: String,
    /// Files to write. TOML escapes (`\r`, `\n`, `\u00XX`) make the bytes
    /// explicit, which is the whole reason the fixture is data rather than a
    /// shell script writing here-documents on three operating systems.
    #[serde(default, rename = "file")]
    pub files: Vec<FileSpec>,
    /// Paths to delete.
    #[serde(default)]
    pub remove: Vec<String>,
}

/// One file in a commit.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSpec {
    /// Repository-relative path, forward slashes.
    pub path: String,
    /// Exact contents.
    pub text: String,
}

/// A built fixture, ready to measure.
#[derive(Debug, Clone, Serialize)]
pub struct Prepared {
    /// Fixture id.
    pub name: String,
    /// Working tree of the fixture repository.
    pub repo: PathBuf,
    /// Branch the commits are on.
    pub branch: String,
    /// The base of the measured range: the first commit.
    pub base: String,
    /// The head of the measured range: the last commit.
    pub head: String,
    /// The committed result-count floor.
    pub expect_result_count: usize,
    /// Every label, resolved to an OID. Useful when a matrix leg has to be
    /// debugged from CI output alone.
    pub labels: BTreeMap<String, String>,
}

/// Load and validate a manifest.
pub fn load(path: &Path) -> Result<Manifest, FixtureError> {
    let display = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| FixtureError::Io {
        detail: format!("read manifest {display}"),
        source,
    })?;
    let manifest: Manifest = toml::from_str(&text).map_err(|source| FixtureError::Manifest {
        path: display.clone(),
        source,
    })?;
    if manifest.schema_version != 1 {
        return Err(FixtureError::Invalid {
            path: display,
            detail: format!(
                "unsupported manifest schema_version {} (expected 1)",
                manifest.schema_version
            ),
        });
    }
    if manifest.commits.len() < 2 {
        return Err(FixtureError::Invalid {
            path: display,
            detail: "a measured range needs a base commit and a head commit".to_string(),
        });
    }
    Ok(manifest)
}

/// Build the fixture repository.
///
/// `dest` is removed first: a fixture that reused a half-built repository would
/// be a fixture whose result depended on what ran before it.
pub fn build(manifest: &Manifest, dest: &Path) -> Result<Prepared, FixtureError> {
    if dest.exists() {
        std::fs::remove_dir_all(dest).map_err(|source| FixtureError::Io {
            detail: format!("clear {}", dest.display()),
            source,
        })?;
    }
    std::fs::create_dir_all(dest).map_err(|source| FixtureError::Io {
        detail: format!("create {}", dest.display()),
        source,
    })?;

    bootstrap_git()?
        .cmd(["init", "--quiet", "--initial-branch", &manifest.branch])
        .arg(dest)
        .output()?;
    let git = Git::open(dest)?;
    let repo = git.workdir().to_path_buf();

    let mut labels = BTreeMap::new();
    for (index, commit) in manifest.commits.iter().enumerate() {
        for file in &commit.files {
            let path = repo.join(&file.path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|source| FixtureError::Io {
                    detail: format!("create {}", parent.display()),
                    source,
                })?;
            }
            // The exact bytes the manifest declares. No newline translation
            // happens here, and none happens in `git add`, because `Git::cmd`
            // pins `core.autocrlf=false`.
            std::fs::write(&path, file.text.as_bytes()).map_err(|source| FixtureError::Io {
                detail: format!("write {}", path.display()),
                source,
            })?;
        }
        for path in &commit.remove {
            let full = repo.join(path);
            if full.exists() {
                std::fs::remove_file(&full).map_err(|source| FixtureError::Io {
                    detail: format!("remove {}", full.display()),
                    source,
                })?;
            }
        }
        git.cmd(["add", "--all", "."]).output()?;
        let stamp = format!("{} +0000", FIXTURE_EPOCH + index as i64 * 60);
        git.cmd(["commit", "--quiet", "--allow-empty", "-m", &commit.message])
            .env("GIT_AUTHOR_NAME", FIXTURE_NAME)
            .env("GIT_AUTHOR_EMAIL", FIXTURE_EMAIL)
            .env("GIT_COMMITTER_NAME", FIXTURE_NAME)
            .env("GIT_COMMITTER_EMAIL", FIXTURE_EMAIL)
            .env("GIT_AUTHOR_DATE", &stamp)
            .env("GIT_COMMITTER_DATE", &stamp)
            .output()?;
        let oid = git
            .cmd(["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"])
            .text()?
            .trim()
            .to_string();
        labels.insert(commit.label.clone(), oid);
    }

    let oid_of = |label: &str| -> Result<String, FixtureError> {
        labels
            .get(label)
            .cloned()
            .ok_or_else(|| FixtureError::Invalid {
                path: manifest.name.clone(),
                detail: format!("no commit labelled '{label}'"),
            })
    };
    let base = oid_of(&manifest.commits[0].label)?;
    let head = oid_of(&manifest.commits[manifest.commits.len() - 1].label)?;

    Ok(Prepared {
        name: manifest.name.clone(),
        repo,
        branch: manifest.branch.clone(),
        base,
        head,
        expect_result_count: manifest.expect_result_count,
        labels,
    })
}

/// A `Git` handle for spawning `git init`, which needs no repository of its own.
///
/// [`Git::open`] insists on being inside a repository and the destination is not
/// one yet — the same bootstrap the spike's scenario builder and the perf
/// fixture generator use. The current directory is tried first (CI runs inside a
/// checkout); this crate's source directory is the fallback.
fn bootstrap_git() -> Result<Git, FixtureError> {
    if let Ok(git) = Git::open(Path::new(".")) {
        return Ok(git);
    }
    Ok(Git::open(Path::new(env!("CARGO_MANIFEST_DIR")))?)
}

/// Path to the matrix fixture manifest inside this crate.
pub fn matrix_manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("matrix.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_matrix_manifest_loads() {
        let manifest = load(&matrix_manifest_path()).expect("the matrix fixture must load");
        assert_eq!(manifest.name, "static-determinism");
        assert!(manifest.expect_result_count > 0);
    }

    #[test]
    fn the_fixture_carries_the_bytes_the_matrix_is_about() {
        // Named rather than counted: each of these exists to break a specific
        // way of getting cross-OS determinism wrong, and a fixture that quietly
        // lost one would still look like a fixture.
        let manifest = load(&matrix_manifest_path()).expect("loads");
        let all: String = manifest
            .commits
            .iter()
            .flat_map(|commit| commit.files.iter())
            .map(|file| format!("{}\n{}", file.path, file.text))
            .collect();
        assert!(all.contains('\r'), "no CRLF content: Story 1 is not staged");
        assert!(
            all.chars().any(|c| c as u32 > 0x2E80),
            "no CJK path: non-ASCII path handling is not staged"
        );
        assert!(
            !manifest
                .commits
                .iter()
                .flat_map(|c| c.files.iter())
                .any(|f| f.path.ends_with(".gitattributes")),
            "a .gitattributes would normalize the working tree and make the \
             matrix pass for the wrong reason"
        );
    }

    #[test]
    fn a_manifest_with_one_commit_is_not_a_range() {
        let text = "schema_version = 1\nname = \"x\"\nrationale = \"x\"\nbranch = \"main\"\n\
                    expect_result_count = 1\n[[commit]]\nlabel = \"a\"\nmessage = \"a\"\n";
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("one.toml");
        std::fs::write(&path, text).expect("write");
        assert!(matches!(load(&path), Err(FixtureError::Invalid { .. })));
    }
}
