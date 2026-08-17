//! Fixtures as data: build a repository, stage an attack, state the verdict.
//!
//! Every row of the P1.5 verdict set (PLAN R2-5, plus the E4 flip and the
//! PREMORTEM S4 skew) is a TOML manifest under `fixtures/honest/` or
//! `fixtures/gamed/`. A manifest says what commits to make, what bytes go in
//! them, what to do to the self-report afterwards, and **what the attestation
//! must come out as**. Nothing about the expected outcome lives in test code.
//!
//! That split is the point. A fixture whose expectation is written in Rust
//! beside the assertion is a test that can be quietly relaxed while still
//! looking green; a fixture whose expectation is committed data has to be
//! *edited*, in a diff, to change what the phase claims. The five R2-5 verdicts
//! are the plan's load-bearing promise, so they are committed where a reviewer
//! reads them rather than where a fix agent edits them.
//!
//! # Bytes, and why the fixture repository has no `.gitattributes`
//!
//! The determinism fixture deliberately contains CRLF files, LF files, files
//! with both, a file ending without a terminator, and paths outside ASCII. It
//! carries **no** `.gitattributes`, so a matrix leg cloning it gets whatever its
//! runner's git config does to the working tree — CRLF everywhere on a default
//! Windows install. That is the PREMORTEM Story 1 setup reproduced on purpose:
//! the worktree is mangled, the blobs are not, and the compared lane reads
//! blobs. Normalizing the fixture would make the matrix pass for the wrong
//! reason.
//!
//! Construction is a different matter, and is pinned: every git invocation goes
//! through [`Git::cmd`], which forces `core.autocrlf=false`, so the bytes a
//! manifest declares are the bytes that reach the object database on every
//! platform.
//!
//! # Non-ASCII paths are CJK, not accented Latin
//!
//! `ResultScope::path` is inside the per-result digest. macOS filesystems
//! normalize filenames to NFD, so a path containing `ü` is reported as `u`+
//! combining-diaeresis on a mac leg and as a single code point everywhere else —
//! a digest mismatch on a fixture nobody tampered with, and a matrix red that
//! thinning the matrix would "fix" while hiding a real limitation. CJK code
//! points have no decomposed form, so they exercise non-ASCII path handling with
//! no normalization exposure. If Andon ever needs to promise NFC/NFD stability
//! that is a real feature with a real design; it is not something to discover
//! from a red matrix.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use andon_core::git::{Git, GitError, Revision};
use andon_core::schema::enums::{Attestation, InvocationSource, RecordKind, TamperSignal};
use serde::Deserialize;

use andon_core::schema::payload::AttestationBlock;

use crate::measure::{measure, MeasureError};
use crate::notes::{Notes, NotesError};

/// Fixed identity and clock for fixture commits.
///
/// Everything that feeds a commit OID is stated, so a manifest produces the same
/// repository twice — which is what makes a failing scenario reproducible from
/// its name alone. Same reasoning as the perf fixture generator's `IDENT`.
const FIXTURE_NAME: &str = "Andon Fixture";
const FIXTURE_EMAIL: &str = "fixture@andon.invalid";
const FIXTURE_EPOCH: i64 = 1_767_225_600;

/// A scenario could not be built or read.
#[derive(Debug, thiserror::Error)]
pub enum ScenarioError {
    /// The manifest is not valid TOML for this schema.
    #[error("{path}: {source}")]
    Manifest {
        /// Manifest that failed to parse.
        path: String,
        /// The parse failure.
        #[source]
        source: toml::de::Error,
    },
    /// A manifest is well-formed TOML and still not a runnable scenario.
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
    /// A measurement failed.
    #[error(transparent)]
    Measure(#[from] MeasureError),
    /// A ledger operation failed.
    #[error(transparent)]
    Notes(#[from] NotesError),
    /// The adversary binary could not be run.
    #[error("could not run the forge binary {path}: {detail}")]
    Forge {
        /// Where the binary was looked for.
        path: String,
        /// What went wrong.
        detail: String,
    },
}

/// One fixture, as committed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Manifest schema version. Only `1` is accepted.
    pub schema_version: u32,
    /// Scenario id, matching its directory name.
    pub name: String,
    /// One line for the verdict table.
    pub title: String,
    /// Why this scenario exists and what a change to its expectation would mean.
    pub rationale: String,
    /// The branch the verifier trusts.
    pub trusted_branch: String,
    /// Ordered construction steps.
    #[serde(default)]
    pub step: Vec<Step>,
    /// What the verifier must conclude.
    pub verify: Expectation,
}

/// One construction step.
///
/// A flat struct with a validated `kind` rather than a tagged enum: `toml`
/// deserializes internally-tagged enums through serde's buffering path, which
/// handles arrays of tables poorly, and a fixture format that fails to parse for
/// reasons unrelated to the fixture is a bad trade for a tidier type. The
/// validation in [`Step::check`] gives the same errors a tagged enum would.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Which operation this is.
    pub kind: StepKind,
    /// `commit`: branch to commit on. Must already exist or be the initial one.
    #[serde(default)]
    pub branch: Option<String>,
    /// `branch`: name of the new branch.
    #[serde(default)]
    pub name: Option<String>,
    /// `branch`: label or ref the new branch starts from.
    #[serde(default)]
    pub from: Option<String>,
    /// `commit`: label the resulting commit is known by.
    #[serde(default)]
    pub label: Option<String>,
    /// `commit`: commit message.
    #[serde(default)]
    pub message: Option<String>,
    /// `commit`: files to write.
    #[serde(default)]
    pub file: Vec<FileSpec>,
    /// `commit`: paths to delete.
    #[serde(default)]
    pub remove: Vec<String>,
    /// `measure`: label of the commit to measure.
    #[serde(default)]
    pub head: Option<String>,
    /// `measure`: `merge-base`, or a label to pin the base to.
    #[serde(default)]
    pub base: Option<String>,
    /// `measure`: engine version to report, staging a PREMORTEM S4 skew.
    #[serde(default)]
    pub engine_version: Option<String>,
    /// `copy-note`: label the note is read from.
    #[serde(default)]
    pub source: Option<String>,
    /// `copy-note`: label the note is written to.
    #[serde(default)]
    pub target: Option<String>,
    /// `forge`: label of the commit whose self-report is attacked.
    #[serde(default)]
    pub commit: Option<String>,
    /// `forge`: which attack.
    #[serde(default)]
    pub op: Option<String>,
    /// `forge`: label whose OID becomes the fabricated base.
    #[serde(default)]
    pub base_label: Option<String>,
}

/// The five things a manifest can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepKind {
    /// Write files and commit them.
    Commit,
    /// Create and check out a branch.
    Branch,
    /// Run the agent-side measurement and write the self-report note.
    Measure,
    /// Carry a note from one commit to another — a squash migration, or an
    /// agent reusing a pre-rebase measurement.
    CopyNote,
    /// Run the adversary binary against a self-report.
    Forge,
}

/// One file in a commit.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSpec {
    /// Repository-relative path, forward slashes.
    pub path: String,
    /// Exact contents. TOML escapes (`\r`, `\n`, `\u00XX`) make the bytes
    /// explicit, which is the whole reason the fixture is data rather than a
    /// shell script writing here-docs on three operating systems.
    pub text: String,
}

/// What the verifier must conclude, as committed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    /// Label of the commit to verify.
    pub head: String,
    /// The attestation value. This is the row of the verdict table.
    pub expect: Attestation,
    /// Tamper signals that must fire, exactly.
    #[serde(default)]
    pub expect_tamper: Vec<TamperSignal>,
    /// Whether the compare must report at least one digest mismatch.
    #[serde(default)]
    pub expect_mismatches: bool,
    /// Whether the compare must report at least one `deterministic` flag
    /// disagreement — the E4 signature.
    #[serde(default)]
    pub expect_flag_disagreements: bool,
    /// Whether to verify as an unprivileged fork job.
    #[serde(default)]
    pub fork_tier: bool,
}

impl Step {
    fn check(&self, manifest_path: &str) -> Result<(), ScenarioError> {
        let need = |present: bool, what: &str| {
            if present {
                Ok(())
            } else {
                Err(ScenarioError::Invalid {
                    path: manifest_path.to_string(),
                    detail: format!("a {:?} step needs {what}", self.kind),
                })
            }
        };
        match self.kind {
            StepKind::Commit => {
                need(self.label.is_some(), "a label")?;
                need(self.message.is_some(), "a message")?;
                need(
                    !self.file.is_empty() || !self.remove.is_empty(),
                    "at least one file or removal",
                )
            }
            StepKind::Branch => {
                need(self.name.is_some(), "a name")?;
                need(self.from.is_some(), "a from")
            }
            StepKind::Measure => need(self.head.is_some(), "a head label"),
            StepKind::CopyNote => {
                need(self.source.is_some(), "a source label")?;
                need(self.target.is_some(), "a target label")
            }
            StepKind::Forge => {
                need(self.commit.is_some(), "a commit label")?;
                need(self.op.is_some(), "an op")
            }
        }
    }
}

/// Load and validate a manifest.
pub fn load(path: &Path) -> Result<Manifest, ScenarioError> {
    let display = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| ScenarioError::Io {
        detail: format!("read manifest {display}"),
        source,
    })?;
    let manifest: Manifest = toml::from_str(&text).map_err(|source| ScenarioError::Manifest {
        path: display.clone(),
        source,
    })?;
    if manifest.schema_version != 1 {
        return Err(ScenarioError::Invalid {
            path: display,
            detail: format!(
                "unsupported manifest schema_version {} (expected 1)",
                manifest.schema_version
            ),
        });
    }
    for step in &manifest.step {
        step.check(&display)?;
    }
    Ok(manifest)
}

/// Where the adversary binary is, and where the fixture goes.
#[derive(Debug, Clone, Default)]
pub struct PrepareOptions {
    /// Path to `andon-spike-forge`. Resolved from the running executable's
    /// directory when absent.
    pub forge_bin: Option<PathBuf>,
}

/// A built fixture, ready to verify.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Prepared {
    /// Scenario id.
    pub name: String,
    /// Working tree of the fixture repository.
    pub repo: PathBuf,
    /// The commit the verifier should be pinned to.
    pub head: String,
    /// Branch the verifier trusts.
    pub trusted_branch: String,
    /// The committed expectation, as a wire string.
    pub expect: Attestation,
    /// Every label, resolved to an OID. Useful when a run has to be debugged
    /// from CI output alone.
    pub labels: BTreeMap<String, String>,
}

/// Build the fixture repository and run every step.
///
/// `dest` is removed first. A scenario that reused a half-built repository would
/// be a scenario whose result depended on what ran before it.
pub fn prepare(
    manifest: &Manifest,
    dest: &Path,
    options: &PrepareOptions,
) -> Result<Prepared, ScenarioError> {
    let mut ctx = Context::init(manifest, dest, options)?;
    for step in &manifest.step {
        ctx.run(step)?;
    }
    let head = ctx.oid_of(&manifest.verify.head)?;
    // Pinned to the head under verification, detached — the shape the action
    // uses, and the shape that makes `VerifyError::NotPinnedToHead` meaningful.
    ctx.git
        .cmd(["checkout", "--quiet", "--detach", &head])
        .output()?;
    Ok(Prepared {
        name: manifest.name.clone(),
        repo: ctx.repo.clone(),
        head,
        trusted_branch: manifest.trusted_branch.clone(),
        expect: manifest.verify.expect,
        labels: ctx.labels,
    })
}

/// Check an attestation block against the committed expectation.
///
/// Takes the block rather than a [`VerifyOutcome`] so that the same check runs
/// two ways: in-process against what [`crate::verify::verify`] returned, and
/// after the fact against the note the composite action actually wrote. The
/// second is what proves the YAML path, not just the code path.
///
/// Returns every disagreement rather than the first, so a scenario that has
/// moved reports what actually happened in one go.
pub fn check(manifest: &Manifest, attestation: &AttestationBlock) -> Vec<String> {
    let expected = &manifest.verify;
    let mut problems = Vec::new();
    if attestation.value != expected.expect {
        problems.push(format!(
            "expected attestation {:?}, observed {:?}",
            expected.expect, attestation.value
        ));
    }
    let observed_signals = &attestation.tamper_signals;
    if observed_signals != &expected.expect_tamper {
        problems.push(format!(
            "expected tamper signals {:?}, observed {observed_signals:?}",
            expected.expect_tamper
        ));
    }
    match &attestation.compare {
        None => {
            if expected.expect_mismatches || expected.expect_flag_disagreements {
                problems.push(
                    "expected compare detail, but no compare was attempted".to_string(),
                );
            }
        }
        Some(compare) => {
            let observed_mismatches = !compare.mismatched.is_empty();
            if expected.expect_mismatches != observed_mismatches {
                problems.push(format!(
                    "expected mismatches={}, observed {:?}",
                    expected.expect_mismatches, compare.mismatched
                ));
            }
            let observed_flag_disagreements = !compare.flag_disagreements.is_empty();
            if expected.expect_flag_disagreements != observed_flag_disagreements {
                problems.push(format!(
                    "expected flag disagreements={}, observed {:?}",
                    expected.expect_flag_disagreements, compare.flag_disagreements
                ));
            }
        }
    }
    problems
}

struct Context<'a> {
    git: Git,
    repo: PathBuf,
    labels: BTreeMap<String, String>,
    manifest: &'a Manifest,
    manifest_path: String,
    options: &'a PrepareOptions,
    commits: i64,
}

impl<'a> Context<'a> {
    fn init(
        manifest: &'a Manifest,
        dest: &Path,
        options: &'a PrepareOptions,
    ) -> Result<Self, ScenarioError> {
        if dest.exists() {
            std::fs::remove_dir_all(dest).map_err(|source| ScenarioError::Io {
                detail: format!("clear {}", dest.display()),
                source,
            })?;
        }
        std::fs::create_dir_all(dest).map_err(|source| ScenarioError::Io {
            detail: format!("create {}", dest.display()),
            source,
        })?;
        bootstrap_git()?
            .cmd([
                "init",
                "--quiet",
                "--initial-branch",
                &manifest.trusted_branch,
            ])
            .arg(dest)
            .output()?;
        let git = Git::open(dest)?;
        Ok(Context {
            repo: git.workdir().to_path_buf(),
            git,
            labels: BTreeMap::new(),
            manifest,
            manifest_path: manifest.name.clone(),
            options,
            commits: 0,
        })
    }

    fn run(&mut self, step: &Step) -> Result<(), ScenarioError> {
        match step.kind {
            StepKind::Commit => self.commit(step),
            StepKind::Branch => self.branch(step),
            StepKind::Measure => self.measure(step),
            StepKind::CopyNote => self.copy_note(step),
            StepKind::Forge => self.forge(step),
        }
    }

    fn commit(&mut self, step: &Step) -> Result<(), ScenarioError> {
        if let Some(branch) = &step.branch {
            // Only switch when we are not already there: `checkout` on the
            // initial unborn branch fails, and the first commit of a scenario is
            // always on the initial branch.
            let current = self
                .git
                .cmd(["symbolic-ref", "--quiet", "--short", "HEAD"])
                .succeeds_with_output()?
                .map(|s| s.trim().to_string());
            if current.as_deref() != Some(branch.as_str()) {
                self.git.cmd(["checkout", "--quiet", branch]).output()?;
            }
        }
        for file in &step.file {
            let path = self.repo.join(&file.path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|source| ScenarioError::Io {
                    detail: format!("create {}", parent.display()),
                    source,
                })?;
            }
            // `write` of the exact bytes the manifest declares. No newline
            // translation happens here and none happens in `git add`, because
            // `Git::cmd` pins `core.autocrlf=false`.
            std::fs::write(&path, file.text.as_bytes()).map_err(|source| ScenarioError::Io {
                detail: format!("write {}", path.display()),
                source,
            })?;
        }
        for path in &step.remove {
            let full = self.repo.join(path);
            if full.exists() {
                std::fs::remove_file(&full).map_err(|source| ScenarioError::Io {
                    detail: format!("remove {}", full.display()),
                    source,
                })?;
            }
        }
        self.git.cmd(["add", "--all", "."]).output()?;
        let stamp = format!("{} +0000", FIXTURE_EPOCH + self.commits * 60);
        self.commits += 1;
        let message = step.message.as_deref().unwrap_or("fixture commit");
        self.git
            .cmd(["commit", "--quiet", "--allow-empty", "-m", message])
            .env("GIT_AUTHOR_NAME", FIXTURE_NAME)
            .env("GIT_AUTHOR_EMAIL", FIXTURE_EMAIL)
            .env("GIT_COMMITTER_NAME", FIXTURE_NAME)
            .env("GIT_COMMITTER_EMAIL", FIXTURE_EMAIL)
            .env("GIT_AUTHOR_DATE", &stamp)
            .env("GIT_COMMITTER_DATE", &stamp)
            .output()?;
        let oid = self.rev_parse("HEAD")?;
        self.labels
            .insert(step.label.clone().expect("validated"), oid);
        Ok(())
    }

    fn branch(&mut self, step: &Step) -> Result<(), ScenarioError> {
        let from = self.resolve(step.from.as_deref().expect("validated"))?;
        let name = step.name.as_deref().expect("validated");
        self.git
            .cmd(["checkout", "--quiet", "-b", name, &from])
            .output()?;
        Ok(())
    }

    fn measure(&mut self, step: &Step) -> Result<(), ScenarioError> {
        let head_label = step.head.as_deref().expect("validated");
        let head_oid = self.oid_of(head_label)?;
        let base = match step.base.as_deref() {
            None | Some("merge-base") => Revision::merge_base(&self.manifest.trusted_branch),
            Some(label) => Revision::Rev(self.resolve(label)?),
        };
        let version = step
            .engine_version
            .clone()
            .unwrap_or_else(|| crate::spike::default_engine_version().to_string());
        let (record, _) = measure(
            &self.git,
            &base,
            &Revision::Rev(head_oid.clone()),
            RecordKind::SelfReport,
            // A hook-driven agent measurement is the flagship path (PREMORTEM
            // A2), so that is what the fixtures stage.
            InvocationSource::Hook,
            &version,
        )?;
        Notes::measure(&self.git).append(&head_oid, &record)?;
        Ok(())
    }

    fn copy_note(&mut self, step: &Step) -> Result<(), ScenarioError> {
        let from = self.oid_of(step.source.as_deref().expect("validated"))?;
        let to = self.oid_of(step.target.as_deref().expect("validated"))?;
        Notes::measure(&self.git).copy(&from, &to)?;
        Ok(())
    }

    fn forge(&mut self, step: &Step) -> Result<(), ScenarioError> {
        let commit = self.oid_of(step.commit.as_deref().expect("validated"))?;
        let op = step.op.as_deref().expect("validated");
        let forge = forge_binary(self.options)?;
        let mut command = std::process::Command::new(&forge);
        command
            .arg("--repo")
            .arg(&self.repo)
            .args(["--commit", &commit, "--op", op]);
        if let Some(label) = &step.base_label {
            let oid = self.resolve(label)?;
            command.args(["--base-oid", &oid]);
        }
        let output = command.output().map_err(|e| ScenarioError::Forge {
            path: forge.display().to_string(),
            detail: e.to_string(),
        })?;
        if !output.status.success() {
            return Err(ScenarioError::Forge {
                path: forge.display().to_string(),
                detail: format!(
                    "exited {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        Ok(())
    }

    /// Resolve a label, falling back to treating the string as a revision.
    fn resolve(&self, name: &str) -> Result<String, ScenarioError> {
        if let Some(oid) = self.labels.get(name) {
            return Ok(oid.clone());
        }
        self.rev_parse(name)
    }

    /// Resolve a label, refusing anything else.
    fn oid_of(&self, label: &str) -> Result<String, ScenarioError> {
        self.labels
            .get(label)
            .cloned()
            .ok_or_else(|| ScenarioError::Invalid {
                path: self.manifest_path.clone(),
                detail: format!(
                    "no step labelled '{label}'; labels so far: {:?}",
                    self.labels.keys().collect::<Vec<_>>()
                ),
            })
    }

    fn rev_parse(&self, rev: &str) -> Result<String, ScenarioError> {
        Ok(self
            .git
            .cmd([
                "rev-parse",
                "--verify",
                "--end-of-options",
                &format!("{rev}^{{commit}}"),
            ])
            .text()?
            .trim()
            .to_string())
    }
}

/// A `Git` handle for spawning `git init`, which needs no repository of its own.
///
/// [`Git::open`] insists on being inside a repository, and the destination is
/// not one yet — the same bootstrap the perf-fixture generator uses. The current
/// directory is tried first (the action and the test harness both run inside a
/// checkout); the crate's own source directory is the fallback for a binary
/// invoked from somewhere else.
fn bootstrap_git() -> Result<Git, ScenarioError> {
    if let Ok(git) = Git::open(Path::new(".")) {
        return Ok(git);
    }
    Ok(Git::open(Path::new(env!("CARGO_MANIFEST_DIR")))?)
}

/// Where the adversary binary lives.
///
/// Next to the running executable, which is true for `cargo run`, for
/// `cargo test` (one directory up from `deps/`), and for the action's release
/// build. Overridable, because a test knows exactly where cargo put it.
fn forge_binary(options: &PrepareOptions) -> Result<PathBuf, ScenarioError> {
    if let Some(path) = &options.forge_bin {
        return Ok(path.clone());
    }
    if let Ok(path) = std::env::var("ANDON_SPIKE_FORGE_BIN") {
        return Ok(PathBuf::from(path));
    }
    let exe = std::env::current_exe().map_err(|e| ScenarioError::Forge {
        path: "<current exe>".to_string(),
        detail: e.to_string(),
    })?;
    let name = format!("andon-spike-forge{}", std::env::consts::EXE_SUFFIX);
    // Two candidates and no search. Beside the executable covers `cargo run`
    // and the action's release build; one directory up covers `cargo test`,
    // whose harness lives in `target/<profile>/deps/`. Walking further would be
    // guessing, and a binary found by guessing is a binary nobody chose.
    for dir in exe.parent().into_iter().chain(
        exe.parent()
            .and_then(Path::parent)
            .filter(|_| exe.parent().is_some_and(|p| p.ends_with("deps"))),
    ) {
        let path = dir.join(&name);
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(ScenarioError::Forge {
        path: name,
        detail: format!(
            "not found beside {} or one directory up; set ANDON_SPIKE_FORGE_BIN",
            exe.display()
        ),
    })
}
