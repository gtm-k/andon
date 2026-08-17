//! The parse-health corpus: pinned real repositories, an ERROR-node budget, and
//! a recorded baseline (PREMORTEM T3).
//!
//! # What the corpus is for
//!
//! The unit tests prove that parse health is *reported*. They cannot prove the
//! pinned grammars actually understand the language people write — a grammar
//! that predates a widely-used syntax degrades a quarter of a real codebase
//! while every unit test stays green, and the first symptom is a payload full of
//! `parse-degraded` results that nobody can act on.
//!
//! So: real repositories, pinned by full commit SHA, measured end to end through
//! [`crate::engine::measure_blob`], against a budget expressed as a *rate* so
//! that adding files to a pinned repository cannot fail the gate by arithmetic
//! alone.
//!
//! # How "re-run per grammar bump" is enforced without spending a CI minute
//!
//! `fixtures/parse-corpus/baseline.toml` records the numbers the last green run
//! produced **and the regime it produced them under** — every grammar version,
//! the tree-sitter runtime, and [`crate::lang::SPEC_REVISION`].
//! `tests/corpus_baseline.rs` fails when that stamp and the engine's current
//! regime disagree.
//!
//! That is the mechanism, and it is stronger than a path filter on the workflow:
//! a path filter can be satisfied by a run that was never looked at, and it does
//! not fire when a *transitive* change moves the grammar. Bumping a grammar
//! without dispatching the corpus job and committing its new baseline turns the
//! ordinary `cargo test` on every push red. The expensive job itself stays on
//! `workflow_dispatch`, which is user decision D2.
//!
//! # Repositories are cloned, never vendored
//!
//! The corpus is a list of URLs and SHAs. The repositories are not redistributed
//! here, so their licences are recorded for provenance rather than complied
//! with in this tree — and every one is permissive in any case.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use andon_core::git::{BlobBatch, BlobError, Git, GitError};
use serde::{Deserialize, Serialize};

use crate::engine::measure_blob;
use crate::lang::Language;

/// The corpus could not be read or run.
#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    /// The manifest is not valid TOML for this schema.
    #[error("{path}: {source}")]
    Manifest {
        /// Manifest that failed to parse.
        path: String,
        /// The parse failure.
        #[source]
        source: toml::de::Error,
    },
    /// Well-formed TOML that is still not a runnable corpus.
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
    /// A blob read failed.
    #[error(transparent)]
    Blob(#[from] BlobError),
    /// A checkout the manifest names is not where it should be.
    #[error("{name}: no checkout at {path}; run `andon-static corpus plan` and fetch first")]
    MissingCheckout {
        /// Repository name from the manifest.
        name: String,
        /// Where it was looked for.
        path: String,
    },
    /// A checkout is not at the pinned revision.
    #[error("{name}: checked out at {found}, but the corpus pins {pinned}")]
    WrongRevision {
        /// Repository name from the manifest.
        name: String,
        /// What is checked out.
        found: String,
        /// What the manifest pins.
        pinned: String,
    },
}

/// The corpus, as committed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusManifest {
    /// Manifest schema version. Only `1` is accepted.
    pub schema_version: u32,
    /// Why these repositories and not others.
    pub rationale: String,
    /// The pinned repositories.
    #[serde(rename = "repo")]
    pub repos: Vec<RepoSpec>,
    /// Per-language budgets.
    #[serde(rename = "budget")]
    pub budgets: Vec<Budget>,
}

/// One pinned repository.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoSpec {
    /// Directory name the checkout takes, and the label in the report.
    pub name: String,
    /// Clone URL.
    pub url: String,
    /// Full 40-character commit SHA. Never a tag: a tag is a mutable pointer.
    pub rev: String,
    /// Upstream licence, recorded for provenance. Nothing is redistributed here.
    pub license: String,
    /// Why this repository earns its place in the corpus.
    pub rationale: String,
    /// Languages this repository is here to exercise, as [`Language::name`]
    /// spells them.
    ///
    /// Declared rather than discovered, so the manifest says what the corpus
    /// covers and a run can be held to it: [`run`] fails when a repository
    /// produces no files in a language it claims, which is how a `include`
    /// prefix that stopped matching after an upstream reorganisation is caught
    /// instead of silently shrinking the corpus.
    pub languages: Vec<String>,
    /// Repository-relative path prefixes to measure. Empty measures everything.
    #[serde(default)]
    pub include: Vec<String>,
}

/// A per-language budget.
///
/// Rates rather than counts: a pinned repository can grow between refreshes, and
/// a gate that fails on arithmetic is a gate somebody eventually raises to make
/// it stop.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// Which language, as [`Language::name`] spells it.
    pub language: String,
    /// Ceiling on degraded files ÷ files measured.
    pub max_degraded_file_ratio: f64,
    /// Ceiling on (ERROR + MISSING) nodes ÷ all nodes.
    pub max_error_node_ratio: f64,
}

/// The recorded outcome of the last green corpus run.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    /// Baseline schema version. Only `1` is accepted.
    pub schema_version: u32,
    /// When the run happened, as a date.
    pub recorded_at: String,
    /// Where the run can be found, when it was a CI run.
    pub run_ref: String,
    /// The grammar tuple and spec revision the numbers were taken under.
    ///
    /// The whole point of the file: `tests/corpus_baseline.rs` fails when this
    /// and [`crate::engine::regime_stamp`] disagree, so a grammar bump cannot
    /// land without a fresh corpus run.
    pub regime: BTreeMap<String, String>,
    /// One row per language measured.
    #[serde(rename = "language")]
    pub languages: Vec<LanguageReport>,
    /// Every file the parser did not fully understand, named.
    ///
    /// Recorded rather than only counted so that a future run's new degradation
    /// is a line in a diff. A rate that moved from 1.8% to 2.4% says something
    /// changed; a list that gained three files says what.
    #[serde(default, rename = "degraded")]
    pub degraded: Vec<DegradedFile>,
}

/// Parse health across every file of one language.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LanguageReport {
    /// Language name.
    pub name: String,
    /// Files measured.
    pub files: u64,
    /// Files with at least one ERROR or MISSING node.
    pub degraded_files: u64,
    /// ERROR nodes across every file.
    pub error_nodes: u64,
    /// MISSING nodes across every file.
    pub missing_nodes: u64,
    /// All nodes across every file. The denominator.
    pub total_nodes: u64,
    /// Files whose bytes this engine refused — not source, or not UTF-8.
    pub unreadable_files: u64,
}

impl LanguageReport {
    /// Degraded files as a fraction of files measured.
    pub fn degraded_file_ratio(&self) -> f64 {
        if self.files == 0 {
            return 0.0;
        }
        self.degraded_files as f64 / self.files as f64
    }

    /// ERROR plus MISSING nodes as a fraction of all nodes.
    pub fn error_node_ratio(&self) -> f64 {
        if self.total_nodes == 0 {
            return 0.0;
        }
        (self.error_nodes + self.missing_nodes) as f64 / self.total_nodes as f64
    }
}

/// One file the parser did not fully understand.
///
/// Named rather than only counted. A rate tells you the grammar is slipping; the
/// paths tell you whether it is one exotic file or a language feature the pin
/// predates, and that is the difference between raising a budget and bumping a
/// grammar.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DegradedFile {
    /// Which corpus repository.
    pub repo: String,
    /// Repository-relative path.
    pub path: String,
    /// Language it was measured as.
    pub language: String,
    /// ERROR nodes.
    pub error_nodes: u64,
    /// MISSING nodes.
    pub missing_nodes: u64,
}

/// The outcome of a corpus run.
#[derive(Debug, Clone)]
pub struct CorpusReport {
    /// Per-language totals, in [`Language::all`] order.
    pub languages: Vec<LanguageReport>,
    /// Every file with at least one ERROR or MISSING node, in corpus order.
    pub degraded: Vec<DegradedFile>,
    /// Budget breaches, empty when the run is within budget.
    pub problems: Vec<String>,
}

impl CorpusReport {
    /// Whether every language stayed within its budget.
    pub fn within_budget(&self) -> bool {
        self.problems.is_empty()
    }

    /// Turn this run into the baseline a future run is checked against.
    pub fn to_baseline(&self, recorded_at: &str, run_ref: &str) -> Baseline {
        Baseline {
            schema_version: 1,
            recorded_at: recorded_at.to_string(),
            run_ref: run_ref.to_string(),
            regime: crate::engine::regime_stamp(),
            languages: self.languages.clone(),
            degraded: self.degraded.clone(),
        }
    }
}

/// Load and validate the corpus manifest.
pub fn load(path: &Path) -> Result<CorpusManifest, CorpusError> {
    let display = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| CorpusError::Io {
        detail: format!("read manifest {display}"),
        source,
    })?;
    let manifest: CorpusManifest =
        toml::from_str(&text).map_err(|source| CorpusError::Manifest {
            path: display.clone(),
            source,
        })?;
    if manifest.schema_version != 1 {
        return Err(CorpusError::Invalid {
            path: display,
            detail: format!(
                "unsupported corpus schema_version {} (expected 1)",
                manifest.schema_version
            ),
        });
    }
    for repo in &manifest.repos {
        if repo.rev.len() != 40 || !repo.rev.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CorpusError::Invalid {
                path: display,
                detail: format!(
                    "{}: rev '{}' is not a full commit SHA; a tag is a mutable pointer \
                     and a short SHA is ambiguous",
                    repo.name, repo.rev
                ),
            });
        }
        for language in &repo.languages {
            if !Language::all().iter().any(|l| l.name() == language) {
                return Err(CorpusError::Invalid {
                    path: display,
                    detail: format!("{}: unknown language '{language}'", repo.name),
                });
            }
        }
    }
    Ok(manifest)
}

/// Load a recorded baseline.
pub fn load_baseline(path: &Path) -> Result<Baseline, CorpusError> {
    let display = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| CorpusError::Io {
        detail: format!("read baseline {display}"),
        source,
    })?;
    let baseline: Baseline = toml::from_str(&text).map_err(|source| CorpusError::Manifest {
        path: display.clone(),
        source,
    })?;
    if baseline.schema_version != 1 {
        return Err(CorpusError::Invalid {
            path: display,
            detail: format!(
                "unsupported baseline schema_version {} (expected 1)",
                baseline.schema_version
            ),
        });
    }
    Ok(baseline)
}

/// Measure every pinned repository under `root` and score it against the
/// budgets.
///
/// Each repository is expected at `root/<name>`, checked out at the pinned SHA —
/// which is verified rather than trusted, because a corpus measured at whatever
/// happened to be checked out is not a pinned corpus.
///
/// Bytes come from `cat-file --batch` over the tree listing, not from the
/// working directory. That is not fussiness: it is the same path a measurement
/// takes, so the corpus exercises the code the product runs, and its numbers do
/// not depend on what the checkout did to the bytes.
pub fn run(manifest: &CorpusManifest, root: &Path) -> Result<CorpusReport, CorpusError> {
    let mut totals: BTreeMap<Language, LanguageReport> = BTreeMap::new();
    let mut degraded = Vec::new();

    for repo in &manifest.repos {
        let path = root.join(&repo.name);
        if !path.exists() {
            return Err(CorpusError::MissingCheckout {
                name: repo.name.clone(),
                path: path.display().to_string(),
            });
        }
        let git = Git::open(&path)?;
        let head = git
            .cmd(["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"])
            .text()?
            .trim()
            .to_string();
        if head != repo.rev {
            return Err(CorpusError::WrongRevision {
                name: repo.name.clone(),
                found: head,
                pinned: repo.rev.clone(),
            });
        }

        let listing = git
            .cmd(["ls-tree", "-r", "-z", "--full-tree", "HEAD"])
            .output()?;
        let entries = parse_ls_tree(&listing);
        let wanted: Vec<(String, String, Language)> = entries
            .into_iter()
            .filter(|(path, _)| included(path, &repo.include))
            .filter_map(|(path, oid)| {
                Language::for_path(&path).map(|language| (path, oid, language))
            })
            .collect();

        // A repository that claims a language and contributes no files in it is
        // a corpus that shrank without anyone noticing — an `include` prefix
        // that stopped matching after an upstream reorganisation looks exactly
        // like this, and looks green.
        for claimed in &repo.languages {
            if !wanted.iter().any(|(_, _, l)| l.name() == claimed) {
                return Err(CorpusError::Invalid {
                    path: repo.name.clone(),
                    detail: format!(
                        "declares {claimed} but no {claimed} file matched include {:?}",
                        repo.include
                    ),
                });
            }
        }

        if wanted.is_empty() {
            continue;
        }
        let mut batch = BlobBatch::open(&git).map_err(BlobError::from)?;
        for (path, oid, language) in wanted {
            let report = totals.entry(language).or_insert_with(|| LanguageReport {
                name: language.name().to_string(),
                ..LanguageReport::default()
            });
            let content = batch.read(&oid)?;
            match measure_blob(language, content.bytes()) {
                Ok(facts) => {
                    report.files += 1;
                    if let Some(health) = facts.health {
                        report.error_nodes += health.error_nodes;
                        report.missing_nodes += health.missing_nodes;
                        report.total_nodes += health.total_nodes;
                        report.degraded_files += u64::from(health.is_degraded());
                        if health.is_degraded() {
                            degraded.push(DegradedFile {
                                repo: repo.name.clone(),
                                path: path.clone(),
                                language: language.name().to_string(),
                                error_nodes: health.error_nodes,
                                missing_nodes: health.missing_nodes,
                            });
                        }
                    }
                }
                // Not source. Counted rather than skipped: a corpus that
                // silently dropped files would report a clean rate over
                // whatever happened to parse.
                Err(_) => report.unreadable_files += 1,
            }
        }
    }

    // Fixed order, so the report's sections do not move between runs.
    let languages: Vec<LanguageReport> = Language::all()
        .into_iter()
        .filter_map(|language| totals.get(&language).cloned())
        .collect();

    let mut problems = Vec::new();
    for budget in &manifest.budgets {
        let Some(report) = languages.iter().find(|r| r.name == budget.language) else {
            // A budget for a language the corpus never measured is a corpus that
            // has drifted from its own manifest, and silence would hide it.
            problems.push(format!(
                "{}: the corpus declares a budget but measured no files",
                budget.language
            ));
            continue;
        };
        if report.degraded_file_ratio() > budget.max_degraded_file_ratio {
            problems.push(format!(
                "{}: {}/{} files degraded ({:.4}), above the budget of {:.4}",
                report.name,
                report.degraded_files,
                report.files,
                report.degraded_file_ratio(),
                budget.max_degraded_file_ratio
            ));
        }
        if report.error_node_ratio() > budget.max_error_node_ratio {
            problems.push(format!(
                "{}: {} ERROR + {} MISSING of {} nodes ({:.6}), above the budget of {:.6}",
                report.name,
                report.error_nodes,
                report.missing_nodes,
                report.total_nodes,
                report.error_node_ratio(),
                budget.max_error_node_ratio
            ));
        }
    }
    // A language the corpus measured with no budget behind it is the same drift
    // in the other direction: files are being parsed and nothing is gating them.
    for report in &languages {
        if !manifest.budgets.iter().any(|b| b.language == report.name) {
            problems.push(format!(
                "{}: {} files measured with no budget declared for them",
                report.name, report.files
            ));
        }
    }

    Ok(CorpusReport {
        languages,
        degraded,
        problems,
    })
}

/// Whether a path is inside one of the manifest's prefixes. No prefixes means
/// the whole tree.
fn included(path: &str, prefixes: &[String]) -> bool {
    prefixes.is_empty() || prefixes.iter().any(|prefix| path.starts_with(prefix))
}

/// Parse `git ls-tree -r -z`: `<mode> SP <type> SP <oid> TAB <path>` per record.
///
/// Non-blob entries and paths that are not UTF-8 are dropped: a submodule
/// pointer is not a file, and a path this crate cannot represent is a path it
/// cannot report on either.
fn parse_ls_tree(raw: &[u8]) -> Vec<(String, String)> {
    raw.split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .filter_map(|record| {
            let text = std::str::from_utf8(record).ok()?;
            let (meta, path) = text.split_once('\t')?;
            let mut fields = meta.split_whitespace();
            let _mode = fields.next()?;
            let kind = fields.next()?;
            let oid = fields.next()?;
            (kind == "blob").then(|| (path.to_string(), oid.to_string()))
        })
        .collect()
}

/// Path to the committed corpus manifest, relative to the workspace root.
pub fn manifest_path() -> PathBuf {
    workspace_root()
        .join("fixtures")
        .join("parse-corpus")
        .join("corpus.toml")
}

/// Path to the committed baseline.
pub fn baseline_path() -> PathBuf {
    workspace_root()
        .join("fixtures")
        .join("parse-corpus")
        .join("baseline.toml")
}

/// The workspace root, from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    // crates/engines/static-metrics -> crates/engines -> crates -> root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("this crate lives three levels below the workspace root")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_corpus_loads_and_pins_full_shas() {
        let manifest = load(&manifest_path()).expect("the corpus manifest must load");
        assert!(!manifest.repos.is_empty());
        assert!(!manifest.budgets.is_empty());
        for repo in &manifest.repos {
            assert_eq!(repo.rev.len(), 40, "{}", repo.name);
            assert!(repo.url.starts_with("https://"), "{}", repo.name);
        }
    }

    #[test]
    fn the_declared_languages_and_the_budgets_are_the_same_set() {
        // Both drift directions, which `run` also checks against what it
        // actually measured. Asserted here so a manifest edit fails on push
        // rather than at the next dispatch.
        use std::collections::BTreeSet;
        let manifest = load(&manifest_path()).expect("loads");
        let declared: BTreeSet<&str> = manifest
            .repos
            .iter()
            .flat_map(|repo| repo.languages.iter().map(String::as_str))
            .collect();
        let budgeted: BTreeSet<&str> = manifest
            .budgets
            .iter()
            .map(|budget| budget.language.as_str())
            .collect();
        assert_eq!(
            declared, budgeted,
            "every language the corpus covers needs a budget, and a budget with \
             nothing behind it gates nothing"
        );
    }

    #[test]
    fn the_corpus_covers_every_language_the_engine_measures() {
        // A language with a parser and no corpus is a grammar nobody is watching
        // — which is the failure PREMORTEM T3 describes.
        let manifest = load(&manifest_path()).expect("loads");
        let declared: Vec<&str> = manifest
            .repos
            .iter()
            .flat_map(|repo| repo.languages.iter().map(String::as_str))
            .collect();
        for language in Language::all() {
            assert!(
                declared.contains(&language.name()),
                "no corpus repository covers {}",
                language.name()
            );
        }
    }

    #[test]
    fn a_short_sha_is_refused() {
        let text = "schema_version = 1\nrationale = \"x\"\n[[repo]]\nname = \"x\"\n\
                    url = \"https://example.com/x.git\"\nrev = \"abc1234\"\n\
                    license = \"MIT\"\nrationale = \"x\"\nlanguages = [\"python\"]\n\
                    [[budget]]\nlanguage = \"python\"\n\
                    max_degraded_file_ratio = 0.1\nmax_error_node_ratio = 0.1\n";
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("corpus.toml");
        std::fs::write(&path, text).expect("write");
        assert!(matches!(load(&path), Err(CorpusError::Invalid { .. })));
    }

    #[test]
    fn ls_tree_records_split_into_blobs_and_paths() {
        let raw = b"100644 blob aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tsrc/a.ts\0\
                    160000 commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\tvendor/sub\0\
                    100644 blob cccccccccccccccccccccccccccccccccccccccc\tsrc/b.py\0";
        let entries = parse_ls_tree(raw);
        assert_eq!(entries.len(), 2, "the submodule pointer is not a file");
        assert_eq!(entries[0].0, "src/a.ts");
        assert_eq!(entries[1].0, "src/b.py");
    }

    #[test]
    fn include_prefixes_narrow_and_an_empty_list_does_not() {
        assert!(included("src/a.ts", &[]));
        assert!(included("src/a.ts", &["src/".to_string()]));
        assert!(!included("test/a.ts", &["src/".to_string()]));
    }

    #[test]
    fn ratios_are_zero_rather_than_divisions_on_an_empty_report() {
        let report = LanguageReport::default();
        assert_eq!(report.degraded_file_ratio(), 0.0);
        assert_eq!(report.error_node_ratio(), 0.0);
    }
}
