//! The frozen corpus, and the precision/recall arithmetic measured over it.
//!
//! # The two corpora, and which number each one produces
//!
//! - `fixtures/adversarial/` — should-fire cases. **Recall** comes from here:
//!   of the cases that declare a signal, how many raised it.
//! - `fixtures/honest/corpus/` — should-pass cases. **Precision**'s false
//!   positives come from here and *only* from here, per PLAN P3 ("precision
//!   floor measured against it").
//!
//! That split is not an implementation convenience. Counting a cross-fire — an
//! adversarial case for one detector legitimately tripping another — as a false
//! positive would poison a detector's precision with evidence of it working:
//! a change that deletes tests *and* adds suppressions is both, and either
//! detector is right to say so. Cross-fires are counted and reported so they
//! are visible, and they do not enter a floor.
//!
//! # The freeze, and why the commit order is the evidence
//!
//! PLAN P3: corpus v1 is frozen and ensemble-reviewed **before** the floors are
//! measured against it, so the test and its subject are not co-authored in one
//! motion. [`FreezeMarker`] records the corpus's content digest and the date it
//! was frozen; `fixtures/adversarial/CORPUS-v1.toml` holds it, and it lands in
//! its own commit ahead of the measurement. [`verify_freeze`] recomputes the
//! digest, so an edit to a case after the freeze is visible rather than
//! implicit.
//!
//! # A case is two directories of plain files
//!
//! ```text
//! fixtures/adversarial/test-removal/deleted-failing-suite/
//!   case.toml     title, the signals expected, and why
//!   base/         the files before
//!   head/         the files after
//! ```
//!
//! A path present in `base/` and absent from `head/` is a deletion; the reverse
//! is an addition. A directory that would be empty is simply absent, because git
//! does not track empty directories. Renames are declared in `case.toml`, since
//! two directories cannot express one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::change::{ChangeKind, ChangeView, FileChange};
use crate::detectors::{self, signal_name};

/// Precision floor, set ex ante in PLAN.md P3. A report below it fails the
/// phase.
pub const PRECISION_FLOOR: f64 = 0.80;

/// Recall floor, set ex ante in PLAN.md P3.
pub const RECALL_FLOOR: f64 = 0.70;

/// Where the should-fire cases live, relative to the repository root.
pub const ADVERSARIAL_DIR: &str = "fixtures/adversarial";

/// Where the should-pass cases live.
///
/// Under `fixtures/honest/` because PLAN.md's shared-files row puts them there,
/// and in a `corpus/` subdirectory because `fixtures/honest/*` already holds
/// P1.5's attestation scenarios — which are enumerated at depth one by their
/// `manifest.toml` and must not acquire new siblings that look like scenarios.
pub const HONEST_DIR: &str = "fixtures/honest/corpus";

/// What a case declares about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseManifest {
    /// One line naming what the case is.
    pub title: String,
    /// The signals this case must raise. Empty for a should-pass case.
    #[serde(default)]
    pub expect: Vec<String>,
    /// Why this is gaming, or why it is legitimate. Read by a reviewer, not by
    /// the harness — and required, because a case nobody can justify is a case
    /// nobody can re-review.
    pub note: String,
    /// Paths that moved, which two directories cannot express.
    #[serde(default, rename = "rename")]
    pub renames: Vec<Rename>,
}

/// One declared rename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rename {
    /// Path on the base side.
    pub from: String,
    /// Path on the head side.
    pub to: String,
}

/// A loaded case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// `<detector>/<case-name>`, the case's identity in reports.
    pub id: String,
    /// Which corpus it came from.
    pub family: Family,
    /// What it declares.
    pub manifest: CaseManifest,
    /// The change it represents.
    pub change: ChangeView,
}

/// Which corpus a case belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Should fire.
    Adversarial,
    /// Should not fire.
    Honest,
}

/// Anything that stopped the corpus from loading.
#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    /// A filesystem operation failed.
    #[error("corpus I/O failed at {path}: {source}")]
    Io {
        /// What was being read.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A `case.toml` does not parse.
    #[error("{path}: {source}")]
    Manifest {
        /// The manifest.
        path: String,
        /// The parse error.
        #[source]
        source: toml::de::Error,
    },
    /// A case declares a signal no detector raises.
    #[error("{case}: expects '{signal}', which no detector raises")]
    UnknownSignal {
        /// The case.
        case: String,
        /// The signal it named.
        signal: String,
    },
    /// An adversarial case declares nothing, or an honest case declares
    /// something.
    #[error("{case}: {problem}")]
    Malformed {
        /// The case.
        case: String,
        /// What is wrong.
        problem: String,
    },
}

fn io(path: &Path, source: std::io::Error) -> CorpusError {
    CorpusError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Load both corpora, rooted at a repository.
pub fn load(repo_root: &Path) -> Result<Vec<Case>, CorpusError> {
    let mut cases = load_family(&repo_root.join(ADVERSARIAL_DIR), Family::Adversarial)?;
    cases.extend(load_family(&repo_root.join(HONEST_DIR), Family::Honest)?);
    cases.sort_by(|a, b| (a.id.clone()).cmp(&b.id));
    Ok(cases)
}

fn load_family(root: &Path, family: Family) -> Result<Vec<Case>, CorpusError> {
    let mut cases = Vec::new();
    if !root.is_dir() {
        return Ok(cases);
    }
    for group in sorted_dirs(root)? {
        let group_name = file_name(&group);
        for case_dir in sorted_dirs(&group)? {
            let id = format!("{group_name}/{}", file_name(&case_dir));
            cases.push(load_case(&id, family, &case_dir)?);
        }
    }
    Ok(cases)
}

fn load_case(id: &str, family: Family, dir: &Path) -> Result<Case, CorpusError> {
    let manifest_path = dir.join("case.toml");
    let text = std::fs::read_to_string(&manifest_path).map_err(|e| io(&manifest_path, e))?;
    let manifest: CaseManifest = toml::from_str(&text).map_err(|source| CorpusError::Manifest {
        path: manifest_path.display().to_string(),
        source,
    })?;

    match family {
        Family::Adversarial if manifest.expect.is_empty() => {
            return Err(CorpusError::Malformed {
                case: id.to_string(),
                problem: "an adversarial case must declare at least one expected signal".into(),
            })
        }
        Family::Honest if !manifest.expect.is_empty() => {
            return Err(CorpusError::Malformed {
                case: id.to_string(),
                problem: "a should-pass case must expect nothing; move it to fixtures/adversarial"
                    .into(),
            })
        }
        _ => {}
    }
    for signal in &manifest.expect {
        if detectors::by_signal(signal).is_none() {
            return Err(CorpusError::UnknownSignal {
                case: id.to_string(),
                signal: signal.clone(),
            });
        }
    }
    if manifest.note.trim().is_empty() {
        return Err(CorpusError::Malformed {
            case: id.to_string(),
            problem: "every case must say why it is what it is".into(),
        });
    }

    Ok(Case {
        id: id.to_string(),
        family,
        change: change_from_trees(dir, &manifest)?,
        manifest,
    })
}

/// Build a change view from a directory holding `base/` and `head/` trees.
///
/// The corpus loader's own path, made public because the cross-OS matrix
/// specimen (`fixtures/matrix/all-seven`) uses the same two-directory layout
/// without being a scored case — it is engineered to fire everything at once,
/// which makes it a fine determinism control and a useless precision one.
pub fn change_from_trees(dir: &Path, manifest: &CaseManifest) -> Result<ChangeView, CorpusError> {
    let base = read_tree(&dir.join("base"))?;
    let head = read_tree(&dir.join("head"))?;
    Ok(assemble(manifest, base, head))
}

/// Turn two file trees and the declared renames into a change.
fn assemble(
    manifest: &CaseManifest,
    mut base: BTreeMap<String, Vec<u8>>,
    mut head: BTreeMap<String, Vec<u8>>,
) -> ChangeView {
    let mut files = Vec::new();

    for rename in &manifest.renames {
        let (Some(from), Some(to)) = (base.remove(&rename.from), head.remove(&rename.to)) else {
            continue;
        };
        files.push(FileChange {
            path: rename.to.clone(),
            old_path: Some(rename.from.clone()),
            kind: ChangeKind::Renamed,
            base: Some(from),
            head: Some(to),
            head_blob_oid: None,
        });
    }

    let paths: Vec<String> = base.keys().chain(head.keys()).cloned().collect();
    let mut seen = std::collections::BTreeSet::new();
    for path in paths {
        if !seen.insert(path.clone()) {
            continue;
        }
        let before = base.get(&path).cloned();
        let after = head.get(&path).cloned();
        let kind = match (&before, &after) {
            (None, Some(_)) => ChangeKind::Added,
            (Some(_), None) => ChangeKind::Deleted,
            _ => ChangeKind::Modified,
        };
        files.push(FileChange {
            path,
            old_path: None,
            kind,
            base: before,
            head: after,
            head_blob_oid: None,
        });
    }
    ChangeView::new(files)
}

/// Every file under `root`, keyed by its path relative to it. An absent
/// directory is an empty tree — git does not track empty directories, so "there
/// were no files before" has to be spelled by the directory not existing.
fn read_tree(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, CorpusError> {
    let mut out = BTreeMap::new();
    if !root.is_dir() {
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| io(&dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io(&dir, e))?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .expect("walked from root")
                .to_string_lossy()
                // Forward slashes, as git spells a path, on every platform.
                .replace('\\', "/");
            out.insert(relative, std::fs::read(&path).map_err(|e| io(&path, e))?);
        }
    }
    Ok(out)
}

fn sorted_dirs(root: &Path) -> Result<Vec<PathBuf>, CorpusError> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .map_err(|e| io(root, e))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    Ok(dirs)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// One detector's tally over the corpus.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Score {
    /// Adversarial cases that expected this signal and got it.
    pub true_positives: u32,
    /// Adversarial cases that expected this signal and did not get it.
    pub false_negatives: u32,
    /// Should-pass cases in which this detector fired. The only false positives
    /// that enter the floor.
    pub false_positives: u32,
    /// Should-pass cases in which it stayed quiet.
    pub true_negatives: u32,
    /// Adversarial cases that did not expect this signal and got it anyway.
    /// Reported, never scored — see the module docs.
    pub cross_fires: u32,
    /// Case ids behind `false_negatives`, so a failure names what it missed.
    pub missed: Vec<String>,
    /// Case ids behind `false_positives`.
    pub fired_on_honest: Vec<String>,
}

impl Score {
    /// True positives over everything this detector claimed. `None` when it
    /// never fired at all: a detector that says nothing has no precision, and
    /// reporting 1.0 for silence would let an empty implementation pass.
    pub fn precision(&self) -> Option<f64> {
        let claimed = self.true_positives + self.false_positives;
        (claimed > 0).then(|| self.true_positives as f64 / claimed as f64)
    }

    /// True positives over everything it should have caught. `None` when the
    /// corpus asks nothing of it.
    pub fn recall(&self) -> Option<f64> {
        let expected = self.true_positives + self.false_negatives;
        (expected > 0).then(|| self.true_positives as f64 / expected as f64)
    }

    /// Whether this detector clears both floors.
    ///
    /// A detector with no precision (it never fired) or no recall (nothing asked
    /// for it) fails: an unmeasured floor is not a met floor, and PLAN P3's
    /// "a report below floor fails the phase" cannot be satisfied by a corpus
    /// that declines to test something.
    pub fn meets_floors(&self) -> bool {
        matches!(self.precision(), Some(p) if p >= PRECISION_FLOOR)
            && matches!(self.recall(), Some(r) if r >= RECALL_FLOOR)
    }
}

/// The whole measurement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// Per-detector, keyed by signal name.
    pub scores: BTreeMap<String, Score>,
    /// How many adversarial cases were run.
    pub adversarial_cases: usize,
    /// How many should-pass cases were run.
    pub honest_cases: usize,
}

impl Report {
    /// Detectors that do not clear both floors.
    pub fn below_floor(&self) -> Vec<&String> {
        self.scores
            .iter()
            .filter(|(_, score)| !score.meets_floors())
            .map(|(name, _)| name)
            .collect()
    }
}

/// Run every detector over every case and tally the result.
pub fn measure(cases: &[Case]) -> Report {
    let mut report = Report::default();
    for detector in detectors::all() {
        report
            .scores
            .insert(signal_name(detector.signal()).to_string(), Score::default());
    }

    for case in cases {
        match case.family {
            Family::Adversarial => report.adversarial_cases += 1,
            Family::Honest => report.honest_cases += 1,
        }
        for detector in detectors::all() {
            let name = signal_name(detector.signal());
            let fired = detector.run(&case.change).fired;
            let expected = case.manifest.expect.iter().any(|s| s == name);
            let score = report.scores.get_mut(name).expect("seeded above");
            match (case.family, expected, fired) {
                (Family::Adversarial, true, true) => score.true_positives += 1,
                (Family::Adversarial, true, false) => {
                    score.false_negatives += 1;
                    score.missed.push(case.id.clone());
                }
                (Family::Adversarial, false, true) => score.cross_fires += 1,
                (Family::Adversarial, false, false) => {}
                (Family::Honest, _, true) => {
                    score.false_positives += 1;
                    score.fired_on_honest.push(case.id.clone());
                }
                (Family::Honest, _, false) => score.true_negatives += 1,
            }
        }
    }
    report
}

/// The freeze marker: what corpus v1 *is*, recorded before anything was measured
/// against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreezeMarker {
    /// Corpus version. `1` is the frozen v1 of PLAN.md P3.
    pub version: u32,
    /// The date the corpus was frozen, ISO 8601.
    pub frozen: String,
    /// When the next quarterly refresh is due (PREMORTEM S1). The scheduled
    /// `corpus-refresh` workflow checks this date and goes red past it.
    pub refresh_due: String,
    /// SHA-256 over the corpus content, as [`content_digest`] computes it.
    pub digest: String,
    /// Adversarial case count at freeze.
    pub adversarial_cases: usize,
    /// Should-pass case count at freeze.
    pub honest_cases: usize,
}

/// A digest over both corpora's content.
///
/// Path and bytes of every file, in sorted order, so a reordering cannot change
/// it and an edit cannot fail to. Case manifests are included: changing what a
/// case *expects* is as much a corpus edit as changing what it contains.
pub fn content_digest(repo_root: &Path) -> Result<String, CorpusError> {
    let mut hasher = Sha256::new();
    for dir in [ADVERSARIAL_DIR, HONEST_DIR] {
        let root = repo_root.join(dir);
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        collect(&root, &root, &mut files)?;
        files.sort();
        for (path, bytes) in files {
            hasher.update(dir.as_bytes());
            hasher.update([0]);
            hasher.update(path.as_bytes());
            hasher.update([0]);
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(&bytes);
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Files under `root`, excluding the freeze marker and prose about the corpus —
/// a README describing the corpus is not part of what the corpus *is*, and
/// including the marker would make the digest depend on itself.
fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), CorpusError> {
    if !dir.is_dir() {
        return Ok(());
    }
    // Iterative, like every other tree walk in this crate. A directory tree is
    // not PR-controlled the way a parse tree is, but "the walkers are iterative"
    // is a property worth being able to state without exceptions.
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|e| io(&dir, e))? {
            let entry = entry.map_err(|e| io(&dir, e))?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = file_name(&path);
            if name == "README.md" || name.starts_with("CORPUS-") {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .expect("walked from root")
                .to_string_lossy()
                .replace('\\', "/");
            out.push((relative, std::fs::read(&path).map_err(|e| io(&path, e))?));
        }
    }
    Ok(())
}

/// Where the freeze marker lives.
pub fn freeze_marker_path(repo_root: &Path) -> PathBuf {
    repo_root.join(ADVERSARIAL_DIR).join("CORPUS-v1.toml")
}

/// Read the freeze marker and check the corpus still matches it.
///
/// Returns the marker on success. A mismatch is not a lint failure to be
/// waved through: the floors in the report were measured against the corpus the
/// marker describes, and a corpus that has moved since needs a re-freeze and a
/// re-measurement, in that order.
pub fn verify_freeze(repo_root: &Path) -> Result<FreezeMarker, String> {
    let path = freeze_marker_path(repo_root);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let marker: FreezeMarker =
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let actual = content_digest(repo_root).map_err(|e| e.to_string())?;
    if actual != marker.digest {
        return Err(format!(
            "the corpus has changed since it was frozen on {}\n  marker: {}\n  actual: {}\n\
             A frozen corpus is what makes the precision and recall floors a test rather than a\n\
             self-assessment. Re-freeze it deliberately (bump the version, record the new digest,\n\
             have the change reviewed) and re-measure after, never the other way round.",
            marker.frozen, marker.digest, actual
        ));
    }
    Ok(marker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_is_none_for_a_detector_that_never_fired() {
        let score = Score {
            true_negatives: 10,
            ..Score::default()
        };
        assert_eq!(score.precision(), None);
        assert!(!score.meets_floors(), "silence is not precision");
    }

    #[test]
    fn the_floors_are_the_ex_ante_numbers() {
        assert_eq!(PRECISION_FLOOR, 0.80);
        assert_eq!(RECALL_FLOOR, 0.70);
    }

    #[test]
    fn a_detector_at_exactly_the_floor_passes() {
        let score = Score {
            true_positives: 4,
            false_positives: 1,
            false_negatives: 1,
            ..Score::default()
        };
        assert_eq!(score.precision(), Some(0.8));
        assert_eq!(score.recall(), Some(0.8));
        assert!(score.meets_floors());
    }

    #[test]
    fn a_detector_below_either_floor_fails() {
        let poor_precision = Score {
            true_positives: 3,
            false_positives: 2,
            false_negatives: 0,
            ..Score::default()
        };
        assert!(!poor_precision.meets_floors());
        let poor_recall = Score {
            true_positives: 3,
            false_positives: 0,
            false_negatives: 3,
            ..Score::default()
        };
        assert!(!poor_recall.meets_floors());
    }

    #[test]
    fn a_cross_fire_does_not_touch_either_floor() {
        let score = Score {
            true_positives: 5,
            false_negatives: 0,
            cross_fires: 4,
            ..Score::default()
        };
        assert_eq!(score.precision(), Some(1.0));
        assert!(score.meets_floors());
    }
}
