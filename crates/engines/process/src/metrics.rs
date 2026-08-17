//! Per-path derivations over a [`HistoryWindow`].
//!
//! Everything here is integer arithmetic over the commit list. No wall clock is
//! read — ages are measured from the anchor commit's own timestamp — and no
//! floating point is used, so two runs over the same window agree bit for bit
//! whatever platform they are on. The one number that wants a logarithm is
//! computed in [`crate::entropy`], for the reason set out there.
//!
//! # The two constants that are counting policy
//!
//! [`COUPLING_MIN_SUPPORT`] and the coupling ratio decide which co-change
//! relationships are worth reporting. They belong in policy in principle, and
//! `.andon.toml` is P0-owned and cannot grow a field from this phase — so they
//! live here as part of the engine's counting spec instead. That is not a
//! workaround with no accountability: `SPEC_REVISION` is folded into the engine
//! version this crate reports, and the engine version is bound into
//! `MeasurementRegime::Process`, so changing either constant makes old and new
//! numbers *incomparable* rather than silently different. A verifier at the old
//! spec meets a report at the new one and says `unwitnessed-version-skew`, which
//! is exactly what a changed definition should produce.

use std::collections::BTreeMap;

use crate::history::{HistoryWindow, SECONDS_PER_DAY};

/// Co-changes required before a coupling relationship is reported at all.
///
/// Two files that changed together twice is a coincidence with a p-value; the
/// floor is what keeps the metric from being a list of every file anyone ever
/// touched in the same commit as this one.
pub const COUPLING_MIN_SUPPORT: u64 = 3;

/// Coupling threshold as an exact rational: a partner must appear in at least
/// `NUMERATOR/DENOMINATOR` of the target's eligible commits.
///
/// A rational and not a float, and compared by cross-multiplication, so the
/// threshold test is integer arithmetic like everything else here.
pub const COUPLING_RATIO_NUMERATOR: u64 = 1;
/// Denominator of [`COUPLING_RATIO_NUMERATOR`]. One half.
pub const COUPLING_RATIO_DENOMINATOR: u64 = 2;

/// Commits touching more paths than this contribute nothing to coupling.
///
/// A repository-wide reformat, a dependency bump that rewrites every lockfile
/// path, or a vendored-tree import couples every file to every other file and
/// swamps the real signal — the sensitivity `docs/metric-families.csv` names for
/// this family. The cap is also what keeps the pair work bounded: without it a
/// single 40,000-file commit is a 1.6-billion-pair loop.
pub const COUPLING_MAX_COMMIT_PATHS: usize = 25;

/// What the window says about one path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathHistory {
    /// Non-merge commits inside the window that touched this path.
    pub commits: u64,
    /// Lines added plus deleted, over the touches that had line counts.
    pub text_lines: u64,
    /// Touches that carried line counts.
    pub text_touches: u64,
    /// Touches git reported as binary, which carry no line counts at all.
    pub binary_touches: u64,
    /// Committer time of the most recent commit in the window touching it.
    pub last_commit_at: Option<i64>,
    /// Commits per author identity. Keys are [`crate::history`]'s author keys,
    /// never names.
    pub authors: BTreeMap<String, u64>,
}

impl PathHistory {
    /// Days between the anchor commit and the most recent change to this path.
    ///
    /// `None` when the window holds no commit touching it — the file's last
    /// change is *older than the window*, and the exact age is a number this
    /// walk deliberately did not pay for. Reporting the window width, or zero,
    /// would be inventing it.
    pub fn age_days(&self, anchor_committed_at: i64) -> Option<u64> {
        let last = self.last_commit_at?;
        // Clamped at zero rather than signed: a committer date ahead of the
        // anchor's is a clock-skewed commit, not a file changed in the future.
        Some(((anchor_committed_at - last).max(0) / SECONDS_PER_DAY) as u64)
    }

    /// Author commit counts, for [`crate::entropy::entropy_microbits`].
    pub fn author_counts(&self) -> Vec<u64> {
        self.authors.values().copied().collect()
    }
}

/// Aggregate the window for a set of paths, in one pass over the commits.
///
/// Paths absent from the window get a default [`PathHistory`] — zero commits —
/// rather than no entry, so a caller cannot silently drop a changed file it
/// asked about. What "zero commits" is allowed to *mean* is the caller's
/// decision and a careful one: see [`crate::engine`], where a path with no
/// commits reports an unwitnessed age rather than an age of zero.
pub fn aggregate(window: &HistoryWindow, paths: &[String]) -> BTreeMap<String, PathHistory> {
    let mut wanted: BTreeMap<u32, &str> = BTreeMap::new();
    for path in paths {
        if let Some(index) = window.path_index(path) {
            wanted.insert(index, path.as_str());
        }
    }

    let mut out: BTreeMap<String, PathHistory> = paths
        .iter()
        .map(|path| (path.clone(), PathHistory::default()))
        .collect();

    for commit in &window.commits {
        for touch in &commit.touches {
            let Some(path) = wanted.get(&touch.path) else {
                continue;
            };
            let entry = out.get_mut(*path).expect("seeded from the same list");
            entry.commits += 1;
            match (touch.added, touch.deleted) {
                (Some(added), Some(deleted)) => {
                    entry.text_lines += added + deleted;
                    entry.text_touches += 1;
                }
                // git reports `-` for both fields on a binary file. A touch with
                // no line count is still a touch.
                _ => entry.binary_touches += 1,
            }
            entry.last_commit_at = Some(match entry.last_commit_at {
                Some(seen) => seen.max(commit.committed_at),
                None => commit.committed_at,
            });
            *entry.authors.entry(commit.author_key.clone()).or_default() += 1;
        }
    }
    out
}

/// Files that habitually change with `path` and are **absent from this change**.
///
/// The count, not the list, because a result carries one value — and the count
/// is the part that answers the question worth asking: *how much of what usually
/// moves with this file has not moved?* A partner already in the diff is not a
/// finding, which is why the changed set is subtracted rather than reported.
///
/// The ratio's denominator is the number of *eligible* commits touching `path` —
/// those under [`COUPLING_MAX_COMMIT_PATHS`] — and not every commit touching it.
/// Numerator and denominator have to be drawn from the same population or a file
/// that mostly appears in sweeping commits looks uncoupled from everything.
pub fn coupled_absent_partners(window: &HistoryWindow, path: &str, changed: &[String]) -> u64 {
    let Some(target) = window.path_index(path) else {
        return 0;
    };

    let mut eligible_commits: u64 = 0;
    let mut co_change: BTreeMap<u32, u64> = BTreeMap::new();
    for commit in &window.commits {
        if commit.touches.len() > COUPLING_MAX_COMMIT_PATHS {
            continue;
        }
        if !commit.touches.iter().any(|t| t.path == target) {
            continue;
        }
        eligible_commits += 1;
        for touch in &commit.touches {
            if touch.path != target {
                *co_change.entry(touch.path).or_default() += 1;
            }
        }
    }
    if eligible_commits == 0 {
        return 0;
    }

    let in_change: std::collections::BTreeSet<&str> = changed.iter().map(String::as_str).collect();
    co_change
        .into_iter()
        .filter(|(_, support)| *support >= COUPLING_MIN_SUPPORT)
        .filter(|(_, support)| {
            // support / eligible >= NUM / DEN, by cross-multiplication.
            support * COUPLING_RATIO_DENOMINATOR >= eligible_commits * COUPLING_RATIO_NUMERATOR
        })
        .filter(|(partner, _)| {
            window
                .paths
                .get(*partner as usize)
                .is_some_and(|p| !in_change.contains(p.as_str()))
        })
        .count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{CommitFacts, PathTouch, WINDOW_VERSION};

    /// `(path index, added, deleted)` — one file's part in one commit.
    type TestTouch = (u32, Option<u64>, Option<u64>);
    /// `(committer time, author key, touches)`.
    type TestCommit = (i64, &'static str, Vec<TestTouch>);

    fn window(paths: &[&str], commits: Vec<TestCommit>) -> HistoryWindow {
        HistoryWindow {
            version: WINDOW_VERSION,
            anchor_oid: "a".repeat(40),
            anchor_committed_at: 1_800_000_000,
            window_days: 365,
            cutoff: 1_800_000_000 - 365 * SECONDS_PER_DAY,
            git_version: "git version 2.39.0".to_string(),
            truncated: false,
            paths: paths.iter().map(|p| p.to_string()).collect(),
            commits: commits
                .into_iter()
                .map(|(at, author, touches)| CommitFacts {
                    oid: "c".repeat(40),
                    committed_at: at,
                    author_key: author.to_string(),
                    touches: touches
                        .into_iter()
                        .map(|(path, added, deleted)| PathTouch {
                            path,
                            added,
                            deleted,
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    #[test]
    fn churn_counts_commits_and_lines_separately() {
        let w = window(
            &["src/a.ts", "src/b.ts"],
            vec![
                (1_800_000_000, "alice", vec![(0, Some(3), Some(1))]),
                (
                    1_799_000_000,
                    "bob",
                    vec![(0, Some(10), Some(0)), (1, Some(1), Some(1))],
                ),
            ],
        );
        let agg = aggregate(&w, &["src/a.ts".to_string()]);
        let a = &agg["src/a.ts"];
        assert_eq!(a.commits, 2);
        assert_eq!(a.text_lines, 14);
        assert_eq!(a.authors.len(), 2);
        assert_eq!(a.age_days(1_800_000_000), Some(0));
    }

    #[test]
    fn a_path_the_window_never_saw_is_present_with_no_history() {
        // Present-and-empty rather than absent: a caller that iterates the map
        // must not silently lose a changed file.
        let w = window(&["src/a.ts"], vec![]);
        let agg = aggregate(&w, &["src/never.ts".to_string()]);
        assert_eq!(agg["src/never.ts"].commits, 0);
        assert_eq!(agg["src/never.ts"].age_days(1_800_000_000), None);
    }

    #[test]
    fn a_binary_touch_carries_no_lines_and_is_still_a_commit() {
        let w = window(
            &["logo.png"],
            vec![(1_800_000_000, "alice", vec![(0, None, None)])],
        );
        let agg = aggregate(&w, &["logo.png".to_string()]);
        assert_eq!(agg["logo.png"].commits, 1);
        assert_eq!(agg["logo.png"].binary_touches, 1);
        assert_eq!(agg["logo.png"].text_touches, 0);
        assert_eq!(agg["logo.png"].text_lines, 0);
    }

    #[test]
    fn age_is_measured_from_the_anchor_and_never_from_the_clock() {
        let w = window(
            &["src/a.ts"],
            vec![(
                1_800_000_000 - 10 * SECONDS_PER_DAY,
                "alice",
                vec![(0, Some(1), Some(0))],
            )],
        );
        let agg = aggregate(&w, &["src/a.ts".to_string()]);
        assert_eq!(agg["src/a.ts"].age_days(1_800_000_000), Some(10));
    }

    #[test]
    fn a_commit_dated_after_the_anchor_does_not_produce_a_negative_age() {
        let w = window(
            &["src/a.ts"],
            vec![(
                1_800_000_000 + 5 * SECONDS_PER_DAY,
                "alice",
                vec![(0, Some(1), Some(0))],
            )],
        );
        let agg = aggregate(&w, &["src/a.ts".to_string()]);
        assert_eq!(agg["src/a.ts"].age_days(1_800_000_000), Some(0));
    }

    #[test]
    fn coupling_reports_the_partners_this_change_left_behind() {
        // a.ts and b.ts moved together in all four commits; a.ts and c.ts twice,
        // which is below the support floor. Changing only a.ts should report
        // exactly one absent partner.
        let commits = (0..4)
            .map(|i| {
                let mut touches = vec![(0u32, Some(1u64), Some(0u64)), (1, Some(1), Some(0))];
                if i < 2 {
                    touches.push((2, Some(1), Some(0)));
                }
                (1_800_000_000 - i * SECONDS_PER_DAY, "alice", touches)
            })
            .collect();
        let w = window(&["src/a.ts", "src/b.ts", "src/c.ts"], commits);
        assert_eq!(
            coupled_absent_partners(&w, "src/a.ts", &["src/a.ts".to_string()]),
            1
        );
        // With b.ts in the diff there is nothing left to report.
        assert_eq!(
            coupled_absent_partners(
                &w,
                "src/a.ts",
                &["src/a.ts".to_string(), "src/b.ts".to_string()]
            ),
            0
        );
    }

    #[test]
    fn a_sweeping_commit_does_not_couple_everything_to_everything() {
        // One commit touching more paths than the cap. Without the cap this
        // would report every other file as a partner of the first.
        let touches: Vec<(u32, Option<u64>, Option<u64>)> = (0..COUPLING_MAX_COMMIT_PATHS as u32
            + 5)
            .map(|i| (i, Some(1), Some(0)))
            .collect();
        let paths: Vec<String> = (0..COUPLING_MAX_COMMIT_PATHS + 5)
            .map(|i| format!("src/f{i}.ts"))
            .collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let w = window(
            &refs,
            vec![
                (1_800_000_000, "alice", touches.clone()),
                (1_799_000_000, "alice", touches.clone()),
                (1_798_000_000, "alice", touches),
            ],
        );
        assert_eq!(
            coupled_absent_partners(&w, "src/f0.ts", &["src/f0.ts".to_string()]),
            0
        );
    }
}
