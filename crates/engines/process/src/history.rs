//! The windowed history: one `git log`, parsed, and everything downstream
//! derived from it.
//!
//! # Why the window is anchored to a commit and not to the clock
//!
//! "The last 365 days" is the obvious reading of a history window and it is the
//! one thing this module must not do. A wall-clock window makes the measured
//! commit set a function of *when* the measurement ran: the agent measures at
//! 09:00, the verifier recomputes the same `(base_oid, head_oid)` at 09:40, a
//! commit has aged past the cutoff in between, and two honest runs produce
//! different churn. Per-result digests cover the value, so that is a
//! `divergent` verdict on clean work — PREMORTEM Story 1 arriving through the
//! process family's front door.
//!
//! So the cutoff is derived from the **anchor commit's own committer
//! timestamp**, which is a fixed property of an immutable object:
//!
//! ```text
//! cutoff = committer_time(anchor) - window_days × 86400
//! ```
//!
//! Both sides pin the same `head_oid`, so both compute the same cutoff, walk the
//! same commits, and get the same numbers — today, tomorrow, and on a runner in
//! another timezone. The clock is never read.
//!
//! # What the traversal is pinned to, and why that is in the regime
//!
//! [`LOG_FLAGS`] is the counting spec. Three of the flags change results rather
//! than formatting:
//!
//! - `--no-merges`. `git log --numstat` reports no per-file numbers for a merge
//!   commit, so counting merges would add commits to a file's churn that
//!   contributed no measurable lines to it.
//! - `--no-renames`. Rename detection is a *heuristic whose defaults have moved
//!   across git releases* (the same drift PREMORTEM Story 1 names beside CRLF),
//!   and with it on, `--numstat` rewrites paths into `{old => new}/x` forms that
//!   have to be parsed back. Off, a rename is a delete and an add: less
//!   informative, and identical on every git. The cost is stated in the
//!   registry's `does_not_predict` — churn does not follow a file across a
//!   rename.
//! - `--no-use-mailmap`. `.mailmap` is read from the **working tree**, so
//!   honouring it would let an uncommitted edit to that file change author
//!   attribution — worktree bytes reaching a compared-lane number, which is the
//!   lane boundary PREMORTEM T1 exists to hold. `log.mailmap` is not in
//!   `PINNED_CONFIG` and cannot be added from here (that file is P1's), so the
//!   flag form does the work: a flag outranks config and cannot be overridden.
//!
//! What remains version-sensitive is git's own date-limited traversal, which
//! prunes with a slop heuristic and can therefore *omit* a clock-skewed commit
//! that a full walk would keep. That is why [`MeasurementRegime::Process`]
//! carries `git_version`: two gits are two regimes, and the verifier says
//! `unwitnessed-version-skew` rather than accusing anyone (PREMORTEM S4). The
//! Rust-side filter below is belt to that brace — it guarantees no commit
//! *outside* the window is ever counted, whatever approxidate did with the
//! cutoff string.
//!
//! # Non-UTF-8 author names are hashed, never decoded
//!
//! Git tracks an author identity as bytes. Entropy needs identity *equality* and
//! never the name itself, so the raw `name\0email` bytes are hashed into
//! [`author_key`] and the name is dropped. One exotic byte in one contributor's
//! name would otherwise take the whole engine down with a UTF-8 error, and
//! rendering it lossily would silently merge two contributors into one — the
//! same collapse `GitError::UnrepresentablePath` refuses for paths.
//!
//! Paths get the opposite treatment for the same reason: they are identities on
//! the wire, so they are decoded strictly and a path that would only survive
//! approximately is refused.

use std::collections::BTreeMap;

use andon_core::git::{Git, GitError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Format version of the serialized window. Part of the cache key material, so
/// a change here abandons old entries rather than reinterpreting them.
pub const WINDOW_VERSION: u32 = 1;

/// Seconds in a day. History windows are expressed in days because that is what
/// the policy field says, and days are 86400 seconds regardless of what the
/// civil calendar did that year — no timezone or leap-second arithmetic is
/// wanted here, only a fixed offset both sides compute identically.
pub const SECONDS_PER_DAY: i64 = 86_400;

/// Record separator planted at the head of every `git log` record.
///
/// A byte rather than a string because git's format placeholders emit bytes
/// (`%x01`). Paths can contain it — see [`split_records`] for why that does not
/// break the parse.
const RECORD_MARK: u8 = 0x01;

/// The traversal and formatting spec. See the module docs: the first three
/// entries change *results*, so changing any of them is an engine-version bump.
const LOG_FLAGS: &[&str] = &[
    "--no-merges",
    "--no-renames",
    "--no-use-mailmap",
    "-z",
    "--numstat",
    "--format=format:%x01%H%x00%ct%x00%an%x00%ae",
];

/// The history could not be read, or git said something this parser does not
/// understand.
#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    /// A git command failed.
    #[error(transparent)]
    Git(#[from] GitError),
    /// git's output did not match the documented `--numstat -z` framing.
    #[error("could not parse `git log --numstat -z` output: {detail}")]
    Protocol {
        /// What was expected and what arrived.
        detail: String,
    },
    /// git named a path that cannot be carried without changing it.
    ///
    /// The same refusal `andon_core::git::GitError::UnrepresentablePath` makes,
    /// for the same reason: a path is a map key and a wire identity here, and a
    /// lossy decode collapses two files into one.
    #[error("`git log` named a path that cannot be carried: {detail} (approximately: {lossy})")]
    UnrepresentablePath {
        /// Which property the path fails.
        detail: String,
        /// The offending record rendered lossily — wrong by construction, and
        /// the only way to point an operator at the file.
        lossy: String,
    },
}

/// One file's part in one commit.
///
/// `added` and `deleted` are `None` for a binary file, which git reports as
/// `-\t-\t<path>`. A binary edit is a real touch with no line count, and
/// recording it as zero lines would be a fabricated number in a family whose
/// whole discipline is not to fabricate them (PLAN P4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathTouch {
    /// Index into [`HistoryWindow::paths`].
    pub path: u32,
    /// Lines added, or `None` for a binary file.
    pub added: Option<u64>,
    /// Lines deleted, or `None` for a binary file.
    pub deleted: Option<u64>,
}

/// One commit inside the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitFacts {
    /// Full commit OID.
    pub oid: String,
    /// Committer timestamp, unix seconds. The field `--since` filters on, and
    /// therefore the one the window is defined in terms of.
    pub committed_at: i64,
    /// Stable hash of the raw `name\0email` bytes. See the module docs.
    pub author_key: String,
    /// Every path this commit touched, sorted by path index.
    pub touches: Vec<PathTouch>,
}

/// The commits in one window, and the path table their touches index into.
///
/// Serialized whole into the history cache. Storing the commit list rather than
/// pre-aggregated per-path totals is deliberate: change coupling is a question
/// about which paths appear *together*, and an aggregate that has already
/// collapsed each commit into per-path counts cannot answer it. The size is
/// linear in the number of path-touches in the window, which is the size of the
/// history itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryWindow {
    /// See [`WINDOW_VERSION`].
    pub version: u32,
    /// The commit the window is anchored to — the head of the measured change.
    pub anchor_oid: String,
    /// The anchor's committer timestamp. Everything time-shaped is measured
    /// from here, never from the clock.
    pub anchor_committed_at: i64,
    /// Window width in days, from `policy.history.window_days`.
    pub window_days: u32,
    /// `anchor_committed_at - window_days × 86400`.
    pub cutoff: i64,
    /// `git --version` that produced the walk. Part of the regime.
    pub git_version: String,
    /// True when the repository is shallow, so the walk may have stopped at a
    /// truncation rather than at the window edge.
    pub truncated: bool,
    /// Every path any commit in the window touched, sorted and deduplicated.
    pub paths: Vec<String>,
    /// The commits, newest first (git's order, preserved).
    pub commits: Vec<CommitFacts>,
}

impl HistoryWindow {
    /// Read the window for `anchor_oid`. Two git spawns, or none on a cache hit
    /// (see [`crate::cache`]).
    ///
    /// The first spawn asks the anchor what time it is; the second walks. There
    /// is no way to collapse them — the cutoff the walk is bounded by is derived
    /// from the answer to the first — and a walk with no bound is the
    /// repository-sized cost PREMORTEM T6 rules out.
    pub fn read(git: &Git, anchor_oid: &str, window_days: u32) -> Result<Self, HistoryError> {
        let anchor_committed_at = committed_at(git, anchor_oid)?;
        let cutoff = anchor_committed_at - i64::from(window_days) * SECONDS_PER_DAY;

        let raw = git
            .cmd(["log"])
            .args(LOG_FLAGS)
            .arg(format!("--since={}", format_utc(cutoff)))
            .args(["--end-of-options", anchor_oid])
            .output()?;

        let parsed = parse_log(&raw)?;

        // Belt to the `--since` brace. git's date-limited traversal prunes with
        // a slop heuristic, so it can hand back a commit fractionally outside
        // the window on skewed clocks; the window's definition is the
        // arithmetic above and not whatever approxidate made of it.
        let mut paths: Vec<String> = Vec::new();
        let mut index: BTreeMap<String, u32> = BTreeMap::new();
        let mut commits = Vec::with_capacity(parsed.len());
        for commit in parsed {
            if commit.committed_at < cutoff {
                continue;
            }
            let mut touches: Vec<PathTouch> = commit
                .touches
                .into_iter()
                .map(|(path, added, deleted)| {
                    let next = paths.len() as u32;
                    let path_index = *index.entry(path.clone()).or_insert_with(|| {
                        paths.push(path);
                        next
                    });
                    PathTouch {
                        path: path_index,
                        added,
                        deleted,
                    }
                })
                .collect();
            // Sorted so a commit's touch list is a property of its content and
            // not of git's output order, which `diff.orderFile` can move.
            touches.sort_by_key(|t| t.path);
            commits.push(CommitFacts {
                oid: commit.oid,
                committed_at: commit.committed_at,
                author_key: commit.author_key,
                touches,
            });
        }

        Ok(HistoryWindow {
            version: WINDOW_VERSION,
            anchor_oid: anchor_oid.to_string(),
            anchor_committed_at,
            window_days,
            cutoff,
            git_version: git.version().to_string(),
            truncated: git.facts().shallow,
            paths,
            commits,
        })
    }

    /// Index of `path` in the path table, if the window saw it at all.
    pub fn path_index(&self, path: &str) -> Option<u32> {
        self.paths.iter().position(|p| p == path).map(|i| i as u32)
    }
}

/// The anchor commit's committer timestamp.
///
/// `%ct` and not `%at`: the author date is metadata a rebase preserves and a
/// forger can set to anything, while `--since` filters on the committer date.
/// The window's edge and the field it selects on have to be the same field, or
/// the cutoff means one thing here and another to git.
fn committed_at(git: &Git, oid: &str) -> Result<i64, HistoryError> {
    let text = git
        .cmd(["log", "-1", "--format=format:%ct", "--end-of-options", oid])
        .text()?;
    text.trim()
        .parse::<i64>()
        .map_err(|_| HistoryError::Protocol {
            detail: format!("expected a unix timestamp for {oid}, got {text:?}"),
        })
}

/// A unix timestamp as an ISO-8601 UTC string git's approxidate accepts.
///
/// Hand-rolled rather than pulled from a date crate: this is the only date
/// formatting the engine does, the input is a plain epoch offset, and the
/// civil-calendar conversion below is the standard days-from-epoch algorithm
/// with no timezone, locale, or leap-second behaviour to get wrong. `+0000` is
/// explicit so the string cannot be read in the runner's local zone.
fn format_utc(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(SECONDS_PER_DAY);
    let seconds = epoch_seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}+0000",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60,
    )
}

/// Days since 1970-01-01 to a civil date. Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// A commit as the parser found it, before windowing and path interning.
struct RawCommit {
    oid: String,
    committed_at: i64,
    author_key: String,
    touches: Vec<(String, Option<u64>, Option<u64>)>,
}

/// Split the stream into records, rejoining fragments that are not headers.
///
/// [`RECORD_MARK`] can legally appear inside a path, which would split one
/// commit's numstat block in two. A fragment is a real record only if it opens
/// with a 40-character lowercase hex OID, a NUL, and then digits followed by
/// another NUL — the `%H%x00%ct%x00` prefix.
///
/// That test cannot be fooled by a path. For a fragment to look like a header
/// its first NUL-delimited piece must be exactly 40 hex characters, which means
/// the path containing the mark ends in `\x01` + 40 hex — and NUL cannot occur
/// in a path, so the piece after it is whatever followed the path's terminator:
/// the next numstat entry, which begins `<digits>\t`, not `<digits>\0`. Both
/// halves of the test have to pass, and the second one cannot.
fn split_records(raw: &[u8]) -> Vec<Vec<u8>> {
    let mut records: Vec<Vec<u8>> = Vec::new();
    for fragment in raw.split(|b| *b == RECORD_MARK) {
        if fragment.is_empty() {
            continue;
        }
        if looks_like_header(fragment) || records.is_empty() {
            records.push(fragment.to_vec());
        } else {
            // Not a header: the mark was inside a path. Put it back.
            let last = records.last_mut().expect("non-empty by the branch above");
            last.push(RECORD_MARK);
            last.extend_from_slice(fragment);
        }
    }
    records
}

fn looks_like_header(fragment: &[u8]) -> bool {
    let mut pieces = fragment.split(|b| *b == 0);
    let oid = pieces.next().unwrap_or_default();
    let time = pieces.next().unwrap_or_default();
    oid.len() == 40
        && oid.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && !time.is_empty()
        && time.iter().all(u8::is_ascii_digit)
}

/// Parse `git log --numstat -z` output framed by [`LOG_FLAGS`].
///
/// The framing, established by running it rather than by reading the manual:
///
/// ```text
/// \x01<oid>\0<ct>\0<name>\0<email>\n<add>\t<del>\t<path>\0<add>\t<del>\t<path>\0\0
/// ```
///
/// The header's last field runs straight into the first numstat entry with only
/// a newline between them — git's `format:` puts one line break before the diff
/// output — so the email and the first entry arrive in the same NUL-delimited
/// piece and are split apart on that newline. Git forbids a newline in an ident,
/// so the first one is always the boundary.
fn parse_log(raw: &[u8]) -> Result<Vec<RawCommit>, HistoryError> {
    let mut commits = Vec::new();
    for record in split_records(raw) {
        let mut pieces = record.split(|b| *b == 0);
        let oid = pieces.next().ok_or_else(|| HistoryError::Protocol {
            detail: "record has no commit id".to_string(),
        })?;
        let time = pieces.next().ok_or_else(|| HistoryError::Protocol {
            detail: "record has no committer time".to_string(),
        })?;
        let name = pieces.next().ok_or_else(|| HistoryError::Protocol {
            detail: "record has no author name".to_string(),
        })?;
        let tail = pieces.next().unwrap_or_default();

        let oid =
            std::str::from_utf8(oid)
                .map(str::to_string)
                .map_err(|_| HistoryError::Protocol {
                    detail: "commit id is not ASCII".to_string(),
                })?;
        let committed_at = std::str::from_utf8(time)
            .ok()
            .and_then(|t| t.parse::<i64>().ok())
            .ok_or_else(|| HistoryError::Protocol {
                detail: format!("committer time of {oid} is not an integer"),
            })?;

        // The email runs up to the newline git puts before the diff block; the
        // rest of the piece is the first numstat entry.
        let split_at = tail.iter().position(|b| *b == b'\n').unwrap_or(tail.len());
        let (email, rest) = tail.split_at(split_at);
        let author_key = author_key(name, email);

        let mut touches = Vec::new();
        let first = rest.strip_prefix(b"\n").unwrap_or(rest);
        for entry in std::iter::once(first).chain(pieces) {
            if entry.is_empty() {
                continue;
            }
            touches.push(parse_numstat(entry)?);
        }

        commits.push(RawCommit {
            oid,
            committed_at,
            author_key,
            touches,
        });
    }
    Ok(commits)
}

/// One `<added>\t<deleted>\t<path>` entry.
fn parse_numstat(entry: &[u8]) -> Result<(String, Option<u64>, Option<u64>), HistoryError> {
    let mut fields = entry.splitn(3, |b| *b == b'\t');
    let added = fields.next().unwrap_or_default();
    let deleted = fields.next().unwrap_or_default();
    let path = fields.next().ok_or_else(|| HistoryError::Protocol {
        detail: format!(
            "numstat entry has fewer than three fields: {:?}",
            String::from_utf8_lossy(entry)
        ),
    })?;

    let path = std::str::from_utf8(path).map_err(|err| HistoryError::UnrepresentablePath {
        detail: format!("not valid UTF-8 at byte {}", err.valid_up_to()),
        lossy: String::from_utf8_lossy(entry).into_owned(),
    })?;

    Ok((path.to_string(), count_field(added), count_field(deleted)))
}

/// A numstat count, or `None` for the `-` git prints for a binary file.
fn count_field(field: &[u8]) -> Option<u64> {
    std::str::from_utf8(field).ok()?.parse::<u64>().ok()
}

/// A stable identity for an author, computed from bytes that are never decoded.
///
/// The NUL between the two halves keeps `("ab", "c")` and `("a", "bc")` apart.
/// Sixteen hex characters is 64 bits: this is a grouping key inside one
/// repository's window, not a security boundary, and a shorter key keeps the
/// serialized cache entry small.
fn author_key(name: &[u8], email: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name);
    hasher.update([0u8]);
    hasher.update(email);
    let digest = hasher.finalize();
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact bytes git 2.39 produced for the two-commit probe, transcribed
    /// from `od -c`. A hand-written fixture rather than a live repository so the
    /// *framing* is under test here and not this machine's git.
    const SAMPLE: &[u8] = b"\x01d0b956fe086d2e33ea7149d98e1f18d53bd3b3b0\x001782864000\x00Bob \xce\xa9\x00b@example.com\n0\t2\tsrc/b.ts\x003\t0\tsrc/c.ts\x00\x00\x01219bfd33f9c818765e65f64cda54cee528b98d58\x001780272000\x00Bob \xce\xa9\x00b@example.com\n1\t0\tsrc/a.ts\x002\t1\tsrc/b.ts\x00\x00";

    #[test]
    fn the_framing_git_actually_emits_parses() {
        let commits = parse_log(SAMPLE).expect("the sample is well formed");
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].committed_at, 1_782_864_000);
        assert_eq!(commits[0].touches.len(), 2);
        assert_eq!(
            commits[0].touches[0],
            ("src/b.ts".to_string(), Some(0), Some(2))
        );
        assert_eq!(commits[1].touches.len(), 2);
    }

    #[test]
    fn a_non_utf8_author_name_does_not_take_the_engine_down() {
        // `\xff` is invalid UTF-8 in any encoding. The name is hashed, never
        // decoded, so it parses — and hashes to something distinct from another
        // author, which is the only property entropy needs.
        let one = author_key(b"\xff\xfe", b"a@example.com");
        let two = author_key(b"\xff\xfd", b"a@example.com");
        assert_ne!(one, two);
        assert_eq!(one.len(), 16);
    }

    #[test]
    fn the_nul_between_name_and_email_keeps_identities_apart() {
        // Without it, ("ab", "c") and ("a", "bc") hash to the same author and
        // two contributors silently become one — an entropy of zero on a file
        // two people own.
        assert_ne!(author_key(b"ab", b"c"), author_key(b"a", b"bc"));
    }

    #[test]
    fn a_binary_file_has_no_line_counts_rather_than_zero_ones() {
        let raw = b"\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x001700000000\x00A\x00a@e\n-\t-\tlogo.png\x00\x00";
        let commits = parse_log(raw).expect("well formed");
        assert_eq!(commits[0].touches[0], ("logo.png".to_string(), None, None));
    }

    #[test]
    fn a_record_mark_inside_a_path_does_not_split_the_commit() {
        // A file named `weird\x01name.ts`. Split naively this is two records and
        // the second one's numstat block is attributed to nothing.
        let raw = b"\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x001700000000\x00A\x00a@e\n1\t0\tweird\x01name.ts\x002\t0\tsrc/b.ts\x00\x00";
        let commits = parse_log(raw).expect("well formed");
        assert_eq!(commits.len(), 1, "the mark inside a path split the record");
        assert_eq!(commits[0].touches.len(), 2);
        assert_eq!(commits[0].touches[0].0, "weird\u{1}name.ts");
    }

    #[test]
    fn a_path_that_would_only_survive_approximately_is_refused() {
        let raw = b"\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x001700000000\x00A\x00a@e\n1\t0\tsrc/\xff.ts\x00\x00";
        assert!(matches!(
            parse_log(raw),
            Err(HistoryError::UnrepresentablePath { .. })
        ));
    }

    #[test]
    fn a_commit_that_touched_nothing_is_a_commit_with_no_touches() {
        let raw = b"\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x001700000000\x00A\x00a@e\n\x00";
        let commits = parse_log(raw).expect("well formed");
        assert_eq!(commits.len(), 1);
        assert!(commits[0].touches.is_empty());
    }

    #[test]
    fn the_cutoff_string_is_utc_and_unambiguous() {
        // 2026-08-17T06:30:00Z. A runner in another zone must read the same
        // instant, which is what the explicit +0000 buys.
        assert_eq!(format_utc(1_786_948_200), "2026-08-17T06:30:00+0000");
        assert_eq!(format_utc(0), "1970-01-01T00:00:00+0000");
        // A leap day, because the civil-date conversion is the only arithmetic
        // here that has a wrong answer available to it.
        assert_eq!(format_utc(1_709_164_800), "2024-02-29T00:00:00+0000");
    }
}
