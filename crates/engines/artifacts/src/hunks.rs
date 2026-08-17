//! Which lines the change added or modified, on the head side.
//!
//! Diff coverage is a question about lines, and `ChangedSet` is a set of paths —
//! it carries blob OIDs and statuses, not line numbers. So this module runs one
//! more diff, at `--unified=0`, and reads only the hunk headers.
//!
//! # Why the head side, and only the head side
//!
//! A coverage report describes the file as it is *now*: line 42 of the file the
//! test run executed. Deleted lines have no line number on that side and no
//! coverage to have. So `@@ -a,b +c,d @@` contributes `c .. c+d-1` and nothing
//! else, and a pure deletion — `d = 0` — contributes nothing at all.
//!
//! # This is advisory-lane work, and that is what makes it cheap
//!
//! Everything the artifacts family produces is `deterministic: false` (see
//! [`crate::engine`]), because a coverage report is an untracked build output
//! that the verifier has no way to reproduce. That removes the constraint the
//! process family lives under: this diff may read the working tree, because
//! nothing derived from it will ever be digest-compared against another machine.
//!
//! # The three flags that are not decoration
//!
//! - `--src-prefix=a/ --dst-prefix=b/`. Git 2.45 added `diff.srcPrefix` and
//!   `diff.dstPrefix` config, and neither is in P1's `PINNED_CONFIG` — which
//!   cannot be extended from this phase. A repository that set them would make
//!   every `+++ b/` header unparseable and every file silently uncovered. A flag
//!   outranks config, so the prefixes are stated rather than assumed.
//! - `--no-renames`. A rename header would name the file twice and attribute
//!   the hunk to whichever half the parser reached first.
//! - `--unified=0`. Context lines are not changed lines; asking for zero of them
//!   means the hunk header alone is the answer.

use std::collections::BTreeMap;

use andon_core::git::{Endpoint, Git, GitError, ResolvedRange};

/// Flags applied to the hunk diff. See the module docs for the load-bearing
/// three.
const DIFF_FLAGS: &[&str] = &[
    "--unified=0",
    "--no-renames",
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    "--src-prefix=a/",
    "--dst-prefix=b/",
];

/// The hunk diff failed, or git named a path this parser cannot carry.
#[derive(Debug, thiserror::Error)]
pub enum HunkError {
    /// A git command failed.
    #[error(transparent)]
    Git(#[from] GitError),
    /// The base endpoint is not a commit, so there is nothing to diff from.
    #[error("the base endpoint is a {kind}, which has no tree to diff against")]
    NotComparable {
        /// The endpoint kind.
        kind: &'static str,
    },
    /// A path in a diff header is not valid UTF-8.
    #[error("`git diff` named a path that cannot be carried (approximately: {lossy})")]
    UnrepresentablePath {
        /// The header rendered lossily.
        lossy: String,
    },
}

/// Head-side line numbers the change touched, per path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangedLines {
    /// Repository-relative path to sorted line numbers.
    pub by_path: BTreeMap<String, Vec<u32>>,
}

impl ChangedLines {
    /// Run the hunk diff for a resolved range. One git spawn.
    pub fn for_range(git: &Git, range: &ResolvedRange) -> Result<Self, HunkError> {
        let Endpoint::Commit { oid: base, .. } = &range.base else {
            return Err(HunkError::NotComparable {
                kind: range.base.kind(),
            });
        };
        let command = git.cmd(["diff"]).args(DIFF_FLAGS);
        let command = match &range.head {
            Endpoint::Commit { oid: head, .. } => command.args(["--end-of-options", base, head]),
            // The index is a tree git can diff directly.
            Endpoint::Index { .. } => command.args(["--cached", "--end-of-options", base]),
            // No second endpoint: `git diff <base>` is base against the working
            // tree, staged and unstaged together.
            Endpoint::Worktree { .. } => command.args(["--end-of-options", base]),
        };
        Ok(ChangedLines {
            by_path: parse_unified(&command.output()?)?,
        })
    }

    /// Lines touched in one path.
    pub fn for_path(&self, path: &str) -> &[u32] {
        self.by_path
            .get(path)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

/// Read `+++` headers and `@@` hunk headers out of a unified diff.
fn parse_unified(raw: &[u8]) -> Result<BTreeMap<String, Vec<u32>>, HunkError> {
    let mut out: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    let mut current: Option<String> = None;

    for line in raw.split(|b| *b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"+++ ") {
            current = destination_path(rest)?;
            if let Some(path) = &current {
                out.entry(path.clone()).or_default();
            }
        } else if line.starts_with(b"@@ ") {
            let Some(path) = current.as_ref() else {
                continue;
            };
            // A header this parser cannot read is skipped rather than guessed
            // at. `@@` lines are produced by git and not by the repository, so
            // an unreadable one is a bug here, and the honest consequence is
            // fewer reported gaps rather than gaps at invented line numbers.
            if let Some((start, count)) = destination_span(line) {
                let lines = out.entry(path.clone()).or_default();
                lines.extend(start..start.saturating_add(count));
            }
        }
    }
    for lines in out.values_mut() {
        lines.sort_unstable();
        lines.dedup();
    }
    Ok(out)
}

/// The path from a `+++ b/<path>` header, or `None` for `/dev/null`.
fn destination_path(rest: &[u8]) -> Result<Option<String>, HunkError> {
    // Git appends a tab and a timestamp in some configurations; the path ends at
    // the first tab when there is one.
    let end = rest.iter().position(|b| *b == b'\t').unwrap_or(rest.len());
    let field = &rest[..end];
    let field = field.strip_suffix(b"\r").unwrap_or(field);
    if field == b"/dev/null" {
        return Ok(None);
    }
    let text = std::str::from_utf8(field).map_err(|_| HunkError::UnrepresentablePath {
        lossy: String::from_utf8_lossy(rest).into_owned(),
    })?;
    // Git quotes a path containing a control character, a quote, or a backslash
    // whatever `core.quotepath` says, so the quoted form has to be understood
    // rather than merely detected.
    let unquoted = if text.starts_with('"') {
        unquote_c_style(text).ok_or_else(|| HunkError::UnrepresentablePath {
            lossy: text.to_string(),
        })?
    } else {
        text.to_string()
    };
    Ok(unquoted.strip_prefix("b/").map(str::to_string))
}

/// `@@ -a,b +c,d @@` — the destination start and count.
///
/// The count defaults to one when omitted, which is git's convention for a
/// single-line hunk, and may be zero for a pure deletion.
fn destination_span(line: &[u8]) -> Option<(u32, u32)> {
    let text = std::str::from_utf8(line).ok()?;
    let plus = text.find(" +")?;
    let rest = &text[plus + 2..];
    let end = rest.find(' ')?;
    let mut fields = rest[..end].split(',');
    let start = fields.next()?.parse::<u32>().ok()?;
    let count = match fields.next() {
        Some(raw) => raw.parse::<u32>().ok()?,
        None => 1,
    };
    Some((start, count))
}

/// Undo git's C-style path quoting.
///
/// The format is git's `quote_c_style`: the path is wrapped in double quotes and
/// `"`, `\`, and the control characters are escaped, the last as three-digit
/// octal. Returns `None` on anything that is not a well-formed quoted string,
/// which the caller turns into a refusal rather than a guess.
fn unquote_c_style(text: &str) -> Option<String> {
    let inner = text.strip_prefix('"')?.strip_suffix('"')?;
    let mut bytes = Vec::with_capacity(inner.len());
    let mut chars = inner.bytes();
    while let Some(byte) = chars.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        match chars.next()? {
            b'n' => bytes.push(b'\n'),
            b't' => bytes.push(b'\t'),
            b'r' => bytes.push(b'\r'),
            b'"' => bytes.push(b'"'),
            b'\\' => bytes.push(b'\\'),
            digit @ b'0'..=b'7' => {
                let mut value = u32::from(digit - b'0');
                for _ in 0..2 {
                    let next = chars.next()?;
                    if !(b'0'..=b'7').contains(&next) {
                        return None;
                    }
                    value = value * 8 + u32::from(next - b'0');
                }
                bytes.push(u8::try_from(value).ok()?);
            }
            _ => return None,
        }
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIFF: &[u8] = b"diff --git a/src/a.ts b/src/a.ts\n--- a/src/a.ts\n+++ b/src/a.ts\n@@ -1 +1 @@\n-old\n+new\n@@ -10,0 +11,3 @@\n+one\n+two\n+three\n";

    #[test]
    fn single_line_and_multi_line_hunks_both_land() {
        let parsed = parse_unified(DIFF).expect("well formed");
        assert_eq!(parsed["src/a.ts"], vec![1, 11, 12, 13]);
    }

    #[test]
    fn a_pure_deletion_contributes_no_lines() {
        // `+4,0`: nothing exists on the head side, so nothing can be uncovered.
        let diff = b"+++ b/src/a.ts\n@@ -5,3 +4,0 @@\n-a\n-b\n-c\n";
        let parsed = parse_unified(diff).expect("well formed");
        assert!(parsed["src/a.ts"].is_empty());
    }

    #[test]
    fn a_deleted_file_is_not_a_path_at_all() {
        let diff = b"--- a/src/gone.ts\n+++ /dev/null\n@@ -1,3 +0,0 @@\n-a\n";
        let parsed = parse_unified(diff).expect("well formed");
        assert!(parsed.is_empty());
    }

    #[test]
    fn a_file_with_no_hunks_is_present_and_empty() {
        // A mode-only change. Present so the engine can tell "no lines changed"
        // apart from "this file was not in the diff".
        let diff = b"+++ b/src/a.ts\n";
        let parsed = parse_unified(diff).expect("well formed");
        assert!(parsed.contains_key("src/a.ts"));
    }

    #[test]
    fn a_quoted_path_is_unquoted_rather_than_taken_literally() {
        // Git quotes a path containing a tab whatever `core.quotepath` says.
        let diff = b"+++ \"b/src/od\\td.ts\"\n@@ -0,0 +1 @@\n+x\n";
        let parsed = parse_unified(diff).expect("well formed");
        assert_eq!(parsed["src/od\td.ts"], vec![1]);
    }

    #[test]
    fn octal_escapes_round_trip() {
        assert_eq!(
            unquote_c_style(r#""b/caf\303\251.ts""#).as_deref(),
            Some("b/café.ts")
        );
        assert_eq!(unquote_c_style(r#""b/a\\b""#).as_deref(), Some("b/a\\b"));
        assert_eq!(unquote_c_style(r#""unterminated"#), None);
        assert_eq!(unquote_c_style(r#""bad \z escape""#), None);
    }

    #[test]
    fn a_header_path_that_is_not_utf8_is_refused() {
        let diff = b"+++ b/src/\xff.ts\n@@ -0,0 +1 @@\n+x\n";
        assert!(matches!(
            parse_unified(diff),
            Err(HunkError::UnrepresentablePath { .. })
        ));
    }
}
