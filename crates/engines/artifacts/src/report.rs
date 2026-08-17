//! Coverage reports: what one is, how one is found, and how bytes become one.
//!
//! # Parse only. Nothing here runs anything.
//!
//! PLAN P4 is explicit and the engine class enforces it: this family reads
//! report files that some other tool produced and never invokes a test runner,
//! a coverage tool, or a build. The distinction matters beyond tidiness —
//! executing repository code is `EngineClass::CodeExec` and needs P7's sandbox,
//! and an engine that quietly shelled out to `npm test` would have crossed that
//! boundary without the trait noticing.
//!
//! # Why every input here is hostile until proven otherwise
//!
//! A coverage report is a file in the repository under measurement, which means
//! its contents are chosen by whoever opened the pull request. Three guards:
//!
//! - **A size cap.** [`MAX_REPORT_BYTES`] is checked before parsing, so a
//!   gigabyte of `<line/>` elements is refused rather than expanded into memory.
//! - **A vetted XML parser.** `roxmltree` bounds entity expansion, which is what
//!   makes the classic billion-laughs input a parse error instead of an
//!   out-of-memory kill.
//! - **A closed extraction.** Only four things are read out of a document —
//!   a class's filename, a line's number, its hit count, and the `<source>`
//!   prefixes — and everything else is ignored. No DTD is fetched, no path in
//!   the file is opened, nothing is resolved.
//!
//! # Path matching is a heuristic, and it is named as one
//!
//! Coverage tools write paths in their own terms: absolute build-machine paths,
//! paths relative to a `<source>` root, Windows separators, `./` prefixes.
//! Git writes repository-relative forward-slash paths. There is no lossless
//! mapping between them, so [`CoverageReport::lines_for`] normalizes and then
//! matches on a **path suffix**, which is the convention every diff-coverage
//! tool uses. Where two files in a repository share a suffix — `a/util.ts` and
//! `b/util.ts` — the shorter report path could match either, so a suffix match
//! is only accepted when exactly one report entry matches. An ambiguous match is
//! reported as no data rather than as a guess, because a coverage gap attributed
//! to the wrong file is worse than a coverage gap nobody reported.

use std::collections::BTreeMap;

/// Largest report this engine will parse.
///
/// Thirty-two mebibytes is far above any real lcov or cobertura file — a
/// hundred-thousand-line project produces single-digit megabytes — and far below
/// anything that would trouble a runner. Refusing is reported as an unwitnessed
/// result, never as a coverage figure computed from the part that fitted.
pub const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;

/// Report formats this engine understands.
///
/// Cobertura and coverage.py share a document shape — coverage.py writes the
/// Cobertura DTD — so one parser reads both. They are named separately anyway
/// because `measurement_regime` carries a parser version per format, and a
/// future divergence between them should be a version bump on one and not on
/// both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReportFormat {
    /// LCOV tracefile: `SF:` / `DA:` records.
    Lcov,
    /// Cobertura XML, as emitted by JaCoCo converters, `cobertura`, and others.
    Cobertura,
    /// coverage.py's `coverage xml` output, which follows the Cobertura DTD.
    CoveragePy,
}

impl ReportFormat {
    /// Wire name, used in the regime's parser-version map.
    pub fn name(self) -> &'static str {
        match self {
            ReportFormat::Lcov => "lcov",
            ReportFormat::Cobertura => "cobertura",
            ReportFormat::CoveragePy => "coverage.py-xml",
        }
    }
}

/// A report could not be turned into coverage data.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// The file is larger than [`MAX_REPORT_BYTES`].
    #[error("coverage report {path} is {size} bytes, above the {MAX_REPORT_BYTES}-byte cap")]
    TooLarge {
        /// The report that was refused.
        path: String,
        /// Its size.
        size: usize,
    },
    /// The bytes are not valid UTF-8.
    #[error("coverage report {path} is not valid UTF-8")]
    NotUtf8 {
        /// The report that was refused.
        path: String,
    },
    /// The document does not parse.
    #[error("coverage report {path} did not parse: {detail}")]
    Malformed {
        /// The report that was refused.
        path: String,
        /// What went wrong.
        detail: String,
    },
    /// Nothing in the file identified it as a report of a known format.
    #[error("coverage report {path} is not in a format this engine reads (lcov, cobertura, coverage.py XML)")]
    Unrecognized {
        /// The file that was examined.
        path: String,
    },
}

/// Line-level coverage for a set of files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageReport {
    /// Which format the bytes were in.
    pub format: ReportFormat,
    /// Where the report was read from, repository-relative.
    pub source_path: String,
    /// Normalized report path to line number to hit count.
    pub files: BTreeMap<String, BTreeMap<u32, u64>>,
    /// True when the document parsed but part of it was skipped — an element
    /// missing the attributes this engine needs, or a line number that is not a
    /// number. Surfaces as `completeness: parse-degraded`, never as silence.
    pub degraded: bool,
}

impl CoverageReport {
    /// Parse bytes whose format is detected from their content.
    ///
    /// Detection is by content and not by filename: a file called `coverage.xml`
    /// that turns out to be an lcov tracefile should be read as one, and a file
    /// called `lcov.info` holding XML is not evidence about anything.
    pub fn parse(source_path: &str, bytes: &[u8]) -> Result<Self, ReportError> {
        if bytes.len() > MAX_REPORT_BYTES {
            return Err(ReportError::TooLarge {
                path: source_path.to_string(),
                size: bytes.len(),
            });
        }
        let text = std::str::from_utf8(bytes).map_err(|_| ReportError::NotUtf8 {
            path: source_path.to_string(),
        })?;
        let first = text.trim_start().as_bytes().first().copied();
        if first == Some(b'<') {
            crate::cobertura::parse(source_path, text)
        } else if text.contains("\nSF:") || text.starts_with("SF:") || text.starts_with("TN:") {
            crate::lcov::parse(source_path, text)
        } else {
            Err(ReportError::Unrecognized {
                path: source_path.to_string(),
            })
        }
    }

    /// Coverage for a repository path, or `None` when the report does not
    /// unambiguously cover it.
    ///
    /// Exact match first, then a unique suffix match. See the module docs on why
    /// an ambiguous suffix is treated as no data.
    pub fn lines_for(&self, repo_path: &str) -> Option<&BTreeMap<u32, u64>> {
        let wanted = normalize_path(repo_path);
        if let Some(lines) = self.files.get(&wanted) {
            return Some(lines);
        }
        let suffix = format!("/{wanted}");
        let mut matches = self
            .files
            .iter()
            .filter(|(path, _)| path.ends_with(&suffix));
        let first = matches.next()?;
        match matches.next() {
            None => Some(first.1),
            Some(_) => None,
        }
    }
}

/// Put a path from a coverage tool into git's terms as far as is possible.
///
/// Backslashes become forward slashes, `./` prefixes are dropped, and a leading
/// slash is kept — an absolute report path stays absolute so that suffix
/// matching, rather than a coincidental prefix, is what relates it to a
/// repository path.
pub fn normalize_path(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    let trimmed = slashed.trim_start_matches("./");
    trimmed.to_string()
}

/// Join a `<source>` prefix to a class filename, in normalized form.
pub fn join_source(source: &str, filename: &str) -> String {
    let source = normalize_path(source);
    let filename = normalize_path(filename);
    if filename.starts_with('/') || source.is_empty() {
        return filename;
    }
    format!("{}/{}", source.trim_end_matches('/'), filename)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(files: &[(&str, &[(u32, u64)])]) -> CoverageReport {
        CoverageReport {
            format: ReportFormat::Lcov,
            source_path: "lcov.info".to_string(),
            files: files
                .iter()
                .map(|(path, lines)| {
                    (
                        path.to_string(),
                        lines.iter().copied().collect::<BTreeMap<u32, u64>>(),
                    )
                })
                .collect(),
            degraded: false,
        }
    }

    #[test]
    fn an_exact_path_wins_outright() {
        let r = report(&[("src/a.ts", &[(1, 1)])]);
        assert!(r.lines_for("src/a.ts").is_some());
    }

    #[test]
    fn an_absolute_report_path_matches_by_suffix() {
        // The ordinary case: the coverage tool ran in /home/runner/work/repo.
        let r = report(&[("/home/runner/work/repo/src/a.ts", &[(1, 0)])]);
        assert_eq!(r.lines_for("src/a.ts").map(|l| l[&1]), Some(0));
    }

    #[test]
    fn an_ambiguous_suffix_reports_nothing_rather_than_guessing() {
        // Two files in the report end in `util.ts`. Attributing a gap to the
        // wrong one is worse than not reporting it.
        let r = report(&[
            ("/build/a/util.ts", &[(1, 0)]),
            ("/build/b/util.ts", &[(1, 5)]),
        ]);
        assert!(r.lines_for("util.ts").is_none());
    }

    #[test]
    fn windows_separators_from_a_windows_runner_still_match() {
        let r = report(&[("C:/work/src/a.ts", &[(3, 0)])]);
        assert!(r.lines_for("src\\a.ts").is_some());
    }

    #[test]
    fn a_report_above_the_cap_is_refused_before_it_is_parsed() {
        let huge = vec![b'<'; MAX_REPORT_BYTES + 1];
        assert!(matches!(
            CoverageReport::parse("coverage.xml", &huge),
            Err(ReportError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_file_of_neither_format_is_refused_rather_than_read_as_empty() {
        // An empty report and an unreadable one must not look the same: one is
        // "nothing was covered", the other is "this is not a coverage report".
        assert!(matches!(
            CoverageReport::parse("notes.txt", b"just some prose\n"),
            Err(ReportError::Unrecognized { .. })
        ));
    }

    #[test]
    fn source_prefixes_join_the_way_coverage_py_writes_them() {
        assert_eq!(
            join_source("/build/repo", "src/a.py"),
            "/build/repo/src/a.py"
        );
        assert_eq!(
            join_source("/build/repo/", "src/a.py"),
            "/build/repo/src/a.py"
        );
        assert_eq!(join_source("", "src/a.py"), "src/a.py");
        assert_eq!(join_source("/build", "/abs/src/a.py"), "/abs/src/a.py");
    }
}
