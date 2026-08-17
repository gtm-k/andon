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

/// Deepest element nesting this engine will hand to the XML parser.
///
/// # The failure this prevents is an abort, not an error
///
/// `roxmltree`'s tokenizer recurses once per nesting level, and a deep document
/// exhausts the thread's stack. A stack overflow is **not a panic**: it aborts
/// the process, `catch_unwind` cannot see it, and no `Result` is ever returned.
/// The size cap above never fires, because the document does not need to be
/// large — measured here, a **14 KB** file is enough. The parser's `nodes_limit`
/// does not help either: it bounds how many nodes a document may have, not how
/// deeply they nest.
///
/// So the depth is counted **before** the parser is given anything, by
/// [`max_element_depth`], which is an iterative scan and cannot itself recurse.
///
/// # Why 64 and not something larger
///
/// Measured on this workspace (Windows, main thread), the depth at which
/// `roxmltree` 0.20 aborts:
///
/// | profile | survives | aborts |
/// |---|---|---|
/// | debug | 165 | 170 |
/// | release | 500 | 2000 |
///
/// A limit near the debug figure would leave `cargo test` — and any developer
/// run — one moderately nested document away from an abort, and the numbers move
/// with the profile, the platform, and the thread's stack size (a libtest thread
/// and a main thread do not get the same one). A real coverage report nests
/// about seven elements: `coverage / packages / package / classes / class /
/// lines / line`. Sixty-four is an order of magnitude above every real document
/// and a factor of two and a half below the worst measured abort, which is the
/// right side of both numbers to be on.
pub const MAX_ELEMENT_DEPTH: usize = 64;

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
    /// The document nests deeper than [`MAX_ELEMENT_DEPTH`].
    ///
    /// A refusal rather than a parse, because the parse would not fail — it
    /// would abort the process. See [`MAX_ELEMENT_DEPTH`].
    #[error(
        "coverage report {path} nests {depth} elements deep, above the limit of \
         {MAX_ELEMENT_DEPTH}; a real coverage report nests about seven"
    )]
    TooDeep {
        /// The report that was refused.
        path: String,
        /// The depth reached, so the operator can see how far off it is.
        depth: usize,
    },
}

impl ReportError {
    /// The report this error is about.
    ///
    /// Every variant carries one, because a failure that cannot name its file is
    /// a failure nobody can act on — and these are surfaced in the payload, not
    /// only in a log.
    pub fn path(&self) -> &str {
        match self {
            ReportError::TooLarge { path, .. }
            | ReportError::NotUtf8 { path }
            | ReportError::Malformed { path, .. }
            | ReportError::Unrecognized { path }
            | ReportError::TooDeep { path, .. } => path,
        }
    }
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
        let text = strip_bom(text);
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

/// Drop a leading byte-order mark.
///
/// `str::trim_start` does not remove U+FEFF — it is not whitespace — so a BOM
/// survives into every prefix test a format sniff makes. That is not an exotic
/// input: .NET's `XmlWriter` and PowerShell's redirection both write UTF-8 with
/// a BOM by default, so a `coverage.xml` produced by a Windows toolchain
/// routinely has one. Before this, such a report was `Unrecognized`, which the
/// engine reported as "a coverage report was found but could not be read" — a
/// perfectly good report, and every gap in it dropped.
///
/// Only a *leading* mark is removed, and only one. A U+FEFF anywhere else is
/// content, and this function is not in the business of laundering it.
pub fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// The deepest element nesting in an XML document, counted without recursing.
///
/// A byte scan, not a parse. It has to run *before* the parser sees the
/// document — the thing it protects against aborts the process rather than
/// returning an error — so it cannot lean on anything the parser knows, and it
/// must not have the property it is guarding against. There is no call stack
/// here: one pass, one counter.
///
/// It is deliberately generous about malformedness. Anything it cannot make
/// sense of it skips, and a document that survives this scan still has to
/// satisfy `roxmltree`. Being approximate is safe in one direction only, and
/// this is that direction: the scan is an upper bound on nesting for any
/// well-formed document, so a document it passes cannot nest deeper than it
/// reported.
///
/// The four constructs that are skipped wholesale rather than counted —
/// comments, CDATA, processing instructions, and declarations — are skipped
/// because each may contain a `<` that opens nothing. Counting one would let a
/// commented-out fragment inflate the depth of an innocent file.
pub fn max_element_depth(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut depth = 0usize;
    let mut max = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'<' {
            index += 1;
            continue;
        }
        let rest = &bytes[index..];
        if rest.starts_with(b"<!--") {
            index += find_after(rest, b"-->").unwrap_or(rest.len());
        } else if rest.starts_with(b"<![CDATA[") {
            index += find_after(rest, b"]]>").unwrap_or(rest.len());
        } else if rest.starts_with(b"<?") {
            index += find_after(rest, b"?>").unwrap_or(rest.len());
        } else if rest.starts_with(b"<!") {
            // A declaration: `<!DOCTYPE ...>`, `<!ENTITY ...>`. Each ends at its
            // own `>`; a DOCTYPE's internal subset is a run of them, and none of
            // them opens an element.
            index += find_after(rest, b">").unwrap_or(rest.len());
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            index += find_after(rest, b">").unwrap_or(rest.len());
        } else {
            let end = find_after(rest, b">").unwrap_or(rest.len());
            let self_closing = end >= 2 && rest[end - 2] == b'/';
            if !self_closing {
                depth += 1;
                max = max.max(depth);
            } else {
                max = max.max(depth + 1);
            }
            index += end;
        }
    }
    max
}

/// Offset just past the first occurrence of `needle`, if there is one.
fn find_after(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| at + needle.len())
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

#[cfg(test)]
mod depth_tests {
    use super::*;

    fn nested(depth: usize) -> String {
        let mut doc = String::from("<coverage>");
        for _ in 0..depth {
            doc.push_str("<a>");
        }
        doc.push_str("<packages/>");
        for _ in 0..depth {
            doc.push_str("</a>");
        }
        doc.push_str("</coverage>");
        doc
    }

    #[test]
    fn a_document_deep_enough_to_abort_the_process_is_refused_instead() {
        // The finding, pinned. Before the guard this test did not fail — it
        // killed the test binary: a stack overflow is an abort, not a panic, so
        // there is nothing for a `#[should_panic]` or a `catch_unwind` to see.
        // The assertion that matters as much as the error value is that the
        // process is still here to make it.
        let doc = nested(2000);
        assert!(
            doc.len() < 20 * 1024,
            "the point of this input is that it is small: {} bytes",
            doc.len()
        );
        match CoverageReport::parse("coverage.xml", doc.as_bytes()) {
            Err(ReportError::TooDeep { depth, .. }) => {
                assert!(depth > MAX_ELEMENT_DEPTH, "reported depth {depth}")
            }
            other => panic!("expected a typed refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_document_at_a_depth_that_would_abort_a_debug_build_is_refused() {
        // Measured on this workspace: a debug build aborts between 165 and 170,
        // which is why the limit is 64 and not the 256 that the release-build
        // figure would have allowed. A test suite runs debug.
        assert!(matches!(
            CoverageReport::parse("coverage.xml", nested(170).as_bytes()),
            Err(ReportError::TooDeep { .. })
        ));
    }

    #[test]
    fn a_real_shaped_report_is_nowhere_near_the_limit() {
        // Guarding is only worth having if it does not refuse real files. A
        // cobertura document nests seven: coverage / packages / package /
        // classes / class / lines / line.
        let text = r#"<coverage><packages><package><classes>
            <class filename="a.ts"><lines><line number="1" hits="1"/></lines></class>
        </classes></package></packages></coverage>"#;
        assert_eq!(max_element_depth(text), 7);
        assert!(CoverageReport::parse("coverage.xml", text.as_bytes()).is_ok());
    }

    #[test]
    fn a_valid_document_just_under_the_limit_still_parses() {
        let doc = nested(MAX_ELEMENT_DEPTH - 2);
        assert!(CoverageReport::parse("coverage.xml", doc.as_bytes()).is_ok());
    }

    #[test]
    fn the_scan_counts_elements_and_not_the_angle_brackets_around_them() {
        // Each of these carries a `<` that opens nothing. Counting one would let
        // a commented-out fragment inflate an innocent file's depth — and, worse
        // for a guard, would make the depth of a document depend on its prose.
        assert_eq!(max_element_depth("<a><!-- <b><c><d> --></a>"), 1);
        assert_eq!(max_element_depth("<a><![CDATA[ <b><c> ]]></a>"), 1);
        assert_eq!(max_element_depth("<?xml version=\"1.0\"?><a></a>"), 1);
        assert_eq!(
            max_element_depth("<!DOCTYPE x [ <!ENTITY e \"v\"> ]><a><b/></a>"),
            2
        );
    }

    #[test]
    fn a_self_closing_element_is_counted_once_and_then_closed() {
        assert_eq!(max_element_depth("<a><b/><b/><b/></a>"), 2);
        assert_eq!(max_element_depth("<a><b><c/></b></a>"), 3);
    }

    #[test]
    fn an_unterminated_tag_does_not_hang_or_overcount() {
        // Malformedness is the parser's to report; this scan only has to answer
        // and stop.
        assert_eq!(max_element_depth("<a><b"), 2);
        assert_eq!(max_element_depth("<!-- unterminated"), 0);
        assert_eq!(max_element_depth(""), 0);
    }
}

#[cfg(test)]
mod bom_tests {
    use super::*;

    /// U+FEFF, which is what a Windows toolchain puts at the head of a UTF-8
    /// file and what `trim_start` does not remove.
    const BOM: &str = "\u{feff}";

    const COBERTURA: &str = r#"<coverage><packages><package><classes>
        <class filename="src/a.ts"><lines><line number="4" hits="0"/></lines></class>
      </classes></package></packages></coverage>"#;
    const LCOV: &str = "SF:src/a.ts\nDA:4,0\nend_of_record\n";

    #[test]
    fn a_bom_does_not_make_a_cobertura_report_unreadable() {
        // Before the fix this was `Unrecognized`, which the engine reported as
        // "a coverage report was found but could not be read" — for a valid
        // report, with every gap in it dropped.
        let report = CoverageReport::parse("coverage.xml", format!("{BOM}{COBERTURA}").as_bytes())
            .expect("a BOM'd cobertura report is still a cobertura report");
        assert_eq!(report.format, ReportFormat::Cobertura);
        assert_eq!(report.files["src/a.ts"][&4], 0);
    }

    #[test]
    fn a_bom_does_not_make_an_lcov_tracefile_unreadable() {
        let report = CoverageReport::parse("lcov.info", format!("{BOM}{LCOV}").as_bytes())
            .expect("a BOM'd tracefile is still a tracefile");
        assert_eq!(report.format, ReportFormat::Lcov);
        assert_eq!(report.files["src/a.ts"][&4], 0);
    }

    #[test]
    fn a_bom_changes_nothing_about_what_is_read() {
        // The stronger statement: not merely that both parse, but that they
        // produce the same report. A fix that stripped the BOM into the first
        // path or the first record would pass the two tests above.
        for text in [COBERTURA, LCOV] {
            let plain = CoverageReport::parse("r", text.as_bytes()).expect("parses");
            let marked =
                CoverageReport::parse("r", format!("{BOM}{text}").as_bytes()).expect("parses");
            assert_eq!(plain, marked);
        }
    }

    #[test]
    fn the_paths_without_a_bom_are_untouched() {
        assert_eq!(strip_bom("SF:src/a.ts"), "SF:src/a.ts");
        assert_eq!(strip_bom(""), "");
    }

    #[test]
    fn only_a_leading_mark_is_removed_and_only_one() {
        // A U+FEFF anywhere else is content. Two of them means the file has one
        // and then some content that starts with one, and laundering the second
        // would be this function deciding what a document meant.
        assert_eq!(strip_bom("\u{feff}\u{feff}x"), "\u{feff}x");
        assert_eq!(strip_bom("x\u{feff}y"), "x\u{feff}y");
    }
}
