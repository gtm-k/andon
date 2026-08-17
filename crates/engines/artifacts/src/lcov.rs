//! The LCOV tracefile reader.
//!
//! LCOV is a line-oriented format with two-letter record prefixes. Only two of
//! them are read here:
//!
//! ```text
//! SF:<absolute or relative source path>
//! DA:<line number>,<execution count>[,<checksum>]
//! end_of_record
//! ```
//!
//! `LF`/`LH` (lines found and hit) are deliberately ignored even though they
//! would be cheaper than counting: they are the file's *summary*, and a summary
//! is a coverage percentage, which is the number PLAN P4 rules out. The engine
//! reports uncovered lines inside the change and nothing else, so the per-line
//! `DA` records are the only ones that answer a question it is allowed to ask.
//!
//! Branch records (`BRDA`) are ignored for the same reason plus one more: branch
//! coverage inside a changed line is a finer question than "was this line ever
//! executed", and the negative signal is already carried by the line record.
//!
//! Unknown records are skipped rather than refused. LCOV has accumulated
//! function, branch, and tool-specific records over the years and a reader that
//! failed on the ones it did not recognise would refuse most real tracefiles.
//! What is *not* skipped silently is a malformed `DA` record: it sets
//! [`CoverageReport::degraded`], and the results carry `parse-degraded`.

use std::collections::BTreeMap;

use crate::report::{normalize_path, strip_bom, CoverageReport, ReportError, ReportFormat};

/// Parser version, stamped into `MeasurementRegime::Artifacts`.
pub const PARSER_VERSION: &str = "1";

/// Parse an LCOV tracefile.
pub fn parse(source_path: &str, text: &str) -> Result<CoverageReport, ReportError> {
    // A BOM would ride into the first `SF:` test and make the whole tracefile
    // one unrecognised line. Stripped here as well as at the sniff, so a caller
    // who reached this function directly is as safe as one who did not.
    let text = strip_bom(text);
    let mut files: BTreeMap<String, BTreeMap<u32, u64>> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut degraded = false;

    for line in text.lines() {
        // `\r` survives on a CRLF tracefile written by a Windows runner and read
        // on Linux. Trimming it here rather than trusting the line splitter is
        // the difference between a path of `src/a.ts` and one of `src/a.ts\r`,
        // which would match nothing.
        let line = line.trim_end_matches('\r');
        if let Some(path) = line.strip_prefix("SF:") {
            let path = normalize_path(path.trim());
            files.entry(path.clone()).or_default();
            current = Some(path);
        } else if line == "end_of_record" {
            current = None;
        } else if let Some(record) = line.strip_prefix("DA:") {
            let Some(path) = current.as_ref() else {
                // A `DA` outside any `SF` block belongs to no file. Skipping it
                // is the only option; saying the document was degraded is what
                // stops that being invisible.
                degraded = true;
                continue;
            };
            match parse_da(record) {
                Some((number, hits)) => {
                    let entry = files.entry(path.clone()).or_default();
                    // Repeated `DA` records for one line happen when a tool
                    // merges runs. The hits add up, which keeps "covered" and
                    // "uncovered" on the right side of zero either way.
                    *entry.entry(number).or_insert(0) += hits;
                }
                None => degraded = true,
            }
        }
    }

    Ok(CoverageReport {
        format: ReportFormat::Lcov,
        source_path: source_path.to_string(),
        files,
        degraded,
    })
}

/// `<line>,<hits>[,<checksum>]`.
fn parse_da(record: &str) -> Option<(u32, u64)> {
    let mut fields = record.trim().split(',');
    let number = fields.next()?.trim().parse::<u32>().ok()?;
    let hits_field = fields.next()?.trim();
    // Some tools write `-` for "not instrumented on this run". That is not zero
    // executions; it is no information, and treating it as zero would invent an
    // uncovered line.
    if hits_field == "-" {
        return None;
    }
    let hits = hits_field.parse::<u64>().ok()?;
    Some((number, hits))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "TN:\nSF:src/a.ts\nDA:1,3\nDA:2,0\nDA:3,1\nLF:3\nLH:2\nend_of_record\nSF:src/b.ts\nDA:1,0\nend_of_record\n";

    #[test]
    fn line_hits_are_read_per_file() {
        let report = parse("lcov.info", SAMPLE).expect("well formed");
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.files["src/a.ts"][&2], 0);
        assert_eq!(report.files["src/a.ts"][&1], 3);
        assert!(!report.degraded);
    }

    #[test]
    fn a_crlf_tracefile_produces_the_same_paths() {
        let crlf = SAMPLE.replace('\n', "\r\n");
        let report = parse("lcov.info", &crlf).expect("well formed");
        assert!(report.files.contains_key("src/a.ts"));
        assert_eq!(report.files["src/a.ts"][&2], 0);
    }

    #[test]
    fn a_checksum_third_field_is_ignored_rather_than_refused() {
        let report =
            parse("lcov.info", "SF:src/a.ts\nDA:1,0,abc123\nend_of_record\n").expect("well formed");
        assert_eq!(report.files["src/a.ts"][&1], 0);
        assert!(!report.degraded);
    }

    #[test]
    fn an_uninstrumented_line_is_not_an_uncovered_line() {
        // `DA:2,-` says the tool has nothing to report for line 2. Recording a
        // zero there would manufacture a coverage gap.
        let report =
            parse("lcov.info", "SF:src/a.ts\nDA:1,1\nDA:2,-\nend_of_record\n").expect("parses");
        assert!(!report.files["src/a.ts"].contains_key(&2));
        assert!(report.degraded, "the skipped record must be visible");
    }

    #[test]
    fn a_file_with_no_da_records_is_present_and_empty() {
        // Present, so the engine knows the report covered it; empty, so no line
        // in it is reported as a gap.
        let report = parse("lcov.info", "SF:src/empty.ts\nend_of_record\n").expect("parses");
        assert!(report.files["src/empty.ts"].is_empty());
    }

    #[test]
    fn unknown_records_do_not_degrade_the_document() {
        let report = parse(
            "lcov.info",
            "SF:src/a.ts\nFN:1,thing\nFNDA:2,thing\nBRDA:1,0,0,1\nDA:1,1\nend_of_record\n",
        )
        .expect("parses");
        assert!(!report.degraded);
        assert_eq!(report.files["src/a.ts"].len(), 1);
    }
}
