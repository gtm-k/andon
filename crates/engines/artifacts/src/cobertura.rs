//! The Cobertura / coverage.py XML reader.
//!
//! One parser for two named formats, because coverage.py writes the Cobertura
//! DTD. The shape both produce:
//!
//! ```xml
//! <coverage ...>
//!   <sources><source>/build/repo</source></sources>
//!   <packages><package><classes>
//!     <class filename="src/a.py"><lines>
//!       <line number="1" hits="1"/>
//!       <line number="2" hits="0"/>
//! ```
//!
//! Four things are read: `<source>` text, `class/@filename`, `line/@number`, and
//! `line/@hits`. Everything else — rates, complexity attributes, branch
//! conditions, timestamps — is ignored, and the ignoring is deliberate rather
//! than unfinished: `line-rate` is a coverage percentage, and PLAN P4 admits
//! coverage as a negative signal only. Reading the summary would put the number
//! this family must not report one field access away from a payload.
//!
//! # Which of the two formats a document is
//!
//! coverage.py stamps `<coverage ... version="7.x">` and always writes a
//! `<sources>` block; generic Cobertura emitters usually do not. The
//! distinction only decides which parser name lands in the regime, so it is made
//! on a cheap, stable marker — the presence of a `<sources>` element — and both
//! answers use the identical extraction below.
//!
//! # Entity expansion
//!
//! `roxmltree` bounds entity expansion internally, which is what turns the
//! classic nested-entity bomb into a parse error rather than an out-of-memory
//! kill. That guard is the reason this file uses a parser at all rather than a
//! forty-line tag scanner: the input is a file the pull request under
//! measurement controls.

use std::collections::BTreeMap;

use crate::report::{
    join_source, max_element_depth, normalize_path, strip_bom, CoverageReport, ReportError,
    ReportFormat, MAX_ELEMENT_DEPTH,
};

/// Parser version, stamped into `MeasurementRegime::Artifacts`.
pub const PARSER_VERSION: &str = "1";

/// Parse a Cobertura-shaped XML document.
pub fn parse(source_path: &str, text: &str) -> Result<CoverageReport, ReportError> {
    // `roxmltree` tolerates a leading BOM — verified, not assumed — so this is
    // belt rather than braces. It is here anyway because a reader of this
    // function should not have to know that, and because the tolerance is a
    // property of a dependency rather than of the format.
    let text = strip_bom(text);

    // Before the parser sees a byte. `roxmltree`'s tokenizer recurses per
    // nesting level, and a deep document overflows the stack — which aborts the
    // process rather than returning an error, so there is no version of this
    // check that runs afterwards. Measured: 14 KB is enough. See
    // `MAX_ELEMENT_DEPTH`.
    //
    // The guard is here rather than only in `CoverageReport::parse` because this
    // function is public: a caller who found their own XML must be as safe as
    // one who went through the sniff.
    let depth = max_element_depth(text);
    if depth > MAX_ELEMENT_DEPTH {
        return Err(ReportError::TooDeep {
            path: source_path.to_string(),
            depth,
        });
    }

    let document = roxmltree::Document::parse(text).map_err(|err| ReportError::Malformed {
        path: source_path.to_string(),
        detail: err.to_string(),
    })?;
    let root = document.root_element();
    if root.tag_name().name() != "coverage" {
        return Err(ReportError::Unrecognized {
            path: source_path.to_string(),
        });
    }

    let sources: Vec<String> = document
        .descendants()
        .filter(|n| n.has_tag_name("source"))
        .filter_map(|n| n.text())
        .map(|s| normalize_path(s.trim()))
        .filter(|s| !s.is_empty())
        .collect();
    let format = if sources.is_empty() {
        ReportFormat::Cobertura
    } else {
        ReportFormat::CoveragePy
    };

    let mut files: BTreeMap<String, BTreeMap<u32, u64>> = BTreeMap::new();
    let mut degraded = false;

    for class in document.descendants().filter(|n| n.has_tag_name("class")) {
        let Some(filename) = class.attribute("filename") else {
            // A class element with no filename covers a file nobody can name.
            degraded = true;
            continue;
        };
        // One entry per source root. A document with several roots does not say
        // which one a class belongs to, so every candidate is recorded and the
        // suffix match in `CoverageReport::lines_for` picks — and refuses to
        // pick when two of them are equally plausible.
        let paths: Vec<String> = if sources.is_empty() {
            vec![normalize_path(filename)]
        } else {
            sources
                .iter()
                .map(|source| join_source(source, filename))
                .collect()
        };

        let mut lines: BTreeMap<u32, u64> = BTreeMap::new();
        for line in class.descendants().filter(|n| n.has_tag_name("line")) {
            match (
                line.attribute("number").and_then(|n| n.parse::<u32>().ok()),
                line.attribute("hits").and_then(|h| h.parse::<u64>().ok()),
            ) {
                (Some(number), Some(hits)) => {
                    *lines.entry(number).or_insert(0) += hits;
                }
                // A `<line>` missing either attribute is not a covered line and
                // not an uncovered one; it is a document this reader does not
                // fully understand, and saying so is what `parse-degraded` is.
                _ => degraded = true,
            }
        }

        for path in paths {
            let entry = files.entry(path).or_default();
            for (number, hits) in &lines {
                *entry.entry(*number).or_insert(0) += hits;
            }
        }
    }

    Ok(CoverageReport {
        format,
        source_path: source_path.to_string(),
        files,
        degraded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COBERTURA: &str = r#"<?xml version="1.0" ?>
<coverage line-rate="0.66" version="1.9">
  <packages><package name="."><classes>
    <class filename="src/a.ts" line-rate="0.5"><lines>
      <line number="1" hits="4"/>
      <line number="2" hits="0"/>
    </lines></class>
  </classes></package></packages>
</coverage>"#;

    const COVERAGE_PY: &str = r#"<?xml version="1.0" ?>
<coverage version="7.4.0">
  <sources><source>/build/repo</source></sources>
  <packages><package name="pkg"><classes>
    <class filename="pkg/mod.py"><lines>
      <line number="7" hits="0"/>
    </lines></class>
  </classes></package></packages>
</coverage>"#;

    #[test]
    fn cobertura_lines_are_read_and_the_summary_is_not() {
        let report = parse("coverage.xml", COBERTURA).expect("well formed");
        assert_eq!(report.format, ReportFormat::Cobertura);
        assert_eq!(report.files["src/a.ts"][&2], 0);
        assert_eq!(report.files["src/a.ts"][&1], 4);
        assert!(!report.degraded);
    }

    #[test]
    fn coverage_py_paths_are_joined_to_the_source_root() {
        let report = parse("coverage.xml", COVERAGE_PY).expect("well formed");
        assert_eq!(report.format, ReportFormat::CoveragePy);
        assert_eq!(report.files["/build/repo/pkg/mod.py"][&7], 0);
        // And the repository path finds it by suffix.
        assert_eq!(report.lines_for("pkg/mod.py").map(|l| l[&7]), Some(0));
    }

    #[test]
    fn a_document_that_is_not_a_coverage_report_is_refused() {
        assert!(matches!(
            parse("thing.xml", "<project><module/></project>"),
            Err(ReportError::Unrecognized { .. })
        ));
    }

    #[test]
    fn malformed_xml_is_an_error_and_not_an_empty_report() {
        assert!(matches!(
            parse("coverage.xml", "<coverage><classes>"),
            Err(ReportError::Malformed { .. })
        ));
    }

    #[test]
    fn a_line_missing_its_attributes_degrades_the_document_visibly() {
        let text = r#"<coverage><packages><package><classes>
            <class filename="a.ts"><lines><line number="1"/></lines></class>
        </classes></package></packages></coverage>"#;
        let report = parse("coverage.xml", text).expect("parses");
        assert!(report.degraded);
        assert!(report.files["a.ts"].is_empty());
    }

    #[test]
    fn an_entity_expansion_bomb_does_not_take_the_process_with_it() {
        // The classic billion-laughs shape. The assertion is not about which
        // answer comes back — a refusal and an expansion-limited parse are both
        // fine — but that one comes back at all, in bounded memory, from a file
        // the pull request under measurement controls.
        let bomb = r#"<?xml version="1.0"?>
<!DOCTYPE coverage [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
  <!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
]>
<coverage><packages><package><classes>
  <class filename="&f;"><lines/></class>
</classes></package></packages></coverage>"#;
        let _ = parse("coverage.xml", bomb);
    }
}
