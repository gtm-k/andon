//! Source lines of code, defined once and computed the same way everywhere.
//!
//! # The definition
//!
//! A physical line counts when it holds at least one byte that is neither
//! whitespace nor part of a comment. Nothing else: not statements, not logical
//! lines, not tokens.
//!
//! Everything about that sentence is chosen so the number reproduces.
//!
//! * **Physical lines, split on `0x0A`.** A CRLF file and its LF twin have the
//!   same source-line count, because `\r` is whitespace and the line break is
//!   the `\n` either way. The bytes come from a git blob, so a Windows checkout
//!   that rewrote the working tree cannot move the number (PREMORTEM T1).
//! * **Comments come from the parse tree**, not from a regular expression, so a
//!   `//` inside a string literal is code and a URL inside a comment is not. For
//!   Rust the ranges come from [`crate::rustlex`], which tracks the same states
//!   a parser would.
//! * **Docstrings are code.** A Python module's opening string literal is a
//!   string expression, not a comment node, and treating it as prose would mean
//!   the number depended on a convention rather than on the grammar. Stated here
//!   because it is a real choice, bound by `SPEC_REVISION`, and the sort of thing
//!   two tools disagree about silently.
//!
//! # Why size is here at all
//!
//! `docs/metric-families.csv` grades size **A — strongest single predictor, but
//! a confound**, and its agent-loop note is "essential as a CONTROL variable,
//! not as a quality target". So `static.sloc` ships as `context-informational`:
//! it is what the complexity numbers have to be read against, and it is never
//! something an agent is asked to reduce.

/// Source lines within a byte range, given the file's comment ranges.
///
/// `comments` must be sorted by start offset — [`crate::parse::comment_ranges`]
/// and [`crate::rustlex::comment_ranges`] both guarantee it. The scan is linear
/// in the range and advances a cursor through the comment list rather than
/// searching it per byte, so a large file with many comments stays linear.
pub fn sloc_range(source: &[u8], comments: &[(usize, usize)], start: usize, end: usize) -> u64 {
    let end = end.min(source.len());
    if start >= end {
        return 0;
    }

    let mut counted = 0u64;
    let mut line_has_code = false;
    // First comment that could still cover a byte at or after `start`.
    let mut next_comment = comments.partition_point(|(_, comment_end)| *comment_end <= start);

    let mut offset = start;
    while offset < end {
        let byte = source[offset];
        if byte == b'\n' {
            counted += u64::from(line_has_code);
            line_has_code = false;
            offset += 1;
            continue;
        }

        // Skip the whole comment in one step. `while` rather than `if`: two
        // comments can be adjacent with nothing between them.
        while next_comment < comments.len() && comments[next_comment].1 <= offset {
            next_comment += 1;
        }
        if let Some(&(comment_start, comment_end)) = comments.get(next_comment) {
            if offset >= comment_start && offset < comment_end {
                // A block comment spans lines, and the lines it crosses are not
                // code unless something else on them is — so the newlines inside
                // it still have to close their lines.
                let stop = comment_end.min(end);
                while offset < stop {
                    if source[offset] == b'\n' {
                        counted += u64::from(line_has_code);
                        line_has_code = false;
                    }
                    offset += 1;
                }
                continue;
            }
        }

        if !byte.is_ascii_whitespace() {
            line_has_code = true;
        }
        offset += 1;
    }
    // A final line with no terminator still counts, the same convention the
    // spike's line counting uses: "add a line" changes the number by one whether
    // or not the file ends in a newline.
    counted + u64::from(line_has_code)
}

/// Source lines in a whole file.
pub fn sloc(source: &[u8], comments: &[(usize, usize)]) -> u64 {
    sloc_range(source, comments, 0, source.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Language;
    use crate::parse::{comment_ranges, parse};

    fn ts(source: &[u8]) -> u64 {
        let parsed = parse(Language::TypeScript, source).expect("parses");
        sloc(source, &comment_ranges(&parsed))
    }

    #[test]
    fn blank_lines_and_comment_lines_do_not_count() {
        let source = b"const a = 1;\n\n// a comment\n   \nconst b = 2;\n";
        assert_eq!(ts(source), 2);
    }

    #[test]
    fn a_line_ending_in_a_comment_still_counts_as_code() {
        assert_eq!(ts(b"const a = 1; // why\n"), 1);
    }

    #[test]
    fn a_block_comment_spanning_lines_contributes_none_of_them() {
        let source = b"const a = 1;\n/* one\n   two\n   three */\nconst b = 2;\n";
        assert_eq!(ts(source), 2);
    }

    #[test]
    fn code_on_the_same_line_as_a_block_comment_still_counts() {
        assert_eq!(ts(b"/* lead */ const a = 1;\n"), 1);
        assert_eq!(ts(b"const a = 1; /* trail\n   more */\n"), 1);
    }

    #[test]
    fn a_comment_marker_inside_a_string_is_code() {
        // The reason comment ranges come from the parse tree rather than from a
        // scan for `//`.
        assert_eq!(ts(b"const url = \"https://example.com\";\n"), 1);
    }

    #[test]
    fn crlf_and_lf_twins_agree() {
        // The cross-OS property in miniature: `\r` is whitespace, the break is
        // the `\n`, and both files are read from blobs.
        let lf = b"const a = 1;\n\nconst b = 2;\n".to_vec();
        let crlf = b"const a = 1;\r\n\r\nconst b = 2;\r\n".to_vec();
        assert_eq!(ts(&lf), ts(&crlf));
        assert_eq!(ts(&crlf), 2);
    }

    #[test]
    fn an_unterminated_final_line_counts() {
        assert_eq!(ts(b"const a = 1;"), 1);
        assert_eq!(ts(b""), 0);
        assert_eq!(ts(b"\n\n\n"), 0);
    }

    #[test]
    fn a_range_counts_only_its_own_lines() {
        let source = b"const a = 1;\nconst b = 2;\nconst c = 3;\n";
        // The middle line only.
        assert_eq!(sloc_range(source, &[], 13, 26), 1);
        assert_eq!(sloc_range(source, &[], 0, 0), 0);
        assert_eq!(sloc_range(source, &[], 99, 120), 0, "out of range is empty");
    }

    #[test]
    fn a_python_docstring_is_code() {
        let source = b"\"\"\"Module docs.\"\"\"\n# a comment\nx = 1\n";
        let parsed = parse(Language::Python, source).expect("parses");
        assert_eq!(sloc(source, &comment_ranges(&parsed)), 2);
    }
}
