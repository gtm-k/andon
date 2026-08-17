//! The Rust tokenization tier: enough lexing to know what is a comment.
//!
//! Rust gets size and nothing else in v1 (APPROACH accepted risks: "Rust
//! cyclomatic/cognitive deferred to v1.1"; the go/defer decision is recorded at
//! P10a). Size still needs comment ranges, and a scan for `//` would find one
//! inside `let url = "https://…"` and stop counting the rest of a real line.
//!
//! So this is a scanner, not a search. It tracks the states in which a `/` is
//! not a comment: string literals with escapes, byte strings, raw strings at any
//! hash depth, and character literals. It is deliberately not a parser — it
//! produces byte ranges and no tree.
//!
//! # The one genuinely ambiguous byte
//!
//! `'` opens a character literal and also introduces a lifetime, and Rust
//! resolves the difference by lookahead. `'a'` is a literal; `'a` is a lifetime;
//! `'\n'` is a literal; `'static` is a lifetime. Reading a lifetime as a literal
//! would swallow source until the next `'` — which in a generic-heavy file is a
//! long way — so the lookahead is done properly:
//!
//! * `'\` always opens a literal, since no lifetime starts with a backslash;
//! * otherwise the next character is taken whole (UTF-8, not one byte) and the
//!   byte after it must be `'` for this to be a literal.
//!
//! Anything else is a lifetime or a loop label, and the `'` is ordinary
//! punctuation.

/// Byte ranges of every comment in a Rust source file, sorted and
/// non-overlapping.
///
/// Nested block comments — legal in Rust and used in practice to comment out
/// code that already contains a block comment — close at the outermost `*/`, so
/// the whole nest is one range.
pub fn comment_ranges(source: &[u8]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut i = 0usize;
    let len = source.len();

    while i < len {
        let byte = source[i];

        // `r"…"`, `r#"…"#`, `b"…"`, `br#"…"#`. Only when the prefix letter does
        // not continue an identifier: `for` ends in `r` and opens nothing.
        if (byte == b'r' || byte == b'b') && !continues_identifier(source, i) {
            if let Some(next) = raw_or_byte_string_end(source, i) {
                i = next;
                continue;
            }
        }

        match byte {
            b'/' if source.get(i + 1) == Some(&b'/') => {
                let start = i;
                while i < len && source[i] != b'\n' {
                    i += 1;
                }
                ranges.push((start, i));
            }
            b'/' if source.get(i + 1) == Some(&b'*') => {
                let start = i;
                let mut depth = 1u32;
                i += 2;
                while i < len && depth > 0 {
                    if source[i] == b'/' && source.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if source[i] == b'*' && source.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                // An unterminated block comment runs to end of file, which is
                // what rustc does with it too.
                ranges.push((start, i));
            }
            b'"' => i = string_end(source, i + 1),
            b'\'' => i = char_literal_end(source, i).unwrap_or(i + 1),
            _ => i += 1,
        }
    }
    ranges
}

/// Whether the byte before `i` is an identifier byte, making `source[i]` a
/// continuation rather than a prefix.
fn continues_identifier(source: &[u8], i: usize) -> bool {
    i > 0 && (source[i - 1].is_ascii_alphanumeric() || source[i - 1] == b'_')
}

/// End of a `"…"` string that has already had its opening quote consumed.
fn string_end(source: &[u8], mut i: usize) -> usize {
    while i < source.len() {
        match source[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    source.len()
}

/// End of a raw or byte string starting at `i`, or `None` if this is not one.
///
/// Handles `b"…"`, `r"…"`, `r#"…"#` at any hash depth, and `br#"…"#`. The hash
/// count is part of the terminator, which is the whole point of the form: a raw
/// string can contain `"` and even `"#` as long as the closing run is longer.
fn raw_or_byte_string_end(source: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let byte_prefix = source.get(i) == Some(&b'b');
    if byte_prefix {
        i += 1;
    }
    if source.get(i) == Some(&b'r') {
        i += 1;
        let mut hashes = 0usize;
        while source.get(i) == Some(&b'#') {
            hashes += 1;
            i += 1;
        }
        if source.get(i) != Some(&b'"') {
            return None;
        }
        i += 1;
        while i < source.len() {
            if source[i] == b'"' {
                let closing = i + 1;
                if source[closing..]
                    .iter()
                    .take(hashes)
                    .filter(|b| **b == b'#')
                    .count()
                    == hashes
                {
                    return Some(closing + hashes);
                }
            }
            i += 1;
        }
        return Some(source.len());
    }
    // `b"…"` — escapes behave as in a normal string.
    if byte_prefix && source.get(i) == Some(&b'"') {
        return Some(string_end(source, i + 1));
    }
    None
}

/// End of a character literal starting at `i`, or `None` when `'` opens a
/// lifetime or a loop label instead.
fn char_literal_end(source: &[u8], i: usize) -> Option<usize> {
    let after = i + 1;
    match source.get(after)? {
        // No lifetime begins with a backslash, so this is unambiguous.
        b'\\' => {
            let mut j = after + 1;
            while j < source.len() {
                match source[j] {
                    b'\'' => return Some(j + 1),
                    // An escape never spans a line; refusing here stops a stray
                    // apostrophe in a comment from swallowing the file.
                    b'\n' => return None,
                    _ => j += 1,
                }
            }
            None
        }
        _ => {
            // One whole character, which may be several bytes. `'é'` is a
            // literal and stepping one byte would land mid-character.
            let text = std::str::from_utf8(&source[after..]).ok()?;
            let character = text.chars().next()?;
            let end = after + character.len_utf8();
            (source.get(end) == Some(&b'\'')).then_some(end + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges_text(source: &[u8]) -> Vec<String> {
        comment_ranges(source)
            .into_iter()
            .map(|(start, end)| String::from_utf8_lossy(&source[start..end]).into_owned())
            .collect()
    }

    #[test]
    fn line_and_block_comments_are_found() {
        let source = b"fn a() {} // one\n/* two */\nfn b() {}\n";
        assert_eq!(ranges_text(source), vec!["// one", "/* two */"]);
    }

    #[test]
    fn doc_comments_are_comments() {
        let source = b"/// docs\n//! inner\nfn a() {}\n";
        assert_eq!(ranges_text(source), vec!["/// docs", "//! inner"]);
    }

    #[test]
    fn block_comments_nest_and_close_at_the_outermost() {
        let source = b"/* outer /* inner */ still outer */ fn a() {}\n";
        assert_eq!(
            ranges_text(source),
            vec!["/* outer /* inner */ still outer */"]
        );
    }

    #[test]
    fn a_comment_marker_inside_a_string_is_not_a_comment() {
        assert!(ranges_text(b"let u = \"https://example.com\";\n").is_empty());
        assert!(ranges_text(b"let s = \"/* not a comment */\";\n").is_empty());
        assert!(ranges_text(b"let e = \"a \\\" // still string\";\n").is_empty());
    }

    #[test]
    fn raw_strings_hide_their_contents_at_any_hash_depth() {
        assert!(ranges_text(b"let r = r\"// no\";\n").is_empty());
        assert!(ranges_text(b"let r = r#\"// no \"# ;\n").is_empty());
        assert!(ranges_text(b"let r = r##\"a \"# b // no\"##;\n").is_empty());
        assert!(ranges_text(b"let r = br#\"// no\"#;\n").is_empty());
        assert!(ranges_text(b"let r = b\"// no\";\n").is_empty());
    }

    #[test]
    fn a_prefix_letter_that_continues_an_identifier_opens_nothing() {
        // `for` ends in `r`; the `"` after it is an ordinary string, and reading
        // it as a raw string would consume to the wrong terminator.
        let source = b"for x in [\"a\"] { } // after\n";
        assert_eq!(ranges_text(source), vec!["// after"]);
    }

    #[test]
    fn lifetimes_are_not_character_literals() {
        // The failure this guards: reading `'a` as an unterminated literal
        // swallows source until the next apostrophe, so the `// gone` below
        // would never be seen.
        let source = b"fn f<'a>(x: &'a str) -> &'static str { x } // gone\n";
        assert_eq!(ranges_text(source), vec!["// gone"]);
    }

    #[test]
    fn character_literals_are_character_literals() {
        assert!(ranges_text(b"let c = '/'; \n").is_empty());
        let source = b"let c = '/'; // after\n";
        assert_eq!(ranges_text(source), vec!["// after"]);
        // Escapes, and a multi-byte character that a per-byte step would land
        // in the middle of.
        assert_eq!(
            ranges_text("let c = '\\''; // a\n".as_bytes()),
            vec!["// a"]
        );
        assert_eq!(ranges_text("let c = 'é'; // b\n".as_bytes()), vec!["// b"]);
    }

    #[test]
    fn a_loop_label_is_not_a_literal_either() {
        let source = b"'outer: for _ in 0..1 { break 'outer; } // end\n";
        assert_eq!(ranges_text(source), vec!["// end"]);
    }

    #[test]
    fn an_unterminated_block_comment_runs_to_the_end_of_file() {
        let source = b"fn a() {}\n/* never closed\n";
        let ranges = comment_ranges(source);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].1, source.len());
    }

    #[test]
    fn ranges_come_back_sorted() {
        let source = b"// a\nfn f() {}\n/* b */\n// c\n";
        let ranges = comment_ranges(source);
        assert!(ranges.windows(2).all(|w| w[0].0 < w[1].0), "{ranges:?}");
    }
}
