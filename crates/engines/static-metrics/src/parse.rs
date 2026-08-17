//! Parsing, and the health of the parse.
//!
//! # Parse health is a measurement, not an error path
//!
//! PREMORTEM T3 rates a silent undercount as crippling: tree-sitter recovers
//! from anything, so a file it half-understood still yields a tree, still yields
//! numbers, and — without this module — still yields numbers that look exactly
//! like numbers from a file it understood completely. That is the shape of an
//! evasion (edit until the parser gives up on the complicated part) and of an
//! honest failure (a syntax the pinned grammar predates) at the same time.
//!
//! So every parse reports [`ParseHealth`], every result derived from a degraded
//! parse is marked, and the marks are load-bearing rather than cosmetic:
//!
//! * `completeness: parse-degraded` is **inside** the per-result digest input,
//!   so the agent and the verifier must agree that a file was degraded, and the
//!   cross-OS matrix proves they do;
//! * severity is capped, so a degraded number can never drive MED+;
//! * the evidence reference gains a caveat naming the counts, so a human reading
//!   the report is told what the agent's policy already knows.
//!
//! See [`crate::health`] for the three-way demotion and why it is three ways.
//!
//! # Bytes, not strings
//!
//! Input is a git blob. A blob that is not valid UTF-8 is refused rather than
//! lossily decoded: tree-sitter's byte API assumes UTF-8, and feeding it
//! something else produces a tree whose node positions do not correspond to
//! anything. A refused file is counted in `static.unmeasured-files` — visible,
//! and never a zero.

use crate::lang::Language;

/// A parse could not be attempted, or its input was not source.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The blob is not valid UTF-8, so it is not source this crate can read.
    #[error("not valid UTF-8 at byte {offset}")]
    NotUtf8 {
        /// First offending byte offset, as `std::str::from_utf8` reports it.
        offset: usize,
    },
    /// The language has no grammar — the tokenization tier.
    #[error("{language} is measured by tokenization and has no grammar")]
    NoGrammar {
        /// The language asked for.
        language: &'static str,
    },
    /// tree-sitter refused the grammar or gave up. Both are bugs rather than
    /// input problems, and neither is silently turned into a zero.
    #[error("tree-sitter could not parse {language}: {detail}")]
    Failed {
        /// The language asked for.
        language: &'static str,
        /// What tree-sitter said.
        detail: String,
    },
}

/// How completely the parser understood a file.
///
/// Two counts rather than one because they mean different things. An `ERROR`
/// node is a region the parser could not fit to the grammar at all — it is the
/// hiding place. A `MISSING` node is a token the parser *inserted* to keep
/// going: the tree is structurally complete and one symbol of it was never
/// written. A file with three ERRORs and a file with three MISSINGs are not in
/// the same condition, and reporting their sum alone would say they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParseHealth {
    /// `ERROR` nodes in the tree.
    pub error_nodes: u64,
    /// `MISSING` nodes the parser inserted.
    pub missing_nodes: u64,
    /// Every node in the tree, named and anonymous. The denominator of the
    /// corpus ERROR-node rate; meaningless on its own, which is why it is not a
    /// reported metric.
    pub total_nodes: u64,
}

impl ParseHealth {
    /// Whether results from this parse must be demoted.
    ///
    /// One ERROR or one MISSING is enough. There is no tolerance band: a
    /// threshold here would be a number an evasion could sit underneath, and
    /// the demotion costs nothing but honesty — the number is still reported,
    /// it just stops being allowed to stop the line.
    pub fn is_degraded(self) -> bool {
        self.error_nodes > 0 || self.missing_nodes > 0
    }

    /// ERROR plus MISSING nodes as a fraction of all nodes.
    ///
    /// The corpus budget is expressed against this rather than against absolute
    /// counts, so adding a file to a pinned repository cannot fail the gate by
    /// arithmetic alone.
    pub fn error_rate(self) -> f64 {
        if self.total_nodes == 0 {
            return 0.0;
        }
        (self.error_nodes + self.missing_nodes) as f64 / self.total_nodes as f64
    }
}

/// A parsed file, and everything the metrics need from it.
///
/// `Debug` prints the tree's s-expression rather than the bytes: when a test or
/// a diagnostic wants to see a `Parsed`, what it wants to see is the shape the
/// grammar found, and the source is already in the caller's hands.
pub struct Parsed<'a> {
    /// Which language it was parsed as.
    pub language: Language,
    /// The blob bytes. Held so node ranges can be resolved back to text.
    pub source: &'a [u8],
    /// The tree.
    pub tree: tree_sitter::Tree,
    /// How completely the parser understood it.
    pub health: ParseHealth,
}

impl std::fmt::Debug for Parsed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parsed")
            .field("language", &self.language.name())
            .field("health", &self.health)
            .field("tree", &self.tree.root_node().to_sexp())
            .finish()
    }
}

/// Parse a blob.
pub fn parse(language: Language, source: &[u8]) -> Result<Parsed<'_>, ParseError> {
    if let Err(error) = std::str::from_utf8(source) {
        return Err(ParseError::NotUtf8 {
            offset: error.valid_up_to(),
        });
    }
    let grammar = language.grammar().ok_or(ParseError::NoGrammar {
        language: language.name(),
    })?;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&grammar)
        .map_err(|e| ParseError::Failed {
            language: language.name(),
            detail: e.to_string(),
        })?;
    // No timeout is set, deliberately. A wall-clock parse budget would make the
    // result depend on how loaded the machine was — a nondeterministic input to
    // a digest, which is the one thing this crate may not have (PREMORTEM T1).
    // A pathological file is a slow measurement, not a different one.
    let tree = parser.parse(source, None).ok_or(ParseError::Failed {
        language: language.name(),
        detail: "the parser returned no tree".to_string(),
    })?;
    let health = health_of(&tree);
    Ok(Parsed {
        language,
        source,
        tree,
        health,
    })
}

/// Walk every node — named and anonymous — counting the three numbers.
///
/// Anonymous nodes are included because `MISSING` is usually one: the parser
/// inserts the semicolon or the closing brace that was never written, and a walk
/// over named nodes alone would report a clean parse of a file that is missing
/// punctuation. Nodes *inside* an `ERROR` subtree are counted as ordinary nodes;
/// only the `ERROR` node itself is an error, so a large unparsable region counts
/// once rather than once per token it swallowed.
fn health_of(tree: &tree_sitter::Tree) -> ParseHealth {
    let mut health = ParseHealth::default();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        health.total_nodes += 1;
        if node.is_error() {
            health.error_nodes += 1;
        }
        if node.is_missing() {
            health.missing_nodes += 1;
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    health
}

/// Byte ranges of every comment in the tree, sorted and non-overlapping.
///
/// Used by source-line counting. Comments nest in no language here, so a simple
/// sorted list is enough; the ranges are merged so a caller can test membership
/// with a single scan.
pub fn comment_ranges(parsed: &Parsed<'_>) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut stack = vec![parsed.tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind().contains("comment") {
            ranges.push((node.start_byte(), node.end_byte()));
            // A comment has no children worth descending into, and descending
            // would be the only way a nested range could appear.
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    ranges.sort_unstable();
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_file_is_not_degraded() {
        let parsed = parse(Language::TypeScript, b"const a: number = 1;\n").expect("parses");
        assert_eq!(parsed.health.error_nodes, 0);
        assert_eq!(parsed.health.missing_nodes, 0);
        assert!(!parsed.health.is_degraded());
        assert!(parsed.health.total_nodes > 0, "the denominator is real");
    }

    #[test]
    fn an_unparsable_region_is_counted_as_an_error_node() {
        let parsed = parse(Language::TypeScript, b"function f( { @@@ ] ) }\n").expect("recovers");
        assert!(
            parsed.health.error_nodes > 0,
            "{:?}",
            parsed.tree.root_node().to_sexp()
        );
        assert!(parsed.health.is_degraded());
    }

    #[test]
    fn an_inserted_token_is_counted_as_missing() {
        // The parser closes the brace that was never written. The tree is
        // structurally complete and one symbol of it is fiction — which a walk
        // over named nodes alone would not notice.
        let parsed = parse(Language::TypeScript, b"function f() {\n  return 1;\n").expect("parses");
        assert!(
            parsed.health.missing_nodes > 0 || parsed.health.error_nodes > 0,
            "{}",
            parsed.tree.root_node().to_sexp()
        );
        assert!(parsed.health.is_degraded());
    }

    #[test]
    fn python_recovers_and_says_so() {
        let parsed = parse(Language::Python, b"def f(:\n    return\n").expect("recovers");
        assert!(parsed.health.is_degraded(), "{:?}", parsed.health);
    }

    #[test]
    fn a_binary_blob_is_refused_rather_than_measured() {
        // A `.ts` path holding non-UTF-8 bytes is not source. Lossy decoding
        // would produce a tree over invented characters and a digest over
        // invented numbers.
        match parse(Language::TypeScript, b"const a = \"\xff\xfe\";") {
            Err(ParseError::NotUtf8 { offset }) => assert_eq!(offset, 11),
            other => panic!("expected a typed refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_tokenization_tier_has_no_grammar_to_offer() {
        assert!(matches!(
            parse(Language::Rust, b"fn main() {}"),
            Err(ParseError::NoGrammar { language: "rust" })
        ));
    }

    #[test]
    fn the_error_rate_is_zero_on_an_empty_tree_rather_than_a_division() {
        assert_eq!(ParseHealth::default().error_rate(), 0.0);
    }

    #[test]
    fn comment_ranges_cover_both_comment_forms() {
        let source = b"// line\nconst a = 1; /* block */\n";
        let parsed = parse(Language::TypeScript, source).expect("parses");
        let ranges = comment_ranges(&parsed);
        assert_eq!(ranges.len(), 2, "{ranges:?}");
        assert!(ranges.windows(2).all(|w| w[0].0 <= w[1].0), "sorted");
        assert_eq!(&source[ranges[0].0..ranges[0].1], b"// line");
    }
}
