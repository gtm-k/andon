//! The tree-sitter facade: which grammar reads a path, and what a token is.
//!
//! # Why the clone engine carries its own facade
//!
//! P2 vendors grammars for the static-metrics engine and P3 needs token streams
//! from the same parsers, but the two phases run in the same wave with disjoint
//! file ownership (PLAN.md shared-files). A shared `crates/engines/syntax` crate
//! would be a third owner of the wave's grammar story, so each crate carries the
//! ~100 lines it needs and consolidation is a later refactor with all the
//! consumers visible. The facade in `andon-engine-tamper` is its sibling: it
//! asks the tree different questions (ERROR nodes, call shapes) and shares only
//! the language table.
//!
//! # Normalization is what makes a clone a clone
//!
//! A token stream that kept identifier spellings would only ever find copies
//! nobody edited. Identifiers, string literals, and numbers each collapse to a
//! single symbol, so a block pasted and renamed still matches — the Type-2
//! clone that actually shows up in agent-authored code. Comments are dropped
//! entirely: a copy with the comments rewritten is still a copy.
//!
//! # Every symbol hash is fixed, never `DefaultHasher`
//!
//! `std::collections::hash_map::DefaultHasher` is seeded per process. A
//! fingerprint built on it would differ between two runs of the same binary on
//! the same bytes, which is PREMORTEM T1's byte-nondeterminism arriving through
//! a hash function. [`fnv1a`] is fixed, specified, and reproduces anywhere.

use andon_core::parse_health::ParseHealth;
use tree_sitter::{Node, Parser, Tree};

/// Version of the normalization rules themselves — the mapping from tree-sitter
/// node kinds to symbols below. Bumped whenever that mapping changes, because a
/// changed mapping changes every fingerprint.
pub const NORMALIZATION_RULES_REVISION: &str = "2";

/// The grammar versions this crate is pinned to.
///
/// These constants are the *claim*; `Cargo.lock` is the *fact*. They are equal
/// only because `tests/regime_pins.rs` fails the build when they are not — a
/// version string a human maintains beside a version a resolver picks is the
/// self-asserted field this project has now caught twice (DEFERRED-APPROVALS
/// E4, E8), and the regime is exactly where it would do damage: an unnoticed
/// grammar bump would change the numbers at an apparently equal regime, which
/// the verifier reads as `divergent` rather than `unwitnessed-version-skew`
/// (PREMORTEM S4, Story 1).
pub const GRAMMAR_PINS: &[(&str, &str)] = &[
    ("javascript", "0.25.0"),
    ("python", "0.25.0"),
    ("tree-sitter", "0.26.12"),
    ("typescript", "0.23.2"),
];

/// A language this engine can tokenize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Language {
    /// TypeScript, without JSX.
    TypeScript,
    /// TypeScript with JSX — a separate grammar, not a flag.
    Tsx,
    /// JavaScript, including JSX.
    JavaScript,
    /// Python 3.
    Python,
}

impl Language {
    /// Which grammar reads this path, if any.
    ///
    /// Extension-based and deliberately not content-sniffing: the answer has to
    /// be identical on every operating system for a digest to reproduce, and a
    /// heuristic over bytes is one more thing that can disagree.
    pub fn for_path(path: &str) -> Option<Language> {
        let name = path.rsplit('/').next().unwrap_or(path);
        // Longest suffix first: `.d.ts` is TypeScript, and `.spec.tsx` must not
        // match the `.ts` arm.
        for (suffix, language) in [
            (".tsx", Language::Tsx),
            (".mts", Language::TypeScript),
            (".cts", Language::TypeScript),
            (".ts", Language::TypeScript),
            (".jsx", Language::JavaScript),
            (".mjs", Language::JavaScript),
            (".cjs", Language::JavaScript),
            (".js", Language::JavaScript),
            (".pyi", Language::Python),
            (".py", Language::Python),
        ] {
            if name.len() > suffix.len() && name.ends_with(suffix) {
                return Some(language);
            }
        }
        None
    }

    /// The name used in the regime string and in diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Language::TypeScript => "typescript",
            Language::Tsx => "tsx",
            Language::JavaScript => "javascript",
            Language::Python => "python",
        }
    }

    /// The tree-sitter grammar.
    pub fn grammar(self) -> tree_sitter::Language {
        match self {
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
        }
    }
}

/// The tokenizer-and-grammar tuple, as it is stamped into the
/// `measurement_regime`.
///
/// # Why the grammar versions ride in `normalization_revision`
///
/// `MeasurementRegime::Clones` is P0-owned schema (`schemas/payload-v1.schema.json`)
/// and carries no grammar map — the variant was written before the clone engine
/// had a parser. Leaving the grammar versions out is not an option: regime
/// equality is what routes a disagreement to `unwitnessed-version-skew` instead
/// of `divergent`, so a grammar bump at an apparently-equal regime would report
/// honest work as tampering (PREMORTEM S4 feeding Story 1).
///
/// Folding them in here is not a workaround either, on inspection: the
/// normalization rules are written *in terms of* tree-sitter node kinds, so a
/// grammar that renames or re-shapes a node changes the normalization. The
/// grammar version and the rules revision are one fact, and this string is its
/// spelling. The schema observation is recorded for P0/P5a all the same.
pub fn normalization_revision() -> String {
    let mut parts = vec![format!("rules{NORMALIZATION_RULES_REVISION}")];
    // `GRAMMAR_PINS` is sorted at the source, and `regime_pins.rs` asserts it,
    // so this string is stable without a sort at every call.
    parts.extend(GRAMMAR_PINS.iter().map(|(name, v)| format!("{name}@{v}")));
    parts.join("+")
}

/// FNV-1a, 64-bit. Fixed constants, no seed, identical everywhere.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// One normalized token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    /// [`fnv1a`] of the normalized symbol.
    pub symbol: u64,
    /// Byte offset of the token's first byte.
    pub start_byte: u32,
    /// Byte offset one past the token's last byte.
    pub end_byte: u32,
    /// Zero-based row the token starts on.
    pub start_row: u32,
}

/// Node kinds dropped from the stream entirely, contents and all.
///
/// # Why imports are not code, for this purpose
///
/// Normalization is what makes a clone a clone, and it is also what makes an
/// import preamble look like one. `import { a, b, c } from 'x';` normalizes to
/// `import { ID , ID , ID } from STR ;` — and so does every other import of
/// three names from anywhere. Two modules that share nothing but a
/// conventional set of imports produce identical token runs, and eight import
/// lines is comfortably over the fifty-token floor.
///
/// Probed, before this existed: a React-flavoured module and a `node:`-flavoured
/// one, sharing not one identifier, reported as one clone group covering 126
/// tokens — 95.5% of the measured set. A duplication figure of 95% on two
/// unrelated files is not a near miss, it is the number being worthless.
///
/// An import block is also not something an agent can act on: it is generated
/// by the editor, ordered by a formatter, and identical across a codebase by
/// design. Dropping it costs no real clone, because a copied *implementation*
/// carries far more than its imports.
const DROPPED_KINDS: &[&str] = &[
    // JavaScript, TypeScript, TSX.
    "import_statement",
    // Python.
    "import_from_statement",
    "future_import_statement",
];

/// Node kinds taken whole rather than descended into.
///
/// A `string` node has the quote characters and the fragment as children, so a
/// leaf walk would emit three tokens for one literal and make the token count
/// depend on quoting style. Taking the container as one token is both the
/// smaller stream and the more faithful one.
fn atomic_symbol(kind: &str) -> Option<&'static str> {
    match kind {
        "comment" | "line_comment" | "block_comment" | "html_comment" => Some(""),
        "string"
        | "template_string"
        | "template_literal"
        | "string_literal"
        | "concatenated_string"
        | "raw_string_literal"
        | "regex" => Some("STR"),
        _ => None,
    }
}

/// The symbol a leaf node collapses to.
fn leaf_symbol<'a>(node: &Node<'a>) -> Option<&'a str> {
    let kind = node.kind();
    match kind {
        "identifier"
        | "property_identifier"
        | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern"
        | "type_identifier"
        | "field_identifier"
        | "statement_identifier"
        | "private_property_identifier" => Some("ID"),
        "number" | "integer" | "float" => Some("NUM"),
        "string_fragment" | "escape_sequence" => Some("STR"),
        // A parse failure is a token in its own right: it keeps the stream
        // aligned instead of silently deleting the unparseable region, and the
        // tamper engine counts these separately (PREMORTEM T3).
        "ERROR" => Some("ERROR"),
        _ => Some(kind),
    }
}

/// Parse and normalize, or `None` when the language has no grammar here.
pub fn tokenize(path: &str, source: &[u8]) -> Option<Vec<Token>> {
    tokenize_with_health(path, source).map(|(tokens, _)| tokens)
}

/// Parse and normalize, reporting how much of the file the parser understood.
///
/// # Why the clone engine has to know
///
/// tree-sitter recovers from anything, so a file it half-understood still
/// tokenizes, still fingerprints, and — before this — still produced numbers
/// indistinguishable from a file it read completely. Duplication measured over a
/// tree with an `ERROR` region in it is duplication measured over less code than
/// the file contains, and the difference is invisible in the result.
///
/// It matters more since the wave-1 integration than it did when this engine was
/// written: the three grammar-holding engines converged on identical pins, so the
/// same degraded input now reaches all of them, and the static engine has marked
/// its numbers `parse-degraded` since P2 while these claimed `complete`. Two
/// engines disagreeing about whether a file was degraded is a disagreement the
/// verifier reads as tampering (PREMORTEM T3, S4).
pub fn tokenize_with_health(path: &str, source: &[u8]) -> Option<(Vec<Token>, ParseHealth)> {
    let language = Language::for_path(path)?;
    let tree = parse(language, source)?;
    Some((tokens_of(&tree, source), health_of(&tree)))
}

/// Count the `ERROR` and `MISSING` nodes in a tree.
///
/// # Why this is not folded into `tokens_of`
///
/// The token walk is not a walk of the tree. It drops import subtrees whole and
/// skips zero-width nodes, both for good reasons of its own — and both of them
/// would hide degradation: an `ERROR` inside a dropped import block, or the
/// `MISSING` semicolon the parser inserted, would go uncounted, and a file could
/// be measured as clean because the thing that broke it was in a region the
/// fingerprint ignores.
///
/// So health is its own complete walk, with semantics identical to the static
/// engine's, node for node: every node named and anonymous, `MISSING` counted
/// wherever it appears, and nodes *inside* an `ERROR` subtree counted as ordinary
/// nodes so a large unparsable region counts once rather than once per token it
/// swallowed. Identical semantics is the point — the two engines write the same
/// digest-bound `completeness` field about the same file.
///
/// Iterative, like every tree walk in this crate: a generated file can nest
/// deeply enough to blow a thread's stack, and a crash on a large input is a
/// denial of measurement.
pub fn health_of(tree: &Tree) -> ParseHealth {
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

/// Parse with the grammar for `language`.
pub fn parse(language: Language, source: &[u8]) -> Option<Tree> {
    let mut parser = Parser::new();
    // Only fails on an ABI mismatch between this crate and the grammar crate,
    // which `tests/regime_pins.rs` and the grammar smoke test cover; a `None`
    // here would be silently unmeasured input, so it is worth being loud about.
    parser
        .set_language(&language.grammar())
        .unwrap_or_else(|e| panic!("grammar {} failed to load: {e}", language.name()));
    parser.parse(source, None)
}

/// Walk a parsed tree into a normalized token stream.
pub fn tokens_of(tree: &Tree, source: &[u8]) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut cursor = tree.walk();
    // An explicit stack rather than recursion: a generated file can nest deeply
    // enough to blow a thread's stack, and a crash on a large input is a denial
    // of measurement.
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if DROPPED_KINDS.contains(&node.kind()) {
            continue;
        }
        if let Some(symbol) = atomic_symbol(node.kind()) {
            if !symbol.is_empty() {
                push(&mut tokens, symbol, &node);
            }
            continue;
        }
        if node.child_count() == 0 {
            // Zero-width nodes are tree-sitter's MISSING markers: they name a
            // token the grammar expected and the bytes do not contain. They
            // carry no source text, so they are counted by the tamper engine
            // and left out of the clone stream.
            if node.end_byte() > node.start_byte() {
                if let Some(symbol) = leaf_symbol(&node) {
                    push(&mut tokens, symbol, &node);
                }
            }
            continue;
        }
        // Children pushed in reverse so the stack yields them in source order.
        let mut children: Vec<Node> = node.children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    // The stack walk visits siblings in order but the reversal above only holds
    // per level; sorting by start byte restores a single source-order stream
    // without depending on the traversal's shape.
    tokens.sort_by_key(|t| (t.start_byte, t.end_byte));
    let _ = source;
    tokens
}

fn push(tokens: &mut Vec<Token>, symbol: &str, node: &Node) {
    tokens.push(Token {
        symbol: fnv1a(symbol.as_bytes()),
        start_byte: node.start_byte() as u32,
        end_byte: node.end_byte() as u32,
        start_row: node.start_position().row as u32,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_map_to_grammars() {
        assert_eq!(Language::for_path("a/b.ts"), Some(Language::TypeScript));
        assert_eq!(Language::for_path("a/b.tsx"), Some(Language::Tsx));
        assert_eq!(Language::for_path("a/b.spec.tsx"), Some(Language::Tsx));
        assert_eq!(Language::for_path("a/b.d.ts"), Some(Language::TypeScript));
        assert_eq!(Language::for_path("a/b.js"), Some(Language::JavaScript));
        assert_eq!(Language::for_path("a/b.py"), Some(Language::Python));
        assert_eq!(Language::for_path("a/b.rs"), None);
        // A file *named* `.ts` is not a TypeScript file; the guard is the
        // length check, and without it a dotfile would tokenize as source.
        assert_eq!(Language::for_path(".ts"), None);
    }

    #[test]
    fn renaming_does_not_change_the_token_stream() {
        let a = tokenize("a.ts", b"function alpha(x: number) { return x + 1; }").unwrap();
        let b = tokenize(
            "b.ts",
            b"function beta(veryLong: number) { return veryLong + 1; }",
        )
        .unwrap();
        let a: Vec<u64> = a.iter().map(|t| t.symbol).collect();
        let b: Vec<u64> = b.iter().map(|t| t.symbol).collect();
        assert_eq!(a, b, "identifier renaming must not move the fingerprint");
    }

    #[test]
    fn comments_and_literal_spelling_are_normalized_away() {
        let a = tokenize("a.py", b"x = 'hello'  # a note\n").unwrap();
        let b = tokenize("b.py", b"y = \"different text entirely\"\n").unwrap();
        let a: Vec<u64> = a.iter().map(|t| t.symbol).collect();
        let b: Vec<u64> = b.iter().map(|t| t.symbol).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn import_preambles_are_not_part_of_the_stream() {
        let with_imports = tokenize(
            "a.ts",
            b"import { one, two } from 'x';
import three from 'y';
export const v = 1;
",
        )
        .unwrap();
        let without = tokenize(
            "b.ts",
            b"export const v = 1;
",
        )
        .unwrap();
        assert_eq!(
            with_imports.iter().map(|t| t.symbol).collect::<Vec<_>>(),
            without.iter().map(|t| t.symbol).collect::<Vec<_>>(),
            "an import block must contribute nothing to the fingerprint"
        );
    }

    #[test]
    fn python_imports_are_dropped_too() {
        let with_imports = tokenize(
            "a.py",
            b"from os import path
import sys

def f():
    return 1
",
        )
        .unwrap();
        let without = tokenize(
            "b.py",
            b"def f():
    return 1
",
        )
        .unwrap();
        assert_eq!(
            with_imports.iter().map(|t| t.symbol).collect::<Vec<_>>(),
            without.iter().map(|t| t.symbol).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_re_export_is_still_code() {
        // `export ... from` is an export statement, not an import one, and
        // dropping export statements would drop every exported function body.
        let tokens = tokenize(
            "a.ts",
            b"export function f() { return 1; }
",
        )
        .unwrap();
        assert!(!tokens.is_empty());
    }

    #[test]
    fn structure_still_separates_different_code() {
        let a = tokenize("a.ts", b"const x = 1;").unwrap();
        let b = tokenize("b.ts", b"let x = 1;").unwrap();
        let a: Vec<u64> = a.iter().map(|t| t.symbol).collect();
        let b: Vec<u64> = b.iter().map(|t| t.symbol).collect();
        assert_ne!(a, b, "keywords are not identifiers and must not collapse");
    }

    #[test]
    fn tokens_come_out_in_source_order() {
        let tokens = tokenize("a.ts", b"function f(a, b) { return a + b; }").unwrap();
        assert!(tokens
            .windows(2)
            .all(|w| w[0].start_byte <= w[1].start_byte));
        assert!(!tokens.is_empty());
    }

    #[test]
    fn unparseable_input_still_yields_a_stream() {
        // A file that does not parse must not vanish: the clone engine still has
        // something to fingerprint, and the tamper engine counts the errors.
        let tokens = tokenize("a.ts", b"function f( { !!! ").unwrap();
        assert!(!tokens.is_empty());
    }

    #[test]
    fn a_degraded_parse_is_reported_and_a_clean_one_is_not() {
        let (_, clean) = tokenize_with_health("a.ts", b"export const x: number = 1;\n").unwrap();
        assert!(!clean.is_degraded(), "{clean:?}");
        assert!(clean.total_nodes > 0, "a clean parse still has a tree");

        let (_, broken) = tokenize_with_health("a.ts", b"function f( { !!! \n").unwrap();
        assert!(broken.is_degraded(), "{broken:?}");
    }

    #[test]
    fn degradation_inside_a_dropped_import_is_still_degradation() {
        // The token walk drops import subtrees whole. If health were counted
        // during that walk instead of over the tree, a file broken inside its
        // import block would fingerprint as clean — measured over less code than
        // it contains, and saying so nowhere.
        let (_, health) = tokenize_with_health("a.ts", b"import { a, from 'x';\n").unwrap();
        assert!(health.is_degraded(), "{health:?}");
    }

    #[test]
    fn an_inserted_token_counts_as_missing_not_as_an_error() {
        // A MISSING node is the token the parser supplied to keep going. It is a
        // different condition from an ERROR region and is reported separately,
        // because a file short one brace and a file with an unreadable block are
        // not in the same state.
        let (_, health) = tokenize_with_health("a.ts", b"function f() { return 1;\n").unwrap();
        assert!(health.missing_nodes > 0, "{health:?}");
        assert!(health.is_degraded());
    }

    #[test]
    fn the_normalization_revision_names_every_pin() {
        let revision = normalization_revision();
        for (name, version) in GRAMMAR_PINS {
            assert!(
                revision.contains(&format!("{name}@{version}")),
                "{revision} is missing {name}@{version}"
            );
        }
    }
}
