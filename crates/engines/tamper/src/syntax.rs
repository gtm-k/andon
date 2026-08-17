//! The tree-sitter facade for the tamper suite.
//!
//! Sibling of `andon_engine_clones::syntax` and deliberately not shared with it:
//! P2, P3, and P4 run in one wave with disjoint file ownership, so a third crate
//! holding a common facade would be a fourth owner of the wave's grammar story.
//! The two facades also want different things — the clone engine wants a flat
//! normalized token stream, this one wants node shapes, call names, and error
//! counts — and the overlap is the language table below. Consolidation is a
//! later refactor with every consumer visible.
//!
//! # Everything here is a *syntactic* question
//!
//! No detector in this crate executes anything, resolves an import, or follows a
//! symbol. That keeps the engine `static-safe` (Codex #19) and keeps every
//! answer a function of the bytes, which is what lets the results into the
//! digest compare set.

use tree_sitter::{Node, Parser, Tree};

/// Version of the detector rule pack: the patterns, keys, and thresholds the
/// seven detectors match on. Bumped whenever any of them changes, because a
/// changed rule changes what fires.
pub const RULE_PACK_VERSION: &str = "1";

/// Revision of the detector *set* — which detectors exist at all.
pub const DETECTOR_SET_REVISION: &str = "1";

/// Grammar pins, held against `Cargo.lock` by `tests/regime_pins.rs`.
///
/// Same reasoning as the clone engine's: the parse-error delta and every
/// AST-shaped detector move when a grammar moves, and an unnoticed bump at an
/// apparently-equal regime is read as tampering rather than skew (PREMORTEM S4).
pub const GRAMMAR_PINS: &[(&str, &str)] = &[
    ("javascript", "0.25.0"),
    ("python", "0.25.0"),
    ("tree-sitter", "0.26.12"),
    ("typescript", "0.23.2"),
];

/// The rule-pack identity stamped into the regime, grammar pins included.
///
/// `MeasurementRegime::Tamper` carries `rule_pack_version` and
/// `detector_set_revision` and no grammar map, so the pins ride here for the
/// same reason they ride in the clone engine's `normalization_revision`: the
/// rules are written in terms of node kinds, and a grammar bump changes what
/// they match.
pub fn rule_pack_version() -> String {
    let mut parts = vec![format!("rules{RULE_PACK_VERSION}")];
    parts.extend(GRAMMAR_PINS.iter().map(|(name, v)| format!("{name}@{v}")));
    parts.join("+")
}

/// A language the suite can parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Language {
    /// TypeScript, without JSX.
    TypeScript,
    /// TypeScript with JSX.
    Tsx,
    /// JavaScript, including JSX.
    JavaScript,
    /// Python 3.
    Python,
}

impl Language {
    /// Which grammar reads this path, if any.
    pub fn for_path(path: &str) -> Option<Language> {
        let name = path.rsplit('/').next().unwrap_or(path);
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

    /// Whether this language's test idioms are the JavaScript family's.
    pub fn is_js_family(self) -> bool {
        !matches!(self, Language::Python)
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

    /// The name used in diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Language::TypeScript => "typescript",
            Language::Tsx => "tsx",
            Language::JavaScript => "javascript",
            Language::Python => "python",
        }
    }
}

/// A parsed file, kept with its bytes so node text can be read back.
pub struct Parsed {
    tree: Tree,
    source: Vec<u8>,
    language: Language,
}

impl Parsed {
    /// Parse, or `None` when no grammar reads the path.
    pub fn new(path: &str, source: &[u8]) -> Option<Parsed> {
        let language = Language::for_path(path)?;
        let mut parser = Parser::new();
        parser
            .set_language(&language.grammar())
            .unwrap_or_else(|e| panic!("grammar {} failed to load: {e}", language.name()));
        let tree = parser.parse(source, None)?;
        Some(Parsed {
            tree,
            source: source.to_vec(),
            language,
        })
    }

    /// The language that read it.
    pub fn language(&self) -> Language {
        self.language
    }

    /// The root node.
    pub fn root(&self) -> Node<'_> {
        self.tree.root_node()
    }

    /// The bytes.
    pub fn source(&self) -> &[u8] {
        &self.source
    }

    /// Source text of a node, lossily — a file that is not valid UTF-8 is still
    /// a file somebody committed, and refusing to look at it would make
    /// non-UTF-8 a way to hide from the suite.
    pub fn text(&self, node: Node<'_>) -> String {
        String::from_utf8_lossy(&self.source[node.byte_range()]).into_owned()
    }

    /// Every node, in a deterministic pre-order walk.
    pub fn nodes(&self) -> Vec<Node<'_>> {
        let mut out = Vec::new();
        let mut cursor = self.tree.walk();
        let mut stack = vec![self.tree.root_node()];
        while let Some(node) = stack.pop() {
            out.push(node);
            let mut children: Vec<Node> = node.children(&mut cursor).collect();
            children.reverse();
            stack.extend(children);
        }
        out.sort_by_key(|n| (n.start_byte(), std::cmp::Reverse(n.end_byte())));
        out
    }

    /// ERROR nodes plus MISSING nodes.
    ///
    /// Both are counted because both hide code from the static engines, and in
    /// opposite ways: an ERROR is a region the parser could not read, a MISSING
    /// is a token it inserted to keep going. PREMORTEM T3 is about the first and
    /// names the second as its sibling.
    pub fn parse_faults(&self) -> u32 {
        self.nodes()
            .iter()
            .filter(|node| node.is_error() || node.is_missing())
            .count() as u32
    }

    /// The 1-based line a byte offset falls on.
    pub fn line_of(&self, byte: usize) -> u32 {
        self.source[..byte.min(self.source.len())]
            .iter()
            .filter(|b| **b == b'\n')
            .count() as u32
            + 1
    }
}

/// The callee of a call expression, as written, e.g. `it.skip` or
/// `self.assertEqual`.
///
/// Returns `None` for anything that is not a call. The text is taken verbatim
/// rather than resolved: a detector that tried to follow `const t = it` would be
/// doing semantic analysis, and would still lose to the next indirection. The
/// corpus contains the honest cases this bluntness could trip over.
pub fn callee_text(parsed: &Parsed, node: Node<'_>) -> Option<String> {
    if node.kind() != "call_expression" && node.kind() != "call" {
        return None;
    }
    let callee = node
        .child_by_field_name("function")
        .or_else(|| node.child(0))?;
    Some(parsed.text(callee))
}

/// The last segment of a dotted callee: `foo.bar.baz` -> `baz`.
pub fn last_segment(callee: &str) -> &str {
    callee.rsplit(['.', '?']).next().unwrap_or(callee).trim()
}

/// The first segment of a dotted callee: `foo.bar.baz` -> `foo`.
pub fn first_segment(callee: &str) -> &str {
    callee
        .split(['.', '(', '?'])
        .next()
        .unwrap_or(callee)
        .trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_faults_are_counted_and_clean_files_have_none() {
        let clean = Parsed::new("a.ts", b"const x: number = 1;\n").unwrap();
        assert_eq!(clean.parse_faults(), 0);
        let broken = Parsed::new("a.ts", b"function f( { !!! \n").unwrap();
        assert!(broken.parse_faults() > 0);
    }

    #[test]
    fn callees_read_as_written() {
        let parsed = Parsed::new("a.ts", b"it.skip('x', () => { expect(1).toBe(1); });").unwrap();
        let callees: Vec<String> = parsed
            .nodes()
            .iter()
            .filter_map(|n| callee_text(&parsed, *n))
            .collect();
        assert!(callees.iter().any(|c| c == "it.skip"), "{callees:?}");
        assert!(callees.iter().any(|c| c == "expect"), "{callees:?}");
    }

    #[test]
    fn segments_split_dotted_names() {
        assert_eq!(last_segment("it.skip"), "skip");
        assert_eq!(first_segment("it.skip"), "it");
        assert_eq!(first_segment("expect"), "expect");
        assert_eq!(last_segment("self.assertEqual"), "assertEqual");
    }

    #[test]
    fn python_calls_are_found_too() {
        let parsed = Parsed::new("a.py", b"def test_x():\n    assert compute(1) == 2\n").unwrap();
        let callees: Vec<String> = parsed
            .nodes()
            .iter()
            .filter_map(|n| callee_text(&parsed, *n))
            .collect();
        assert!(callees.iter().any(|c| c == "compute"), "{callees:?}");
    }

    #[test]
    fn lines_are_one_based() {
        let parsed = Parsed::new("a.ts", b"const a = 1;\nconst b = 2;\n").unwrap();
        assert_eq!(parsed.line_of(0), 1);
        assert_eq!(parsed.line_of(14), 2);
    }
}
