//! Which languages the static family measures, and at what grammar.
//!
//! # Two tiers, and the line between them
//!
//! **Parsed tier** — TypeScript, TSX, JavaScript and Python get a real
//! tree-sitter parse, and therefore size, cyclomatic complexity, cognitive
//! complexity and parse health.
//!
//! **Tokenization tier** — Rust gets source-line counting from a hand-written
//! scanner and nothing else (APPROACH: "Rust tokenization-tier (size+clones) so
//! Andon passes its own measurement"; the cyclomatic/cognitive go/defer decision
//! is recorded at P10a). A Rust file therefore emits `static.sloc` and **no**
//! parse-health results — not zeros. There is no parser, so "zero parse errors"
//! would be a number about something that never happened, which is the
//! fabricated-zero failure the completeness vocabulary exists to prevent.
//!
//! # The grammar tuple is the regime
//!
//! Every version below is stamped into [`MeasurementRegime::Static`] and
//! therefore into every per-result digest. Two binaries at different grammar
//! versions produce `unwitnessed-version-skew` rather than `divergent`
//! (PREMORTEM S4), which is only true if the versions are actually in the
//! regime — so they are constants here, asserted against `Cargo.toml` by
//! `tests/grammar_pins.rs`, and asserted against the recorded parse-corpus
//! baseline by `tests/corpus_baseline.rs`.
//!
//! The tree-sitter *runtime* version is in the map alongside the grammars. A
//! runtime upgrade can change how a parse recovers from an error, which changes
//! ERROR-node counts, which changes `completeness` — a value inside the digest
//! input. Leaving the runtime out would let that move silently.

use std::collections::BTreeMap;

/// Version of the tree-sitter runtime, as pinned in `Cargo.toml`.
///
/// # Why the grammars are all on the 0.23 line
///
/// `tree-sitter-typescript` has no release past 0.23.2, and TypeScript is the
/// language the corpus finds real gaps in — so it anchors the set. The
/// JavaScript and Python grammars have 0.25 releases and are deliberately left
/// where they are: both measure the corpus at **zero** degraded files, so a bump
/// buys nothing measurable and costs a wider runtime-ABI surface across a set
/// that currently agrees with itself. A grammar bump is a regime change and
/// therefore a corpus re-run (see `fixtures/parse-corpus`); doing one without a
/// number that improves is churn stamped onto every digest.
pub const TREE_SITTER_VERSION: &str = "0.25.10";
/// Version of the vendored-by-pin TypeScript grammar crate (TypeScript + TSX).
pub const TYPESCRIPT_GRAMMAR_VERSION: &str = "0.23.2";
/// Version of the vendored-by-pin JavaScript grammar crate.
pub const JAVASCRIPT_GRAMMAR_VERSION: &str = "0.23.1";
/// Version of the vendored-by-pin Python grammar crate.
pub const PYTHON_GRAMMAR_VERSION: &str = "0.23.6";

/// Revision of the metric definitions in this crate.
///
/// Bumped whenever a counting rule changes: what a source line is, which nodes
/// are cyclomatic decision points, how cognitive complexity treats `else if`, or
/// which nodes get their own function-scope result. It is in the regime, so old
/// and new numbers become **incomparable** rather than silently different —
/// which is the whole point of having it.
///
/// The rules themselves are documented where they are implemented — [`crate::sloc`],
/// [`crate::cyclomatic`], [`crate::cognitive`], [`crate::functions`] — and this
/// constant is what the digest binds them to.
pub const SPEC_REVISION: &str = "p2-static-1";

/// A language the static family knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Language {
    /// TypeScript, `.ts` / `.mts` / `.cts`.
    TypeScript,
    /// TypeScript with JSX, `.tsx`. A separate grammar, the same claim scope.
    Tsx,
    /// JavaScript in every module flavour, plus JSX.
    JavaScript,
    /// Python, `.py` / `.pyi`.
    Python,
    /// Rust. Tokenization tier: size only.
    Rust,
}

impl Language {
    /// The language a path is measured as, or `None` when the static family has
    /// nothing to say about it.
    ///
    /// Extension-based and case-sensitive. Case-insensitive matching would make
    /// the answer depend on how a filesystem spells a name, and
    /// `ResultScope::path` is inside the digest — a case-folding host would
    /// then measure a different set from a case-preserving one. Git records the
    /// path as committed, and that is what is matched.
    pub fn for_path(path: &str) -> Option<Self> {
        let name = path.rsplit('/').next().unwrap_or(path);
        // `rsplit_once` rather than `Path::extension`: the argument is a git
        // path with forward slashes, not a filesystem path, and it must be read
        // the same way on every platform.
        let ext = name.rsplit_once('.').map(|(_, ext)| ext)?;
        Some(match ext {
            "ts" | "mts" | "cts" => Language::TypeScript,
            "tsx" => Language::Tsx,
            "js" | "jsx" | "mjs" | "cjs" => Language::JavaScript,
            "py" | "pyi" => Language::Python,
            "rs" => Language::Rust,
            _ => return None,
        })
    }

    /// True when this language is parsed rather than scanned.
    pub fn is_parsed(self) -> bool {
        self != Language::Rust
    }

    /// The `language` component of a claim tuple.
    ///
    /// TSX collapses onto `typescript`: the evidence for cognitive complexity is
    /// about the language, not about whether a file happens to contain JSX. The
    /// two grammars remain distinct in the regime, where the difference is a
    /// fact about the measurement rather than about the claim.
    pub fn claim_language(self) -> &'static str {
        match self {
            Language::TypeScript | Language::Tsx => "typescript",
            Language::JavaScript => "javascript",
            Language::Python => "python",
            Language::Rust => "rust",
        }
    }

    /// Stable spelling for diagnostics and the corpus report.
    pub fn name(self) -> &'static str {
        match self {
            Language::TypeScript => "typescript",
            Language::Tsx => "tsx",
            Language::JavaScript => "javascript",
            Language::Python => "python",
            Language::Rust => "rust",
        }
    }

    /// Every language, in a fixed order. Used by the corpus report so its
    /// sections do not move between runs.
    pub fn all() -> [Language; 5] {
        [
            Language::TypeScript,
            Language::Tsx,
            Language::JavaScript,
            Language::Python,
            Language::Rust,
        ]
    }

    /// The tree-sitter grammar, for the parsed tier.
    pub fn grammar(self) -> Option<tree_sitter::Language> {
        Some(match self {
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::Rust => return None,
        })
    }
}

/// The engine-and-grammar tuple every static result is stamped with.
///
/// Always the full set, never only the grammars a particular run happened to
/// use. The shape of a record must not vary with its content (P0 shape-stability
/// doctrine), and a regime that listed only the grammars in play would make two
/// honest measurements of different file sets incomparable by construction.
pub fn grammar_versions() -> BTreeMap<String, String> {
    [
        ("tree-sitter", TREE_SITTER_VERSION),
        ("typescript", TYPESCRIPT_GRAMMAR_VERSION),
        ("tsx", TYPESCRIPT_GRAMMAR_VERSION),
        ("javascript", JAVASCRIPT_GRAMMAR_VERSION),
        ("python", PYTHON_GRAMMAR_VERSION),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_map_to_the_languages_the_plan_names() {
        assert_eq!(Language::for_path("src/a.ts"), Some(Language::TypeScript));
        assert_eq!(Language::for_path("src/a.mts"), Some(Language::TypeScript));
        assert_eq!(Language::for_path("src/a.tsx"), Some(Language::Tsx));
        assert_eq!(Language::for_path("a.jsx"), Some(Language::JavaScript));
        assert_eq!(Language::for_path("a.cjs"), Some(Language::JavaScript));
        assert_eq!(Language::for_path("pkg/a.pyi"), Some(Language::Python));
        assert_eq!(Language::for_path("src/main.rs"), Some(Language::Rust));
    }

    #[test]
    fn a_path_with_nothing_to_measure_says_so() {
        assert_eq!(Language::for_path("README.md"), None);
        assert_eq!(Language::for_path("Makefile"), None);
        assert_eq!(Language::for_path("a/b/noextension"), None);
        // A dot in a directory name is not an extension on the file.
        assert_eq!(Language::for_path("v1.2/LICENSE"), None);
    }

    #[test]
    fn case_is_not_folded() {
        // `ResultScope::path` is inside the digest. Folding case here would make
        // the measured set depend on the host filesystem's opinion about names,
        // which is a cross-OS divergence with no honest explanation.
        assert_eq!(Language::for_path("src/A.TS"), None);
    }

    #[test]
    fn tsx_and_typescript_share_a_claim_and_not_a_grammar() {
        assert_eq!(
            Language::Tsx.claim_language(),
            Language::TypeScript.claim_language()
        );
        let versions = grammar_versions();
        assert!(versions.contains_key("tsx") && versions.contains_key("typescript"));
    }

    #[test]
    fn rust_is_the_tokenization_tier() {
        assert!(!Language::Rust.is_parsed());
        assert!(Language::Rust.grammar().is_none());
        for language in Language::all() {
            if language != Language::Rust {
                assert!(language.grammar().is_some(), "{}", language.name());
            }
        }
    }

    #[test]
    fn the_regime_lists_every_grammar_whatever_was_measured() {
        // Shape stability: the tuple is a property of the binary, not of the
        // change. Two honest runs over different file sets must be comparable.
        let versions = grammar_versions();
        assert_eq!(versions.len(), 5, "{versions:?}");
        assert!(versions.values().all(|v| !v.is_empty()));
    }
}
