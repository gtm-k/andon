//! The grammar pins, checked against the manifest that resolves them.
//!
//! PLAN P2 asks for "vendored pinned grammars". These are `=`-pinned registry
//! dependencies rather than generated C committed into the tree — the reasoning
//! is in `Cargo.toml` — and this test is what makes the substitution honest.
//!
//! Two things have to stay true for a grammar to be unable to drift under a
//! measurement:
//!
//! 1. **The manifest pins an exact version.** A caret or a wildcard means "what
//!    the registry serves today", and cargo would move it on any `cargo update`.
//! 2. **The constants in `lang.rs` say the same version.** Those constants are
//!    what reaches `measurement_regime` and therefore every per-result digest.
//!    If they disagree with the manifest, the regime describes a build that
//!    is not the one running — and a real version difference would be invisible
//!    while a fictional one was stamped on every number.
//!
//! Reading the manifest rather than trusting a comment is the point: this test
//! fails on `cargo update` moving a grammar, on someone loosening `=` to `^`,
//! and on a constant edited without its dependency.

use std::collections::BTreeMap;

use andon_static_metrics::lang;

/// `<crate name> -> <exact version>` for every dependency pinned with `=`.
fn exact_pins() -> BTreeMap<String, String> {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("this crate has a manifest");
    let value: toml::Value = manifest.parse().expect("the manifest is TOML");
    let dependencies = value
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .expect("the manifest has dependencies");

    dependencies
        .iter()
        .filter_map(|(name, spec)| {
            let requirement = match spec {
                toml::Value::String(text) => text.as_str(),
                table => table.get("version")?.as_str()?,
            };
            requirement
                .strip_prefix('=')
                .map(|version| (name.clone(), version.to_string()))
        })
        .collect()
}

#[test]
fn every_grammar_dependency_is_pinned_to_an_exact_version() {
    let pins = exact_pins();
    for crate_name in [
        "tree-sitter",
        "tree-sitter-typescript",
        "tree-sitter-javascript",
        "tree-sitter-python",
    ] {
        assert!(
            pins.contains_key(crate_name),
            "{crate_name} is not pinned with `=`. A range requirement means the \
             grammar can move on any `cargo update`, and PLAN P2's pinning \
             requirement would be satisfied only in the comments."
        );
    }
}

#[test]
fn the_regime_constants_equal_the_pinned_versions() {
    let pins = exact_pins();
    let expected: BTreeMap<String, String> = [
        ("tree-sitter", lang::TREE_SITTER_VERSION),
        ("tree-sitter-typescript", lang::TYPESCRIPT_GRAMMAR_VERSION),
        ("tree-sitter-javascript", lang::JAVASCRIPT_GRAMMAR_VERSION),
        ("tree-sitter-python", lang::PYTHON_GRAMMAR_VERSION),
    ]
    .into_iter()
    .map(|(name, version)| (name.to_string(), version.to_string()))
    .collect();

    for (crate_name, constant) in &expected {
        assert_eq!(
            pins.get(crate_name),
            Some(constant),
            "{crate_name}: the manifest and `lang.rs` disagree. The constant is \
             what reaches `measurement_regime` and every per-result digest, so a \
             disagreement means the regime describes a build nobody is running."
        );
    }
}

#[test]
fn the_regime_map_uses_the_same_versions_the_constants_hold() {
    // The last link in the chain: manifest -> constants -> the map that is
    // actually serialized into a record.
    let versions = lang::grammar_versions();
    assert_eq!(
        versions.get("tree-sitter").map(String::as_str),
        Some(lang::TREE_SITTER_VERSION)
    );
    assert_eq!(
        versions.get("typescript").map(String::as_str),
        Some(lang::TYPESCRIPT_GRAMMAR_VERSION)
    );
    assert_eq!(
        versions.get("tsx").map(String::as_str),
        Some(lang::TYPESCRIPT_GRAMMAR_VERSION),
        "TSX comes from the same crate as TypeScript"
    );
    assert_eq!(
        versions.get("javascript").map(String::as_str),
        Some(lang::JAVASCRIPT_GRAMMAR_VERSION)
    );
    assert_eq!(
        versions.get("python").map(String::as_str),
        Some(lang::PYTHON_GRAMMAR_VERSION)
    );
}

#[test]
fn no_grammar_feature_pulls_a_runtime_that_has_not_been_through_the_licence_gate() {
    // `tree-sitter`'s `wasm` feature pulls wasmtime-c-api and a dependency tree
    // `cargo deny check licenses` has never seen. `default-features = false`
    // with `std` named explicitly means enabling it would be an edit to the
    // manifest rather than a side effect of one.
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("this crate has a manifest");
    let value: toml::Value = manifest.parse().expect("the manifest is TOML");
    let tree_sitter = value
        .get("dependencies")
        .and_then(|d| d.get("tree-sitter"))
        .expect("tree-sitter is a dependency");
    assert_eq!(
        tree_sitter
            .get("default-features")
            .and_then(toml::Value::as_bool),
        Some(false)
    );
    let features: Vec<&str> = tree_sitter
        .get("features")
        .and_then(toml::Value::as_array)
        .expect("features are named explicitly")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    assert_eq!(features, vec!["std"], "only `std` may be enabled");
}
