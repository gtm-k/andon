//! The committed JSON Schema artifacts match the Rust types they came from.
//!
//! `schemas/*.json` is the published contract — VISION §3.4 makes the versioned
//! payload schema the stability guarantee for all four downstream consumers. A
//! generated artifact that is allowed to drift from its source is worse than no
//! artifact: integrators build against a document that describes a payload the
//! tool no longer emits.
//!
//! Regenerate after an intentional schema change:
//!
//! ```text
//! ANDON_UPDATE_SCHEMAS=1 cargo test -p andon-core --test schema_drift
//! ```

use std::path::{Path, PathBuf};

use andon_core::canonical::to_canonical_string;
use andon_core::schema::{
    agent_profile_schema, measurement_record_schema, policy_schema, registry_schema,
};
use schemars::schema::RootSchema;

fn schemas_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("schemas")
}

/// Render a schema deterministically.
///
/// Canonicalizing first sorts every key; re-parsing preserves that order
/// (`serde_json` runs with `preserve_order`) and pretty-printing keeps it. The
/// artifact is therefore both stable across runs and readable in a diff, rather
/// than one 40KB line that no reviewer can inspect.
fn render(schema: &RootSchema) -> String {
    let canonical = to_canonical_string(schema).expect("schema is serializable");
    let value: serde_json::Value =
        serde_json::from_str(&canonical).expect("canonical output is valid JSON");
    let mut text = serde_json::to_string_pretty(&value).expect("pretty-printable");
    text.push('\n');
    text
}

fn check(file_name: &str, schema: RootSchema) {
    let path = schemas_dir().join(file_name);
    let generated = render(&schema);

    if std::env::var_os("ANDON_UPDATE_SCHEMAS").is_some() {
        std::fs::create_dir_all(schemas_dir()).expect("schemas directory is writable");
        std::fs::write(&path, &generated).expect("schema is writable");
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}\nRegenerate with: \
             ANDON_UPDATE_SCHEMAS=1 cargo test -p andon-core --test schema_drift",
            path.display()
        )
    });

    // Compare on normalized line endings: the artifact is committed with
    // `core.autocrlf` in play on Windows checkouts, and a line-ending difference
    // is not a schema change.
    assert_eq!(
        committed.replace("\r\n", "\n"),
        generated,
        "{} is out of date with the Rust types.\nRegenerate with: \
         ANDON_UPDATE_SCHEMAS=1 cargo test -p andon-core --test schema_drift",
        path.display()
    );
}

#[test]
fn measurement_record_schema_is_committed_and_current() {
    check("payload-v1.schema.json", measurement_record_schema());
}

#[test]
fn agent_profile_schema_is_committed_and_current() {
    check("agent-profile-v1.schema.json", agent_profile_schema());
}

#[test]
fn policy_schema_is_committed_and_current() {
    check("policy-v1.schema.json", policy_schema());
}

#[test]
fn registry_schema_is_committed_and_current() {
    check("registry-v1.schema.json", registry_schema());
}

/// Rendering is deterministic, which is what lets the drift test above mean
/// anything.
#[test]
fn rendering_is_stable_across_runs() {
    assert_eq!(
        render(&measurement_record_schema()),
        render(&measurement_record_schema())
    );
}

/// Exactly one float carrier is declared, and it is `MetricValue::Ratio`.
///
/// `canonical.rs` cannot enforce its own "non-finite floats are rejected" rule:
/// `serde_json::to_value` turns NaN into `null` before the canonicalizer sees a
/// number, so a digest would be taken over a hole. The rejection lives on
/// `MetricValue::Ratio`'s serializer instead, which is sound only for as long as
/// `Ratio` really is the only float in the schema. A future `f64` field with
/// serde's default impl would reopen the hole silently — and be invisible in
/// review, because nothing about adding a float looks dangerous.
///
/// This counts them in the *committed* artifacts, so the guard fails on the
/// schema regeneration that introduces a second one.
#[test]
fn the_schemas_declare_exactly_one_float_carrier() {
    for file_name in [
        "payload-v1.schema.json",
        "agent-profile-v1.schema.json",
        "policy-v1.schema.json",
        "registry-v1.schema.json",
    ] {
        let path = schemas_dir().join(file_name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let schema: serde_json::Value =
            serde_json::from_str(&text).expect("committed schema is valid JSON");

        let floats = float_carriers(&schema, String::new());
        let expected: &[&str] = match file_name {
            "payload-v1.schema.json" | "agent-profile-v1.schema.json" => {
                &["definitions.MetricValue.oneOf[2].properties.value"]
            }
            _ => &[],
        };
        assert_eq!(
            floats, expected,
            "{file_name} declares an unexpected float. Every float needs a \
             serializer that rejects non-finite and non-quantizable values, the \
             way MetricValue::Ratio does — see canonical.rs, \"Where rule 5 is \
             actually enforced\"."
        );
    }
}

/// Every `"type": "number"` in a schema, by JSON path.
fn float_carriers(value: &serde_json::Value, path: String) -> Vec<String> {
    let mut found = Vec::new();
    match value {
        serde_json::Value::Object(map) => {
            if map.get("type") == Some(&serde_json::Value::String("number".to_string())) {
                found.push(path.clone());
            }
            for (key, child) in map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                found.extend(float_carriers(child, child_path));
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                found.extend(float_carriers(item, format!("{path}[{i}]")));
            }
        }
        _ => {}
    }
    found
}

/// The doc comments on the schema types reach the published artifact.
///
/// This is why `andon-core` denies `missing_docs`: schemars turns doc comments
/// into `description` fields, so documenting a field is documenting the contract
/// a stranger integrates against.
#[test]
fn the_published_schema_carries_field_descriptions() {
    let rendered = render(&measurement_record_schema());
    assert!(
        rendered.contains("\"description\""),
        "the generated schema has no descriptions; doc comments are not reaching it"
    );
    assert!(
        rendered.contains("never the synthetic merge ref"),
        "head_oid's documentation should reach the published schema"
    );
}
