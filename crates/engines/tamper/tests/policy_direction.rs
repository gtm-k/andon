//! The detector and the policy direction table, held to one answer.
//!
//! # Two readings of the same edit, and only one of them is right
//!
//! `tamper.threshold-config-edit` classifies a configuration edit with generic
//! heuristics over key names, because it has to work on ESLint, mypy, tsconfig,
//! coverage configuration and a dozen more file formats it cannot possibly know
//! the semantics of. `andon_core::verdict::policy_change::direction_of`
//! classifies `.andon.toml` from a table written against what each field
//! actually does.
//!
//! For every file except `.andon.toml`, the heuristic is all there is. For
//! `.andon.toml` the table is authoritative — and the two used to disagree.
//! `severity.med_plus_requires_diff_actionable` looks like a strictness flag and
//! is the opposite of one: it *restricts* the MED+ band to metrics the agent can
//! act on, so turning it off lets more findings block. Turning it off is an
//! unwise tightening, not a gaming move, and the detector put a tamper signal in
//! the payload for it.
//!
//! Codex found it by probe: `direction_of` answered `Tightening` and the real
//! engine emitted `ThresholdConfigEdit` anyway. The detector was corrected. This
//! walks every field of `Policy` in both directions so that the next
//! disagreement fails here rather than in a payload.

use andon_core::policy::Policy;
use andon_core::verdict::policy_change::{self, Direction};
use andon_engine_tamper::change::{ChangeView, FileChange};
use andon_engine_tamper::detectors::{self, Detector};

/// The `.andon.toml` a policy serializes to.
fn as_toml(policy: &Policy) -> String {
    toml::to_string(policy).expect("policy serializes to TOML")
}

/// Every leaf field of `Policy`, as its dotted path.
fn leaf_paths(prefix: &str, value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                leaf_paths(&path, child, out);
            }
        }
        // Arrays are leaves to the direction table too — see `policy_change`.
        _ => out.push(prefix.to_string()),
    }
}

/// Set one leaf of a serialized policy, by dotted path.
fn set_leaf(value: &mut serde_json::Value, path: &str, new: serde_json::Value) {
    let mut cursor = value;
    let mut parts = path.split('.').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            cursor[part] = new;
            return;
        }
        cursor = cursor.get_mut(part).expect("the path exists");
    }
}

/// What the detector says about a `.andon.toml` edit: did it fire?
fn detector_fires(base: &str, head: &str) -> bool {
    let view = ChangeView::new(vec![FileChange::modified(".andon.toml", base, head)]);
    detectors::threshold_config_edit::ThresholdConfigEdit
        .run(&view)
        .fired
}

#[test]
fn the_detector_and_the_direction_table_agree_about_every_policy_field() {
    let base = Policy::default();
    let base_json = serde_json::to_value(&base).expect("policy serializes");
    let base_toml = as_toml(&base);

    let mut paths = Vec::new();
    leaf_paths("", &base_json, &mut paths);
    assert!(
        paths.len() > 10,
        "the walk must actually reach the fields: {paths:?}"
    );

    let mut checked = 0usize;
    for path in &paths {
        // Booleans only. A number needs a direction-specific nudge and a string
        // needs a vocabulary, and both are covered by `policy_change`'s own
        // tests; what this test exists for is the boolean case, which is where
        // the two classifiers disagreed.
        let Some(before) = base_json.pointer(&format!("/{}", path.replace('.', "/"))) else {
            continue;
        };
        let Some(flag) = before.as_bool() else {
            continue;
        };

        let mut head_json = base_json.clone();
        set_leaf(&mut head_json, path, serde_json::Value::Bool(!flag));
        let head: Policy = serde_json::from_value(head_json).expect("still a policy");
        let head_toml = as_toml(&head);

        let table = policy_change::direction_of(
            path,
            &serde_json::Value::Bool(flag),
            &serde_json::Value::Bool(!flag),
        );
        let fired = detector_fires(&base_toml, &head_toml);

        assert_eq!(
            fired,
            table == Direction::Loosening,
            "{path}: {flag} -> {} — the direction table says {table:?} and the detector {}",
            !flag,
            if fired { "fired" } else { "stayed quiet" }
        );
        checked += 1;
    }
    assert!(
        checked >= 4,
        "the shipped policy carries at least four booleans; checked {checked}"
    );
}

#[test]
fn turning_off_the_diff_actionable_requirement_is_a_tightening_to_both_of_them() {
    // The specific disagreement, named, so the general walk above cannot be
    // weakened without this failing too.
    let base = Policy::default();
    let mut head = base.clone();
    assert!(base.severity.med_plus_requires_diff_actionable);
    head.severity.med_plus_requires_diff_actionable = false;

    assert_eq!(
        policy_change::direction_of(
            "severity.med_plus_requires_diff_actionable",
            &serde_json::Value::Bool(true),
            &serde_json::Value::Bool(false),
        ),
        Direction::Tightening,
        "the flag restricts the MED+ band, so removing it lets more findings block"
    );
    assert!(
        !detector_fires(&as_toml(&base), &as_toml(&head)),
        "an honest tightening must not put a tamper signal in the payload"
    );
}

#[test]
fn turning_off_tamper_blocking_is_a_loosening_to_both_of_them() {
    // The control. A test that only proved the detector had gone quiet would
    // pass on a detector that had stopped working.
    let base = Policy::default();
    let mut head = base.clone();
    head.severity.block_on_tamper = false;

    assert_eq!(
        policy_change::direction_of(
            "severity.block_on_tamper",
            &serde_json::Value::Bool(true),
            &serde_json::Value::Bool(false),
        ),
        Direction::Loosening
    );
    assert!(detector_fires(&as_toml(&base), &as_toml(&head)));
}
