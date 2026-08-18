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

/// Codex's `.eslintrc.json` probe, from the real detector to the real verdict.
///
/// The finding this reproduces: the `ThresholdConfigEdit` exemption was keyed on
/// the signal's enum variant, and the justification route behind it parsed
/// `.andon.toml` and nothing else. So an ESLint rule moved from `error` to
/// `warn` fired the real detector, took the exemption, and could only ever
/// advise. The reported artifact was `left: Advise, right: Block`.
///
/// Deliberately not a hand-built flag. A fixture that asserts a severity nobody
/// measured is what let a whole band of this system go dead unnoticed, and the
/// probe this test answers to was end-to-end.
mod eslint_probe {
    use andon_core::policy::Policy;
    use andon_core::schema::enums::{Completeness, Verdict};
    use andon_core::schema::payload::{IterationState, MeasurementResult};
    use andon_core::verdict::policy_change::{Justification, PolicyChange};
    use andon_core::verdict::{evaluate, reason, VerdictContext};
    use andon_engine_tamper::change::{ChangeView, FileChange};
    use andon_engine_tamper::TamperEngine;

    const BASE: &str = r#"{ "rules": { "no-explicit-any": "error", "eqeqeq": "error" } }"#;
    const HEAD: &str = r#"{ "rules": { "no-explicit-any": "warn", "eqeqeq": "error" } }"#;

    /// The real tamper engine over the real edit, unsealed results included.
    fn measure() -> Vec<MeasurementResult> {
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", BASE, HEAD)]);
        let engine = TamperEngine::for_view(view);
        let ctx = andon_core::engine::MeasureContext {
            compare_context: andon_core::testing::sample_compare_context(),
            policy: Policy::default(),
            changed_paths: vec![".eslintrc.json".to_string()],
            sandbox_available: false,
        };
        andon_core::engine::run_engine(&engine, &ctx).expect("the suite measures")
    }

    fn context<'a>(policy: &'a Policy, change: Option<&'a PolicyChange>) -> VerdictContext<'a> {
        VerdictContext {
            policy,
            policy_change: change,
            engine_failures: &[],
            stale_claim_ids: &[],
            iteration_state_recovered: false,
            completeness: Completeness::Complete,
            registry_skew: &[],
        }
    }

    fn iteration() -> IterationState {
        IterationState {
            count: 1,
            cap: 3,
            escalated: false,
        }
    }

    #[test]
    fn an_eslint_rule_lowered_to_warn_stops_the_line() {
        let results = measure();
        let fired = results
            .iter()
            .find(|r| r.metric_id == "tamper.threshold-config-edit")
            .expect("the detector emits its flag either way");
        assert_eq!(
            fired.value,
            andon_core::schema::payload::MetricValue::Flag(true),
            "the real detector fires on error -> warn"
        );

        let policy = Policy::default();
        let summary = evaluate(&results, &context(&policy, None), iteration());
        assert_eq!(
            summary.verdict,
            Verdict::Block,
            "a loosening in a file the policy parser cannot read is still a loosening"
        );
        assert!(summary
            .reasons
            .iter()
            .any(|r| r.code == reason::TAMPER_SIGNAL
                && r.metric_ids == vec!["tamper.threshold-config-edit"]));
    }

    #[test]
    fn and_advises_once_the_ledger_accounts_for_it() {
        // B6's other half, which the enum-wide exemption was standing in for:
        // policy evolution a project can account for must stay possible, in
        // ESLint as much as in `.andon.toml`.
        let results = measure();
        let policy = Policy::default();
        let change = PolicyChange {
            deltas: Vec::new(),
            justification: Some(Justification::Verified {
                reference: "andon-ledger#12".to_string(),
                summary: "no-explicit-any relaxed for the codemod, restored in #13".to_string(),
            }),
        };
        let summary = evaluate(&results, &context(&policy, Some(&change)), iteration());
        assert_eq!(summary.verdict, Verdict::Advise);
        let advisory = summary
            .reasons
            .iter()
            .find(|r| r.code == reason::TAMPER_SIGNAL_ADVISORY)
            .expect("reported, and not blocking");
        assert!(
            advisory.message.contains("andon-ledger#12"),
            "the reason names what excused it: {}",
            advisory.message
        );
    }

    #[test]
    fn an_unverified_claim_does_not_buy_the_same_exit() {
        let results = measure();
        let policy = Policy::default();
        let change = PolicyChange {
            deltas: Vec::new(),
            justification: Some(Justification::Unverified {
                reference: "trust me".to_string(),
                summary: "not checked against any ledger".to_string(),
            }),
        };
        assert_eq!(
            evaluate(&results, &context(&policy, Some(&change)), iteration()).verdict,
            Verdict::Block
        );
    }

    #[test]
    fn tightening_the_same_rule_says_nothing_at_all() {
        // The control. A test that only proved `Block` would pass on a detector
        // that had started firing on everything.
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", HEAD, BASE)]);
        let engine = TamperEngine::for_view(view);
        let ctx = andon_core::engine::MeasureContext {
            compare_context: andon_core::testing::sample_compare_context(),
            policy: Policy::default(),
            changed_paths: vec![".eslintrc.json".to_string()],
            sandbox_available: false,
        };
        let results = andon_core::engine::run_engine(&engine, &ctx).expect("measures");
        let policy = Policy::default();
        assert_eq!(
            evaluate(&results, &context(&policy, None), iteration()).verdict,
            Verdict::Pass
        );
    }
}
