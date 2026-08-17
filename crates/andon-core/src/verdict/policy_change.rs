//! `policy-change`: what happens when the change under measurement edits
//! `.andon.toml`.
//!
//! # The rule, and the failure it was written against
//!
//! PLAN round-1 B6. The obvious design — treat any policy edit inside a pull
//! request as tampering — is a designed-in false positive that makes legitimate
//! policy evolution impossible, and a project that cannot change its own
//! thresholds changes tools instead. The rule that survived review is narrower:
//!
//! - **Every** policy edit produces an advisory `policy-change` finding carrying
//!   the threshold delta — which field, from what, to what.
//! - Only a **loosening** can block, and only when it carries **no ledgered
//!   justification**.
//!
//! Nothing is laundered by the advisory half. The verifier loads policy from the
//! BASE commit (`crate::policy`), so a threshold edited inside the PR does not
//! govern the PR that edits it; this finding is about telling a reviewer what
//! moved, not about stopping the edit from taking effect.
//!
//! # Where "ledgered justification" comes from at P5a
//!
//! It is supplied by the caller ([`Justification`]) and **unverified here**. P8
//! builds the ledger that makes it a durable record, and P9's verifier reads it
//! from the trusted side. Until then this module owns the *rule* and not the
//! *transport*, which keeps the rule testable now and leaves exactly one seam to
//! reconnect later. The type carries a `reference` for that reason: whatever
//! ends up being authoritative, the finding says where it claimed to come from.
//!
//! # The direction table, and where it deliberately disagrees with a detector
//!
//! [`direction_of`] classifies each field. `tamper.threshold-config-edit`
//! classifies the same file with generic heuristics over key names, and the two
//! disagree in one place on purpose:
//!
//! `severity.med_plus_requires_diff_actionable` appears in that detector's
//! `STRICT_WHEN_TRUE` list, so turning it off reads there as "strictness turned
//! off". Read against what the field *does*, it is the opposite: the flag
//! restricts MED+ to metrics the agent can act on, so turning it off lets **more**
//! findings block. That is a tightening — an unwise one, since it is the
//! uninstall loop of PREMORTEM A4, but not a gaming move. The generic heuristic
//! cannot know that and this table can, so for `.andon.toml` this table is
//! authoritative. The detector's firing is still reported; it simply does not
//! block on its own (`super::severity::signal_stops_the_line`).
//!
//! # Unrecognised fields advise and never block
//!
//! A field this table has never heard of is [`Direction::Unclassified`]: named
//! in the finding, never a reason to stop the line. Guessing in the blocking
//! direction is how B6's false positive comes back through a field nobody
//! thought about.

use serde_json::Value;

use crate::policy::{Policy, PolicyError};

/// Which way an edit moved the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The gate got easier to pass. The only direction that can block.
    Loosening,
    /// The gate got harder to pass.
    Tightening,
    /// Moved, but neither loosens nor tightens — a window width, a token budget.
    Neutral,
    /// A field this table does not know. Reported, never blocking.
    Unclassified,
}

/// One field that moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDelta {
    /// Dotted path, spelled as the TOML file spells it, e.g.
    /// `severity.block_on_tamper`.
    pub field: String,
    /// Value in the base commit's policy.
    pub before: String,
    /// Value in the head's policy.
    pub after: String,
    /// Which way it moved.
    pub direction: Direction,
}

impl PolicyDelta {
    /// The delta as a reviewer reads it.
    pub fn describe(&self) -> String {
        let direction = match self.direction {
            Direction::Loosening => "loosens",
            Direction::Tightening => "tightens",
            Direction::Neutral => "neither loosens nor tightens",
            Direction::Unclassified => "direction unclassified",
        };
        format!(
            "{}: {} -> {} ({direction})",
            self.field, self.before, self.after
        )
    }
}

/// A recorded reason for loosening policy.
///
/// Unverified at P5a — see the module documentation. Carried rather than reduced
/// to a boolean so that the finding can say *what* was cited, which is the part
/// a reviewer needs and a boolean throws away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Justification {
    /// Where the justification was recorded: a ledger note ref, a commit
    /// trailer, an issue. Free text at P5a because the transport is P8's.
    pub reference: String,
    /// What was said.
    pub summary: String,
}

/// Everything the verdict needs to know about a policy edit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyChange {
    /// Every field that moved, in path order.
    pub deltas: Vec<PolicyDelta>,
    /// The justification the caller supplied, if any.
    pub justification: Option<Justification>,
}

impl PolicyChange {
    /// Whether anything moved at all.
    pub fn is_empty(&self) -> bool {
        self.deltas.is_empty()
    }

    /// The deltas that loosened the gate.
    pub fn loosenings(&self) -> impl Iterator<Item = &PolicyDelta> {
        self.deltas
            .iter()
            .filter(|d| d.direction == Direction::Loosening)
    }

    /// Whether this edit stops the line.
    ///
    /// Loosening without a ledgered justification, and nothing else.
    pub fn stops_the_line(&self) -> bool {
        self.justification.is_none() && self.loosenings().next().is_some()
    }
}

/// Read a policy file that may be absent.
///
/// Absent means the conservative defaults were in force, which is what the
/// binary would have used. A pull request that *adds* `.andon.toml` is therefore
/// compared against the defaults rather than against nothing — adding a file
/// that turns tamper blocking off is a loosening, and comparing it against an
/// empty base would have made it invisible.
pub fn resolve(text: Option<&str>) -> Result<Policy, PolicyError> {
    match text {
        Some(text) => Policy::from_toml(text),
        None => Ok(Policy::default()),
    }
}

/// Compare two policies field by field.
pub fn evaluate(
    base: &Policy,
    head: &Policy,
    justification: Option<Justification>,
) -> PolicyChange {
    let (Ok(before), Ok(after)) = (serde_json::to_value(base), serde_json::to_value(head)) else {
        // `Policy` is a plain derived `Serialize` over owned data; there is no
        // input that makes this fail. Returning an empty change rather than
        // panicking keeps a measurement alive if that ever stops being true.
        return PolicyChange::default();
    };

    let mut deltas = Vec::new();
    walk("", &before, &after, &mut deltas);
    // Path order, so two runs over the same edit report it identically and a
    // reviewer reading two reports can diff them.
    deltas.sort_by(|a, b| a.field.cmp(&b.field));
    PolicyChange {
        deltas,
        justification,
    }
}

/// Walk two serialized policies, emitting one delta per leaf that differs.
///
/// Derived from the serialization rather than from a hand-written field list, so
/// a field added to [`Policy`] is reported the day it lands. An unknown field
/// classifies as [`Direction::Unclassified`] and advises; a hand-written list
/// would simply not have mentioned it.
///
/// Arrays are leaves. Recursing into them would report `excluded_paths.3`
/// changing when an entry was inserted at position zero, which describes the
/// serialization rather than the edit.
fn walk(prefix: &str, before: &Value, after: &Value, out: &mut Vec<PolicyDelta>) {
    if before == after {
        return;
    }
    if let (Value::Object(before_map), Value::Object(after_map)) = (before, after) {
        let mut keys: Vec<&String> = before_map.keys().chain(after_map.keys()).collect();
        keys.sort();
        keys.dedup();
        for key in keys {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            let null = Value::Null;
            walk(
                &path,
                before_map.get(key).unwrap_or(&null),
                after_map.get(key).unwrap_or(&null),
                out,
            );
        }
        return;
    }
    out.push(PolicyDelta {
        field: prefix.to_string(),
        before: render(before),
        after: render(after),
        direction: direction_of(prefix, before, after),
    });
}

/// A value as a reviewer should read it: bare strings, compact JSON otherwise.
fn render(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "(unset)".to_string(),
        other => other.to_string(),
    }
}

/// What kind of knob a field is.
enum Knob {
    /// Turning it off relaxes the gate.
    RelaxesWhenFalse,
    /// Turning it on relaxes the gate.
    RelaxesWhenTrue,
    /// A number where raising it relaxes a limit.
    Ceiling,
    /// Named values, **strictest first**. Moving later in the list relaxes.
    Ordered(&'static [&'static str]),
    /// A set where adding an entry relaxes.
    GrowRelaxes,
    /// A set where removing an entry relaxes.
    ShrinkRelaxes,
    /// Moves without loosening or tightening.
    Neutral,
}

/// Every field of [`Policy`], and which way it moves the gate.
///
/// Exhaustive against the policy schema as of v1; `policy_v1_is_fully_classified`
/// fails the build if a field is added without a decision being made about it.
fn knob(field: &str) -> Option<Knob> {
    Some(match field {
        // Only `1` parses, so this can never be a live edit; classified so that
        // the exhaustiveness test has an answer for it.
        "schema_version" => Knob::Neutral,

        "severity.block_on_tamper" | "severity.block_on_test_failure" => Knob::RelaxesWhenFalse,
        // Strictest first: a lower ceiling for C-tier evidence is the stricter
        // setting, so moving down the severity ladder relaxes.
        "severity.max_severity_for_c_tier" => {
            Knob::Ordered(&["critical", "high", "medium", "low", "info"])
        }
        // The deliberate divergence from `tamper.threshold-config-edit` — see the
        // module documentation. Restricting MED+ to diff-actionable metrics is
        // what *relaxes* the gate; removing the restriction lets more block.
        "severity.med_plus_requires_diff_actionable" => Knob::RelaxesWhenTrue,
        // Dropping a tier from the MED+ band means fewer findings can block.
        "severity.med_plus_tiers" => Knob::ShrinkRelaxes,

        // More passes before `escalate_to_human` is more room to grind.
        "loop.iteration_cap" => Knob::Ceiling,
        // Counting context-informational findings escalates sooner, not later.
        "loop.count_context_informational" => Knob::RelaxesWhenFalse,

        // A view budget for the agent-mode profile. Neither gate nor threshold.
        "agent.profile_token_budget" | "agent.bytes_per_token" => Knob::Neutral,

        "perf.fast_lane_warm_p95_ms"
        | "perf.fast_lane_warm_fallback_p95_ms"
        | "perf.fast_lane_cold_cap_ms"
        | "perf.max_git_spawns_per_measure" => Knob::Ceiling,

        // Changing the window makes old and new numbers incomparable rather than
        // more or less permissive; the regime stamp is what carries it.
        "history.window_days" => Knob::Neutral,

        "registry.claim_budget" | "registry.max_claims_expiring_per_month" => Knob::Ceiling,

        // Strictest first: the rule, then the bootstrap exception.
        "self_measure.binary" => Knob::Ordered(&["last-attested-release", "current-build"]),
        // More paths excluded from self-measurement is less of Andon measured.
        "self_measure.excluded_paths" => Knob::GrowRelaxes,
        "self_measure.exclusion_drift_signal" => Knob::RelaxesWhenFalse,

        _ => return None,
    })
}

/// Which way one field moved.
pub fn direction_of(field: &str, before: &Value, after: &Value) -> Direction {
    let Some(knob) = knob(field) else {
        return Direction::Unclassified;
    };
    match knob {
        Knob::Neutral => Direction::Neutral,
        Knob::RelaxesWhenFalse => match (before.as_bool(), after.as_bool()) {
            (Some(true), Some(false)) => Direction::Loosening,
            (Some(false), Some(true)) => Direction::Tightening,
            _ => Direction::Unclassified,
        },
        Knob::RelaxesWhenTrue => match (before.as_bool(), after.as_bool()) {
            (Some(false), Some(true)) => Direction::Loosening,
            (Some(true), Some(false)) => Direction::Tightening,
            _ => Direction::Unclassified,
        },
        Knob::Ceiling => match (before.as_f64(), after.as_f64()) {
            (Some(b), Some(a)) if a > b => Direction::Loosening,
            (Some(b), Some(a)) if a < b => Direction::Tightening,
            _ => Direction::Unclassified,
        },
        Knob::Ordered(ladder) => {
            let rank = |value: &Value| {
                value
                    .as_str()
                    .and_then(|s| ladder.iter().position(|step| *step == s))
            };
            match (rank(before), rank(after)) {
                (Some(b), Some(a)) if a > b => Direction::Loosening,
                (Some(b), Some(a)) if a < b => Direction::Tightening,
                _ => Direction::Unclassified,
            }
        }
        Knob::GrowRelaxes => set_direction(before, after, true),
        Knob::ShrinkRelaxes => set_direction(before, after, false),
    }
}

/// Direction for a set-valued field.
///
/// An edit that both adds and removes counts as a loosening if it moved
/// *anything* in the relaxing direction. Netting the two out would let a
/// widened exclusion list hide behind a tidy-up in the same commit.
fn set_direction(before: &Value, after: &Value, growing_relaxes: bool) -> Direction {
    let (Some(before), Some(after)) = (before.as_array(), after.as_array()) else {
        return Direction::Unclassified;
    };
    let added = after.iter().any(|v| !before.contains(v));
    let removed = before.iter().any(|v| !after.contains(v));
    let relaxed = if growing_relaxes { added } else { removed };
    let tightened = if growing_relaxes { removed } else { added };
    match (relaxed, tightened) {
        (true, _) => Direction::Loosening,
        (false, true) => Direction::Tightening,
        // Same members, different order. TOML arrays are ordered and these are
        // read as sets, so this is a formatting edit.
        (false, false) => Direction::Neutral,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::enums::{EvidenceTier, Severity};

    fn justified() -> Justification {
        Justification {
            reference: "refs/notes/andon-measure@abcdef".to_string(),
            summary: "perf budget raised for the 100k-file fixture; measured".to_string(),
        }
    }

    fn direction_for(field: &str, change: impl FnOnce(&mut Policy)) -> Direction {
        let base = Policy::default();
        let mut head = base.clone();
        change(&mut head);
        let out = evaluate(&base, &head, None);
        out.deltas
            .iter()
            .find(|d| d.field == field)
            .unwrap_or_else(|| panic!("{field} did not appear in {:?}", out.deltas))
            .direction
    }

    #[test]
    fn an_unedited_policy_produces_no_finding() {
        let change = evaluate(&Policy::default(), &Policy::default(), None);
        assert!(change.is_empty());
        assert!(!change.stops_the_line());
    }

    #[test]
    fn turning_tamper_blocking_off_is_a_loosening_and_blocks_unjustified() {
        let base = Policy::default();
        let mut head = base.clone();
        head.severity.block_on_tamper = false;
        let change = evaluate(&base, &head, None);
        assert_eq!(change.deltas.len(), 1);
        assert_eq!(change.deltas[0].field, "severity.block_on_tamper");
        assert_eq!(change.deltas[0].before, "true");
        assert_eq!(change.deltas[0].after, "false");
        assert_eq!(change.deltas[0].direction, Direction::Loosening);
        assert!(change.stops_the_line());
    }

    #[test]
    fn the_same_loosening_with_a_justification_does_not_block() {
        // B6's whole point: policy evolution stays possible, it just has to be
        // recorded.
        let base = Policy::default();
        let mut head = base.clone();
        head.severity.block_on_tamper = false;
        let change = evaluate(&base, &head, Some(justified()));
        assert!(!change.stops_the_line());
        assert_eq!(
            change.loosenings().count(),
            1,
            "still reported, not blocking"
        );
    }

    #[test]
    fn a_tightening_never_blocks_even_unjustified() {
        let base = Policy::default();
        let mut head = base.clone();
        head.loop_policy.iteration_cap = 1;
        let change = evaluate(&base, &head, None);
        assert_eq!(change.deltas[0].direction, Direction::Tightening);
        assert!(!change.stops_the_line());
    }

    #[test]
    fn raising_the_iteration_cap_loosens() {
        assert_eq!(
            direction_for("loop.iteration_cap", |p| p.loop_policy.iteration_cap = 20),
            Direction::Loosening
        );
    }

    #[test]
    fn lowering_the_c_tier_ceiling_loosens_and_raising_it_tightens() {
        assert_eq!(
            direction_for("severity.max_severity_for_c_tier", |p| p
                .severity
                .max_severity_for_c_tier =
                Severity::Info),
            Direction::Loosening
        );
        assert_eq!(
            direction_for("severity.max_severity_for_c_tier", |p| p
                .severity
                .max_severity_for_c_tier =
                Severity::High),
            Direction::Tightening
        );
    }

    #[test]
    fn dropping_a_tier_from_the_med_plus_band_loosens() {
        assert_eq!(
            direction_for("severity.med_plus_tiers", |p| p.severity.med_plus_tiers =
                vec![EvidenceTier::A]),
            Direction::Loosening
        );
        assert_eq!(
            direction_for("severity.med_plus_tiers", |p| p.severity.med_plus_tiers =
                vec![EvidenceTier::A, EvidenceTier::B, EvidenceTier::C]),
            Direction::Tightening
        );
    }

    #[test]
    fn widening_the_self_measure_exclusions_loosens() {
        assert_eq!(
            direction_for("self_measure.excluded_paths", |p| p
                .self_measure
                .excluded_paths
                .push("crates/**".to_string())),
            Direction::Loosening
        );
    }

    #[test]
    fn an_exclusion_added_alongside_one_removed_still_loosens() {
        // Netting out would let a widened exclusion hide behind a tidy-up.
        assert_eq!(
            direction_for("self_measure.excluded_paths", |p| {
                p.self_measure.excluded_paths = vec!["crates/**".to_string()];
            }),
            Direction::Loosening
        );
    }

    #[test]
    fn reordering_a_list_is_neither_direction() {
        assert_eq!(
            direction_for("self_measure.excluded_paths", |p| p
                .self_measure
                .excluded_paths
                .reverse()),
            Direction::Neutral
        );
    }

    #[test]
    fn taking_the_bootstrap_exception_is_a_loosening() {
        use crate::policy::SelfMeasureBinary;
        assert_eq!(
            direction_for("self_measure.binary", |p| p.self_measure.binary =
                SelfMeasureBinary::CurrentBuild),
            Direction::Loosening
        );
    }

    #[test]
    fn removing_the_diff_actionable_requirement_tightens_not_loosens() {
        // The documented divergence from `tamper.threshold-config-edit`'s generic
        // `STRICT_WHEN_TRUE` heuristic. Turning this off lets MORE findings
        // block, which is unwise (PREMORTEM A4) and is not a gaming move.
        assert_eq!(
            direction_for("severity.med_plus_requires_diff_actionable", |p| p
                .severity
                .med_plus_requires_diff_actionable =
                false),
            Direction::Tightening
        );
    }

    #[test]
    fn counting_context_informational_findings_tightens() {
        assert_eq!(
            direction_for("loop.count_context_informational", |p| p
                .loop_policy
                .count_context_informational =
                true),
            Direction::Tightening
        );
    }

    #[test]
    fn the_history_window_moves_without_loosening_or_tightening() {
        assert_eq!(
            direction_for("history.window_days", |p| p.history.window_days = 30),
            Direction::Neutral
        );
    }

    #[test]
    fn adding_a_policy_file_is_compared_against_the_defaults() {
        // A pull request that introduces `.andon.toml` with tamper blocking off
        // must not be invisible because the base commit had no file.
        let base = resolve(None).expect("absent policy resolves to the defaults");
        let head = resolve(Some(
            "schema_version = 1\n[severity]\nblock_on_tamper = false\n",
        ))
        .expect("parses");
        let change = evaluate(&base, &head, None);
        assert!(change.stops_the_line());
        assert_eq!(change.deltas[0].field, "severity.block_on_tamper");
    }

    #[test]
    fn several_edits_are_reported_in_path_order() {
        let base = Policy::default();
        let mut head = base.clone();
        head.severity.block_on_tamper = false;
        head.loop_policy.iteration_cap = 9;
        head.history.window_days = 90;
        let change = evaluate(&base, &head, None);
        let fields: Vec<&str> = change.deltas.iter().map(|d| d.field.as_str()).collect();
        assert_eq!(
            fields,
            vec![
                "history.window_days",
                "loop.iteration_cap",
                "severity.block_on_tamper"
            ]
        );
    }

    #[test]
    fn an_unknown_field_is_reported_and_never_blocks() {
        // Simulated directly: `Policy` rejects unknown keys, so the case can only
        // arise from a field added to the struct without a table entry — which
        // `policy_v1_is_fully_classified` catches. This pins the fallback.
        assert_eq!(
            direction_of(
                "severity.some_future_knob",
                &Value::Bool(true),
                &Value::Bool(false)
            ),
            Direction::Unclassified
        );
        let change = PolicyChange {
            deltas: vec![PolicyDelta {
                field: "severity.some_future_knob".to_string(),
                before: "true".to_string(),
                after: "false".to_string(),
                direction: Direction::Unclassified,
            }],
            justification: None,
        };
        assert!(
            !change.stops_the_line(),
            "guessing in the blocking direction is how B6's false positive returns"
        );
    }

    #[test]
    fn policy_v1_is_fully_classified() {
        // Every leaf of the policy schema has a decision recorded about it. A
        // field added without one fails here rather than silently defaulting to
        // `Unclassified`, which would mean a new gate nobody could block on.
        let value = serde_json::to_value(Policy::default()).expect("policy serializes");
        let mut leaves = Vec::new();
        collect_leaves("", &value, &mut leaves);
        let unclassified: Vec<&String> = leaves.iter().filter(|f| knob(f).is_none()).collect();
        assert!(
            unclassified.is_empty(),
            "policy fields with no direction recorded: {unclassified:?}"
        );
    }

    fn collect_leaves(prefix: &str, value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    collect_leaves(&path, child, out);
                }
            }
            _ => out.push(prefix.to_string()),
        }
    }
}
