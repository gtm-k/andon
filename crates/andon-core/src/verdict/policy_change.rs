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
//! # Where "ledgered justification" comes from, and what an unverified one buys
//!
//! P8 builds the ledger that makes a justification a durable record and P9's
//! verifier reads it from the trusted side. Neither exists yet, and the first
//! version of this module handled that by accepting whatever the caller passed
//! and letting it suppress blocking — so the string `trust me` turned a
//! `block` into an `advise`, and the string never reached the emitted reason
//! either. Deferring the transport is not a reason to make unverified text
//! verdict-authoritative in the meantime; it is a reason to say which kind of
//! justification this is.
//!
//! So [`Justification`] has two forms. An **unverified** one is reported and
//! changes nothing: the reader sees what was claimed and sees that nobody
//! checked it. A **verified** one is the ledger's answer, and only it suppresses
//! blocking.
//!
//! Minting a verified justification is not a matter of discipline. A self-report
//! is written by the binary under measurement, and a binary that could mark its
//! own excuse as checked is a binary that could pass itself — the same argument
//! that keeps [`crate::payload`] from setting its own attestation value. So
//! `crate::payload::prepare` refuses a verified justification on a
//! `RecordKind::SelfReport` outright. The agent-side path cannot reach it; the
//! verifier, which writes attestation records, can. That is the seam P8 and P9
//! reconnect to, and until they do nothing in this workspace produces one
//! outside a test.
//!
//! # The direction table, and where it deliberately disagrees with a detector
//!
//! [`direction_of`] classifies each field. `tamper.threshold-config-edit`
//! classifies the same file with generic heuristics over key names, and the two
//! disagree in one place on purpose:
//!
//! `severity.med_plus_requires_diff_actionable` reads to a generic key-name
//! heuristic as a strictness flag, so turning it off reads as "strictness turned
//! off". Read against what the field *does*, it is the opposite: the flag
//! restricts MED+ to metrics the agent can act on, so turning it off lets **more**
//! findings block. That is a tightening — an unwise one, since it is the
//! uninstall loop of PREMORTEM A4, but not a gaming move.
//!
//! This was a live disagreement rather than a hypothetical one: the field was in
//! the detector's `STRICT_WHEN_TRUE` list, so an honest tightening put a tamper
//! signal in the payload. The detector was corrected, and
//! `tamper::detectors::threshold_config_edit`'s
//! `the_detector_and_the_direction_table_agree_about_every_policy_field` now
//! walks every `Policy` field in both directions and fails if the two ever
//! disagree again. For `.andon.toml` this table is authoritative; the test is
//! what keeps the other one from needing to be.
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

/// A recorded reason for loosening a quality gate.
///
/// Two forms, and the difference is the whole of it: one has been checked
/// against the ledger and one is a caller's assertion. See the module
/// documentation.
///
/// Carried rather than reduced to a boolean so that the finding can say *what*
/// was cited and *whether anyone checked it* — both of which a boolean throws
/// away, and the second of which is the part that decides the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Justification {
    /// Supplied by the caller and checked against nothing.
    ///
    /// Reported, never authoritative. A loosening carrying only this still stops
    /// the line, and the reason says so in as many words.
    Unverified {
        /// Where the caller says the justification was recorded.
        reference: String,
        /// What the caller says it says.
        summary: String,
    },
    /// Read from the ledger by a party in a position to check it.
    ///
    /// The only form that suppresses blocking. `crate::payload::prepare` refuses
    /// one on a self-report, so the binary under measurement cannot mint its own.
    Verified {
        /// The ledger reference that was resolved.
        reference: String,
        /// What it says.
        summary: String,
    },
}

impl Justification {
    /// Where the justification claims to come from.
    pub fn reference(&self) -> &str {
        match self {
            Justification::Unverified { reference, .. }
            | Justification::Verified { reference, .. } => reference,
        }
    }

    /// What it says.
    pub fn summary(&self) -> &str {
        match self {
            Justification::Unverified { summary, .. } | Justification::Verified { summary, .. } => {
                summary
            }
        }
    }

    /// Whether anyone checked it.
    pub fn is_verified(&self) -> bool {
        matches!(self, Justification::Verified { .. })
    }

    /// The justification as a reader should see it, verification status
    /// included.
    ///
    /// The status is in the sentence rather than beside it, because a reference
    /// with no word about whether it was checked reads as though it was.
    pub fn describe(&self) -> String {
        if self.is_verified() {
            format!(
                "justified by {} (verified against the ledger): {}",
                self.reference(),
                self.summary()
            )
        } else {
            format!(
                "cites {} (UNVERIFIED — nothing has checked this): {}",
                self.reference(),
                self.summary()
            )
        }
    }
}

/// What this change says about the quality gates it is measured by.
///
/// Two things, and the second is why a `PolicyChange` with no deltas is still
/// worth carrying: the `.andon.toml` fields that moved, and the justification
/// offered for loosening a gate. The justification covers the change rather than
/// the file — the tamper suite's `threshold-config-edit` fires over ESLint,
/// mypy, coverage and tsconfig too, and a loosening there needs the same exit
/// this module gives an `.andon.toml` loosening or it has none at all
/// ([`super::severity::signal_stops_the_line`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyChange {
    /// Every field that moved, in path order.
    pub deltas: Vec<PolicyDelta>,
    /// The justification offered for any loosening in this change.
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

    /// Whether a verified justification covers this change.
    ///
    /// The single question both blocking routes ask — this module's own
    /// loosenings, and the tamper suite's `threshold-config-edit` firing over a
    /// configuration file this module cannot parse. One answer, so the two
    /// cannot drift into disagreeing about the same change.
    pub fn is_justified(&self) -> bool {
        self.justification
            .as_ref()
            .is_some_and(Justification::is_verified)
    }

    /// Whether this edit stops the line.
    ///
    /// Loosening without a **verified** ledgered justification, and nothing
    /// else. An unverified one is reported and does not suppress: it is a claim
    /// about a ledger nobody has read.
    pub fn stops_the_line(&self) -> bool {
        !self.is_justified() && self.loosenings().next().is_some()
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
///
/// # Recursion, against the tree-walk policy
///
/// The systemic rule is that every tree-walk over PR-controlled input uses an
/// explicit stack or a typed depth cap, never unbounded recursion — the
/// exemplar is `clones/src/syntax.rs:229`, and the reason is that a crash on a
/// large input is a denial of measurement.
///
/// This walk recurses, and the cap is the type. Both `Value`s come from
/// `serde_json::to_value(&Policy)` and never from parsing a file: `Policy` is a
/// fixed-shape struct three levels deep whose arrays are leaves here, so the
/// depth is a property of the Rust type and not of the input. A hostile
/// `.andon.toml` cannot deepen it — `Policy` carries `deny_unknown_fields`, so
/// any key that is not one of the declared ones fails to parse long before this
/// function sees a value. The only way to make this walk deeper is to add a
/// nesting level to `Policy` itself, which is a P0-owned schema edit.
///
/// If the input ever becomes a `Value` parsed from a file rather than one
/// derived from the struct, that argument is void and this needs an explicit
/// stack.
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
        Justification::Verified {
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
        // Every leaf of the policy **type** has a decision recorded about it. A
        // field added without one fails here rather than silently defaulting to
        // `Unclassified`, which would mean a new gate nobody could block on.
        //
        // Read off the JSON schema and not off `Policy::default()`, which is
        // what it used to do. A serialized instance shows the fields that
        // instance happens to have values for: a nested struct whose default is
        // empty contributes no leaves at all, and a field skipped when empty
        // contributes none either. Both are exactly the shape of "a new field
        // nobody classified", so the guard was blind to its own subject.
        let unclassified: Vec<String> = schema_leaves()
            .into_iter()
            .filter(|field| knob(field).is_none())
            .collect();
        assert!(
            unclassified.is_empty(),
            "policy fields with no direction recorded: {unclassified:?}"
        );
    }

    #[test]
    fn the_classification_guard_reads_the_type_and_not_an_instance() {
        // The guard's own premise. If the schema walk stopped finding fields,
        // `policy_v1_is_fully_classified` would pass over an empty list and
        // prove nothing — which is how the instance-based version failed.
        let leaves = schema_leaves();
        for expected in [
            "severity.block_on_tamper",
            "severity.med_plus_tiers",
            "loop.iteration_cap",
            "self_measure.excluded_paths",
        ] {
            assert!(
                leaves.iter().any(|f| f == expected),
                "the schema walk missed {expected}: {leaves:?}"
            );
        }
        assert!(leaves.len() >= 12, "{leaves:?}");
    }

    /// Every leaf field of the `Policy` **schema**, as its dotted path.
    ///
    /// Nested objects arrive as `$ref`s into the schema's definitions, so the
    /// walk resolves them; arrays are leaves, as they are to [`walk`].
    fn schema_leaves() -> Vec<String> {
        let root = schemars::schema_for!(Policy);
        let definitions = root.definitions.clone();
        let mut out = Vec::new();
        walk_schema(
            "",
            &schemars::schema::Schema::Object(root.schema),
            &definitions,
            &mut out,
        );
        out.sort();
        out
    }

    fn walk_schema(
        prefix: &str,
        schema: &schemars::schema::Schema,
        definitions: &schemars::Map<String, schemars::schema::Schema>,
        out: &mut Vec<String>,
    ) {
        let schemars::schema::Schema::Object(object) = schema else {
            out.push(prefix.to_string());
            return;
        };
        if let Some(reference) = &object.reference {
            let name = reference.rsplit('/').next().unwrap_or(reference);
            match definitions.get(name) {
                Some(resolved) => walk_schema(prefix, resolved, definitions, out),
                None => out.push(prefix.to_string()),
            }
            return;
        }
        // schemars wraps a `$ref` to a named struct in an `allOf` when the field
        // also carries its own metadata, which every documented field here does.
        if let Some(subschemas) = &object.subschemas {
            if let Some(all_of) = &subschemas.all_of {
                if all_of.len() == 1 {
                    walk_schema(prefix, &all_of[0], definitions, out);
                    return;
                }
            }
        }
        let Some(validation) = &object.object else {
            out.push(prefix.to_string());
            return;
        };
        if validation.properties.is_empty() {
            out.push(prefix.to_string());
            return;
        }
        for (key, child) in &validation.properties {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            walk_schema(&path, child, definitions, out);
        }
    }
}
