//! The false-positive budget window, measured (PLAN P9b, PREMORTEM S6).
//!
//! # What this measures and what it deliberately does not decide
//!
//! S6 is the failure where anti-grinding inverts: the tool stops the line on
//! honest work often enough that humans route around it, and the routing-around
//! is silent. The mitigation is a numeric budget set ex ante (round-1 B9,
//! R2-3): **≥30 honest changes over ≥14 days; MED+ on <10% of them;
//! escalations <1/week** — checked at the **P10b entry gate**, over a window
//! whose start is ledgered when the instrumentation goes live.
//!
//! This module is the instrumentation: it reads the measure ledger and reports
//! the quantities the gate will compare. It does not compare them. A tool that
//! graded its own window would be the measured party marking the exam — the
//! same reason a self-report cannot mint a verified justification — so the
//! budget appears in the CLI rendering as a citation, and the pass/fail
//! judgement stays with the gate that owns it.
//!
//! # The units, stated precisely because the gate will lean on them
//!
//! - **A change is a distinct `head_oid`** among the window's self-reports.
//!   `head_oid` identifies content for commits and uncommitted snapshots alike,
//!   so re-measuring the same bytes is one change however many records it
//!   produced, and every edit is a new one.
//! - **A change carries MED+** when any of its in-window records carries any
//!   result whose post-policy severity is in the MED+ band
//!   ([`andon_core::schema::enums::Severity::is_med_plus`]). Post-policy on
//!   purpose: the budget counts what actually fired at the operator, not what
//!   an engine proposed before policy capped it.
//! - **The P2 rider split**: MED+ changes are additionally counted as
//!   cognitive/cyclomatic-driven when any of their MED+ results' `metric_id`
//!   prefix-matches [`RIDER_PREFIXES`] — the language-suffixed ids
//!   (`static.cognitive-complexity.typescript` etc.) all share those prefixes.
//!   This is the pre-flip empirical check the P2 Tier-B ruling asked for: the
//!   cross-language extrapolation earns its tier only if these two families do
//!   not dominate the false-positive rate.
//! - **An escalation is a record** whose verdict is `escalate_to_human`: each
//!   one is one demand on a human, which is what the S6 rate bounds.
//!
//! # When a record happened: the note's landing time, not a field on it
//!
//! Records carry a `freshness.measured_at` field and every shipped engine
//! leaves it empty — a reviewed design statement, verbatim in
//! `andon-sandbox/src/engine.rs`: *"Engines in this workspace do not stamp
//! wall-clock times (the artifacts engine is the precedent); the ledger's note
//! carries when the record landed."* So this module reads the time from where
//! the design put it: [`landing_times`] walks the notes ref's own commit
//! history and dates each record line by the **earliest committer timestamp
//! among all notes commits whose trees contain it — across every history
//! merged into the ref**. That fold has a consequence worth stating
//! precisely: a `cat_sort_uniq` merge adopts remote notes commits *with
//! their original committer times*, so a record written on another machine
//! keeps that machine's clock, not the time the sync ran here — and a wrong
//! or hostile remote clock can therefore move a record across a window
//! boundary in either direction, backdating included. What makes the reading
//! sound for THIS window is the ledgered single-machine protocol (E54): the
//! window's records accrue from this machine's own installs and recipe runs,
//! so the only clock that participates is the local one. A multi-machine
//! window would need a design decision here first, not a bigger claim.
//!
//! # Nothing is silently dropped
//!
//! Records that cannot be counted are counted as uncountable: a record whose
//! canonical line cannot be found in the notes history is reported in
//! `undated`, and a non-self-report record (a verifier attestation filed into
//! the measure ref) is reported in `non_self_reports`. Excluding a record
//! silently would make "the window held N changes" and "the instrumentation
//! saw N changes" the same observation — the vacuity shape this project keeps
//! finding.

use std::collections::{BTreeMap, BTreeSet};

use andon_core::git::Git;
use andon_core::schema::enums::{RecordKind, Verdict};
use andon_core::schema::payload::MeasurementRecord;

use crate::stats::LedgerEntry;

/// The metric-id prefixes of the P2 rider: cognitive and cyclomatic complexity
/// across their language-suffixed ids.
pub const RIDER_PREFIXES: [&str; 2] = [
    "static.cognitive-complexity",
    "static.cyclomatic-complexity",
];

/// What one window held. Quantities only; the budget comparison is the P10b
/// gate's, not this struct's.
#[derive(Debug, Clone, PartialEq)]
pub struct FpWindow {
    /// Window start, `YYYY-MM-DDTHH:MM:SSZ`, inclusive.
    pub since: String,
    /// Window end, same shape, inclusive.
    pub until: String,
    /// Window span in days.
    pub days: f64,
    /// Every record the scanned ref held, in or out of the window.
    pub total_records: usize,
    /// Self-report records inside the window — the population everything below
    /// is computed over.
    pub in_window: usize,
    /// Records excluded because their canonical line has no landing time in
    /// the notes history (see [`landing_times`]).
    pub undated: usize,
    /// Records excluded because they are not self-reports.
    pub non_self_reports: usize,
    /// Distinct measured changes (by `head_oid`) among in-window self-reports.
    pub changes: usize,
    /// Changes that carried at least one MED+ result.
    pub med_plus_changes: usize,
    /// MED+ changes driven by a cognitive/cyclomatic metric (the P2 rider).
    pub rider_changes: usize,
    /// For each metric id that reached MED+, how many changes it reached it on.
    pub med_plus_by_metric: BTreeMap<String, usize>,
    /// In-window records whose verdict was `escalate_to_human`.
    pub escalations: usize,
    /// `policy_hash` values the in-window records carried, with record counts —
    /// the witness for "one policy governed this window" (or that none did).
    pub policy_hashes: BTreeMap<String, usize>,
    /// In-window records by invocation source (wire spelling), because "honest
    /// changes" are expected to arrive through hooks and real sessions, and a
    /// window of nothing but `human-cli` re-runs would deserve a second look.
    pub by_source: BTreeMap<String, usize>,
}

impl FpWindow {
    /// Escalations per week, or `None` for a zero-length window.
    pub fn escalations_per_week(&self) -> Option<f64> {
        if self.days <= 0.0 {
            return None;
        }
        Some(self.escalations as f64 / (self.days / 7.0))
    }

    /// MED+ changes as a share of all changes, or `None` when nothing was
    /// measured.
    pub fn med_plus_share(&self) -> Option<f64> {
        if self.changes == 0 {
            return None;
        }
        Some(self.med_plus_changes as f64 / self.changes as f64)
    }
}

/// When each record line landed in the local notes ref.
///
/// The map is keyed by the record's canonical serialization — the note's own
/// line discipline (one canonical JSON document per line) — and the value is
/// the committer date, in epoch seconds, of the **earliest** notes commit
/// whose tree contains that line, whichever history that commit came from.
/// Earliest is the right fold because the notes machinery only ever unions
/// (`append`, `cat_sort_uniq`, migrate-union): once a line is in the ledger
/// it stays, whatever merges re-sort it later. See the module docs for what
/// that timestamp means once remote histories are merged in — remote
/// committer clocks participate, so "when it landed here" is only the sound
/// reading under the single-machine window protocol.
///
/// One `log` plus one `ls-tree` and one `show` per notes commit and blob —
/// the same order of spawn cost as the stats loader's per-commit reads, over
/// the same single-repo dogfood scale.
pub fn landing_times(git: &Git, notes_ref: &str) -> Result<BTreeMap<String, i64>, String> {
    let ref_exists = git
        .cmd(["rev-parse", "--verify", "--quiet", notes_ref])
        .succeeds()
        .map_err(|e| e.to_string())?;
    if !ref_exists {
        return Ok(BTreeMap::new());
    }
    let log = git
        .cmd(["log", "--format=%H %ct", notes_ref])
        .text()
        .map_err(|e| e.to_string())?;
    let mut commits: Vec<(String, i64)> = Vec::new();
    for line in log.lines() {
        let mut parts = line.split_whitespace();
        let (Some(oid), Some(secs)) = (parts.next(), parts.next()) else {
            return Err(format!("unreadable notes log line: '{line}'"));
        };
        let secs = secs
            .parse::<i64>()
            .map_err(|_| format!("unreadable notes log line: '{line}'"))?;
        commits.push((oid.to_string(), secs));
    }
    commits.sort_by_key(|(_, secs)| *secs);

    let mut map = BTreeMap::new();
    for (oid, secs) in commits {
        let files = git
            .cmd(["ls-tree", "-r", "--name-only", &oid])
            .text()
            .map_err(|e| e.to_string())?;
        for file in files.lines() {
            let body = git
                .cmd(["show", &format!("{oid}:{file}")])
                .text()
                .map_err(|e| e.to_string())?;
            for line in body.lines() {
                map.entry(line.to_string()).or_insert(secs);
            }
        }
    }
    Ok(map)
}

/// Measure one window over a scanned ledger.
///
/// `since` and `until` are inclusive bounds in the ledger's own timestamp
/// shape; a bound that does not parse is the caller's error. A record whose
/// landing time is missing from `landing` is counted in
/// [`FpWindow::undated`], not dropped.
pub fn window(
    entries: &[LedgerEntry],
    landing: &BTreeMap<String, i64>,
    since: &str,
    until: &str,
) -> Result<FpWindow, String> {
    let since_secs = parse_stamp(since)?;
    let until_secs = parse_stamp(until)?;
    if until_secs < since_secs {
        return Err(format!(
            "the window ends before it starts ({until} < {since})"
        ));
    }

    let mut report = FpWindow {
        since: since.to_string(),
        until: until.to_string(),
        days: (until_secs - since_secs) as f64 / 86_400.0,
        total_records: entries.len(),
        in_window: 0,
        undated: 0,
        non_self_reports: 0,
        changes: 0,
        med_plus_changes: 0,
        rider_changes: 0,
        med_plus_by_metric: BTreeMap::new(),
        escalations: 0,
        policy_hashes: BTreeMap::new(),
        by_source: BTreeMap::new(),
    };

    // head_oid -> the metric ids that reached MED+ on that change (empty set =
    // measured, nothing fired).
    let mut per_change: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for entry in entries {
        let record = &entry.record;
        if record.record_kind != RecordKind::SelfReport {
            report.non_self_reports += 1;
            continue;
        }
        let Some(stamp) = record_stamp(record, landing) else {
            report.undated += 1;
            continue;
        };
        if stamp < since_secs || stamp > until_secs {
            continue;
        }
        report.in_window += 1;
        *report
            .policy_hashes
            .entry(record.policy_hash.clone())
            .or_insert(0) += 1;
        *report
            .by_source
            .entry(wire_name(&record.invocation.source))
            .or_insert(0) += 1;
        if record.verdict.verdict == Verdict::EscalateToHuman {
            report.escalations += 1;
        }
        let fired = per_change
            .entry(record.compare_context.head_oid.as_str())
            .or_default();
        for result in &record.results {
            if result.severity.is_med_plus() {
                fired.insert(result.metric_id.as_str());
            }
        }
    }

    report.changes = per_change.len();
    for fired in per_change.values() {
        if fired.is_empty() {
            continue;
        }
        report.med_plus_changes += 1;
        if fired
            .iter()
            .any(|id| RIDER_PREFIXES.iter().any(|p| id.starts_with(p)))
        {
            report.rider_changes += 1;
        }
        for id in fired {
            *report
                .med_plus_by_metric
                .entry((*id).to_string())
                .or_insert(0) += 1;
        }
    }

    Ok(report)
}

/// When a record landed: its canonical line, looked up in the notes history.
///
/// The lookup leans on canonical round-trip stability (a P0 property test):
/// the stored line was written by `to_canonical_string` and re-serializing the
/// parsed record reproduces it byte for byte. If that ever stops being true
/// the lookup misses and the record is counted `undated` — visible in the
/// report, never silently in or out of the window.
fn record_stamp(record: &MeasurementRecord, landing: &BTreeMap<String, i64>) -> Option<i64> {
    let line = andon_core::canonical::to_canonical_string(record).ok()?;
    landing.get(&line).copied()
}

/// The wire spelling of a serde unit enum, read off the serializer so the
/// schema's rename rule cannot drift from a restated copy here.
fn wire_name(value: &impl serde::Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => "(unrepresentable)".to_string(),
    }
}

/// Parse the ledger's own timestamp shape — `YYYY-MM-DDTHH:MM:SSZ`, UTC,
/// exactly as `now_rfc3339` writes it — into epoch seconds.
///
/// Strict on purpose: every producer in this workspace writes exactly this
/// shape, so anything else is either a hand-edited bound (worth refusing with
/// the expected shape) or a record from a producer this code does not know
/// (worth counting as undated rather than misfiling).
pub fn parse_stamp(text: &str) -> Result<i64, String> {
    let refuse =
        || format!("'{text}' is not a ledger timestamp; the shape is YYYY-MM-DDTHH:MM:SSZ (UTC)");
    let bytes = text.as_bytes();
    if bytes.len() != 20 || bytes[10] != b'T' || bytes[19] != b'Z' {
        return Err(refuse());
    }
    let date = andon_core::date::Date::try_from(text[..10].to_string()).map_err(|_| refuse())?;
    let num = |range: std::ops::Range<usize>| -> Result<i64, String> {
        text[range].parse::<i64>().map_err(|_| refuse())
    };
    if bytes[13] != b':' || bytes[16] != b':' {
        return Err(refuse());
    }
    let (hours, minutes, seconds) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if hours > 23 || minutes > 59 || seconds > 59 {
        return Err(refuse());
    }
    Ok(days_from_civil(&date) * 86_400 + hours * 3_600 + minutes * 60 + seconds)
}

/// Days since 1970-01-01 for a civil date — Howard Hinnant's `days_from_civil`,
/// the inverse of [`andon_core::date::Date::from_days_since_epoch`], and pinned
/// against it by a round-trip test below.
fn days_from_civil(date: &andon_core::date::Date) -> i64 {
    let y = i64::from(date.year) - i64::from(date.month <= 2);
    let m = i64::from(date.month);
    let d = i64::from(date.day);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use andon_core::schema::enums::{InvocationSource, Severity};
    use andon_core::testing::sample_record;

    fn entry(record: MeasurementRecord) -> LedgerEntry {
        LedgerEntry {
            commit: record.compare_context.head_oid.clone(),
            record,
        }
    }

    /// A self-report on a head derived from `head_seed`.
    fn record_on(head_seed: char) -> MeasurementRecord {
        let mut record = sample_record();
        record.compare_context.head_oid = head_seed.to_string().repeat(40);
        record
    }

    /// A landing map placing each record at `stamp`.
    fn landed_at(records: &[&MeasurementRecord], stamp: &str) -> BTreeMap<String, i64> {
        let secs = parse_stamp(stamp).expect("test stamp parses");
        records
            .iter()
            .map(|r| {
                (
                    andon_core::canonical::to_canonical_string(r).expect("serializes"),
                    secs,
                )
            })
            .collect()
    }

    const IN: &str = "2026-08-22T12:00:00Z";
    const SINCE: &str = "2026-08-21T00:00:00Z";
    const UNTIL: &str = "2026-09-04T00:00:00Z";

    #[test]
    fn the_stamp_parser_round_trips_the_date_module() {
        // `days_from_civil` must invert `from_days_since_epoch` exactly, over a
        // range wide enough to cross leap years and the 400-year cycle's edges.
        for days in (-200_000..200_000).step_by(97) {
            let date = andon_core::date::Date::from_days_since_epoch(days);
            assert_eq!(days_from_civil(&date), days, "{date}");
        }
        assert_eq!(parse_stamp("1970-01-01T00:00:00Z"), Ok(0));
        assert_eq!(parse_stamp("1970-01-02T00:00:01Z"), Ok(86_401));
    }

    #[test]
    fn malformed_stamps_are_refused_with_the_expected_shape() {
        for bad in [
            "2026-08-22",
            "2026-08-22T12:00:00",
            "2026-08-22 12:00:00Z",
            "2026-13-22T12:00:00Z",
            "2026-08-22T25:00:00Z",
            "2026-08-22T12:61:00Z",
            "not a stamp",
        ] {
            let err = parse_stamp(bad).expect_err(bad);
            assert!(err.contains("YYYY-MM-DDTHH:MM:SSZ"), "{err}");
        }
    }

    #[test]
    fn a_window_that_ends_before_it_starts_is_refused() {
        assert!(window(&[], &BTreeMap::new(), UNTIL, SINCE).is_err());
    }

    #[test]
    fn membership_is_inclusive_of_both_bounds() {
        let at_start = record_on('a');
        let inside = record_on('b');
        let at_end = record_on('c');
        let after = record_on('d');
        let mut landing = landed_at(&[&at_start], SINCE);
        landing.extend(landed_at(&[&inside], IN));
        landing.extend(landed_at(&[&at_end], UNTIL));
        landing.extend(landed_at(&[&after], "2026-09-05T00:00:00Z"));

        let report = window(
            &[entry(at_start), entry(inside), entry(at_end), entry(after)],
            &landing,
            SINCE,
            UNTIL,
        )
        .expect("window");
        assert_eq!(report.total_records, 4);
        assert_eq!(report.in_window, 3);
        assert_eq!(report.changes, 3);
    }

    #[test]
    fn uncountable_records_are_counted_as_uncountable() {
        // Absent from the landing map — the notes history never held its line.
        let unlanded = record_on('a');
        let mut attestation = record_on('b');
        attestation.record_kind = RecordKind::Attestation;
        let landing = landed_at(&[&attestation], IN);

        let report = window(
            &[entry(unlanded), entry(attestation)],
            &landing,
            SINCE,
            UNTIL,
        )
        .expect("window");
        assert_eq!(report.in_window, 0);
        assert_eq!(report.undated, 1);
        assert_eq!(report.non_self_reports, 1);
        assert_eq!(report.changes, 0);
    }

    #[test]
    fn a_change_is_a_head_not_a_record() {
        // Three records, two heads: a re-measure of the same bytes is the same
        // change, and MED+ on any record marks the change once.
        let honest = record_on('a');
        let mut re_measured = record_on('a');
        re_measured.results[0].severity = Severity::Medium;
        let other = record_on('b');
        let landing = landed_at(&[&honest, &re_measured, &other], IN);

        let report = window(
            &[entry(honest), entry(re_measured), entry(other)],
            &landing,
            SINCE,
            UNTIL,
        )
        .expect("window");
        assert_eq!(report.in_window, 3);
        assert_eq!(report.changes, 2);
        assert_eq!(report.med_plus_changes, 1);
        assert_eq!(
            report.med_plus_by_metric.get("sample.metric"),
            Some(&1),
            "one change, however many records fired on it"
        );
        assert_eq!(report.med_plus_share(), Some(0.5));
    }

    #[test]
    fn the_rider_split_prefix_matches_the_language_suffixed_ids() {
        let mut cognitive = record_on('a');
        cognitive.results[0].severity = Severity::High;
        cognitive.results[0].metric_id = "static.cognitive-complexity.python".to_string();
        let mut cyclomatic = record_on('b');
        cyclomatic.results[0].severity = Severity::Medium;
        cyclomatic.results[0].metric_id = "static.cyclomatic-complexity.typescript".to_string();
        let mut clones = record_on('c');
        clones.results[0].severity = Severity::Medium;
        clones.results[0].metric_id = "clones.duplicated-tokens".to_string();
        let landing = landed_at(&[&cognitive, &cyclomatic, &clones], IN);

        let report = window(
            &[entry(cognitive), entry(cyclomatic), entry(clones)],
            &landing,
            SINCE,
            UNTIL,
        )
        .expect("window");
        assert_eq!(report.med_plus_changes, 3);
        assert_eq!(report.rider_changes, 2);
        assert_eq!(
            report
                .med_plus_by_metric
                .get("static.cognitive-complexity.python"),
            Some(&1)
        );
    }

    #[test]
    fn escalations_are_records_and_the_rate_is_per_week() {
        let mut escalated = record_on('a');
        escalated.verdict.verdict = Verdict::EscalateToHuman;
        let calm = record_on('b');
        let landing = landed_at(&[&escalated, &calm], IN);

        let report =
            window(&[entry(escalated), entry(calm)], &landing, SINCE, UNTIL).expect("window");
        assert_eq!(report.escalations, 1);
        assert_eq!(report.days, 14.0);
        assert_eq!(report.escalations_per_week(), Some(0.5));
    }

    #[test]
    fn policy_hashes_and_sources_are_witnessed_per_record() {
        let one = record_on('a');
        let mut two = record_on('b');
        two.policy_hash = "6".repeat(64);
        two.invocation.source = InvocationSource::AgentInitiated;
        let landing = landed_at(&[&one, &two], IN);

        let report = window(&[entry(one), entry(two)], &landing, SINCE, UNTIL).expect("window");
        assert_eq!(report.policy_hashes.len(), 2);
        assert_eq!(report.by_source.get("hook"), Some(&1));
        assert_eq!(report.by_source.get("agent-initiated"), Some(&1));
    }

    #[test]
    fn empty_windows_decline_the_ratios_rather_than_inventing_them() {
        let report = window(&[], &BTreeMap::new(), SINCE, SINCE).expect("window");
        assert_eq!(report.days, 0.0);
        assert_eq!(report.med_plus_share(), None);
        assert_eq!(report.escalations_per_week(), None);
    }
}
