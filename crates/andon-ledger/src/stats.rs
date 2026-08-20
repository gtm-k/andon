//! `andon ledger stats` — the ledger as a longitudinal dataset.
//!
//! # Scope
//!
//! Single-repo local analytics for the maintainer's dogfood loop. Everything
//! here reads one repository's notes and answers questions about that
//! repository's own history of being measured. It is **not** fleet analytics —
//! the Gatekeeper fleet product is an explicit non-goal (PLAN round-1 3.4) —
//! and [`SCOPE_LINE`] is printed at the top of the output so the scope travels
//! with the numbers.
//!
//! # Every record arrives through the guarded reader
//!
//! [`load_ref`] walks `annotated_commits` and calls [`Notes::read`] per commit
//! — the -min crate's reader, the one place the ledger's integrity checks
//! live. A record that reader refuses stops the whole stats run with the
//! reader's own error naming the ref, commit, and line: skipping it and
//! reporting over the rest would be a report over a subset the output never
//! announced, the exact defect the notes doctrine names.
//!
//! # The threshold-clustering warning (PREMORTEM S1)
//!
//! The adversarial corpus is public, so the one signal an evader cannot avoid
//! leaving is in the *distribution*: values that pile up just under a declared
//! severity rung are the shape of iteration against the gate — measure, shave,
//! measure again until the number slips under the line. The warning triggers
//! per metric, per regime, per rung; its three constants are declared ex ante
//! below, with the reasoning beside them.
//!
//! # Cross-regime aggregation is refused by default (PREMORTEM S4)
//!
//! A number's meaning is bound to the [`MeasurementRegime`] that produced it.
//! Pooling values across regimes turns an engine or grammar upgrade into a
//! "distribution shift" — and in a tool whose job is spotting gaming pressure,
//! a distribution shift is an accusation waiting to be misread. So the
//! distribution is grouped by regime always; a pooled view exists only behind
//! an explicit opt-in, stays labeled as mixed, and the refusal that stands in
//! for it names every regime involved and says why (the AC's own wording).
//! Clustering detection is **never** pooled, opt-in or not: "hugging a
//! threshold" is only a meaningful shape within one regime.

use std::collections::BTreeMap;

use andon_core::git::Git;
use andon_core::schema::payload::{MeasurementRecord, MetricValue};
use andon_core::schema::regime::MeasurementRegime;
use andon_core::verdict::ladder::{SeverityLadder, Threshold};
use andon_ledger_min::notes::{Notes, NotesError};
use serde::Serialize;

/// The scope statement, printed at the top of every stats rendering.
pub const SCOPE_LINE: &str = "Scope: this repository's own ledger, read locally, for its \
     maintainer's dogfood loop. Single-repo analytics — not a fleet dashboard; the Gatekeeper \
     fleet product is an explicit non-goal.";

/// Width of the "just under the rung" band, as a fraction of the rung value.
///
/// Project-declared, ex ante (the stance `verdict::ladder` takes on its own
/// thresholds: a judgement about how loud to be, stated as such, not dressed up
/// as literature). One tenth below the rung is the region a value lands in when
/// someone shaves a number until it stops firing; integer-kinded rungs widen
/// the band to at least one unit so a rung of 10 still has a band at all.
pub const CLUSTER_BAND_FRACTION: f64 = 0.10;

/// Fewest in-band values before the warning can fire.
///
/// Project-declared, ex ante. Below five samples a "cluster" is an anecdote:
/// one function measured on three passes can put three honest values in the
/// band. Five keeps the warning quiet on toy ledgers without meaningfully
/// delaying it on a ledger that accumulates every dogfood run.
pub const CLUSTER_MIN_SAMPLES: usize = 5;

/// Fraction of a group's population that must sit in one rung's band to warn.
///
/// Project-declared, ex ante. Honest complexity-like distributions concentrate
/// far below the rung (most functions are simple), so even a third of all
/// values inside the top tenth below a rung is already strange; half is chosen
/// to make the warning hard to trip by chance and cheap to audit when it does
/// — the message names the exact values' metric, regime, and rung.
///
/// # What the denominator is
///
/// For the kinds where zero means nothing-found (counts and ratios — see
/// [`zero_means_nothing_found`]), **the population is the non-zero values**,
/// and both this fraction and [`CLUSTER_MIN_SAMPLES`] are judged against it.
/// Zeros are not part of a shaved distribution, so they belong neither in the
/// band nor in the population being judged for shaving: with zeros in the
/// denominator, six blatantly hugging values beside seven honest zeros read as
/// 6/13 = 46% and stayed silent, so a genuine S1 streak was undetectable
/// unless gamed values outnumbered the metric's own honest zeros — and on a
/// real dogfood ledger the duplicated-tokens column is all zeros. Judging
/// `MIN_SAMPLES` against the same non-zero population keeps the other edge
/// honest too: five zeros and one hugging value is not a distribution, it is
/// one value.
pub const CLUSTER_WARN_FRACTION: f64 = 0.5;

/// One record, and the commit whose note carries it.
#[derive(Debug, Clone)]
pub struct LedgerEntry {
    /// The annotated commit.
    pub commit: String,
    /// The record, as the guarded reader returned it.
    pub record: MeasurementRecord,
}

/// What was loaded, and how big it is on disk.
#[derive(Debug, Clone)]
pub struct LedgerScan {
    /// Which ref this came from.
    pub notes_ref: String,
    /// Every record, in sorted-commit order.
    pub entries: Vec<LedgerEntry>,
    /// Total note-body bytes across the ref, for the size line. The plan
    /// assumed few-KB records; real dogfood records run far larger, and the
    /// honest response is to print the number rather than gate on a hope.
    pub body_bytes: u64,
}

/// Load every record on `notes_ref` through the guarded reader.
pub fn load_ref(git: &Git, notes_ref: &str) -> Result<LedgerScan, NotesError> {
    let notes = Notes::new(git, notes_ref);
    let mut commits = notes.annotated_commits()?;
    commits.sort();
    let mut entries = Vec::new();
    let mut body_bytes = 0u64;
    for commit in commits {
        body_bytes += notes
            .read_raw(&commit)?
            .map(|body| body.len() as u64)
            .unwrap_or(0);
        for record in notes.read(&commit)? {
            entries.push(LedgerEntry {
                commit: commit.clone(),
                record,
            });
        }
    }
    Ok(LedgerScan {
        notes_ref: notes_ref.to_string(),
        entries,
        body_bytes,
    })
}

/// A queryable ledger dimension (PLAN P0's dimensions, P8's query).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dimension {
    /// `invocation.source` — hook, agent-initiated, human-cli, ci-verifier.
    InvocationSource,
    /// `invocation.harness`.
    Harness,
    /// `invocation.model`.
    Model,
    /// `invocation.author`.
    Author,
    /// `invocation.iteration` — which pass around the loop.
    Iteration,
}

impl Dimension {
    /// Every dimension, in rendering order.
    pub const ALL: [Dimension; 5] = [
        Dimension::InvocationSource,
        Dimension::Harness,
        Dimension::Model,
        Dimension::Author,
        Dimension::Iteration,
    ];

    /// Parse a user-facing name.
    pub fn parse(name: &str) -> Option<Dimension> {
        match name {
            "source" | "invocation-source" => Some(Dimension::InvocationSource),
            "harness" => Some(Dimension::Harness),
            "model" => Some(Dimension::Model),
            "author" => Some(Dimension::Author),
            "iteration" => Some(Dimension::Iteration),
            _ => None,
        }
    }

    /// The user-facing name.
    pub fn name(self) -> &'static str {
        match self {
            Dimension::InvocationSource => "invocation-source",
            Dimension::Harness => "harness",
            Dimension::Model => "model",
            Dimension::Author => "author",
            Dimension::Iteration => "iteration",
        }
    }

    /// This dimension's value for one record.
    ///
    /// Enum-valued dimensions go through the serializer rather than a
    /// hand-written match: the wire spelling is the schema's own rename rule,
    /// and a restated copy of it here would drift the day the schema moves.
    pub fn value_of(self, record: &MeasurementRecord) -> String {
        let unrecorded = || "(unrecorded)".to_string();
        match self {
            Dimension::InvocationSource => wire_name(&record.invocation.source),
            Dimension::Harness => record.invocation.harness.clone().unwrap_or_else(unrecorded),
            Dimension::Model => record.invocation.model.clone().unwrap_or_else(unrecorded),
            Dimension::Author => record.invocation.author.clone().unwrap_or_else(unrecorded),
            Dimension::Iteration => record.invocation.iteration.to_string(),
        }
    }
}

/// The wire spelling of a serde enum value.
fn wire_name(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        // Unreachable for the unit enums this is called on; a non-string
        // serialization would be a schema change this module should not paper
        // over with a guess.
        _ => "(unrepresentable)".to_string(),
    }
}

/// One restriction: keep records whose `dimension` equals `value`.
#[derive(Debug, Clone)]
pub struct Filter {
    /// Which dimension.
    pub dimension: Dimension,
    /// The value to keep. Compared against [`Dimension::value_of`], so
    /// `(unrecorded)` selects records that did not record the dimension.
    pub value: String,
}

impl Filter {
    /// Parse `dimension=value`.
    pub fn parse(text: &str) -> Result<Filter, String> {
        let (name, value) = text.split_once('=').ok_or_else(|| {
            format!(
                "'{text}' is not a filter; the shape is <dimension>=<value>, e.g. \
                 harness=claude-code"
            )
        })?;
        let dimension = Dimension::parse(name).ok_or_else(|| {
            format!(
                "'{name}' is not a ledger dimension; the dimensions are source, harness, \
                 model, author, iteration"
            )
        })?;
        Ok(Filter {
            dimension,
            value: value.to_string(),
        })
    }

    /// Whether a record passes this filter.
    pub fn matches(&self, record: &MeasurementRecord) -> bool {
        self.dimension.value_of(record) == self.value
    }
}

/// Counts for one value of one dimension.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SliceCell {
    /// Records carrying this value.
    pub records: usize,
    /// Their verdicts, by wire name.
    pub verdicts: BTreeMap<String, usize>,
}

/// Record counts sliced along one dimension.
pub fn slice(entries: &[LedgerEntry], dimension: Dimension) -> BTreeMap<String, SliceCell> {
    let mut out: BTreeMap<String, SliceCell> = BTreeMap::new();
    for entry in entries {
        let cell = out.entry(dimension.value_of(&entry.record)).or_default();
        cell.records += 1;
        *cell
            .verdicts
            .entry(wire_name(&entry.record.verdict.verdict))
            .or_default() += 1;
    }
    out
}

/// A one-line human label for a regime, naming every field of its variant.
///
/// Exhaustive on purpose: a new regime variant must fail compilation here
/// rather than fall through to a label that hides what changed.
pub fn regime_label(regime: &MeasurementRegime) -> String {
    fn map(pairs: &BTreeMap<String, String>) -> String {
        pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",")
    }
    match regime {
        MeasurementRegime::Static {
            engine_version,
            spec_revision,
            grammars,
        } => format!(
            "static v{engine_version} spec {spec_revision} grammars [{}]",
            map(grammars)
        ),
        MeasurementRegime::Clones {
            engine_version,
            algorithm,
            min_tokens,
            window_tokens,
            normalization_revision,
        } => format!(
            "clones v{engine_version} {algorithm} min-tokens {min_tokens} window {window_tokens} \
             normalization {normalization_revision}"
        ),
        MeasurementRegime::Tamper {
            engine_version,
            detector_set_revision,
            rule_pack_version,
        } => format!(
            "tamper v{engine_version} detectors {detector_set_revision} rules {rule_pack_version}"
        ),
        MeasurementRegime::Process {
            engine_version,
            git_version,
            history_window_days,
        } => format!("process v{engine_version} git {git_version} window {history_window_days}d"),
        MeasurementRegime::Artifacts {
            engine_version,
            parser_versions,
        } => format!(
            "artifacts v{engine_version} parsers [{}]",
            map(parser_versions)
        ),
    }
}

/// Summary of one metric's values within one regime.
#[derive(Debug, Clone, PartialEq)]
pub struct ValueSummary {
    /// Numeric values seen (counts, integers, ratios, durations — as f64 for
    /// the summary line only; clustering compares in the rung's own kind).
    pub numeric: usize,
    /// Smallest numeric value.
    pub min: Option<f64>,
    /// Largest numeric value.
    pub max: Option<f64>,
    /// Mean of the numeric values.
    pub mean: Option<f64>,
    /// Flag results that fired.
    pub fired: usize,
    /// Flag results that did not.
    pub unfired: usize,
    /// Text markers — absences, not numbers.
    pub absent: usize,
}

/// One metric's values under one regime.
#[derive(Debug, Clone)]
pub struct RegimeGroup {
    /// The regime, labeled.
    pub regime_label: String,
    /// The values, summarized.
    pub summary: ValueSummary,
    /// The raw numeric values, kept for clustering.
    values: Vec<MetricValue>,
}

/// One metric across the ledger.
#[derive(Debug, Clone)]
pub struct MetricDistribution {
    /// The metric.
    pub metric_id: String,
    /// Per-regime groups, keyed and ordered by label.
    pub groups: Vec<RegimeGroup>,
    /// The pooled summary across regimes. `None` unless explicitly requested
    /// via `across_regimes` AND more than one regime exists.
    pub pooled: Option<ValueSummary>,
}

/// A distribution that hugs a rung from below (PREMORTEM S1).
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterWarning {
    /// The metric whose values cluster.
    pub metric_id: String,
    /// The regime they were measured under.
    pub regime_label: String,
    /// The rung being hugged, rendered in its own unit.
    pub rung: String,
    /// Values inside the band.
    pub in_band: usize,
    /// All numeric values in the group.
    pub total: usize,
    /// The full warning sentence.
    pub message: String,
}

/// The refusal that stands in for a pooled cross-regime aggregate (S4).
#[derive(Debug, Clone, PartialEq)]
pub struct CrossRegimeRefusal {
    /// The metric that spans regimes.
    pub metric_id: String,
    /// Every regime involved, labeled.
    pub regimes: Vec<String>,
    /// The refusal sentence: why, naming the regimes, and what to do instead.
    pub message: String,
}

/// The full `--distribution` answer.
#[derive(Debug, Clone)]
pub struct Distribution {
    /// Per-metric, per-regime value distributions, sorted by metric id.
    pub metrics: Vec<MetricDistribution>,
    /// Every clustering warning that fired.
    pub warnings: Vec<ClusterWarning>,
    /// Every cross-regime refusal in force.
    pub refusals: Vec<CrossRegimeRefusal>,
}

/// Build the distribution.
///
/// `ladder_for` is the caller's severity-ladder lookup — the CLI passes the
/// same shipped roster the verdict path reads, so the rungs the warning checks
/// are the rungs the gate actually applies, by construction rather than by a
/// second table.
pub fn distribution(
    entries: &[LedgerEntry],
    ladder_for: &dyn Fn(&str) -> Option<SeverityLadder>,
    across_regimes: bool,
) -> Distribution {
    // (metric, regime label) -> values. BTreeMap end to end so the output
    // order is deterministic — randomized ordering in a report invites reading
    // the same ledger twice and seeing two different documents.
    let mut by_metric: BTreeMap<String, BTreeMap<String, Vec<MetricValue>>> = BTreeMap::new();
    for entry in entries {
        for result in &entry.record.results {
            by_metric
                .entry(result.metric_id.clone())
                .or_default()
                .entry(regime_label(&result.measurement_regime))
                .or_default()
                .push(result.value.clone());
        }
    }

    let mut metrics = Vec::new();
    let mut warnings = Vec::new();
    let mut refusals = Vec::new();
    for (metric_id, groups) in by_metric {
        let ladder = ladder_for(&metric_id);
        let groups: Vec<RegimeGroup> = groups
            .into_iter()
            .map(|(regime_label, values)| RegimeGroup {
                summary: summarize(&values),
                regime_label,
                values,
            })
            .collect();

        for group in &groups {
            if let Some(SeverityLadder::Thresholds(rungs)) = ladder {
                warnings.extend(cluster_warnings(
                    &metric_id,
                    &group.regime_label,
                    rungs.iter().map(|rung| rung.at),
                    &group.values,
                ));
            }
        }

        let pooled = if groups.len() > 1 {
            if across_regimes {
                let all: Vec<MetricValue> = groups
                    .iter()
                    .flat_map(|g| g.values.iter().cloned())
                    .collect();
                Some(summarize(&all))
            } else {
                let labels: Vec<String> = groups.iter().map(|g| g.regime_label.clone()).collect();
                refusals.push(CrossRegimeRefusal {
                    message: refusal_message(&metric_id, &labels),
                    metric_id: metric_id.clone(),
                    regimes: labels,
                });
                None
            }
        } else {
            None
        };

        metrics.push(MetricDistribution {
            metric_id,
            groups,
            pooled,
        });
    }
    Distribution {
        metrics,
        warnings,
        refusals,
    }
}

/// The refusal sentence: why pooling is refused, naming every regime.
fn refusal_message(metric_id: &str, labels: &[String]) -> String {
    format!(
        "{metric_id}: refusing to aggregate across {} measurement regimes. A number's meaning \
         is bound to the regime that produced it, and pooling regimes turns an engine or \
         grammar upgrade into a distribution shift — which in this tool reads as gaming \
         pressure, so the aggregate would invite calling a regime change tampering \
         (PREMORTEM S4). The regimes seen:\n{}\n\
         Per-regime distributions are reported above. To pool anyway, pass --across-regimes; \
         the pooled view stays labeled as mixed-regime, and clustering is still judged \
         per regime only.",
        labels.len(),
        labels
            .iter()
            .map(|label| format!("      - {label}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// Summarize values of one metric under one regime.
fn summarize(values: &[MetricValue]) -> ValueSummary {
    let mut numeric = Vec::new();
    let mut fired = 0;
    let mut unfired = 0;
    let mut absent = 0;
    for value in values {
        match value {
            MetricValue::Count(v) => numeric.push(*v as f64),
            MetricValue::Integer(v) => numeric.push(*v as f64),
            MetricValue::Ratio(v) => numeric.push(*v),
            MetricValue::Duration { millis } => numeric.push(*millis as f64),
            MetricValue::Flag(true) => fired += 1,
            MetricValue::Flag(false) => unfired += 1,
            MetricValue::Text(_) => absent += 1,
        }
    }
    let count = numeric.len();
    let (min, max, mean) = if count == 0 {
        (None, None, None)
    } else {
        let min = numeric.iter().copied().fold(f64::INFINITY, f64::min);
        let max = numeric.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let mean = numeric.iter().sum::<f64>() / count as f64;
        (Some(min), Some(max), Some(mean))
    };
    ValueSummary {
        numeric: count,
        min,
        max,
        mean,
        fired,
        unfired,
        absent,
    }
}

/// Clustering warnings for one metric under one regime, one check per rung.
///
/// Every rung is checked, not only the lowest: whoever is shaving a number
/// sits under whichever rung was biting them.
fn cluster_warnings(
    metric_id: &str,
    regime_label: &str,
    rungs: impl Iterator<Item = Threshold>,
    values: &[MetricValue],
) -> Vec<ClusterWarning> {
    let mut out = Vec::new();
    for rung in rungs {
        // A rung whose band would contain zero has no hugging shape to detect
        // — see `band_of`. Skipped before any value is read.
        let Some((floor, ceiling)) = band_of(rung) else {
            continue;
        };
        let excludes_zero = zero_means_nothing_found(rung);
        let mut in_band = 0usize;
        let mut total = 0usize;
        for value in values {
            let Some(v) = value_on_axis(rung, value) else {
                continue;
            };
            // Zeros leave the population entirely for the nothing-found kinds
            // — see `zero_means_nothing_found`. They cannot be in-band (the
            // band never contains zero) and they must not pad the denominator:
            // six shaved values beside seven honest zeros is a 100% hugging
            // streak among the values that exist, not a 46% non-event.
            if excludes_zero && v == 0.0 {
                continue;
            }
            total += 1;
            if v >= floor && v < ceiling {
                in_band += 1;
            }
        }
        if in_band >= CLUSTER_MIN_SAMPLES && in_band as f64 / total as f64 >= CLUSTER_WARN_FRACTION
        {
            let rung_text = threshold_text(rung);
            let population = if excludes_zero {
                "non-zero values"
            } else {
                "values"
            };
            out.push(ClusterWarning {
                metric_id: metric_id.to_string(),
                regime_label: regime_label.to_string(),
                rung: rung_text.clone(),
                in_band,
                total,
                message: format!(
                    "{metric_id} under [{regime_label}]: {in_band} of {total} {population} sit \
                     just below the rung at {rung_text} (within the top {percent}% under it). A \
                     distribution that hugs a threshold from below is the shape of iterating \
                     against the gate until the number slips under the line (PREMORTEM S1). \
                     Look at which changes produced these values — `andon ledger stats --by \
                     source` and `--by iteration` slice them — before trusting the streak.",
                    percent = (CLUSTER_BAND_FRACTION * 100.0) as u32,
                ),
            });
        }
    }
    out
}

/// Whether zero on this rung's axis means "nothing found" rather than a
/// measured quantity.
///
/// For counts and ratios, zero is the absence the ladder exists to notice the
/// end of: 0 duplicated tokens, 0.0 duplication ratio. `band_of` already keeps
/// such zeros out of every band; this predicate finishes the same reasoning on
/// the denominator side — a value that is not part of a shaved distribution
/// belongs neither in the band nor in the population being judged for shaving.
/// Without it, honest zeros dilute the fraction and a genuine hugging streak
/// is undetectable on exactly the metrics whose honest mode IS zero (a real
/// dogfood ledger's duplicated-tokens column is all zeros), which would hollow
/// the S1 monitor where the cron points it.
///
/// Integer and duration rungs are left alone: an integer is a delta where zero
/// is a measured "no change", and a duration of zero is a measured time, not
/// an absence. No shipped ladder ranks either today; the conservative reading
/// costs nothing.
fn zero_means_nothing_found(rung: Threshold) -> bool {
    matches!(rung, Threshold::Count(_) | Threshold::Ratio(_))
}

/// The "just under" band for one rung: `(floor, ceiling)` in f64, or `None`
/// when the rung has no meaningful band.
///
/// # A band that contains zero detects nothing
///
/// Integer-kinded bands are widened to at least one unit so a small rung still
/// has a band — and that widening gives every rung at 1 the band `[0, 1)`,
/// which contains **zero**. Zero is not a shaved number; it is the value of
/// nothing found, and for most count metrics it is the honest mode: a clean
/// change has 0 duplicated tokens, 0 clone groups, 0 coupled files. Counting
/// zeros as "hugging just below the rung" turned five honest measurements into
/// five warnings and would have made the weekly S1 cron permanently red on
/// honest data — the PREMORTEM A4 shape, a gate whose red means nothing. So a
/// rung whose band would contain zero declares no band at all: there is no
/// value strictly between nothing-found and the rung to shave down to, so
/// hugging under such a rung is not an observable shape. Rungs further up keep
/// their bands, and blatant hugging there still fires — the named tests pin
/// both directions.
fn band_of(rung: Threshold) -> Option<(f64, f64)> {
    // The ratio band is the fraction alone, since a ratio has no smallest unit.
    let (floor, ceiling) = match rung {
        Threshold::Count(at) => {
            let width = ((at as f64) * CLUSTER_BAND_FRACTION).max(1.0);
            (at as f64 - width, at as f64)
        }
        Threshold::Integer(at) => {
            let width = ((at as f64).abs() * CLUSTER_BAND_FRACTION).max(1.0);
            (at as f64 - width, at as f64)
        }
        Threshold::Ratio(at) => (at * (1.0 - CLUSTER_BAND_FRACTION), at),
        Threshold::Millis(at) => {
            let width = ((at as f64) * CLUSTER_BAND_FRACTION).max(1.0);
            (at as f64 - width, at as f64)
        }
    };
    let contains_zero = floor <= 0.0 && 0.0 < ceiling;
    (!contains_zero).then_some((floor, ceiling))
}

/// `value` on the same axis as `rung`, or `None` when the kinds do not match.
fn value_on_axis(rung: Threshold, value: &MetricValue) -> Option<f64> {
    match (rung, value) {
        (Threshold::Count(_), MetricValue::Count(v)) => Some(*v as f64),
        (Threshold::Integer(_), MetricValue::Integer(v)) => Some(*v as f64),
        (Threshold::Ratio(_), MetricValue::Ratio(v)) => Some(*v),
        (Threshold::Millis(_), MetricValue::Duration { millis }) => Some(*millis as f64),
        _ => None,
    }
}

/// A threshold rendered in its own unit.
fn threshold_text(rung: Threshold) -> String {
    match rung {
        Threshold::Count(at) => at.to_string(),
        Threshold::Integer(at) => at.to_string(),
        Threshold::Ratio(at) => format!("{at}"),
        Threshold::Millis(at) => format!("{at}ms"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andon_core::schema::enums::Severity;
    use andon_core::verdict::ladder::Rung;

    fn count_values(values: &[u64]) -> Vec<MetricValue> {
        values.iter().map(|v| MetricValue::Count(*v)).collect()
    }

    const LADDER: &[Rung] = &[Rung {
        at: Threshold::Count(20),
        severity: Severity::Medium,
    }];

    fn count_ladder(metric_id: &str) -> Option<SeverityLadder> {
        (metric_id == "static.cognitive-complexity").then_some(SeverityLadder::Thresholds(LADDER))
    }

    fn entry_with_values(values: Vec<MetricValue>, regime_bump: Option<&str>) -> LedgerEntry {
        use andon_core::testing::sample_record;
        let mut record = sample_record();
        let template = record.results[0].clone();
        record.results = values
            .into_iter()
            .map(|value| {
                let mut result = template.clone();
                result.metric_id = "static.cognitive-complexity".to_string();
                result.value = value;
                if let Some(version) = regime_bump {
                    if let MeasurementRegime::Static { engine_version, .. } =
                        &mut result.measurement_regime
                    {
                        *engine_version = version.to_string();
                    }
                }
                result
            })
            .collect();
        LedgerEntry {
            commit: "0".repeat(40),
            record,
        }
    }

    #[test]
    fn a_distribution_hugging_a_rung_from_below_warns_and_names_everything() {
        // Six of eight values in [18, 20): unmistakable hugging.
        let entries = vec![entry_with_values(
            count_values(&[3, 5, 18, 19, 19, 19, 18, 19]),
            None,
        )];
        let built = distribution(&entries, &count_ladder, false);
        assert_eq!(built.warnings.len(), 1, "{:?}", built.warnings);
        let warning = &built.warnings[0];
        assert_eq!(warning.in_band, 6);
        assert_eq!(warning.total, 8);
        for needle in [
            "static.cognitive-complexity",
            "rung at 20",
            "6 of 8",
            "static v", // the regime label
            "S1",
        ] {
            assert!(
                warning.message.contains(needle),
                "missing {needle:?} in: {}",
                warning.message
            );
        }
    }

    // A ladder shaped like the shipped clones tables: the first rung at 1,
    // where the widened band would be [0, 1) — the honest-zero trap.
    const LOW_RUNGS: &[Rung] = &[
        Rung {
            at: Threshold::Count(1),
            severity: Severity::Low,
        },
        Rung {
            at: Threshold::Count(20),
            severity: Severity::Medium,
        },
    ];

    fn low_rung_ladder(metric_id: &str) -> Option<SeverityLadder> {
        (metric_id == "static.cognitive-complexity")
            .then_some(SeverityLadder::Thresholds(LOW_RUNGS))
    }

    #[test]
    fn honest_zeros_under_a_rung_at_one_never_warn() {
        // The review's repro in miniature: zero is the honest mode of a count
        // metric (a clean change has 0 duplicated tokens), and a rung at 1
        // must not read eight of them as eight values shaved to just under
        // the line. Before `band_of` refused zero-containing bands, this was
        // eight-of-eight "hugging" and a permanently red S1 cron.
        let entries = vec![entry_with_values(
            count_values(&[0, 0, 0, 0, 0, 0, 0, 0]),
            None,
        )];
        let built = distribution(&entries, &low_rung_ladder, false);
        assert!(built.warnings.is_empty(), "{:?}", built.warnings);
    }

    #[test]
    fn a_disabled_zero_band_rung_does_not_shield_the_rungs_above_it() {
        // The other direction the fix must hold: refusing the rung at 1 must
        // not quiet the ladder — blatant hugging under the rung at 20 still
        // fires with the zeros sitting in the same distribution. The zeros
        // are outside the population entirely, so six of the six non-zero
        // values are in the band.
        let entries = vec![entry_with_values(
            count_values(&[0, 0, 19, 19, 19, 18, 19, 19]),
            None,
        )];
        let built = distribution(&entries, &low_rung_ladder, false);
        assert_eq!(built.warnings.len(), 1, "{:?}", built.warnings);
        let warning = &built.warnings[0];
        assert!(
            warning.message.contains("rung at 20"),
            "{}",
            warning.message
        );
        assert_eq!(warning.in_band, 6);
        assert_eq!(warning.total, 6);
    }

    #[test]
    fn honest_zeros_cannot_dilute_a_hugging_streak() {
        // The confirm-pass MED, count shape: six blatantly hugging values
        // beside seven honest zeros. With zeros padding the denominator this
        // was 6/13 = 46% and silent — a genuine S1 streak undetectable unless
        // gamed values outnumbered the metric's own honest zeros, on metrics
        // whose honest mode IS zero. Among the values that exist, it is 6/6.
        let entries = vec![entry_with_values(
            count_values(&[18, 19, 19, 19, 18, 19, 0, 0, 0, 0, 0, 0, 0]),
            None,
        )];
        let built = distribution(&entries, &count_ladder, false);
        assert_eq!(built.warnings.len(), 1, "{:?}", built.warnings);
        let warning = &built.warnings[0];
        assert_eq!(warning.in_band, 6);
        assert_eq!(warning.total, 6, "zeros must not pad the denominator");
        assert!(
            warning.message.contains("6 of 6 non-zero values"),
            "{}",
            warning.message
        );
    }

    const RATIO_RUNGS: &[Rung] = &[Rung {
        at: Threshold::Ratio(0.20),
        severity: Severity::Medium,
    }];

    fn ratio_ladder(metric_id: &str) -> Option<SeverityLadder> {
        (metric_id == "static.cognitive-complexity")
            .then_some(SeverityLadder::Thresholds(RATIO_RUNGS))
    }

    #[test]
    fn honest_zeros_cannot_dilute_a_hugging_streak_of_ratios() {
        // The same dilution, ratio shape: 0.0 is the nothing-found value of a
        // ratio metric (a change with no duplication has ratio 0.0), and six
        // values at 0.19 under the rung at 0.20 are a streak whatever number
        // of honest zeros sit beside them.
        let values: Vec<MetricValue> = [0.19, 0.19, 0.19, 0.19, 0.19, 0.19, 0.0, 0.0, 0.0, 0.0]
            .iter()
            .map(|v| MetricValue::Ratio(*v))
            .collect();
        let entries = vec![entry_with_values(values, None)];
        let built = distribution(&entries, &ratio_ladder, false);
        assert_eq!(built.warnings.len(), 1, "{:?}", built.warnings);
        let warning = &built.warnings[0];
        assert_eq!(warning.in_band, 6);
        assert_eq!(warning.total, 6);
    }

    #[test]
    fn a_sub_minimum_cluster_stays_quiet_however_many_zeros_sit_beside_it() {
        // MIN_SAMPLES is judged against the same non-zero population: four
        // hugging values and ten zeros is four values, below the floor of
        // five, and four values are an anecdote whichever way they lean.
        let entries = vec![entry_with_values(
            count_values(&[19, 19, 18, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            None,
        )];
        let built = distribution(&entries, &count_ladder, false);
        assert!(built.warnings.is_empty(), "{:?}", built.warnings);
    }

    #[test]
    fn an_honest_spread_does_not_warn() {
        let entries = vec![entry_with_values(
            count_values(&[1, 2, 3, 5, 8, 4, 2, 25, 6, 3]),
            None,
        )];
        let built = distribution(&entries, &count_ladder, false);
        assert!(built.warnings.is_empty(), "{:?}", built.warnings);
    }

    #[test]
    fn a_cluster_smaller_than_the_minimum_sample_count_stays_quiet() {
        // Four of four values in the band — 100% — but under CLUSTER_MIN_SAMPLES.
        let entries = vec![entry_with_values(count_values(&[19, 19, 18, 19]), None)];
        let built = distribution(&entries, &count_ladder, false);
        assert!(built.warnings.is_empty(), "{:?}", built.warnings);
    }

    #[test]
    fn cross_regime_aggregation_is_refused_by_default_naming_the_regimes() {
        let entries = vec![
            entry_with_values(count_values(&[1, 2, 3]), None),
            entry_with_values(count_values(&[4, 5, 6]), Some("9.9.9")),
        ];
        let built = distribution(&entries, &count_ladder, false);

        // The pooled view is absent…
        let metric = &built.metrics[0];
        assert_eq!(metric.groups.len(), 2);
        assert!(
            metric.pooled.is_none(),
            "pooling across regimes must be refused by default"
        );

        // …and the refusal names both regimes and says why.
        assert_eq!(built.refusals.len(), 1);
        let refusal = &built.refusals[0];
        assert_eq!(refusal.regimes.len(), 2);
        for needle in [
            "refusing to aggregate",
            "regime change tampering",
            "S4",
            "v9.9.9",
            "--across-regimes",
        ] {
            assert!(
                refusal.message.contains(needle),
                "missing {needle:?} in: {}",
                refusal.message
            );
        }
    }

    #[test]
    fn the_explicit_opt_in_pools_and_the_refusal_stands_down() {
        let entries = vec![
            entry_with_values(count_values(&[1, 2, 3]), None),
            entry_with_values(count_values(&[4, 5, 6]), Some("9.9.9")),
        ];
        let built = distribution(&entries, &count_ladder, true);
        let metric = &built.metrics[0];
        let pooled = metric.pooled.as_ref().expect("opt-in pools");
        assert_eq!(pooled.numeric, 6);
        assert!(built.refusals.is_empty());
    }

    #[test]
    fn clustering_is_judged_per_regime_even_when_pooling_is_requested() {
        // Regime A holds three just-under values, regime B another three. The
        // pooled six would cross CLUSTER_MIN_SAMPLES; per-regime, neither trio
        // does — so no warning may fire, however the pooling flag is set. A
        // warning from pooled values would be exactly the S4 misread: two
        // regimes' honest tails stacked into one "cluster".
        let entries = vec![
            entry_with_values(count_values(&[19, 19, 18]), None),
            entry_with_values(count_values(&[19, 18, 19]), Some("9.9.9")),
        ];
        for across in [false, true] {
            let built = distribution(&entries, &count_ladder, across);
            assert!(
                built.warnings.is_empty(),
                "across={across}: {:?}",
                built.warnings
            );
        }
    }

    #[test]
    fn a_single_regime_needs_no_refusal_and_no_flag() {
        let entries = vec![entry_with_values(count_values(&[1, 2]), None)];
        let built = distribution(&entries, &count_ladder, false);
        assert!(built.refusals.is_empty());
        assert!(built.metrics[0].pooled.is_none());
    }

    #[test]
    fn dimension_values_come_from_the_schema_spelling() {
        use andon_core::testing::sample_record;
        let record = sample_record();
        // `sample_record` invokes as a hook; the wire spelling is kebab-case
        // via the schema's own rename rule, not a copy here.
        assert_eq!(Dimension::InvocationSource.value_of(&record), "hook");
        assert_eq!(Dimension::Harness.value_of(&record), "claude-code");
        assert_eq!(Dimension::Iteration.value_of(&record), "1");
    }

    #[test]
    fn absent_dimensions_read_as_unrecorded_and_are_filterable() {
        use andon_core::testing::sample_record;
        let mut record = sample_record();
        record.invocation.model = None;
        assert_eq!(Dimension::Model.value_of(&record), "(unrecorded)");
        let filter = Filter::parse("model=(unrecorded)").expect("parses");
        assert!(filter.matches(&record));
    }

    #[test]
    fn filters_parse_and_reject_with_guidance() {
        assert!(Filter::parse("harness=claude-code").is_ok());
        let err = Filter::parse("nonsense").expect_err("no equals sign");
        assert!(err.contains("<dimension>=<value>"), "{err}");
        let err = Filter::parse("colour=red").expect_err("unknown dimension");
        assert!(err.contains("source, harness"), "{err}");
    }

    #[test]
    fn slices_count_records_and_verdicts() {
        use andon_core::testing::sample_record;
        let entries: Vec<LedgerEntry> = (0..3)
            .map(|i| {
                let mut record = sample_record();
                record.invocation.iteration = if i < 2 { 1 } else { 2 };
                LedgerEntry {
                    commit: "0".repeat(40),
                    record,
                }
            })
            .collect();
        let sliced = slice(&entries, Dimension::Iteration);
        assert_eq!(sliced["1"].records, 2);
        assert_eq!(sliced["2"].records, 1);
        assert_eq!(sliced["1"].verdicts["advise"], 2);
    }
}
