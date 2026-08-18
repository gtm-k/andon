//! Pre-policy severity: the declared ladder each engine maps its own numbers
//! onto, before any ceiling is applied.
//!
//! # The seam this closes
//!
//! Two phases wrote down two different divisions of labour, each internally
//! consistent, each passing its own gate. `clones/src/engine.rs` said "the
//! engine knows what it found; **policy** decides what that is worth".
//! [`super::severity`] said "**engines** set a pre-policy severity, the strength
//! of the thing they found, in their own terms". Each named the other as the
//! owner of severity assignment, neither built it, and so nothing in the shipped
//! configuration could reach the MED+ band at all: every write to `severity`
//! outside a test was `Info`, `Low`, or a `.min()`. The ceiling was built
//! correctly and the thing it caps was never built.
//!
//! [`super::severity`]'s sentence is the one that stands (PLAN decision log,
//! mini-G2 ruling). This module is the half that was missing.
//!
//! # Declared once per metric, applied at one boundary
//!
//! The risk in "engines assign" is five engines drifting into five different
//! ideas of what a severity means. It is bounded here by construction rather
//! than by discipline:
//!
//! - An engine declares **one** [`SeverityLadder`] per metric id, in the same
//!   table where it already declares that metric exactly once
//!   ([`crate::engine::MeasureEngine::severity_ladders`]). There is one
//!   declaration site per metric and it is the metric's own.
//! - [`crate::engine::run_engine`] — the one supported way to invoke an engine —
//!   **assigns** `severity` from that declaration. Engines do not write the
//!   field at their result-construction sites at all, so there is nowhere for a
//!   second opinion to live.
//! - A result whose metric declares no ladder is refused, not defaulted. A
//!   silent default is the failure class this module exists to close.
//!
//! # What a ladder ranks, and what it does not
//!
//! A ladder reads the result's own `value` and nothing else. It does not read
//! the delta (three of the four engines emit no delta at all, by their own
//! documented reasoning), it does not read policy, and it does not read the
//! registry. Its answer is the *strength of the thing the engine found*, in the
//! engine's own units — which is exactly what [`super::severity::ceiling`] then
//! caps by completeness, tier, actionability, and operator appetite.
//!
//! A value with no number in it — [`MetricValue::Text`], which every engine uses
//! to say "the inputs were not there" — ranks at [`Severity::Info`] under every
//! ladder. There is nothing to rank, and inventing a rank for an absent
//! measurement is the fabricated zero PLAN P4 rules out.
//!
//! # Thresholds are declarations, not findings
//!
//! Where a metric's band comes from published work, the declaration says so and
//! names it. Where it does not — and for most of these it does not — the
//! declaration says **project-declared** in as many words. A threshold is a
//! judgement about how loud to be, not a result from the literature, and
//! dressing one up as the other is the overstatement the evidence registry
//! exists to prevent. The registry keeps its own job: `tier` and `class` decide
//! what a claim is *allowed* to reach, and in the shipped configuration they cap
//! most of these ladders well below the band they can express.

use crate::schema::enums::Severity;
use crate::schema::payload::MetricValue;

/// A value at which a metric reaches the next rung.
///
/// Typed to the [`MetricValue`] kind it compares against rather than collapsed
/// to one float. A ladder declared in the wrong units is then a refusal at the
/// engine boundary instead of a comparison that silently always answers `Info`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Threshold {
    /// Compares against [`MetricValue::Count`].
    Count(u64),
    /// Compares against [`MetricValue::Integer`].
    Integer(i64),
    /// Compares against [`MetricValue::Ratio`]. Quantized like the value is, so
    /// a threshold and a value that render identically compare identically.
    Ratio(f64),
    /// Compares against [`MetricValue::Duration`].
    Millis(u64),
}

impl Threshold {
    /// Whether `value` has reached this rung.
    ///
    /// `None` when the value is of a kind this threshold cannot compare against
    /// — a mis-declared ladder, which the caller turns into a refusal.
    fn reached_by(self, value: &MetricValue) -> Option<bool> {
        match (self, value) {
            (Threshold::Count(at), MetricValue::Count(v)) => Some(*v >= at),
            (Threshold::Integer(at), MetricValue::Integer(v)) => Some(*v >= at),
            (Threshold::Ratio(at), MetricValue::Ratio(v)) => Some(*v >= at),
            (Threshold::Millis(at), MetricValue::Duration { millis }) => Some(*millis >= at),
            _ => None,
        }
    }

    /// Whether `next` sits strictly above this rung on the same axis.
    ///
    /// `None` when the two compare against different kinds of value — a rung
    /// list that changes units partway through, which has no ordering at all
    /// and is a refusal rather than a comparison.
    fn strictly_below(self, next: Threshold) -> Option<bool> {
        match (self, next) {
            (Threshold::Count(a), Threshold::Count(b)) => Some(a < b),
            (Threshold::Integer(a), Threshold::Integer(b)) => Some(a < b),
            (Threshold::Ratio(a), Threshold::Ratio(b)) => Some(a < b),
            (Threshold::Millis(a), Threshold::Millis(b)) => Some(a < b),
            _ => None,
        }
    }

    /// The kind name, for a refusal a reader can act on.
    fn kind(self) -> &'static str {
        match self {
            Threshold::Count(_) => "count",
            Threshold::Integer(_) => "integer",
            Threshold::Ratio(_) => "ratio",
            Threshold::Millis(_) => "duration",
        }
    }
}

/// One rung of a ladder: at or above `at`, the metric reaches `severity`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rung {
    /// The value at which this rung is reached.
    pub at: Threshold,
    /// The severity reached there.
    pub severity: Severity,
}

/// How one metric turns its own number into a pre-policy severity.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeverityLadder {
    /// This metric has no severity opinion. Every result stays at `Info`.
    ///
    /// Not an omission and not a default: a metric declares this deliberately,
    /// because ranking it would be inventing a judgement. The P1.5 trust spike
    /// counts sizes; the static family's parse-error and parse-missing counts
    /// are the *report of* a degradation, whose severity question belongs to
    /// `tamper.parse-error-delta` and not to the counts themselves.
    NoOpinion,
    /// Ascending rungs over the metric's own value. The highest rung the value
    /// reaches wins; a value below every rung is `Info`.
    Thresholds(&'static [Rung]),
    /// A boolean detector: this severity when the flag is true, `Info` when it
    /// is false.
    Flag(Severity),
    /// The engine assigns per result, from a rule a threshold table cannot
    /// express.
    ///
    /// The only shipped user is the tamper suite, whose severity is declared
    /// per *detector* (`Detector::severity_when_fired`, with one detector
    /// overriding it per firing) rather than per metric — a declaration that
    /// already exists, is already reviewed, and would become a second, driftable
    /// copy if it were restated as a table here. `run_engine` still applies the
    /// completeness ceiling to it, so the escape hatch is from the *table*, not
    /// from the rules.
    ///
    /// `shipped_severity_band::per_result_ladders_are_the_tamper_suite_and_nothing_else`
    /// enumerates every metric that declares this, so a second user is a visible
    /// diff rather than a quiet spread.
    PerResult,
}

/// A ladder that cannot be applied to the value it met.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LadderError {
    /// A rung compares against a different kind of value than the metric emits.
    #[error(
        "the declared ladder compares a {threshold_kind} threshold against a {value_kind} value"
    )]
    KindMismatch {
        /// What the rung declared.
        threshold_kind: &'static str,
        /// What the result carried.
        value_kind: &'static str,
    },
    /// [`SeverityLadder::Flag`] was declared for a metric that is not a flag.
    #[error("the declared ladder is a flag ladder but the value is a {value_kind}")]
    NotAFlag {
        /// What the result carried.
        value_kind: &'static str,
    },
    /// [`SeverityLadder::Thresholds`] was declared for a boolean.
    #[error("the declared ladder has thresholds but the value is a flag")]
    ThresholdsOverAFlag,
    /// The rungs are not in ascending severity order.
    #[error("the declared rungs are not in ascending severity order")]
    UnorderedRungs,
    /// The rungs' severities ascend but their thresholds do not.
    #[error("the declared thresholds do not ascend with the severities they carry")]
    UnorderedThresholds,
    /// Two rungs compare against different kinds of value.
    #[error("the declared rungs mix a {first} threshold with a {second} one")]
    MixedThresholdKinds {
        /// The lower rung's kind.
        first: &'static str,
        /// The rung declared above it.
        second: &'static str,
    },
}

/// The [`MetricValue`] kind name, for refusals.
fn value_kind(value: &MetricValue) -> &'static str {
    match value {
        MetricValue::Count(_) => "count",
        MetricValue::Integer(_) => "integer",
        MetricValue::Ratio(_) => "ratio",
        MetricValue::Duration { .. } => "duration",
        MetricValue::Flag(_) => "flag",
        MetricValue::Text(_) => "text",
    }
}

impl SeverityLadder {
    /// The pre-policy severity this ladder gives that value.
    ///
    /// [`SeverityLadder::PerResult`] answers `None`: the engine has already
    /// written the severity and `run_engine` keeps it.
    pub fn severity_for(self, value: &MetricValue) -> Result<Option<Severity>, LadderError> {
        match self {
            SeverityLadder::PerResult => Ok(None),
            SeverityLadder::NoOpinion => Ok(Some(Severity::Info)),
            SeverityLadder::Flag(fired) => match value {
                MetricValue::Flag(true) => Ok(Some(fired)),
                MetricValue::Flag(false) => Ok(Some(Severity::Info)),
                // An absent measurement is not a firing and not a non-firing.
                MetricValue::Text(_) => Ok(Some(Severity::Info)),
                other => Err(LadderError::NotAFlag {
                    value_kind: value_kind(other),
                }),
            },
            SeverityLadder::Thresholds(rungs) => {
                ascending(rungs)?;
                match value {
                    // No number, nothing to rank. The `unwitnessed` case every
                    // engine spells as text.
                    MetricValue::Text(_) => return Ok(Some(Severity::Info)),
                    MetricValue::Flag(_) => return Err(LadderError::ThresholdsOverAFlag),
                    _ => {}
                }
                let mut reached = Severity::Info;
                for rung in rungs {
                    match rung.at.reached_by(value) {
                        Some(true) => reached = reached.max(rung.severity),
                        Some(false) => {}
                        None => {
                            return Err(LadderError::KindMismatch {
                                threshold_kind: rung.at.kind(),
                                value_kind: value_kind(value),
                            })
                        }
                    }
                }
                Ok(Some(reached))
            }
        }
    }

    /// The strongest severity this ladder can ever produce.
    ///
    /// What the shipped-band assertion reads: whether a family *can* reach MED+
    /// is a property of the declarations, and answering it by measuring one
    /// fixture would only ever prove the fixture.
    pub fn strongest(self) -> Severity {
        match self {
            SeverityLadder::NoOpinion => Severity::Info,
            SeverityLadder::Flag(fired) => fired,
            SeverityLadder::Thresholds(rungs) => rungs
                .iter()
                .map(|rung| rung.severity)
                .max()
                .unwrap_or(Severity::Info),
            // A deliberate upper bound, and it IS a restatement — the previous
            // comment claimed otherwise. The real declaration is per detector
            // (`Detector::severity_when_fired`, `High` for the six that describe
            // evidence being removed and `Low` for the threshold edit) and it
            // lives downstream of this crate, which depends on no engine and so
            // cannot read it. `Critical` is the ceiling of the scale rather than
            // the suite's actual maximum, chosen because the one direction this
            // answer must never take is under-reporting what a ladder can do:
            // no caller may conclude "this family cannot reach MED+" from a
            // number this module had to guess.
            SeverityLadder::PerResult => Severity::Critical,
        }
    }
}

/// Whether the rungs ascend — on **both** axes, in lockstep, in one unit.
///
/// The severity axis alone is not enough, and the reason is the over-reporting
/// direction this project ranks worse than a miss. `severity_for` takes the
/// maximum over every rung the value reached, so a table whose severities
/// ascend while its thresholds descend hands the *lowest* value the *highest*
/// rung: invert the cyclomatic table to 51/21/11 and a function needing eleven
/// test paths reports `Critical`. That mutation left the whole workspace green
/// while the check read one axis.
///
/// The units are checked here too. A rung list that changes kind partway
/// through has no ordering to verify, and at `severity_for` time only the rungs
/// matching the value's kind would ever be compared — the others would refuse
/// or, worse, be the ones that happened to match.
fn ascending(rungs: &[Rung]) -> Result<(), LadderError> {
    for pair in rungs.windows(2) {
        let (lower, upper) = (pair[0], pair[1]);
        match lower.at.strictly_below(upper.at) {
            None => {
                return Err(LadderError::MixedThresholdKinds {
                    first: lower.at.kind(),
                    second: upper.at.kind(),
                })
            }
            Some(false) => return Err(LadderError::UnorderedThresholds),
            Some(true) => {}
        }
        if lower.severity >= upper.severity {
            return Err(LadderError::UnorderedRungs);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTS: &[Rung] = &[
        Rung {
            at: Threshold::Count(10),
            severity: Severity::Medium,
        },
        Rung {
            at: Threshold::Count(20),
            severity: Severity::High,
        },
        Rung {
            at: Threshold::Count(50),
            severity: Severity::Critical,
        },
    ];

    fn severity(ladder: SeverityLadder, value: MetricValue) -> Severity {
        ladder
            .severity_for(&value)
            .expect("the ladder applies")
            .expect("not a per-result ladder")
    }

    #[test]
    fn a_value_below_every_rung_is_info() {
        assert_eq!(
            severity(SeverityLadder::Thresholds(COUNTS), MetricValue::Count(9)),
            Severity::Info
        );
    }

    #[test]
    fn the_highest_rung_reached_wins() {
        let ladder = SeverityLadder::Thresholds(COUNTS);
        assert_eq!(severity(ladder, MetricValue::Count(10)), Severity::Medium);
        assert_eq!(severity(ladder, MetricValue::Count(19)), Severity::Medium);
        assert_eq!(severity(ladder, MetricValue::Count(20)), Severity::High);
        assert_eq!(severity(ladder, MetricValue::Count(49)), Severity::High);
        assert_eq!(severity(ladder, MetricValue::Count(50)), Severity::Critical);
        assert_eq!(
            severity(ladder, MetricValue::Count(u64::MAX)),
            Severity::Critical
        );
    }

    #[test]
    fn a_rung_is_reached_at_its_own_value_not_above_it() {
        // The boundary, pinned in both directions: an off-by-one here moves
        // every threshold in the workspace by one unit and nothing else fails.
        let ladder = SeverityLadder::Thresholds(COUNTS);
        assert_eq!(severity(ladder, MetricValue::Count(9)), Severity::Info);
        assert_eq!(severity(ladder, MetricValue::Count(10)), Severity::Medium);
    }

    #[test]
    fn an_absent_measurement_ranks_at_info_under_every_ladder() {
        // Every engine spells "the inputs were not there" as text. Ranking it
        // would be the fabricated number PLAN P4 rules out.
        let absent = MetricValue::Text("no-history".to_string());
        assert_eq!(
            severity(SeverityLadder::Thresholds(COUNTS), absent.clone()),
            Severity::Info
        );
        assert_eq!(
            severity(SeverityLadder::Flag(Severity::High), absent),
            Severity::Info
        );
    }

    #[test]
    fn a_flag_ladder_ranks_only_a_firing() {
        let ladder = SeverityLadder::Flag(Severity::High);
        assert_eq!(severity(ladder, MetricValue::Flag(true)), Severity::High);
        assert_eq!(severity(ladder, MetricValue::Flag(false)), Severity::Info);
    }

    #[test]
    fn no_opinion_is_info_whatever_the_number() {
        assert_eq!(
            severity(SeverityLadder::NoOpinion, MetricValue::Count(1_000_000)),
            Severity::Info
        );
    }

    #[test]
    fn a_per_result_ladder_defers_to_the_engine() {
        assert_eq!(
            SeverityLadder::PerResult
                .severity_for(&MetricValue::Flag(true))
                .expect("applies"),
            None
        );
    }

    #[test]
    fn a_ladder_declared_in_the_wrong_units_is_a_refusal_not_an_info() {
        // The silent-default failure, in miniature. A count ladder over a ratio
        // would compare nothing and answer `Info` forever, which reads exactly
        // like a metric that never fires.
        let err = SeverityLadder::Thresholds(COUNTS)
            .severity_for(&MetricValue::Ratio(0.9))
            .expect_err("a kind mismatch must refuse");
        assert!(matches!(err, LadderError::KindMismatch { .. }), "{err:?}");

        assert!(matches!(
            SeverityLadder::Thresholds(COUNTS).severity_for(&MetricValue::Flag(true)),
            Err(LadderError::ThresholdsOverAFlag)
        ));
        assert!(matches!(
            SeverityLadder::Flag(Severity::High).severity_for(&MetricValue::Count(3)),
            Err(LadderError::NotAFlag { .. })
        ));
    }

    #[test]
    fn rungs_that_do_not_ascend_are_refused() {
        const DESCENDING: &[Rung] = &[
            Rung {
                at: Threshold::Count(10),
                severity: Severity::High,
            },
            Rung {
                at: Threshold::Count(20),
                severity: Severity::Medium,
            },
        ];
        assert!(matches!(
            SeverityLadder::Thresholds(DESCENDING).severity_for(&MetricValue::Count(30)),
            Err(LadderError::UnorderedRungs)
        ));
    }

    #[test]
    fn an_inverted_threshold_axis_is_refused() {
        // THE MUTANT THIS KILLS, in the reviewer's own shape: the shipped
        // cyclomatic table (11/21/51 → Medium/High/Critical) with its threshold
        // axis reversed. The severities still ascend, so a check that read one
        // axis passed it — and because `severity_for` takes the maximum over
        // every rung reached, a function needing eleven test paths then reported
        // `Critical`. Over-reporting, which this project ranks worse than a
        // miss, with the whole workspace green.
        const INVERTED: &[Rung] = &[
            Rung {
                at: Threshold::Count(51),
                severity: Severity::Medium,
            },
            Rung {
                at: Threshold::Count(21),
                severity: Severity::High,
            },
            Rung {
                at: Threshold::Count(11),
                severity: Severity::Critical,
            },
        ];
        assert!(matches!(
            SeverityLadder::Thresholds(INVERTED).severity_for(&MetricValue::Count(11)),
            Err(LadderError::UnorderedThresholds)
        ));

        // A repeated threshold is the same defect one unit smaller: the lower
        // rung can never be the highest one reached, so it is a rung that does
        // nothing, and the next editor reads it as if it did.
        const REPEATED: &[Rung] = &[
            Rung {
                at: Threshold::Count(10),
                severity: Severity::Medium,
            },
            Rung {
                at: Threshold::Count(10),
                severity: Severity::High,
            },
        ];
        assert!(matches!(
            SeverityLadder::Thresholds(REPEATED).severity_for(&MetricValue::Count(10)),
            Err(LadderError::UnorderedThresholds)
        ));
    }

    #[test]
    fn rungs_that_mix_threshold_kinds_are_refused() {
        // A list that changes units partway through has no ordering to check,
        // and at application time only the rungs matching the value's kind would
        // be compared at all — so the ladder's answer would depend on which of
        // its own rungs the metric happened to agree with.
        const MIXED: &[Rung] = &[
            Rung {
                at: Threshold::Count(10),
                severity: Severity::Medium,
            },
            Rung {
                at: Threshold::Ratio(0.5),
                severity: Severity::High,
            },
        ];
        assert!(matches!(
            SeverityLadder::Thresholds(MIXED).severity_for(&MetricValue::Count(30)),
            Err(LadderError::MixedThresholdKinds {
                first: "count",
                second: "ratio"
            })
        ));
    }

    #[test]
    fn every_shipped_ladder_shape_is_well_formed_before_it_is_read() {
        // The refusals above are only worth anything if the check runs on the
        // path the engines use, which is `severity_for` — so a well-formed
        // ladder must still answer, and the ordering check must not have become
        // a refusal of everything.
        assert_eq!(
            severity(SeverityLadder::Thresholds(COUNTS), MetricValue::Count(20)),
            Severity::High
        );
    }

    #[test]
    fn ratio_rungs_compare_against_ratios() {
        const RATIOS: &[Rung] = &[Rung {
            at: Threshold::Ratio(0.25),
            severity: Severity::Medium,
        }];
        let ladder = SeverityLadder::Thresholds(RATIOS);
        assert_eq!(severity(ladder, MetricValue::Ratio(0.24)), Severity::Info);
        assert_eq!(severity(ladder, MetricValue::Ratio(0.25)), Severity::Medium);
    }

    #[test]
    fn the_strongest_rung_is_what_the_band_assertion_reads() {
        assert_eq!(
            SeverityLadder::Thresholds(COUNTS).strongest(),
            Severity::Critical
        );
        assert_eq!(SeverityLadder::NoOpinion.strongest(), Severity::Info);
        assert_eq!(
            SeverityLadder::Flag(Severity::High).strongest(),
            Severity::High
        );
        assert!(!SeverityLadder::NoOpinion.strongest().is_med_plus());
    }
}
