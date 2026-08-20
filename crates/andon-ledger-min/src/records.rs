//! Reading, writing, and cross-comparing records outside the ledger.
//!
//! The cross-OS matrix is the reason this module exists. Three agent legs each
//! measure the same fixture and write a record to a file; a Linux verifier leg
//! collects them and asks one question — **are the per-result digests
//! byte-identical?** That question is not the attestation compare: there is no
//! self-report and no verdict here, only "did these machines produce the same
//! bytes". Keeping it separate keeps the matrix's failure message about
//! determinism rather than about trust.
//!
//! # What is compared, and what deliberately is not
//!
//! Per-result digests, paired by `(metric_id, scope)`. Not the whole record:
//! `freshness.measured_at` is a wall clock, `compare_context.git_version` is
//! whatever the runner image ships, and `tool.build_oid` depends on how the leg
//! was built. All three legitimately differ between two honest machines, and all
//! three are outside [`andon_core::schema::payload::ResultDigestInput`] for that
//! reason. A matrix that compared whole records would be red every run and prove
//! nothing.
//!
//! The `(base_oid, head_oid)` tuple *is* checked, first and separately. Every
//! digest binds the tuple, so a leg that measured a different commit would fail
//! every row at once with no indication why — and "you measured a different
//! thing" is a different problem from "you got a different answer".

use std::path::Path;

use andon_core::canonical::{self, CanonicalError};
use andon_core::schema::payload::MeasurementRecord;

/// A record could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// Filesystem work failed.
    #[error("{detail}: {source}")]
    Io {
        /// What was being attempted.
        detail: String,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not a measurement record.
    #[error("{path} is not a measurement record: {source}")]
    Parse {
        /// The file at fault.
        path: String,
        /// The parse failure.
        #[source]
        source: serde_json::Error,
    },
    /// The file parsed as a record whose fields do not hash to its own digests.
    ///
    /// The matrix's whole question is whether independent legs produced the
    /// same bytes, and a leg record edited after sealing would answer it with
    /// bytes nobody produced.
    #[error("{path} holds a record that cannot be believed: {source}")]
    SealBroken {
        /// The file at fault.
        path: String,
        /// Which seal does not hold, and why that is a refusal.
        #[source]
        source: andon_core::schema::payload::SealError,
    },
    /// The record could not be canonically serialized.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

/// Read a record from a JSON file.
pub fn read(path: &Path) -> Result<MeasurementRecord, RecordError> {
    let text = std::fs::read_to_string(path).map_err(|source| RecordError::Io {
        detail: format!("read {}", path.display()),
        source,
    })?;
    let record: MeasurementRecord =
        serde_json::from_str(&text).map_err(|source| RecordError::Parse {
            path: path.display().to_string(),
            source,
        })?;
    record
        .verify_seals()
        .map_err(|source| RecordError::SealBroken {
            path: path.display().to_string(),
            source,
        })?;
    Ok(record)
}

/// Write a record as canonical JSON.
///
/// Canonical rather than pretty, so a record written on one leg and read on
/// another is byte-identical when the measurement is — which makes a plain
/// `diff` of two artifacts a usable first diagnostic before anyone reaches for
/// the digest table.
pub fn write(path: &Path, record: &MeasurementRecord) -> Result<(), RecordError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| RecordError::Io {
                detail: format!("create {}", parent.display()),
                source,
            })?;
        }
    }
    let mut text = canonical::to_canonical_string(record)?;
    text.push('\n');
    std::fs::write(path, text).map_err(|source| RecordError::Io {
        detail: format!("write {}", path.display()),
        source,
    })
}

/// One result's identity and digest, as the matrix reads it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DigestRow {
    /// Which metric.
    pub metric_id: String,
    /// Canonical JSON of the scope. The pairing key, spelled out so that a
    /// mismatch names which file the disagreement is about.
    pub scope: String,
    /// The per-result digest.
    pub digest: String,
    /// Whether the producing side put this result in the compare set.
    pub deterministic: bool,
}

/// Every result of a record as a sorted digest table.
pub fn digest_rows(record: &MeasurementRecord) -> Result<Vec<DigestRow>, RecordError> {
    let mut rows: Vec<DigestRow> = record
        .results
        .iter()
        .map(|result| {
            Ok(DigestRow {
                metric_id: result.metric_id.clone(),
                scope: canonical::to_canonical_string(&result.scope)?,
                digest: result.digest.clone(),
                deterministic: result.deterministic,
            })
        })
        .collect::<Result<_, CanonicalError>>()?;
    rows.sort();
    Ok(rows)
}

/// The outcome of comparing several legs' records.
#[derive(Debug, Clone)]
pub struct CrossCompare {
    /// Leg labels, in the order given.
    pub legs: Vec<String>,
    /// One entry per `(metric_id, scope)`: the digest each leg produced.
    pub rows: Vec<CrossRow>,
    /// Why the comparison failed, empty when it did not.
    pub problems: Vec<String>,
}

impl CrossCompare {
    /// Whether every leg agreed.
    pub fn agreed(&self) -> bool {
        self.problems.is_empty()
    }
}

/// One result, across every leg.
#[derive(Debug, Clone)]
pub struct CrossRow {
    /// Which metric.
    pub metric_id: String,
    /// Canonical scope.
    pub scope: String,
    /// Each leg's digest, `None` where that leg produced no such result.
    pub digests: Vec<Option<String>>,
    /// True when every leg produced this result and every digest agrees.
    pub agreed: bool,
}

/// Compare per-result digests across legs.
///
/// The first leg is the reference only for ordering; disagreement is symmetric
/// and reported as such. `expected_results` is the count the fixture manifest
/// declares — see the note inside on why an observed count would prove nothing.
pub fn compare(
    legs: &[(String, MeasurementRecord)],
    expected_results: Option<usize>,
) -> Result<CrossCompare, RecordError> {
    let mut problems = Vec::new();
    if legs.len() < 2 {
        problems.push(format!(
            "a cross-leg comparison needs at least two records, got {}",
            legs.len()
        ));
    }

    // The floor, stated by the caller from the fixture manifest rather than
    // read off whatever the run produced. Four legs that each measured nothing
    // agree perfectly about nothing, and every assertion below would be
    // vacuously true — an engine that silently stopped emitting results would
    // turn this workflow green rather than red.
    if let Some(wanted) = expected_results {
        for (label, record) in legs {
            if record.results.len() != wanted {
                problems.push(format!(
                    "{label} produced {} result(s); the fixture declares {wanted}",
                    record.results.len()
                ));
            }
        }
    }

    // Tuple equality first: every digest binds `(base_oid, head_oid)`, so a leg
    // that measured a different commit fails every row and says nothing useful
    // about determinism.
    if let Some((reference_label, reference)) = legs.first() {
        for (label, record) in &legs[1..] {
            let a = &reference.compare_context;
            let b = &record.compare_context;
            if a.base_oid != b.base_oid || a.head_oid != b.head_oid {
                problems.push(format!(
                    "{label} measured ({}..{}) but {reference_label} measured ({}..{}); \
                     the legs are not measuring the same change",
                    b.base_oid, b.head_oid, a.base_oid, a.head_oid
                ));
            }
        }
    }

    let tables: Vec<Vec<DigestRow>> = legs
        .iter()
        .map(|(_, record)| digest_rows(record))
        .collect::<Result<_, _>>()?;

    // The union of keys, not the first leg's: a leg that produced *fewer*
    // results than the others is a disagreement, and keying off one table would
    // hide it.
    let mut keys: Vec<(String, String)> = tables
        .iter()
        .flat_map(|rows| rows.iter().map(|r| (r.metric_id.clone(), r.scope.clone())))
        .collect();
    keys.sort();
    keys.dedup();

    let mut rows = Vec::with_capacity(keys.len());
    for (metric_id, scope) in keys {
        let digests: Vec<Option<String>> = tables
            .iter()
            .map(|table| {
                table
                    .iter()
                    .find(|r| r.metric_id == metric_id && r.scope == scope)
                    .map(|r| r.digest.clone())
            })
            .collect();
        let present: Vec<&String> = digests.iter().flatten().collect();
        let agreed =
            present.len() == legs.len() && present.windows(2).all(|pair| pair[0] == pair[1]);
        if !agreed {
            problems.push(format!(
                "{metric_id} {scope}: {}",
                digests
                    .iter()
                    .zip(legs)
                    .map(|(digest, (label, _))| format!(
                        "{label}={}",
                        digest.as_deref().unwrap_or("<absent>")
                    ))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
        }
        rows.push(CrossRow {
            metric_id,
            scope,
            digests,
            agreed,
        });
    }

    Ok(CrossCompare {
        legs: legs.iter().map(|(label, _)| label.clone()).collect(),
        rows,
        problems,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use andon_core::schema::payload::MetricValue;
    use andon_core::testing::sample_record;

    /// A record whose value was edited without re-sealing must not read back.
    ///
    /// There is no recompute at a file read, so the read itself is the only
    /// place the edit can be noticed: the digest beside the value still
    /// describes the number that used to be there.
    #[test]
    fn a_value_edited_without_resealing_does_not_read_back() {
        let dir = std::env::temp_dir().join(format!("andon-records-seal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("record.json");

        let mut record = sample_record();
        write(&path, &record).expect("writes");
        read(&path).expect("an honest record reads back");

        record.results[0].value = MetricValue::Count(999_999);
        write(&path, &record).expect("the write path does not judge");
        let err = read(&path).expect_err("a record that contradicts itself must not read back");
        assert!(err.to_string().contains("sample.metric"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identical_records_agree() {
        let compared = compare(
            &[
                ("linux".to_string(), sample_record()),
                ("windows".to_string(), sample_record()),
                ("macos".to_string(), sample_record()),
            ],
            None,
        )
        .expect("records compare");
        assert!(compared.agreed(), "{:?}", compared.problems);
        assert!(compared.rows.iter().all(|r| r.agreed));
    }

    #[test]
    fn a_single_digest_difference_names_the_leg_and_the_metric() {
        let mut windows = sample_record();
        windows.results[0].digest = "0".repeat(64);
        let compared = compare(
            &[
                ("linux".to_string(), sample_record()),
                ("windows".to_string(), windows),
            ],
            None,
        )
        .expect("records compare");
        assert!(!compared.agreed());
        let report = compared.problems.join("\n");
        assert!(report.contains("sample.metric"), "{report}");
        assert!(report.contains("windows="), "{report}");
    }

    #[test]
    fn a_leg_that_produced_fewer_results_is_a_disagreement() {
        // Keying off the first leg's table would report agreement here, which is
        // the shape of a matrix that passes because one leg measured nothing.
        let mut sparse = sample_record();
        sparse.results.clear();
        let compared = compare(
            &[
                ("linux".to_string(), sample_record()),
                ("macos".to_string(), sparse),
            ],
            None,
        )
        .expect("records compare");
        assert!(!compared.agreed());
        assert!(compared.problems.join("\n").contains("<absent>"));
    }

    #[test]
    fn legs_that_measured_different_commits_are_refused_before_the_digests() {
        let mut other = sample_record();
        other.compare_context.head_oid = "9".repeat(40);
        let compared = compare(
            &[
                ("linux".to_string(), sample_record()),
                ("windows".to_string(), other),
            ],
            None,
        )
        .expect("records compare");
        assert!(compared.problems[0].contains("not measuring the same change"));
    }

    #[test]
    fn a_leg_short_of_the_declared_result_count_fails_the_comparison() {
        // Four legs that each measured nothing agree perfectly about nothing.
        // Without a floor stated by the fixture, an engine that silently stopped
        // emitting results would turn the matrix green rather than red.
        let mut empty = sample_record();
        empty.results.clear();
        let compared = compare(
            &[
                ("linux".to_string(), sample_record()),
                ("macos".to_string(), empty),
            ],
            Some(1),
        )
        .expect("records compare");
        assert!(!compared.agreed());
        assert!(
            compared
                .problems
                .iter()
                .any(|p| p.contains("the fixture declares 1")),
            "{:?}",
            compared.problems
        );
    }

    #[test]
    fn a_floor_the_legs_meet_is_not_a_complaint() {
        let compared = compare(
            &[
                ("linux".to_string(), sample_record()),
                ("macos".to_string(), sample_record()),
            ],
            Some(1),
        )
        .expect("records compare");
        assert!(compared.agreed(), "{:?}", compared.problems);
    }

    #[test]
    fn one_record_is_not_a_comparison() {
        let compared =
            compare(&[("linux".to_string(), sample_record())], None).expect("records compare");
        assert!(!compared.agreed(), "a single leg proves nothing");
    }
}
