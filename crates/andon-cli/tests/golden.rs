//! The golden set: frozen fixtures, reference payloads, and the ex-ante
//! tolerance.
//!
//! # What this suite is for
//!
//! Three consumers, named before it existed (PLAN P5b, P0's self-measure
//! contract, PREMORTEM S3):
//!
//! 1. **The two-binary comparison.** When a change touches `crates/engines/**`,
//!    the attested release binary and the working tree's binary measure the same
//!    fixtures and their answers are compared. A difference is the *intended*
//!    output of an engine change; the comparison makes it explicit and
//!    reviewable rather than leaving a reviewer to guess which numbers moved on
//!    purpose. Until an attested release exists the comparison runs one binary
//!    against these committed reference payloads, which detects the same class
//!    of change with one fewer party.
//! 2. **The cross-environment determinism study** (VISION §6): byte-identical
//!    per-result digests over the deterministic compare set.
//! 3. **P10a's stability study.**
//!
//! # The tolerance, fixed ex ante and not negotiable after the fact
//!
//! PLAN P5b sets it before any number was recorded, which is the point — a
//! tolerance chosen after seeing the diff is a tolerance chosen to make the diff
//! pass:
//!
//! - **Categorical agreement is 100%.** Verdict, attestation, completeness,
//!   severity, metric class, engine roster, tamper signals, verdict reason codes.
//!   None of these has a tolerance; a disagreement is a failure.
//! - **Counts are always exact.** `Count`, `Integer`, `Flag` and `Text` are
//!   exact values, not measurements with error bars, and comparing them loosely
//!   would mean an off-by-one in a walker passed.
//! - **Numerics get `max(1 absolute unit, 10% relative)`** — the round-2 R2 fold,
//!   which fixes the degenerate case where a purely relative band collapses to
//!   zero near zero.
//! - **Exact where deterministic.** A metric the registry marks deterministic is
//!   in the digest compare set, so its *digest* is pinned rather than its value.
//!   That is strictly stronger than any tolerance and it is the claim VISION §6
//!   actually makes.
//!
//! **Where the band currently bites, stated rather than left to be discovered:**
//! exactly one shipped metric is non-deterministic —
//! `artifacts.uncovered-changed-lines`, because a coverage report is an
//! untracked build output no verifier can reproduce — and its value is a count,
//! so it is compared exactly too. The relative band is therefore implemented,
//! tested, and currently unreached. Saying so is better than a suite that looks
//! like it has slack it does not have.

mod common;

use std::collections::BTreeMap;

use andon_core::schema::enums::InvocationSource;
use andon_core::schema::payload::{MeasurementRecord, MeasurementResult, MetricValue};

/// One result, reduced to the facts a reference payload pins.
///
/// Deliberately not the whole `MeasurementResult`. `freshness` carries wall
/// clock timings and cache state, and `digest` is pinned separately and only for
/// the metrics whose digest is meaningful — comparing whole records would make
/// this suite fail on the clock.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Reference {
    metric_id: String,
    scope: String,
    engine_id: String,
    claim_id: String,
    value: MetricValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delta: Option<MetricValue>,
    severity: String,
    completeness: String,
    metric_class: String,
    deterministic: bool,
    /// Present only for metrics in the compare set. `None` says "this metric's
    /// digest is not a claim anyone makes", which is different from an empty
    /// string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
}

/// A whole reference payload.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Expected {
    /// Recorded so a re-record against a different fixture build is visible.
    base_oid: String,
    head_oid: String,
    verdict: String,
    /// Codes and severities, never messages. A reason's wording is prose that
    /// improves; its code and severity are the contract a consumer branches on
    /// (`verdict::reason`), and pinning the prose would make every wording fix a
    /// golden re-record and train everyone to re-record without reading.
    reasons: Vec<(String, String)>,
    attestation: String,
    completeness: String,
    tamper_signals: Vec<String>,
    engines: Vec<String>,
    policy_hash: String,
    results: Vec<Reference>,
}

fn scope_key(result: &MeasurementResult) -> String {
    andon_core::canonical::to_canonical_string(&result.scope)
        .unwrap_or_else(|_| format!("{:?}", result.scope))
}

fn reference_of(record: &MeasurementRecord) -> Expected {
    let mut results: Vec<Reference> = record
        .results
        .iter()
        .map(|r| Reference {
            metric_id: r.metric_id.clone(),
            scope: scope_key(r),
            engine_id: r.engine_id.clone(),
            claim_id: r.claim_id.clone(),
            value: r.value.clone(),
            delta: r.delta.clone(),
            severity: format!("{:?}", r.severity).to_lowercase(),
            completeness: format!("{:?}", r.completeness).to_lowercase(),
            metric_class: format!("{:?}", r.metric_class).to_lowercase(),
            deterministic: r.deterministic,
            digest: r.deterministic.then(|| r.digest.clone()),
        })
        .collect();
    results.sort_by(|a, b| {
        a.metric_id
            .cmp(&b.metric_id)
            .then_with(|| a.scope.cmp(&b.scope))
    });

    let mut engines: Vec<String> = record.results.iter().map(|r| r.engine_id.clone()).collect();
    engines.sort();
    engines.dedup();

    Expected {
        base_oid: record.compare_context.base_oid.clone(),
        head_oid: record.compare_context.head_oid.clone(),
        verdict: format!("{:?}", record.verdict.verdict).to_lowercase(),
        reasons: record
            .verdict
            .reasons
            .iter()
            .map(|r| (r.code.clone(), format!("{:?}", r.severity).to_lowercase()))
            .collect(),
        attestation: format!("{:?}", record.attestation.value).to_lowercase(),
        completeness: format!("{:?}", record.completeness).to_lowercase(),
        tamper_signals: record
            .attestation
            .tamper_signals
            .iter()
            .map(|s| format!("{s:?}"))
            .collect(),
        engines,
        policy_hash: record.policy_hash.clone(),
        results,
    }
}

/// Whether two values agree under the ex-ante tolerance.
///
/// `deterministic` decides which rule applies, and it comes from the registry
/// rather than from the value's shape: the registry is where "is this in the
/// compare set" is declared, and a second opinion here could disagree with the
/// verifier's.
fn values_agree(expected: &MetricValue, actual: &MetricValue, deterministic: bool) -> bool {
    match (expected, actual) {
        // Counts are always exact — an off-by-one in a walker is a defect, not
        // measurement noise.
        (MetricValue::Count(a), MetricValue::Count(b)) => a == b,
        (MetricValue::Integer(a), MetricValue::Integer(b)) => a == b,
        (MetricValue::Flag(a), MetricValue::Flag(b)) => a == b,
        (MetricValue::Text(a), MetricValue::Text(b)) => a == b,
        (MetricValue::Ratio(a), MetricValue::Ratio(b)) => {
            if deterministic {
                a == b
            } else {
                within_band(*a, *b)
            }
        }
        (MetricValue::Duration { millis: a }, MetricValue::Duration { millis: b }) => {
            if deterministic {
                a == b
            } else {
                within_band(*a as f64, *b as f64)
            }
        }
        // A kind change is a schema change, never a tolerance question.
        _ => false,
    }
}

/// `max(1 absolute unit, 10% relative)`, the round-2 R2 band.
///
/// The absolute floor is the whole point: a purely relative band collapses to
/// nothing near zero, so a metric that moved from 0.0 to 0.4 would fail while
/// one that moved from 1000 to 1099 would pass.
fn within_band(expected: f64, actual: f64) -> bool {
    let tolerance = (expected.abs() * 0.10).max(1.0);
    (expected - actual).abs() <= tolerance
}

/// Measure one built fixture with every shipped engine.
fn measure(built: &common::Built) -> MeasurementRecord {
    andon_cli_measure(built).expect("the fixture measures")
}

/// The measurement, through the same entry point the binary uses.
///
/// Invoked as a subprocess rather than as a library call, deliberately: the
/// golden set is a claim about what **the binary** produces, and a library call
/// would leave the wiring between `main` and the pipeline — argument handling,
/// the registry choice, the policy source — outside everything this suite pins.
fn andon_cli_measure(built: &common::Built) -> Result<MeasurementRecord, String> {
    let exe = env!("CARGO_BIN_EXE_andon");
    let output = std::process::Command::new(exe)
        .args([
            "measure",
            "--repo",
            &built.path().display().to_string(),
            "--base",
            &built.base_oid,
            "--head",
            &built.head_oid,
            "--json",
            "--source",
            source_name(InvocationSource::HumanCli),
        ])
        .output()
        .map_err(|e| format!("{exe}: {e}"))?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err(format!(
            "andon measure exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| {
        format!(
            "{e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn source_name(source: InvocationSource) -> &'static str {
    match source {
        InvocationSource::Hook => "hook",
        InvocationSource::AgentInitiated => "agent-initiated",
        _ => "human-cli",
    }
}

/// Re-record every reference payload. Never run in CI; a deliberate act.
///
/// Guarded by an environment variable rather than by a comment, because
/// re-recording a golden set is exactly the operation that must not happen by
/// accident: a suite that rewrote its own expectations on failure would agree
/// with itself for ever.
#[test]
fn record_reference_payloads() {
    if std::env::var_os("ANDON_RERECORD_GOLDEN").is_none() {
        return;
    }
    for dir in common::cases() {
        let case = common::read_case(&dir);
        let built = common::build(&dir, &case);
        let record = measure(&built);
        let expected = reference_of(&record);
        let text = serde_json::to_string_pretty(&expected).expect("serializes");
        std::fs::write(dir.join("expected.json"), format!("{text}\n")).expect("writes");
        eprintln!("re-recorded {}", case.name);
    }
}

#[test]
fn the_golden_set_is_not_empty() {
    // A suite over zero fixtures passes, which is the shape of vacuity this
    // project has now shipped twice (an empty engine set assembling into a
    // `pass`; a band assertion nothing fed). Named here so it cannot recur
    // quietly.
    let cases = common::cases();
    assert!(
        cases.len() >= 2,
        "the golden set has {} case(s); it needs at least an honest one and a gamed one, or \
         'agreement with reference' is a claim about nothing",
        cases.len()
    );
}

#[test]
fn every_case_agrees_with_its_reference_payload() {
    for dir in common::cases() {
        let case = common::read_case(&dir);
        let built = common::build(&dir, &case);
        let record = measure(&built);
        let actual = reference_of(&record);

        let path = dir.join("expected.json");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}\nRe-record with ANDON_RERECORD_GOLDEN=1 cargo test -p andon-cli --test \
                 golden",
                path.display()
            )
        });
        let expected: Expected =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));

        compare(&case.name, &expected, &actual);
    }
}

fn compare(name: &str, expected: &Expected, actual: &Expected) {
    // The fixture build itself is pinned first. Everything below is a function
    // of these two OIDs — they are inside `ResultDigestInput` — so a drift here
    // would produce a wall of digest failures whose real cause is that the
    // fixture no longer builds the same repository.
    assert_eq!(
        (&expected.base_oid, &expected.head_oid),
        (&actual.base_oid, &actual.head_oid),
        "{name}: the fixture no longer builds the same commits. Every digest below is a \
         function of this tuple, so nothing else in this case is meaningful until it agrees."
    );

    // Categorical agreement: 100%, no band.
    assert_eq!(expected.verdict, actual.verdict, "{name}: verdict");
    assert_eq!(
        expected.attestation, actual.attestation,
        "{name}: attestation"
    );
    assert_eq!(
        expected.completeness, actual.completeness,
        "{name}: record completeness"
    );
    assert_eq!(
        expected.tamper_signals, actual.tamper_signals,
        "{name}: tamper signals"
    );
    assert_eq!(expected.engines, actual.engines, "{name}: engine roster");
    assert_eq!(expected.reasons, actual.reasons, "{name}: verdict reasons");
    assert_eq!(
        expected.policy_hash, actual.policy_hash,
        "{name}: the policy schema moved, so every record's policy_hash did"
    );

    let key = |r: &Reference| (r.metric_id.clone(), r.scope.clone());
    let expected_by: BTreeMap<_, _> = expected.results.iter().map(|r| (key(r), r)).collect();
    let actual_by: BTreeMap<_, _> = actual.results.iter().map(|r| (key(r), r)).collect();

    let missing: Vec<_> = expected_by
        .keys()
        .filter(|k| !actual_by.contains_key(*k))
        .collect();
    let extra: Vec<_> = actual_by
        .keys()
        .filter(|k| !expected_by.contains_key(*k))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{name}: the result set moved.\n  no longer produced: {missing:?}\n  newly produced: \
         {extra:?}"
    );

    for (id, expected) in &expected_by {
        let actual = actual_by[id];
        let where_ = format!("{name}: {} at {}", id.0, id.1);
        assert_eq!(expected.engine_id, actual.engine_id, "{where_}: engine");
        assert_eq!(expected.claim_id, actual.claim_id, "{where_}: claim");
        assert_eq!(expected.severity, actual.severity, "{where_}: severity");
        assert_eq!(
            expected.completeness, actual.completeness,
            "{where_}: completeness"
        );
        assert_eq!(
            expected.metric_class, actual.metric_class,
            "{where_}: class"
        );
        assert_eq!(
            expected.deterministic, actual.deterministic,
            "{where_}: compare-set membership"
        );
        assert!(
            values_agree(&expected.value, &actual.value, expected.deterministic),
            "{where_}: value {:?} vs {:?}",
            expected.value,
            actual.value
        );
        match (&expected.delta, &actual.delta) {
            (Some(a), Some(b)) => assert!(
                values_agree(a, b, expected.deterministic),
                "{where_}: delta {a:?} vs {b:?}"
            ),
            (a, b) => assert_eq!(a.is_some(), b.is_some(), "{where_}: delta presence"),
        }
        // The strongest assertion in the file, and the one VISION §6 actually
        // claims: for a metric in the compare set, the digest itself is pinned.
        // A tolerance on the value would still pass a change that moved the
        // bytes the verifier compares.
        assert_eq!(
            expected.digest, actual.digest,
            "{where_}: per-result digest"
        );
    }
}

#[test]
fn the_deterministic_set_is_digest_pinned_and_non_empty() {
    // The guard against this suite going quietly vacuous. If every reference
    // payload lost its digests — a re-record from a build where the flag had
    // flipped, say — the comparison above would still pass, comparing `None`
    // against `None` for every metric in the tool.
    for dir in common::cases() {
        let case = common::read_case(&dir);
        let text = std::fs::read_to_string(dir.join("expected.json")).expect("a reference");
        let expected: Expected = serde_json::from_str(&text).expect("valid reference");
        let pinned = expected
            .results
            .iter()
            .filter(|r| r.digest.as_ref().is_some_and(|d| d.len() == 64))
            .count();
        assert!(
            pinned > 0,
            "{}: no result in this reference payload carries a pinned digest",
            case.name
        );
        for result in &expected.results {
            assert_eq!(
                result.deterministic,
                result.digest.is_some(),
                "{}: {} pins a digest it is not in the compare set for, or omits one it is",
                case.name,
                result.metric_id
            );
        }
    }
}

#[test]
fn the_fixture_sources_are_lf_so_the_commit_oids_do_not_depend_on_the_checkout() {
    // Every reference digest is a function of `base_oid` and `head_oid`, which
    // are functions of these bytes. A CR in one of them means the fixture builds
    // different commits on a machine that checks out differently, and the
    // failure arrives as a wall of digest mismatches whose real cause is
    // invisible in the diff.
    //
    // `.gitattributes` normalizes `fixtures/golden/**` on the way in, so this
    // should be unreachable — which is the point. It is the assertion that says
    // so, and it survives somebody editing that rule.
    for dir in common::cases() {
        for path in walk(&dir) {
            let bytes = std::fs::read(&path).expect("a fixture file");
            assert!(
                !bytes.windows(2).any(|w| w == b"\r\n"),
                "{} contains CRLF; the commit OIDs this fixture builds would depend on the \
                 checkout that produced it",
                path.display()
            );
        }
    }
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            found.extend(walk(&entry.path()));
        } else {
            found.push(entry.path());
        }
    }
    found
}

#[test]
fn the_band_has_an_absolute_floor_near_zero() {
    // The R2 fold, checked rather than described. A purely relative band would
    // answer `false` to the first of these.
    assert!(within_band(0.0, 0.4));
    assert!(within_band(0.0, 1.0));
    assert!(!within_band(0.0, 1.5));
    // And a relative band above the floor.
    assert!(within_band(1000.0, 1090.0));
    assert!(!within_band(1000.0, 1200.0));
}

#[test]
fn counts_are_exact_whatever_the_compare_set_says() {
    // "counts always exact" is unconditional in the acceptance criterion, so it
    // must not depend on the determinism flag. An off-by-one that passed
    // because a metric happened to be CI-authoritative would be the tolerance
    // covering a defect.
    let a = MetricValue::Count(100);
    let b = MetricValue::Count(101);
    assert!(!values_agree(&a, &b, true));
    assert!(!values_agree(&a, &b, false));
    assert!(values_agree(&a, &a, false));
}

#[test]
fn a_kind_change_is_never_within_tolerance() {
    assert!(!values_agree(
        &MetricValue::Count(1),
        &MetricValue::Integer(1),
        false
    ));
}

#[test]
fn every_case_describes_what_it_is_for() {
    // A fixture nobody can explain is a fixture nobody re-records correctly.
    for dir in common::cases() {
        let case = common::read_case(&dir);
        assert_eq!(case.schema_version, 1, "{}", case.name);
        assert!(
            case.description.len() > 40,
            "{}: describe what this case exists to catch",
            case.name
        );
        assert_eq!(
            case.name,
            dir.file_name().unwrap().to_string_lossy(),
            "case name and directory disagree"
        );
    }
}
