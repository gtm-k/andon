//! The floors, enforced. A report below one of them fails the phase.
//!
//! PLAN.md P3 sets them ex ante — precision >= 0.80, recall >= 0.70 per
//! detector on corpus v1 — and says publication alone is not the gate. This
//! file is what makes that true: the numbers are asserted here, in the test
//! suite that every gate runs, rather than printed into a README somebody reads
//! once.
//!
//! Four things are checked, and each closes a different way for the gate to be
//! satisfied without being met:
//!
//! 1. **The floors themselves.** The arithmetic in `corpus::Score`.
//! 2. **The freeze.** A corpus that has moved since it was frozen invalidates
//!    the numbers; the check is what stops a disappointing measurement from
//!    being answered by editing a case.
//! 3. **The corpus is big enough to mean anything.** With one adversarial case
//!    per detector, recall is 1.00 or 0.00 and the floor is a coin toss.
//! 4. **The published table matches the measured one.** A README that drifts
//!    from the implementation is a claim nobody is checking.

use std::path::{Path, PathBuf};

use andon_engine_tamper::corpus::{self, Family, PRECISION_FLOOR, RECALL_FLOOR};
use andon_engine_tamper::detectors;

/// The fewest cases of each kind a detector needs before its ratios carry
/// information. Five gives recall a 0.2 resolution, which is what makes a 0.70
/// floor a real bar rather than a rounding accident.
const MIN_CASES_PER_DETECTOR: usize = 5;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root is reachable from the crate")
}

#[test]
fn the_corpus_is_still_the_one_that_was_frozen() {
    let marker = corpus::verify_freeze(&repo_root()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(marker.version, 1);
    assert!(
        marker.adversarial_cases >= 7 * MIN_CASES_PER_DETECTOR,
        "corpus v1 declares {} adversarial cases",
        marker.adversarial_cases
    );
}

#[test]
fn every_case_declares_itself_and_loads() {
    let cases = corpus::load(&repo_root()).unwrap_or_else(|e| panic!("{e}"));
    assert!(!cases.is_empty(), "the corpus is empty");
    for case in &cases {
        assert!(
            !case.change.is_empty(),
            "{}: a case with no files cannot demonstrate anything",
            case.id
        );
        assert!(
            !case.manifest.title.trim().is_empty(),
            "{}: no title",
            case.id
        );
    }
}

#[test]
fn each_detector_has_enough_cases_for_its_ratios_to_mean_something() {
    let cases = corpus::load(&repo_root()).unwrap_or_else(|e| panic!("{e}"));
    for detector in detectors::all() {
        let name = detectors::signal_name(detector.signal());
        let expecting = cases
            .iter()
            .filter(|c| c.manifest.expect.iter().any(|s| s == name))
            .count();
        assert!(
            expecting >= MIN_CASES_PER_DETECTOR,
            "{name} has {expecting} should-fire case(s); at least {MIN_CASES_PER_DETECTOR} are \
             needed before its recall is a measurement rather than a coin toss"
        );
    }
    let honest = cases.iter().filter(|c| c.family == Family::Honest).count();
    assert!(
        honest >= 7 * MIN_CASES_PER_DETECTOR,
        "{honest} should-pass cases; precision is measured against them and needs the same floor"
    );

    // And per detector, not only in total. A should-pass corpus of thirty-five
    // cases all aimed at one detector would satisfy the count above while
    // leaving six detectors with no false-positive evidence at all — and
    // precision is the number that separates a useful detector from one that
    // fires on everything.
    for detector in detectors::all() {
        let name = detectors::signal_name(detector.signal());
        let prefix = format!("{name}/");
        let aimed = cases
            .iter()
            .filter(|c| c.family == Family::Honest && c.id.starts_with(&prefix))
            .count();
        assert!(
            aimed >= MIN_CASES_PER_DETECTOR,
            "{name} has {aimed} should-pass case(s) written against it; at least              {MIN_CASES_PER_DETECTOR} are needed before its precision means anything"
        );
    }
}

#[test]
fn every_detector_meets_its_ex_ante_floors() {
    let cases = corpus::load(&repo_root()).unwrap_or_else(|e| panic!("{e}"));
    let report = corpus::measure(&cases);

    // Printed unconditionally: the table is the phase's evidence, and a gate
    // whose evidence only appears on failure is a gate nobody can cite.
    println!(
        "\ncorpus v1 — {} adversarial, {} should-pass; floors precision >= {PRECISION_FLOOR:.2}, \
         recall >= {RECALL_FLOOR:.2}\n",
        report.adversarial_cases, report.honest_cases
    );
    println!("detector                    TP  FN  FP  TN  precision  recall  cross-fires");
    for detector in detectors::all() {
        let name = detectors::signal_name(detector.signal());
        let score = &report.scores[name];
        println!(
            "{:<26}  {:>2}  {:>2}  {:>2}  {:>2}  {:>9}  {:>6}  {:>11}",
            name,
            score.true_positives,
            score.false_negatives,
            score.false_positives,
            score.true_negatives,
            score
                .precision()
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".into()),
            score
                .recall()
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".into()),
            score.cross_fires,
        );
    }

    let mut failures = Vec::new();
    for detector in detectors::all() {
        let name = detectors::signal_name(detector.signal());
        let score = &report.scores[name];
        if score.meets_floors() {
            continue;
        }
        failures.push(format!(
            "{name}: precision {:?}, recall {:?}\n    missed: {}\n    fired on should-pass: {}",
            score.precision(),
            score.recall(),
            if score.missed.is_empty() {
                "-".to_string()
            } else {
                score.missed.join(", ")
            },
            if score.fired_on_honest.is_empty() {
                "-".to_string()
            } else {
                score.fired_on_honest.join(", ")
            },
        ));
    }
    assert!(
        failures.is_empty(),
        "\n{} detector(s) below the ex ante floors:\n  {}\n\n\
         The floors were set before the corpus was written and the corpus was frozen before it \
         was measured. The corpus is not the variable here — the detector is.",
        failures.len(),
        failures.join("\n  ")
    );
}

#[test]
fn the_published_table_is_the_measured_one() {
    let root = repo_root();
    let cases = corpus::load(&root).unwrap_or_else(|e| panic!("{e}"));
    let report = corpus::measure(&cases);
    let readme = std::fs::read_to_string(root.join(corpus::ADVERSARIAL_DIR).join("README.md"))
        .expect("the corpus documents itself");

    for detector in detectors::all() {
        let name = detectors::signal_name(detector.signal());
        let score = &report.scores[name];
        let row = format!(
            "| `{name}` | {} | {} | {} | {} | {} | {} |",
            score.true_positives,
            score.false_negatives,
            score.false_positives,
            score.true_negatives,
            score
                .precision()
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".into()),
            score
                .recall()
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".into()),
        );
        assert!(
            readme.contains(&row),
            "fixtures/adversarial/README.md does not carry the measured row for {name}.\n\
             expected: {row}\n\
             Regenerate it — a published precision figure that no longer describes the build is \
             the registry-rot failure of PREMORTEM S2, in the one table this phase is judged on."
        );
    }
}

/// The language census the registry's honesty fields describe, pinned.
///
/// # Why this exists
///
/// Three tamper claims carry a `does_not_predict` line saying which languages
/// their false-positive rate was actually measured on. Those numbers were
/// hand-counted, shipped wrong, and caught in review — the first version said
/// `lookup-table-blowup` had no non-TypeScript should-pass case, and it has a
/// JSON one; two other counts were off by one because files were counted where
/// cases were meant.
///
/// Nothing derived them, which is the same shape as the held-back set's status
/// table drifting for eight days. `the_published_table_is_the_measured_one` keeps
/// the precision table honest by rebuilding it; this keeps the language claims
/// honest by pinning what they describe. It cannot read the prose — so if this
/// fails, the prose in `registry/tamper.toml` is what has to move with it.
#[test]
fn the_language_census_the_claims_disclose_is_the_measured_one() {
    use std::collections::BTreeMap;

    let honest = repo_root().join(corpus::HONEST_DIR);
    let mut census: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();

    for detector in std::fs::read_dir(&honest).expect("the honest corpus is readable") {
        let detector = detector.expect("entry").path();
        if !detector.is_dir() {
            continue;
        }
        let name = detector
            .file_name()
            .expect("named")
            .to_string_lossy()
            .into_owned();
        for case in std::fs::read_dir(&detector).expect("detector dir") {
            let case = case.expect("entry").path();
            if !case.join("case.toml").is_file() {
                continue;
            }
            // One language per CASE, not per file: a case is the unit the
            // corpus counts in, and counting files is precisely the mistake the
            // shipped disclosure made.
            let mut exts: Vec<String> = Vec::new();
            let mut stack = vec![case.join("head")];
            while let Some(dir) = stack.pop() {
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for e in entries.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if let Some(ext) = p.extension() {
                        exts.push(ext.to_string_lossy().into_owned());
                    }
                }
            }
            exts.sort();
            exts.dedup();
            let lang = exts.join("+");
            *census
                .entry(name.clone())
                .or_default()
                .entry(lang)
                .or_default() += 1;
        }
    }

    let got = |d: &str, l: &str| census.get(d).and_then(|m| m.get(l)).copied().unwrap_or(0);

    // Pinned against what the three `does_not_predict` lines state. A corpus
    // change that moves any of these makes one of those lines false.
    assert_eq!(
        got("test-removal", "ts"),
        8,
        "test-evidence-withdrawal's line says 8 TypeScript for test-removal:
{census:#?}"
    );
    assert_eq!(
        census["test-removal"].len(),
        1,
        "it also says test-removal has NO other language:
{census:#?}"
    );

    assert_eq!(
        got("assertion-free-test", "ts"),
        6,
        "test-evidence-withdrawal's line says 6 TypeScript:
{census:#?}"
    );
    assert_eq!(
        got("assertion-free-test", "py"),
        1,
        "...beside 1 Python:
{census:#?}"
    );

    assert_eq!(
        got("suppression-density", "ts"),
        5,
        "analysis-blind-spot's line says 5 TypeScript:
{census:#?}"
    );
    assert_eq!(
        got("suppression-density", "py"),
        2,
        "...beside 2 Python:
{census:#?}"
    );

    assert_eq!(
        got("parse-error-delta", "ts"),
        5,
        "analysis-blind-spot's line says 5 TypeScript:
{census:#?}"
    );
    assert_eq!(
        got("parse-error-delta", "js"),
        1,
        "...1 JavaScript:
{census:#?}"
    );
    assert_eq!(
        got("parse-error-delta", "rs"),
        1,
        "...and 1 Rust:
{census:#?}"
    );

    assert_eq!(
        got("lookup-table-blowup", "ts"),
        6,
        "hard-coded-answers' line says 6 TypeScript:
{census:#?}"
    );
    assert_eq!(
        got("lookup-table-blowup", "json"),
        1,
        "...and one JSON fixture, which the line now names:
{census:#?}"
    );

    // The claim every disclosure makes and none of them counts: no TSX anywhere.
    for (detector, langs) in &census {
        assert!(
            !langs.keys().any(|l| l.split('+').any(|e| e == "tsx")),
            "a TSX should-pass case appeared under {detector}; three claims state there is none"
        );
    }
}
