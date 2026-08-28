//! `andon explain` and `andon measure` answer "can this stop the line?" the
//! same way, on the same checkout.
//!
//! `explain`'s "The strongest this finding can be" used to be computed from the
//! severity ceilings alone, so for every tamper detector and for
//! `tests.suite-failure` it printed *"this can advise; it cannot stop the line"*
//! — on the very checkout where `measure` had just returned BLOCK on
//! `tamper.test-removal`. The verdict has two routes that bypass the ceilings
//! (a fired tamper flag; a failed suite), and `explain` consulted neither. An
//! agent that reads `explain` to decide whether a finding matters was told the
//! opposite of what the verdict does.
//!
//! The pin is against the verdict's own route on one measured fixture, not
//! against a sentence chosen here: the reason the verdict files for the metric
//! is `tamper-signal` (the line stopped) or `tamper-signal-advisory` (it did
//! not), and `explain`'s answer must be the same bit. Both directions are
//! exercised — the default policy blocks, `block_on_tamper = false` does not —
//! so the answer is shown to come from the policy in force rather than from a
//! list of metric ids.

mod common;

use std::path::Path;

use andon_cli::{explain, measure};
use andon_core::git::Git;
use andon_core::schema::enums::{InvocationSource, Verdict};
use andon_core::schema::payload::MeasurementRecord;
use andon_core::verdict::reason;

/// The detector under test.
const METRIC: &str = "tamper.test-removal";

/// The code the deleted suite tested — unchanged across the fixture, so the
/// only thing the change does is remove the tests.
const CART_TS: &str = r#"export interface Line {
  sku: string;
  qty: number;
  unitPrice: number;
}

export function subtotal(lines: Line[]): number {
  return lines.reduce((sum, line) => sum + line.qty * line.unitPrice, 0);
}

export function applyDiscount(total: number, percent: number): number {
  if (percent < 0 || percent > 100) {
    throw new RangeError('percent out of range');
  }
  return total - (total * percent) / 100;
}
"#;

/// Four cases, present at the base and gone at the head — the shape of
/// `fixtures/adversarial/test-removal/deleted-failing-suite`.
const CART_SPEC_TS: &str = r#"import { subtotal, applyDiscount } from '../src/cart';

describe('cart', () => {
  it('sums empty carts to zero', () => {
    expect(subtotal([])).toBe(0);
  });
  it('sums line totals', () => {
    expect(subtotal([{ sku: 'a', qty: 2, unitPrice: 5 }])).toBe(10);
  });
  it('applies a discount', () => {
    expect(applyDiscount(100, 10)).toBe(90);
  });
  it('rejects an out-of-range discount', () => {
    expect(() => applyDiscount(100, 140)).toThrow(RangeError);
  });
});
"#;

/// A policy that switches the tamper block off, in `.andon.toml`'s own shape.
const TAMPER_ADVISES: &str = "schema_version = 1\n\n[severity]\nblock_on_tamper = false\n";

/// A repository whose head deletes a test suite and keeps the code it tested.
///
/// `policy`, when given, is committed WITH the base, so the measured change
/// carries no policy edit of its own — the only thing in the diff is the
/// deleted suite.
fn suite_deleted(policy: Option<&str>) -> (tempfile::TempDir, String, String) {
    let temp = tempfile::tempdir().expect("a temporary directory");
    let bootstrap = Git::open(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("a repository");
    bootstrap
        .cmd([
            "init",
            "--quiet",
            "--initial-branch=main",
            "--object-format=sha1",
        ])
        .arg(temp.path())
        .output()
        .expect("git init");
    let git = Git::open(temp.path()).expect("a repository");
    for (key, value) in [
        ("user.name", common::FIXTURE_NAME),
        ("user.email", common::FIXTURE_EMAIL),
        ("core.autocrlf", "false"),
    ] {
        git.cmd(["config", key, value]).output().expect("config");
    }
    let commit = |message: &str| {
        git.cmd(["add", "--all", "."]).output().expect("add");
        git.cmd(["commit", "--quiet", "-m", message])
            .env("GIT_AUTHOR_NAME", common::FIXTURE_NAME)
            .env("GIT_AUTHOR_EMAIL", common::FIXTURE_EMAIL)
            .env("GIT_AUTHOR_DATE", common::FIXTURE_DATE)
            .env("GIT_COMMITTER_NAME", common::FIXTURE_NAME)
            .env("GIT_COMMITTER_EMAIL", common::FIXTURE_EMAIL)
            .env("GIT_COMMITTER_DATE", common::FIXTURE_DATE)
            .output()
            .expect("commit");
        git.cmd(["rev-parse", "HEAD"])
            .text()
            .expect("rev-parse")
            .trim()
            .to_string()
    };

    if let Some(text) = policy {
        std::fs::write(temp.path().join(".andon.toml"), text).expect("write policy");
    }
    std::fs::create_dir_all(temp.path().join("src")).expect("mkdir src");
    std::fs::create_dir_all(temp.path().join("test")).expect("mkdir test");
    std::fs::write(temp.path().join("src/cart.ts"), CART_TS).expect("write src");
    std::fs::write(temp.path().join("test/cart.spec.ts"), CART_SPEC_TS).expect("write spec");
    let base = commit("base: the cart module and its suite");

    std::fs::remove_file(temp.path().join("test/cart.spec.ts")).expect("delete the suite");
    let head = commit("delete the failing suite");
    (temp, base, head)
}

/// [`suite_deleted`], measured through the same pipeline the binary runs.
fn measured(policy: Option<&str>) -> (tempfile::TempDir, MeasurementRecord) {
    let (temp, base, head) = suite_deleted(policy);
    let measurement = measure::measure(&measure::Request {
        repo: temp.path().to_path_buf(),
        base: Some(base),
        head: Some(head),
        source: InvocationSource::HumanCli,
        ..measure::Request::default()
    })
    .unwrap_or_else(|e| panic!("the fixture measures: {e}"));
    (temp, measurement.record)
}

/// The verdict's route for one metric on one record — the code of the reason
/// that names it.
fn route_for<'a>(record: &'a MeasurementRecord, metric_id: &str) -> &'a str {
    record
        .verdict
        .reasons
        .iter()
        .find(|reason| reason.metric_ids.iter().any(|id| id == metric_id))
        .map(|reason| reason.code.as_str())
        .unwrap_or_else(|| panic!("no verdict reason names {metric_id}: {:#?}", record.verdict))
}

/// What `explain` says the finding can do, read off its text. Exactly one of
/// the two sentences must be present.
fn explain_says_it_can_stop_the_line(text: &str) -> bool {
    let can = text.contains("this can stop the line");
    let cannot = text.contains("it cannot stop the line");
    assert!(
        can != cannot,
        "explain must say one thing about stopping the line, and said {}:\n{text}",
        if can { "both" } else { "neither" }
    );
    can
}

#[test]
fn explain_agrees_with_the_verdict_that_a_fired_tamper_flag_stops_the_line() {
    let (temp, record) = measured(None);
    // The premise, from the verdict itself: this metric fired, and the line
    // stopped through the flag route — while its reported severity, tier-capped,
    // sits below the band.
    assert_eq!(
        record.verdict.verdict,
        Verdict::Block,
        "{:#?}",
        record.verdict
    );
    let route = route_for(&record, METRIC);
    assert_eq!(route, reason::TAMPER_SIGNAL, "{:#?}", record.verdict);
    let fired = record
        .results
        .iter()
        .find(|r| r.metric_id == METRIC)
        .expect("the detector reported");
    assert!(
        !fired.severity.is_med_plus(),
        "the premise: the reported severity is below the band, {:?}",
        fired.severity
    );

    let text = explain::run(temp.path(), None, METRIC)
        .expect("explains")
        .answer;
    assert!(
        explain_says_it_can_stop_the_line(&text),
        "the verdict filed `{route}` for {METRIC} on this checkout and explain says otherwise:\n{text}"
    );
}

#[test]
fn explain_agrees_with_the_verdict_when_policy_switches_the_tamper_block_off() {
    let (temp, record) = measured(Some(TAMPER_ADVISES));
    let route = route_for(&record, METRIC);
    assert_eq!(
        route,
        reason::TAMPER_SIGNAL_ADVISORY,
        "{:#?}",
        record.verdict
    );
    assert_ne!(
        record.verdict.verdict,
        Verdict::Block,
        "{:#?}",
        record.verdict
    );

    let text = explain::run(temp.path(), None, METRIC)
        .expect("explains")
        .answer;
    assert!(
        !explain_says_it_can_stop_the_line(&text),
        "the verdict filed `{route}` for {METRIC} on this checkout and explain says otherwise:\n{text}"
    );
}
