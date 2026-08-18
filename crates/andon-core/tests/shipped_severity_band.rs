//! Can anything the shipped engines actually emit stop the line?
//!
//! # The question no crate could be asked
//!
//! This file exists because of a defect that survived six phases of review, and
//! the reason it survived is worth stating before the assertions: **no test in
//! the assembly phase was fed by a real engine.** Every fixture was built by
//! hand from `andon_core::testing`, one of them impersonating `static-metrics`
//! and assigning it a severity that engine had never once produced. Against
//! those fixtures the MED+ machinery looked exercised. Against the shipped
//! binaries, nothing could reach the band at all: three engines hardcoded
//! `Info`, one emitted a binary `Low`, and the tamper suite's every firing was
//! capped at `Low` by a tier the default policy does not admit.
//!
//! Each engine's own crate could not see the answer, because the answer is about
//! all five at once. This crate could not see it either, because it depends on
//! no engine. So the question had nowhere to be asked. It is asked here, over
//! real output from real engines measuring a real repository, and the
//! dev-dependency cycle in `Cargo.toml` is what makes that possible.
//!
//! # Both directions, deliberately
//!
//! An assertion that *something* reaches MED+ would pass on a tool that shouted
//! about everything. An assertion that the process family never blocks would
//! pass on a tool that says nothing at all — which is precisely the state that
//! shipped. So both are here, and they pin each other:
//!
//! - [`the_static_family_can_still_reach_the_med_plus_band`] fails if the band
//!   goes dead again, whatever makes it go dead: a ladder reduced to
//!   `NoOpinion`, a tier demoted out of `med_plus_tiers`, a class flipped to
//!   `context-informational`, `severity::apply` deleted from the assembly path.
//! - [`the_capped_families_stay_where_policy_puts_them`] fails if the ceilings
//!   stop working, which is what a `severity::apply` that had quietly become a
//!   no-op would look like from the other side.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::git::{ChangedSet, Git, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_core::schema::enums::{EngineFamily, Severity};
use andon_core::schema::payload::MeasurementResult;
use andon_core::verdict::ladder::SeverityLadder;
use andon_core::verdict::severity;

use common::TestRepo;

/// A TypeScript function nobody could test in eleven cases.
///
/// Twelve sequential branches, so cyclomatic complexity is thirteen — past the
/// `High` rung at eleven — and the nesting takes cognitive complexity past its
/// own. Written out rather than generated so that the number a reader computes
/// by hand is the number the engine reports.
const COMPLEX_TS: &[u8] = br#"
export function classify(a: number, b: number, c: number): string {
  if (a > 0) {
    if (b > 0) {
      if (c > 0) {
        return "aaa";
      }
      return "aab";
    }
    if (c > 0) {
      return "aba";
    }
    return "abb";
  }
  if (b > 0) {
    if (c > 0) {
      return "baa";
    }
    return "bab";
  }
  if (c > 0) {
    if (a < -10) {
      return "bba";
    }
    return "bbb";
  }
  if (a < -100 && b < -100) {
    return "ccc";
  }
  return "none";
}
"#;

/// The same function again under another name, so the clone detector has real
/// duplication to find rather than a synthetic repetition of one token.
const DUPLICATE_TS: &[u8] = br#"
export function classifyAgain(a: number, b: number, c: number): string {
  if (a > 0) {
    if (b > 0) {
      if (c > 0) {
        return "aaa";
      }
      return "aab";
    }
    if (c > 0) {
      return "aba";
    }
    return "abb";
  }
  if (b > 0) {
    if (c > 0) {
      return "baa";
    }
    return "bab";
  }
  if (c > 0) {
    if (a < -10) {
      return "bba";
    }
    return "bbb";
  }
  if (a < -100 && b < -100) {
    return "cccc";
  }
  return "none";
}
"#;

/// A test file present in the base and deleted by the change, so the tamper
/// suite has a real firing to report rather than a hand-built flag.
const TEST_TS: &[u8] = br#"
import { classify } from "./classify";

it("classifies", () => {
  expect(classify(1, 1, 1)).toBe("aaa");
});
"#;

/// An lcov tracefile calling the added lines unexecuted.
const LCOV: &str = "SF:src/classify.ts\nDA:2,0\nDA:3,0\nDA:4,0\nend_of_record\n";

/// One repository, measured by all five shipped engines.
struct Measured {
    results: Vec<MeasurementResult>,
    _dir: tempfile::TempDir,
}

impl Measured {
    /// Results from one engine, by id.
    fn from(&self, engine_id: &str) -> Vec<&MeasurementResult> {
        self.results
            .iter()
            .filter(|r| r.engine_id == engine_id)
            .collect()
    }

    /// The strongest severity any result of this family reached.
    fn strongest(&self, family: EngineFamily) -> Severity {
        self.results
            .iter()
            .filter(|r| r.family == family)
            .map(|r| r.severity)
            .max()
            .unwrap_or(Severity::Info)
    }
}

/// Build a repository and run every shipped engine over the same change.
///
/// The change is deliberately one an agent could plausibly produce: a complex
/// function added, a near-copy of it added beside it, and no test covering
/// either. Every engine has something real to say about it.
fn measure_everything() -> Measured {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let repo = TestRepo::init(dir.path());

    // A history the process engine can walk. Ten commits to one file, so its
    // churn ladder has a number to rank rather than a one-commit repository in
    // which every history metric is trivially zero.
    let base = {
        repo.commit_file("src/seed.ts", b"export const seed = 0;\n", "seed");
        let mut last = repo.commit_file("src/classify.test.ts", TEST_TS, "a test");
        for n in 1..10 {
            last = repo.commit_file(
                "src/seed.ts",
                format!("export const seed = {n};\n").as_bytes(),
                &format!("churn {n}"),
            );
        }
        last
    };

    repo.write("src/classify.ts", COMPLEX_TS);
    repo.write("src/classify_again.ts", DUPLICATE_TS);
    repo.write("src/seed.ts", b"export const seed = 10;\n");
    // The detector's own case: a whole test file removed alongside the change
    // that made the code harder to test.
    repo.remove("src/classify.test.ts");
    repo.add_all();
    let head = repo.commit("the change under measurement");

    let git: &Git = repo.git();
    let range = ResolvedRange::resolve(git, &Revision::Rev(base), &Revision::Rev(head))
        .expect("both endpoints are commits");
    let changed = ChangedSet::enumerate(git, &range).expect("enumerating the change");
    let ctx = MeasureContext {
        compare_context: range.compare_context().expect("a commit range"),
        policy: Policy::default(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        sandbox_available: false,
    };

    let mut results = Vec::new();

    let static_engine =
        andon_static_metrics::StaticMetricsEngine::for_change(git, &changed, "0.1.0")
            .expect("the static engine reads the change");
    results.extend(run_engine(&static_engine, &ctx).expect("static-metrics measures"));

    let clones = andon_engine_clones::ClonesEngine::for_change(git, &changed, None)
        .expect("the clone engine reads the change");
    results.extend(run_engine(&clones, &ctx).expect("clones measures"));

    let tamper = andon_engine_tamper::TamperEngine::for_change(git, &changed)
        .expect("the tamper suite reads the change");
    results.extend(run_engine(&tamper, &ctx).expect("tamper measures"));

    let complexity: BTreeMap<String, u64> = BTreeMap::new();
    let process = andon_engine_process::ProcessEngine::for_change(
        git,
        &range,
        &changed,
        &Policy::default(),
        &complexity,
        None,
    )
    .expect("the process engine walks the history");
    results.extend(run_engine(&process, &ctx).expect("process measures"));

    let report =
        andon_engine_artifacts::CoverageReport::parse("lcov.info", LCOV.as_bytes()).expect("lcov");
    let artifacts =
        andon_engine_artifacts::ArtifactsEngine::for_change(git, &range, &changed, &[report])
            .expect("the artifacts engine reads the hunks");
    results.extend(run_engine(&artifacts, &ctx).expect("artifacts measures"));

    Measured { results, _dir: dir }
}

/// Every shipped engine, paired with the ladders it declares.
fn shipped_ladders() -> Vec<(&'static str, BTreeMap<String, SeverityLadder>)> {
    vec![
        (
            "static-metrics",
            andon_static_metrics::metrics::severity_ladders(),
        ),
        ("clones", andon_engine_clones::engine::severity_ladders()),
        ("tamper", andon_engine_tamper::engine::severity_ladders()),
        ("process", andon_engine_process::engine::severity_ladders()),
        (
            "artifacts",
            andon_engine_artifacts::engine::severity_ladders(),
        ),
    ]
}

#[test]
fn every_shipped_engine_produced_something() {
    // The premise of every assertion below. A fixture that stopped exercising an
    // engine would make that engine's absence from the results indistinguishable
    // from a clean measurement, and the band assertions would go vacuous without
    // reddening — which is exactly how the original defect hid.
    let measured = measure_everything();
    for engine_id in ["static-metrics", "clones", "tamper", "process", "artifacts"] {
        assert!(
            !measured.from(engine_id).is_empty(),
            "{engine_id} produced no results over the fixture change"
        );
    }
}

#[test]
fn the_static_family_can_still_reach_the_med_plus_band() {
    // THE GUARD. Real engines, real repository, real policy — and after the
    // ceilings have been applied exactly as `payload::prepare` applies them.
    //
    // In the shipped configuration `static` is the only family that can get
    // here, and that is not an accident to be tidied away: `clones` and `tamper`
    // are tier N, `artifacts` is tier C, and every `process` metric is
    // context-informational, so policy caps all four at `Low` by design. One
    // family reaching the band is what "the band is alive" looks like today.
    let mut measured = measure_everything();
    severity::apply(&mut measured.results, &Policy::default());

    let reaching: BTreeSet<EngineFamily> = measured
        .results
        .iter()
        .filter(|r| r.severity.is_med_plus())
        .map(|r| r.family)
        .collect();
    assert!(
        !reaching.is_empty(),
        "no shipped engine can reach the MED+ band: severities were {:?}",
        measured
            .results
            .iter()
            .map(|r| (&r.metric_id, r.severity))
            .collect::<Vec<_>>()
    );
    assert!(
        reaching.contains(&EngineFamily::Static),
        "the static family is the one that reaches it in the shipped configuration, got {reaching:?}"
    );

    // And it must actually stop the line, not merely carry the number: the band
    // is only worth anything if `stops_the_line` agrees.
    let policy = Policy::default();
    let ctx = andon_core::verdict::VerdictContext {
        policy: &policy,
        policy_change: None,
        engine_failures: &[],
        stale_claim_ids: &[],
        iteration_state_recovered: false,
        completeness: andon_core::schema::enums::Completeness::Complete,
    };
    assert!(
        measured
            .results
            .iter()
            .any(|r| severity::stops_the_line(r, &ctx)),
        "a MED+ finding that does not stop the line is a band with nothing behind it"
    );
}

#[test]
fn the_capped_families_stay_where_policy_puts_them() {
    // The other direction, and the mutant it kills: delete `severity::apply`
    // from the assembly path, or hollow out one of its ceilings, and these
    // families climb out of `Low` on ladders that are now genuinely able to
    // reach `High`. Before this repair round the same deletion changed nothing
    // anywhere in the workspace.
    let mut measured = measure_everything();

    // Pre-policy, the engines really do rank their findings — otherwise the cap
    // below would be a cap over nothing, which is the state that shipped.
    assert!(
        measured.strongest(EngineFamily::Clones) > Severity::Info,
        "the clone engine found duplication and said nothing about its strength"
    );

    severity::apply(&mut measured.results, &Policy::default());
    for family in [
        EngineFamily::Clones,
        EngineFamily::Tamper,
        EngineFamily::Process,
        EngineFamily::Artifacts,
    ] {
        assert!(
            !measured.strongest(family).is_med_plus(),
            "{family:?} reached {:?} after policy; its tier or its class should have capped it",
            measured.strongest(family)
        );
    }
}

#[test]
fn every_shipped_metric_declares_exactly_one_ladder() {
    // A metric added without a ladder is refused by `run_engine` — but only if
    // something emits it. This is the same rule at build time, over the
    // declarations rather than over one fixture's output.
    let engines: Vec<(&str, Vec<String>)> = vec![
        (
            "static-metrics",
            andon_static_metrics::metrics::descriptors()
                .into_iter()
                .map(|d| d.metric_id)
                .collect(),
        ),
        (
            "clones",
            andon_engine_clones::engine::metric_descriptors()
                .into_iter()
                .map(|d| d.metric_id)
                .collect(),
        ),
        (
            "tamper",
            andon_engine_tamper::engine::metric_descriptors()
                .into_iter()
                .map(|d| d.metric_id)
                .collect(),
        ),
        (
            "process",
            andon_engine_process::engine::metric_descriptors()
                .into_iter()
                .map(|d| d.metric_id)
                .collect(),
        ),
        (
            "artifacts",
            andon_engine_artifacts::engine::metric_descriptors()
                .into_iter()
                .map(|d| d.metric_id)
                .collect(),
        ),
    ];
    let ladders: BTreeMap<&str, BTreeMap<String, SeverityLadder>> =
        shipped_ladders().into_iter().collect();

    for (engine_id, metrics) in engines {
        let declared: BTreeSet<String> = metrics.into_iter().collect();
        let ranked: BTreeSet<String> = ladders[engine_id].keys().cloned().collect();
        assert_eq!(declared, ranked, "{engine_id}");
    }
}

#[test]
fn per_result_ladders_are_the_tamper_suite_and_nothing_else() {
    // `PerResult` is the one way out of the declaration table, and the argument
    // for it is specific to the tamper suite: its severity is declared per
    // detector, that declaration is what the muzzle rule was written against,
    // and restating it here would make two copies of it. A second engine taking
    // the same exit has to be a visible diff, because the argument does not
    // transfer.
    for (engine_id, ladders) in shipped_ladders() {
        let deferring: Vec<&String> = ladders
            .iter()
            .filter(|(_, ladder)| **ladder == SeverityLadder::PerResult)
            .map(|(id, _)| id)
            .collect();
        if engine_id == "tamper" {
            assert_eq!(
                deferring.len(),
                ladders.len(),
                "the whole suite defers, or the argument for deferring is only half true"
            );
        } else {
            assert!(
                deferring.is_empty(),
                "{engine_id} declares PerResult for {deferring:?}"
            );
        }
    }
}

#[test]
fn the_tamper_suite_still_stops_the_line_on_its_flag_and_not_on_its_severity() {
    // The muzzle rule, over real engine output rather than a hand-built flag.
    // Every shipped tamper claim is tier N, so `apply` caps every firing at
    // `Low` — with no degraded parse anywhere — and a severity-keyed rule would
    // therefore never stop the line for a tamper signal on any change at all.
    let policy = Policy::default();
    let mut measured = measure_everything();
    severity::apply(&mut measured.results, &policy);

    let flags: Vec<&MeasurementResult> = measured
        .from("tamper")
        .into_iter()
        .filter(|r| severity::fired_signal(r).is_some())
        .collect();
    assert!(
        !flags.is_empty(),
        "the fixture change must fire at least one detector for this to test anything"
    );
    for flag in flags {
        assert!(
            !flag.severity.is_med_plus(),
            "{} reached {:?}: the tier ceiling is the premise of the muzzle rule",
            flag.metric_id,
            flag.severity
        );
    }
}

#[test]
fn the_shape_fixture_does_not_impersonate_a_shipped_engine() {
    // GUARD (b), pinned where the real ids are visible. `andon_core::testing`
    // cannot make this assertion itself — it depends on no engine — which is
    // exactly why the impersonation lasted: the fixture said `static-metrics`
    // with `Severity::Medium`, and no crate was in a position to notice that the
    // engine of that name had never emitted a severity above `Info`.
    let fixture = andon_core::testing::sample_result();
    for (engine_id, _) in shipped_ladders() {
        assert_ne!(
            fixture.engine_id, engine_id,
            "a shape fixture must not wear a shipped engine's name"
        );
    }
    assert_eq!(
        fixture.severity,
        Severity::Info,
        "a fixture that arrives pre-ranked answers a question nobody measured"
    );

    // And the metric it names is not one any engine declares, so a test written
    // against the fixture cannot be read as a test about a shipped metric.
    let shipped_metrics: BTreeSet<String> = shipped_ladders()
        .into_iter()
        .flat_map(|(_, ladders)| ladders.into_keys())
        .collect();
    assert!(
        !shipped_metrics.contains(&fixture.metric_id),
        "{} is a shipped metric id",
        fixture.metric_id
    );
}

#[test]
fn every_shipped_tamper_claim_stays_outside_the_default_med_plus_tiers() {
    // The muzzle rule's *premise*, bound to the registry the binary compiles in
    // rather than to a hardcoded `EvidenceTier::N` in a unit test. Retier one
    // shipped tamper claim from N to A and the argument in
    // `verdict::severity`'s module documentation stops being true — "the tier
    // ceiling caps every tamper firing at Low" — while every muzzle test keeps
    // passing, because each of them sets the tier itself.
    let as_of: andon_core::date::Date = "2026-08-17".parse().expect("a valid date");
    let registry = andon_engine_tamper::engine::registry(as_of).expect("the tamper registry lints");
    let admitted = Policy::default().severity.med_plus_tiers;
    assert!(!registry.claims.is_empty(), "the suite ships claims");
    for (claim_id, resolved) in &registry.claims {
        assert!(
            !admitted.contains(&resolved.claim.tier),
            "{claim_id} is tier {:?}, which the default policy admits to the MED+ band — the \
             muzzle rule's stated premise is that no tamper claim is",
            resolved.claim.tier
        );
    }
}

/// Which engine each family belongs to, so the assertions above cannot be read
/// as being about `EngineFamily` alone.
///
/// Two engines report the `static` family — `static-metrics` and the P1.5 trust
/// spike — which is why the assembly module groups by `engine_id` and never by
/// family (PLAN wave-1 integration, P5a-entry note 2). The spike is not measured
/// here: it is not a shipped product engine, it declares `NoOpinion` throughout,
/// and including it would let its `Info` results stand in for the production
/// engine's in a family-keyed assertion.
#[test]
fn the_static_family_results_asserted_on_come_from_the_production_engine() {
    let mut measured = measure_everything();
    severity::apply(&mut measured.results, &Policy::default());
    for result in measured.results.iter().filter(|r| r.severity.is_med_plus()) {
        assert_eq!(
            result.engine_id, "static-metrics",
            "{} is stamped `static` but came from another engine",
            result.metric_id
        );
    }
}
