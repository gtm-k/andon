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
//!
//! # And one assertion that something GOOD is reachable
//!
//! Everything above, and every other guard this phase added, asserts that a bad
//! state cannot be reached. A suite made only of prohibitions passes most easily
//! on a tool that does nothing — which is how the dead band shipped, and then
//! how a gate that withheld `confirmed` from every ordinary pull request shipped
//! behind 859 green tests.
//! [`a_record_this_tool_really_produces_can_still_be_confirmed`] is the other
//! kind: two honest measurements of one change, assembled and classified, and
//! the pass they earn.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use andon_core::engine::{run_engine, MeasureContext, MetricDescriptor};
use andon_core::git::{ChangedSet, Git, ResolvedRange, Revision};
use andon_core::policy::Policy;
use andon_core::schema::enums::{EngineFamily, Severity};
use andon_core::schema::payload::MeasurementResult;
use andon_core::verdict::ladder::SeverityLadder;
use andon_core::verdict::severity;

use common::TestRepo;

/// A TypeScript function nobody could test in fifteen cases.
///
/// The engine reports **cyclomatic 15** and **cognitive 20**, both asserted by
/// [`the_fixture_sits_in_the_middle_of_the_band_it_reaches`] rather than
/// described here, because a doc comment is the half that rots. The version this
/// replaced said thirteen and called eleven the `High` rung; the engine reported
/// eleven and eleven is the `Medium` rung, so the prose was wrong twice about
/// the code beside it.
///
/// The numbers are mid-band on purpose. `Medium` is reached at 11 and 15 and
/// `High` at 21 and 25, so each number has at least four units of room below it
/// and five above. Retuning a rung by a unit or two — an expected kind of change
/// — therefore leaves [`the_static_family_can_still_reach_the_med_plus_band`]
/// green. At eleven against a rung of eleven it did not.
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
  if (a > 1000) {
    return "big-a";
  }
  if (b > 1000) {
    return "big-b";
  }
  if (c > 1000) {
    return "big-c";
  }
  if (a > 2000) {
    return "huge-a";
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
  if (a > 1000) {
    return "big-a";
  }
  if (b > 1000) {
    return "big-b";
  }
  if (c > 1000) {
    return "big-c";
  }
  if (a > 2000) {
    return "huge-a";
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
    compare_context: andon_core::schema::payload::CompareContext,
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

    Measured {
        results,
        compare_context: ctx.compare_context.clone(),
        _dir: dir,
    }
}

/// The five engines' outputs, assembled the way a measurement assembles them.
///
/// Through `payload::prepare`, not through a hand call to `severity::apply`.
/// That distinction is the whole point of `the_assembly_path_applies_the_ceilings`
/// below: a test that applies the ceilings itself proves the ceilings work and
/// says nothing about whether the assembly path still calls them.
fn assemble(measured: &Measured) -> andon_core::schema::payload::MeasurementRecord {
    use andon_core::engine::EngineDescriptor;
    use andon_core::payload::{registry_load, AssembleRequest, EngineOutput};
    use andon_core::schema::enums::{EngineClass, InvocationSource, RecordKind};
    use andon_core::schema::payload::{Invocation, Reserved, ToolIdentity};
    use andon_core::verdict::iteration::Advance;

    let registry_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("registry");
    let registry = registry_load::load(
        &registry_dir,
        &andon_core::policy::RegistryPolicy::default(),
        andon_core::date::Date::today_utc().expect("a clock"),
    )
    .expect("the shipped registry loads");

    let engines: Vec<EngineOutput> = registry
        .expected_engines
        .iter()
        .map(|engine_id| {
            let results: Vec<_> = measured
                .results
                .iter()
                .filter(|r| &r.engine_id == engine_id)
                .cloned()
                .collect();
            let family = results
                .first()
                .map(|r| r.family)
                .expect("every shipped engine produced something");
            EngineOutput {
                descriptor: EngineDescriptor {
                    engine_id: engine_id.clone(),
                    family,
                    class: EngineClass::StaticSafe,
                    version: "0.1.0".to_string(),
                },
                results,
            }
        })
        .collect();

    let policy = Policy::default();
    let prepared = andon_core::payload::prepare(AssembleRequest {
        substitution: None,
        unreadable_paths: Vec::new(),
        self_measure: None,
        tool: ToolIdentity {
            name: "andon".to_string(),
            version: "0.1.0".to_string(),
            build_oid: "4".repeat(40),
            attested_release: false,
        },
        record_kind: RecordKind::SelfReport,
        compare_context: measured.compare_context.clone(),
        invocation: Invocation {
            source: InvocationSource::HumanCli,
            harness: None,
            model: None,
            author: None,
            iteration: 0,
        },
        reserved: Reserved::default(),
        policy: &policy,
        registry: &registry,
        engines,
        engine_failures: Vec::new(),
        policy_change: None,
    })
    .expect("real engine output assembles");
    prepared.finish(Advance {
        contended: false,
        state: andon_core::schema::payload::IterationState {
            count: 0,
            cap: 3,
            escalated: false,
        },
        recovered: false,
    })
}

#[test]
fn the_assembly_path_applies_the_ceilings() {
    // THE MUTANT THIS KILLS: delete `severity::apply` from `payload::prepare`.
    // Before the ladders existed, that deletion changed nothing anywhere in the
    // workspace — every engine emitted `Info` and there was nothing to cap. It
    // is caught here rather than in the band assertions above, because those
    // call `apply` themselves and would go on passing over a payload that never
    // did.
    //
    // Real engines, real registry, real `prepare`, and the record it produced.
    let measured = measure_everything();
    let record = assemble(&measured);

    for result in &record.results {
        if result.family == EngineFamily::Static {
            continue;
        }
        assert!(
            !result.severity.is_med_plus(),
            "{} left assembly at {:?}: the ceilings were not applied",
            result.metric_id,
            result.severity
        );
    }
    assert!(
        record
            .results
            .iter()
            .any(|r| r.family == EngineFamily::Static && r.severity.is_med_plus()),
        "and the band is still reachable through the assembly path"
    );
    assert_eq!(
        record.verdict.verdict,
        andon_core::schema::enums::Verdict::Block,
        "a complexity finding in the MED+ band on a diff-actionable, tier-B claim stops the line"
    );
}

/// Every engine this build ships, and the two things these assertions ask of
/// each one.
///
/// # One roster, because three was the finding
///
/// This list used to be written out three times in this file — once as engine
/// id and ladders, once as a bare array of five names, once as engine id and
/// metric descriptors — and a sixth engine would have joined none of them. P5a
/// filed that as an entry note for the next phase, and `lens-final` named it
/// correctly: E19's recorded lesson recurring in a different medium. The lesson
/// is that anything kept in sync by hand eventually is not, and the fix is
/// always the same shape — state it once, and bind the statement to something
/// that cannot be edited independently.
///
/// [`the_roster_is_the_registry_this_repository_ships`] is that binding.
struct Shipped {
    engine_id: &'static str,
    metrics: fn() -> Vec<MetricDescriptor>,
    ladders: fn() -> BTreeMap<String, SeverityLadder>,
}

/// The roster. Not a list of five: a list of whatever this build carries.
const SHIPPED: &[Shipped] = &[
    Shipped {
        engine_id: "static-metrics",
        metrics: andon_static_metrics::metrics::descriptors,
        ladders: andon_static_metrics::metrics::severity_ladders,
    },
    Shipped {
        engine_id: "clones",
        metrics: andon_engine_clones::engine::metric_descriptors,
        ladders: andon_engine_clones::engine::severity_ladders,
    },
    Shipped {
        engine_id: "tamper",
        metrics: andon_engine_tamper::engine::metric_descriptors,
        ladders: andon_engine_tamper::engine::severity_ladders,
    },
    Shipped {
        engine_id: "process",
        metrics: andon_engine_process::engine::metric_descriptors,
        ladders: andon_engine_process::engine::severity_ladders,
    },
    Shipped {
        engine_id: "artifacts",
        metrics: andon_engine_artifacts::engine::metric_descriptors,
        ladders: andon_engine_artifacts::engine::severity_ladders,
    },
];

/// Every shipped engine, paired with the ladders it declares.
fn shipped_ladders() -> Vec<(&'static str, BTreeMap<String, SeverityLadder>)> {
    SHIPPED
        .iter()
        .map(|engine| (engine.engine_id, (engine.ladders)()))
        .collect()
}

#[test]
fn the_roster_is_the_registry_this_repository_ships() {
    // The guard the entry note asks for, and the reason one roster is safer than
    // three rather than merely tidier: an engine that lands a registry file and
    // not a table entry reddens here, so the roster and the deployment cannot
    // drift apart in silence. `expected_engines` is what `payload::prepare`
    // holds a payload to, so this binds these assertions to the same fact the
    // assembly boundary enforces.
    let listed: BTreeSet<String> = SHIPPED
        .iter()
        .map(|engine| engine.engine_id.to_string())
        .collect();
    assert_eq!(
        listed,
        shipped_registry().expected_engines,
        "the roster in this file and the registry this repository ships disagree"
    );
}

/// The registry directory this repository ships, loaded the way assembly loads
/// it.
fn shipped_registry() -> andon_core::payload::registry_load::LoadedRegistry {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("registry");
    andon_core::payload::registry_load::load(
        &dir,
        &andon_core::policy::RegistryPolicy::default(),
        andon_core::date::Date::today_utc().expect("a clock"),
    )
    .expect("the shipped registry loads")
}

#[test]
fn every_shipped_engine_produced_something() {
    // The premise of every assertion below. A fixture that stopped exercising an
    // engine would make that engine's absence from the results indistinguishable
    // from a clean measurement, and the band assertions would go vacuous without
    // reddening — which is exactly how the original defect hid.
    let measured = measure_everything();
    for engine in SHIPPED {
        assert!(
            !measured.from(engine.engine_id).is_empty(),
            "{} produced no results over the fixture change",
            engine.engine_id
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
        registry_skew: &[],
        unreadable_paths: &[],
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
    for engine in SHIPPED {
        let declared: BTreeSet<String> = (engine.metrics)()
            .into_iter()
            .map(|d| d.metric_id)
            .collect();
        let ranked: BTreeSet<String> = (engine.ladders)().into_keys().collect();
        assert_eq!(declared, ranked, "{}", engine.engine_id);
    }
}

#[test]
fn the_metrics_with_no_severity_opinion_are_exactly_these() {
    // The test above compares KEY SETS: which metric ids have a ladder, on both
    // sides. It says nothing about what any ladder holds, and neither did
    // anything else here — so a ladder reduced to `NoOpinion` was a silent
    // change. Setting the artifacts engine's sole ladder to `NoOpinion`, or the
    // clone engine's `clone-groups`, took a family's strength opinion away with
    // 859 tests green, which is the dead band the mini-G2 ruling exists to
    // prevent arriving one metric at a time.
    //
    // `the_static_family_can_still_reach_the_med_plus_band` could not catch it
    // either: it is a 1-of-N assertion over the one family policy lets through,
    // so the other four could go silent underneath it without reddening.
    //
    // Each engine also states this over its own metrics, where the *reason* for
    // an abstention lives. What can only be said here is the whole list at once:
    // this is everything the shipped tool declines to rank, and it is short.
    let declining: BTreeSet<(&str, String)> = shipped_ladders()
        .into_iter()
        .flat_map(|(engine_id, ladders)| {
            ladders
                .into_iter()
                .filter(|(_, ladder)| ladder.strongest() == Severity::Info)
                .map(move |(metric_id, _)| (engine_id, metric_id))
        })
        .collect();

    let expected: BTreeSet<(&str, String)> = [
        // A control variable, never a target: a ladder over a line count is an
        // instruction to an agent to delete lines (PREMORTEM A4).
        ("static-metrics", "static.sloc"),
        // The *report of* a degradation. Exact, must stay loud, and whether a
        // rise in it is an evasion is `tamper.parse-error-delta`'s question.
        ("static-metrics", "static.parse-errors"),
        ("static-metrics", "static.parse-missing"),
        // The markers already carry `completeness: unwitnessed` and cap below
        // MED+ whatever they say; ranking the count is the same fact twice.
        ("static-metrics", "static.unmeasured-files"),
        ("static-metrics", "static.unmeasured-file"),
        // The one history claim whose direction is not established.
        ("process", "process.code-age-days"),
    ]
    .into_iter()
    .map(|(engine, metric)| (engine, metric.to_string()))
    .collect();

    assert_eq!(
        declining, expected,
        "a metric joining this list is a family going quieter and has to be read as one; \
         a metric leaving it is a new judgement that has to be argued for"
    );
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
/// family (PLAN wave-1 integration, P5a-entry note 2).
///
/// The spike is not among the engines measured here, and the earlier wording of
/// this comment claimed that as a judgement: it is not a shipped product engine,
/// so it is excluded. That overstated what this file does. `spike-size` lives in
/// `andon-ledger-min`, which depends on `andon-core`, so **this crate cannot
/// reach it at all** — the exclusion is structural, not chosen. The judgement
/// the comment described is real and it lives elsewhere: `payload::prepare`
/// refuses `spike-size` as an `UnknownEngine` because its registry is not in
/// `registry/`, and `andon_cli::shipped` records why it is off the product
/// roster. A comment claiming a guard its own file does not contain leaves a
/// reader believing a check exists where it does not.
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

#[test]
fn the_fixture_sits_in_the_middle_of_the_band_it_reaches() {
    // The mandatory band guard is only as robust as the fixture under it, and
    // the fixture had none: it reported cyclomatic 11 against a `Medium` rung of
    // 11 and cognitive 16 against a rung of 15. Retuning either rung by one unit
    // — an expected kind of change, and one the ladders invite by declaring the
    // thresholds in one place — would have turned the ruling's guard red for a
    // reason no reader could have found in it.
    //
    // So the numbers are asserted here, where the guard can say what it
    // measured, and they are asserted with their room either side.
    use andon_core::schema::payload::MetricValue;

    let measured = measure_everything();
    let ladders = shipped_ladders()
        .into_iter()
        .collect::<BTreeMap<&str, BTreeMap<String, SeverityLadder>>>();

    for (metric_id, expected_value) in [
        ("static.cyclomatic-complexity.typescript", 15u64),
        ("static.cognitive-complexity.typescript", 20),
    ] {
        let values: Vec<&MetricValue> = measured
            .from("static-metrics")
            .into_iter()
            .filter(|r| r.metric_id == metric_id)
            .map(|r| &r.value)
            .collect();
        assert!(!values.is_empty(), "{metric_id} was not measured at all");
        assert!(
            values
                .iter()
                .all(|v| **v == MetricValue::Count(expected_value)),
            "{metric_id}: the two copies of the fixture function report one number, and it \
             is the number this file's doc comment states — got {values:?}"
        );

        // The margin, asserted rather than described: the ladder puts that
        // number in the MED+ band and keeps it there three units either way, so
        // the fixture is legibly not sitting on a rung. Read against the tables,
        // that is four units above `Medium` and six below `High` for cyclomatic,
        // five and five for cognitive — where the version this replaced was on
        // the rung exactly, and a one-unit retune reddened the ruling's guard.
        let ladder = ladders["static-metrics"][metric_id];
        for value in [expected_value - 3, expected_value, expected_value + 3] {
            assert_eq!(
                ladder
                    .severity_for(&MetricValue::Count(value))
                    .expect("a count ladder over a count")
                    .expect("not a per-result ladder"),
                Severity::Medium,
                "{metric_id} at {value}"
            );
        }
    }
}

#[test]
fn a_record_this_tool_really_produces_can_still_be_confirmed() {
    // THE POSITIVE CONTROL, and the assertion whose absence let two defects ship
    // with the whole suite green.
    //
    // Every other guard in this phase asserts that a bad state is UNREACHABLE:
    // the band cannot go dead, the ceilings cannot be skipped, the fixture
    // cannot impersonate an engine. Not one asserted that the good state is
    // REACHABLE. So a gate that withheld `confirmed` from every ordinary pull
    // request read as 859 tests passing — and, before it, a configuration in
    // which nothing could reach the MED+ band read the same way. A suite made
    // only of prohibitions passes most easily on a tool that does nothing.
    //
    // Two honest measurements of the same change, assembled the way a
    // measurement assembles them, and the verifier's own classification of the
    // pair. The record deliberately carries honest `unwitnessed` markers — a
    // file absent from the coverage report, a path with no complexity input for
    // the hotspot product — because that is what a real record looks like and it
    // is exactly what the reverted gate keyed on. Anything that re-reads record
    // completeness as a precondition for confirmation reddens here.
    use andon_core::compare::{classify, BaseRelation, CompareInputs};
    use andon_core::schema::enums::{Attestation, Completeness};

    let measured = measure_everything();
    let report = assemble(&measured);
    let recompute = assemble(&measured);

    assert_ne!(
        recompute.completeness,
        Completeness::Complete,
        "the premise: an ordinary honest record rolls up below `complete`, because an \
         absence honestly reported is still an absence"
    );

    let outcome = classify(
        Some(&report),
        &recompute,
        CompareInputs {
            base_relation: BaseRelation::Equal,
            head_equal: true,
            fork_tier: false,
        },
    );
    assert_eq!(
        outcome.attestation,
        Attestation::Confirmed,
        "two honest measurements of one change agreeing on every compared result must \
         confirm; a tool that can only ever withhold the pass is not a trust channel"
    );

    let compare = outcome.compare.expect("a compare was attempted");
    assert!(
        !compare.matched.is_empty(),
        "and the pass has to be legible: something was actually compared"
    );
    assert!(compare.mismatched.is_empty() && compare.unpaired.is_empty());
    assert!(compare.tuple_equal && compare.regime_equal);
}

#[test]
fn an_uncommitted_head_is_never_classified_as_a_disagreement() {
    // The false-accusation guard for the uncommitted lane, over records this
    // tool really produces rather than over hand-built shapes.
    //
    // A record measured against a working tree carries a content hash where a
    // commit OID would be. Without the step-0 check in `compare::classify` the
    // tuple comparison finds it unequal, asks how the base relates to the
    // trusted branch, and reports `unwitnessed-base-mismatch` — or, if the base
    // had also moved, `base-fabrication` and `divergent`. That is a tamper
    // accusation against somebody who did nothing but forget to commit, and this
    // project ranks false accusation above missed detection.
    use andon_core::compare::{self, BaseRelation, CompareInputs};
    use andon_core::schema::enums::Attestation;
    use andon_core::schema::payload::HeadKind;

    let measured = measure_everything();
    let record = assemble(&measured);
    assert!(
        record.compare_context.head_kind.is_witnessable(),
        "the fixture is a commit range; the dirty case is derived from it below"
    );

    // The same record, relabelled as what an uncommitted measurement is: a
    // content hash for a head, and the kind that says so.
    let mut dirty = record.clone();
    dirty.compare_context.head_kind = HeadKind::UncommittedWorktree;
    dirty.compare_context.head_oid = "c".repeat(64);

    // Every hostile-looking arrangement of the inputs, because the point is that
    // none of them can reach an accusation.
    for base_relation in [
        BaseRelation::Equal,
        BaseRelation::Ancestor,
        BaseRelation::NotAncestor,
        BaseRelation::Unknown,
    ] {
        for head_equal in [true, false] {
            let classification = compare::classify(
                Some(&dirty),
                &record,
                CompareInputs {
                    base_relation,
                    head_equal,
                    fork_tier: false,
                },
            );
            assert_eq!(
                classification.attestation,
                Attestation::UnwitnessedUncommitted,
                "{base_relation:?}/{head_equal} classified an uncommitted head as something else"
            );
            assert!(
                classification.tamper_signals.is_empty(),
                "{base_relation:?}/{head_equal} raised a tamper signal over uncommitted work"
            );
            assert!(
                classification.compare.is_none(),
                "a compare was reported over a head nothing can recompute"
            );
        }
    }

    // And the control in the other direction: the commit record this fixture
    // really produces still earns a real classification, so the check above is
    // not passing because `classify` stopped working.
    let confirmed = compare::classify(
        Some(&record),
        &record,
        CompareInputs {
            base_relation: BaseRelation::Equal,
            head_equal: true,
            fork_tier: false,
        },
    );
    assert_eq!(confirmed.attestation, Attestation::Confirmed);
}
