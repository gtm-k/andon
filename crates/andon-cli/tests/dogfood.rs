//! Dogfood switch-on: Andon measures Andon, and the gate is not a green tick.
//!
//! # Why the assertions are here and not in the workflow
//!
//! PLAN P5b: *"gate asserts non-empty results + expected engine count, not
//! exit-code green (round-1 vacuity fix)"*. The vacuity it names is specific and
//! it has already happened once in this project: a payload assembled from **no
//! engines at all** came out `complete` and `pass`, so a job checking only that
//! the command exited zero would have gone green over a run in which nothing was
//! measured.
//!
//! So the gate is a typed assertion over the record the binary produced, and it
//! lives in Rust rather than in YAML for two reasons. It runs on a developer's
//! machine before CI sees it, and it needs no JSON shell-parsing — a gate whose
//! own correctness depends on `grep` over a payload is a gate with a defect
//! class of its own.
//!
//! `scripts/self-measure.sh` drives this, and prints the human-readable report
//! beside it so the CI log carries what the measurement actually said.
//!
//! # The bootstrap exception, stated where it applies
//!
//! `docs/self-measure.md`'s rule is that self-measurement runs the **last
//! attested release** binary, so that a broken detector cannot bless the change
//! that broke it. No attested release exists yet, so this runs the working
//! tree's own build under the recorded override
//! `bootstrap-no-attested-release`, which is self-expiring: it stops being
//! available the moment the first attested release ships.
//!
//! That is exactly why the verdict does not gate. A binary judging itself has
//! produced an opinion, not evidence — and the acceptance criterion says the
//! gate is the assertions above, not the verdict.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use andon_core::policy::Policy;
use andon_core::schema::payload::MeasurementRecord;

const EXE: &str = env!("CARGO_BIN_EXE_andon");

/// The workspace root — the repository under measurement.
fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Measure this repository the way the dogfood job does.
fn measure_self() -> Result<MeasurementRecord, String> {
    let output = Command::new(EXE)
        .args([
            "measure",
            "--repo",
            workspace().to_str().expect("utf-8"),
            "--self-measure",
            "--json",
            // The verdict is reported and does not gate here, so a blocking
            // finding must not turn into a process failure that hides the
            // record this test exists to check.
            "--exit-zero",
        ])
        .output()
        .map_err(|e| format!("{EXE}: {e}"))?;
    if output.stdout.is_empty() {
        return Err(format!(
            "andon measure produced no record: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
}

/// Whether this checkout can be measured at all.
///
/// A shallow clone with a single commit has nothing to compare against, and the
/// honest answer is a refusal rather than a measurement (`crate::resolve`). CI
/// checks out with full depth precisely so this does not happen; a developer
/// running the suite inside a `--depth 1` clone gets a skip with the reason,
/// never a silent pass.
fn measurable() -> Result<(), String> {
    let git = andon_core::git::Git::open(&workspace()).map_err(|e| e.to_string())?;
    match git
        .cmd(["rev-parse", "--verify", "--quiet", "HEAD~1^{commit}"])
        .succeeds_with_output()
    {
        Ok(Some(_)) => Ok(()),
        _ => Err(
            "this checkout has no commit before HEAD (a shallow clone?), so there is \
                  nothing to measure against"
                .to_string(),
        ),
    }
}

#[test]
fn andon_measures_andon_and_the_record_is_not_empty() {
    if let Err(reason) = measurable() {
        eprintln!("dogfood skipped: {reason}");
        return;
    }
    let record = measure_self().expect("the self-measurement runs");

    // The vacuity fix, in the two forms the criterion names.
    assert!(
        !record.results.is_empty(),
        "the self-measurement produced no results at all. A run in which no engine ran \
         assembles into an empty record that reads `complete` and `pass`, which is the state \
         this assertion exists to make impossible."
    );

    let engines: BTreeSet<&str> = record
        .results
        .iter()
        .map(|r| r.engine_id.as_str())
        .collect();
    let expected: BTreeSet<&str> = andon_cli_roster();
    assert_eq!(
        engines, expected,
        "the self-measurement did not hear from every shipped engine"
    );
}

/// The engine roster this build ships.
///
/// Read from `andon_cli::shipped::SHIPPED`, which is the same roster the binary
/// measured with and is itself asserted equal to the `engine =` headers of the
/// registry files the engine crates compile in. Writing a list of five here
/// instead would be a second roster to keep in sync by hand — the entry note P5a
/// handed this phase, recreated by the test meant to guard against it.
fn andon_cli_roster() -> BTreeSet<&'static str> {
    andon_cli::shipped::SHIPPED
        .iter()
        .map(|engine| engine.engine_id)
        .collect()
}

#[test]
fn the_declared_exclusions_are_the_ones_that_were_applied() {
    // The drift signal's premise. `[self_measure] excluded_paths` exists so the
    // exclusion is reviewable in a diff; a run that quietly withheld more than
    // the file declares would make the review meaningless.
    let policy_path = workspace().join(".andon.toml");
    let policy = Policy::from_toml(&std::fs::read_to_string(&policy_path).expect("a policy"))
        .expect("the policy parses");
    assert!(
        !policy.self_measure.excluded_paths.is_empty(),
        "self-measurement with no declared exclusions would measure the adversarial fixtures, \
         which exist to fire the tamper suite"
    );
    assert!(
        policy.self_measure.exclusion_drift_signal,
        "an exclusion list that can widen without a signal is how a dogfood gate stops meaning \
         anything"
    );
    for pattern in &policy.self_measure.excluded_paths {
        let prefix = pattern.strip_suffix("/**").unwrap_or(pattern);
        assert!(
            workspace().join(prefix).exists(),
            "{pattern} excludes a path that does not exist; an exclusion that matches nothing \
             is an exclusion nobody notices going stale"
        );
    }
}

#[test]
fn the_bootstrap_exception_is_still_the_state_of_the_world() {
    // The override is self-expiring by construction: it names a condition, and
    // the condition stops being true when the first attested release ships. This
    // asserts the condition rather than the override, so the day a release is
    // attested the claim in `scripts/self-measure.sh` fails instead of quietly
    // becoming false.
    if measurable().is_err() {
        return;
    }
    let record = measure_self().expect("the self-measurement runs");
    assert!(
        !record.tool.attested_release,
        "this binary reports itself as an attested release. If that is now true, the \
         bootstrap exception in docs/self-measure.md has expired and self-measurement must \
         switch to the released binary."
    );
}

#[test]
fn the_workflow_gate_asserts_the_record_and_not_the_exit_code() {
    // The criterion is about what the *job* checks, so it is checked against the
    // job. A workflow that reverted to `andon measure && echo ok` would pass
    // every test in this file and fail the acceptance criterion.
    let workflow = std::fs::read_to_string(
        workspace()
            .join(".github")
            .join("workflows")
            .join("dogfood.yml"),
    )
    .expect("the dogfood workflow exists");
    assert!(
        workflow.contains("--test dogfood"),
        "the dogfood job does not run the assertions in this file"
    );
    assert!(
        workflow.contains("fetch-depth: 0"),
        "a shallow checkout has no history for the process family and no parent to measure \
         against, so the job would gate on a refusal"
    );
}

#[test]
fn the_placeholder_that_announced_no_measurement_is_gone() {
    // P0 left a loud placeholder and a tripwire: it fails the moment
    // `crates/andon-cli` exists, so the exception cannot outlive its condition.
    // This is the other half — the script must now actually measure.
    let script = std::fs::read_to_string(workspace().join("scripts").join("self-measure.sh"))
        .expect("the self-measure script exists");
    assert!(
        !script.contains("NO MEASUREMENT WAS PERFORMED"),
        "the bootstrap placeholder is still in place after the CLI shipped"
    );
    assert!(
        script.contains("--self-measure"),
        "the self-measure script does not run a measurement under the declared exclusions"
    );
    assert!(
        script.contains("--test dogfood"),
        "the self-measure script does not name the gate, so a reader of the CI log has no way \
         to tell that the verdict it prints is not the thing being enforced"
    );
}

#[test]
fn the_two_binary_gate_activates_now_that_the_golden_set_exists() {
    // P0 wired the bridge and left it failing on purpose: `fixtures/golden`
    // present with no comparison implemented is a hard error, so the first
    // engine change could not land before somebody remembered to add the gate.
    // This phase creates the golden set, so it owes the comparison.
    let ci = std::fs::read_to_string(workspace().join(".github").join("workflows").join("ci.yml"))
        .expect("ci.yml exists");
    assert!(
        !ci.contains("the comparison is not implemented"),
        "fixtures/golden exists and ci.yml still carries P0's not-implemented tripwire"
    );
    assert!(
        ci.contains("--test golden"),
        "the engines-change job does not run the golden comparison"
    );
    assert!(
        Path::new(&workspace().join("fixtures").join("golden")).is_dir(),
        "the golden set the gate depends on is missing"
    );
}

#[test]
fn the_self_measurement_carries_its_own_provenance() {
    // `SelfMeasureProvenance` was written, documented and unit-tested, and
    // nothing constructed one. The facts it describes lived for exactly one
    // process: a fresh terminal named the paths `[self_measure] excluded_paths`
    // withheld, and the saved record, the read-back report, `wait`, `--json` and
    // the agent profile all lost them — including this job's own payload, which
    // is the artefact somebody opens to find out what the gate covered.
    if let Err(reason) = measurable() {
        eprintln!("dogfood skipped: {reason}");
        return;
    }
    let record = measure_self().expect("the self-measurement runs");
    let provenance = record
        .self_measure
        .as_ref()
        .expect("a --self-measure run records how it was arrived at");

    // Which binary judged, from the same values the record's `tool` block
    // carries, so the two cannot disagree.
    assert_eq!(provenance.measuring_binary_version, record.tool.version);
    assert_eq!(provenance.measuring_binary_oid, record.tool.build_oid);
    assert_eq!(provenance.attested, record.tool.attested_release);

    // The bootstrap exception, durable rather than announced in a shell banner.
    // `docs/self-measure.md`: every self-measurement carries it until the first
    // attested release exists.
    let over = provenance
        .override_record
        .as_ref()
        .expect("the bootstrap exception is in force and must be recorded");
    assert_eq!(
        over.reason,
        andon_core::selfmeasure::OverrideReason::BootstrapNoAttestedRelease
    );
    for (field, value) in [
        ("justification", &over.justification),
        ("reference", &over.reference),
        ("approved_by", &over.approved_by),
        ("head_oid", &over.head_oid),
    ] {
        assert!(
            !value.is_empty(),
            "the override's {field} is empty, which is indistinguishable from a silent bypass"
        );
    }
    assert!(
        !provenance.is_clean(),
        "a run under an override reported itself as a clean one"
    );

    // What the policy withheld, named rather than counted, because a reader
    // deciding what the gate covered needs the files.
    let policy_path = workspace().join(".andon.toml");
    let policy = Policy::from_toml(&std::fs::read_to_string(&policy_path).expect("a policy"))
        .expect("the policy parses");
    for path in &provenance.excluded_paths {
        assert!(
            policy.self_measure.excluded_paths.iter().any(|pattern| {
                let prefix = pattern.strip_suffix("/**").unwrap_or(pattern);
                path == prefix || path.starts_with(&format!("{prefix}/"))
            }),
            "{path} was withheld by nothing the policy declares, so the exclusion is not \
             reviewable in a diff"
        );
    }
}

#[test]
fn the_dogfood_run_is_a_ledgered_event() {
    // PLAN P5b: "switch is a ledgered event (S3)". It was not one. The job
    // printed a report, uploaded an artefact, and left nothing behind that
    // anybody could query afterwards — which is the difference between "we think
    // the gate ran" and a record attached to the commit it was taken under.
    //
    // Asserted against the script rather than by running it: the assertion is
    // about what the job does, and a script that dropped `--record` would pass
    // every other test in this file.
    let script = std::fs::read_to_string(workspace().join("scripts").join("self-measure.sh"))
        .expect("the self-measure script exists");
    // The flag on the invocation, not the word anywhere in the file. A first
    // draft of this asserted `script.contains("--record")` and still passed with
    // the flag deleted, because the paragraph above the command explains why it
    // is there — a guard satisfied by its own documentation.
    assert!(
        script
            .lines()
            .any(|line| line.trim().trim_end_matches('\\').trim() == "--record"),
        "the self-measure run is not filed against the commit, so the switch-on is a log line \
         rather than a ledgered event"
    );
    assert!(
        script.contains("andon-measure"),
        "the script does not show the reader what was filed, so a note that silently failed to \
         land would look exactly like one that did"
    );
}

#[test]
fn every_surface_that_renders_a_self_measurement_says_what_it_withheld() {
    // The disclosure half, across the surfaces that lost it. A measurement that
    // withheld eighteen paths and one that withheld none are different
    // measurements, and the difference has to survive being serialized.
    if measurable().is_err() {
        return;
    }
    let record = measure_self().expect("the self-measurement runs");
    let provenance = record.self_measure.as_ref().expect("provenance");
    assert!(
        !provenance.excluded_paths.is_empty(),
        "this repository's own policy withholds fixtures, so a run that withheld none is not \
         the run this test is about"
    );

    let dir = tempfile::tempdir().expect("a temporary directory");
    let saved = dir.path().join("self.json");
    std::fs::write(
        &saved,
        andon_core::canonical::to_canonical_string(&record).expect("serializes"),
    )
    .expect("writes");
    let input = saved.to_str().expect("utf-8").to_string();
    let sample = provenance.excluded_paths[0].clone();

    let run = |args: &[&str]| {
        let out = Command::new(EXE).args(args).output().expect("andon runs");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let reported = run(&["report", "--input", &input, "--no-color"]);
    assert!(
        reported.contains(&sample) && reported.contains("withheld"),
        "the read-back report does not say what the policy withheld"
    );

    let waited = run(&["wait", "--input", &input]);
    assert!(
        waited.contains("withheld"),
        "`wait` renders the record and says nothing about what it withheld:\n{waited}"
    );

    let html_path = dir.path().join("self.html");
    let _ = run(&[
        "report",
        "--input",
        &input,
        "--html",
        html_path.to_str().expect("utf-8"),
    ]);
    let html = std::fs::read_to_string(&html_path).expect("the report reads back");
    assert!(
        html.contains(&sample),
        "the HTML report lost the withheld paths"
    );
    assert!(
        html.contains("bootstrap") || html.contains("Bootstrap"),
        "the HTML report does not say which binary judged, or under what exception"
    );

    // The agent gets a count, because this view has a byte budget.
    let profile = run(&["report", "--input", &input, "--profile", "agent-mode"]);
    let parsed: serde_json::Value = serde_json::from_str(&profile).expect("valid profile");
    assert_eq!(
        parsed["withheld_paths"],
        provenance.excluded_paths.len(),
        "{profile}"
    );
}
