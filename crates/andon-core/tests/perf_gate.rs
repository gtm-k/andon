//! The perf gate (PREMORTEM T6).
//!
//! ```text
//! ./fixtures/perf/generate.sh
//! cargo test --release -p andon-core --test perf_gate -- --ignored --nocapture
//! ```
//!
//! `#[ignore]` by default because it needs the generated fixture, and
//! **release only**: a debug build breaches every budget on arithmetic that
//! ships optimized, which would make the gate a measurement of `-O0`.
//!
//! # What is measured
//!
//! A *fast-lane git pass*: open the repository, resolve base and head, enumerate
//! the changed set, read every changed blob, and key the result. At P1 that is
//! the whole of a measurement's git work — engines arrive in P2 — so the budgets
//! are asserted against the full policy figure and the headroom is printed, so
//! that later phases can see what they are spending into.
//!
//! # Warm and cold
//!
//! - **Cold** — empty cache directory, a repository this process has not touched,
//!   one pass. The worst realistic case: `andon measure` on a fresh checkout.
//! - **Warm** — cache populated, repeated passes, p95 of twenty.
//!
//! Warm deliberately still does the git work. A key lookup returning a stored
//! value would measure a hash-map hit and prove nothing about T6, whose claim is
//! that the *incremental* path scales with diff size and not repository size.
//! The evidence for that claim is the shape across the three series: small,
//! medium, and large differ by three orders of magnitude in file count against
//! one fixed 100,000-file repository.
//!
//! # Budgets
//!
//! Read from `.andon.toml`, never written here. A hardcoded budget is a number
//! nobody can ledger a change to, and the ratchet it enables — nudge the
//! constant, watch the gate go green — is exactly the failure PLAN P1 calls
//! "ratchet-proof" (`[policy.perf]`).
//!
//! The dirty-tree path has **two** budgets and **both gate**: the accelerated
//! arrangement against `fast_lane_warm_p95_ms`, the one with no watching
//! fsmonitor daemon against `fast_lane_warm_fallback_p95_ms`. There is a second
//! ratchet besides nudging a constant, and it is subtler: choosing which leg the
//! budget applies to. That is how the un-accelerated path came to be measured at
//! 1306.9 ms while the gate was green on a 1000 ms figure — the number was
//! printed and nothing asserted it. A leg that genuinely cannot run on a
//! platform reports why; it never disappears.
//!
//! # Two dirty scenarios
//!
//! A tree dirty on top of the base commit is the simple shape. A branch that
//! already carries commits *and* is dirty on top is the default `andon measure`
//! shape — merge base against the trusted branch, working tree as head — and it
//! is what an agent measuring its own change mid-loop always looks like. It
//! costs a `diff-tree` over the committed segment and a `cat-file` batch to read
//! the blobs that turns up, so it is measured rather than assumed to cost what
//! the simple one costs.
//!
//! # Spawn count
//!
//! Asserted, not observed. A regression that turns one batched `cat-file` into
//! one spawn per file reads as a modest slowdown on a laptop and as a timeout on
//! a monorepo; the count catches it on the laptop.
//!
//! Two kinds of assertion, because there are two claims. The committed series
//! asserts *flatness* — one, fifty, and a thousand changed files must cost the
//! same number of processes, which is PREMORTEM T6's shape claim. The dirty legs
//! assert an *exact figure per scenario*, derived in
//! [`DirtyScenario::expected_spawns`], because they legitimately differ from each
//! other and "flat" would be the wrong property to demand. A number that moves
//! fails here and has to be argued for.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use andon_core::cache::{CacheKey, CacheStore};
use andon_core::git::{ChangedSet, Git, ResolvedRange, Revision};
use andon_core::policy::Policy;

/// Passes per warm scenario. Twenty gives a p95 at the nineteenth value, which
/// is the smallest sample where "p95" is not a rename of "the maximum".
const WARM_PASSES: usize = 20;

/// The engine identity the key is built for. There are no engines yet; the key
/// still needs one, and naming it here keeps the harness honest about measuring
/// a real key rather than a placeholder.
const ENGINE_ID: &str = "git-plumbing";
const ENGINE_VERSION: &str = "0.1.0";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root")
}

fn fixture_dir() -> PathBuf {
    std::env::var_os("ANDON_PERF_FIXTURE")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join(".perf-fixture"))
}

/// Commits and dirty paths, as the generator recorded them.
struct Manifest {
    commits: Vec<(String, String)>,
    dirty_paths: Vec<String>,
}

impl Manifest {
    fn load(dir: &Path) -> Self {
        let path = dir.join("fixture.json");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "no fixture at {}.\n\nRun ./fixtures/perf/generate.sh first.",
                path.display()
            )
        });
        let value: serde_json::Value = serde_json::from_str(&text).expect("manifest parses");
        Manifest {
            commits: value["commits"]
                .as_object()
                .expect("commits")
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().expect("oid").to_string()))
                .collect(),
            dirty_paths: value["dirty_paths"]
                .as_array()
                .expect("dirty_paths")
                .iter()
                .map(|v| v.as_str().expect("path").to_string())
                .collect(),
        }
    }

    fn commit(&self, name: &str) -> &str {
        &self
            .commits
            .iter()
            .find(|(k, _)| k == name)
            .unwrap_or_else(|| panic!("no {name} commit in the manifest"))
            .1
    }
}

fn policy() -> Policy {
    let path = workspace_root().join(".andon.toml");
    Policy::from_toml(&std::fs::read_to_string(&path).expect("policy is readable"))
        .expect("policy parses")
}

/// One dirty-tree arrangement, its own budget, and whether it could run here.
struct DirtyLeg {
    label: String,
    budget: f64,
    runnable: bool,
    /// Git subprocesses one pass of this scenario must cost. Asserted, not
    /// reported — see [`DirtyScenario::expected_spawns`].
    expected_spawns: u64,
    summary: Pass,
}

/// What the working tree looks like when the dirty legs run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirtyScenario {
    /// `HEAD` is the base commit: the whole change is uncommitted.
    HeadAtBase,
    /// `HEAD` is a branch with a thousand committed files on it, *and* the tree
    /// is dirty on top. The default `andon measure` shape — merge base against
    /// the trusted branch, working tree as head — from a branch that has been
    /// worked on, which is what an agent measuring its own change mid-loop
    /// always looks like.
    BranchWithCommits,
}

impl DirtyScenario {
    fn label(self) -> &'static str {
        match self {
            DirtyScenario::HeadAtBase => "warm-dirty",
            DirtyScenario::BranchWithCommits => "warm-branch",
        }
    }

    /// The branch to sit on. Both are pinned by `expected.toml`.
    fn branch(self) -> &'static str {
        match self {
            DirtyScenario::HeadAtBase => "base",
            DirtyScenario::BranchWithCommits => "large",
        }
    }

    /// Git subprocesses one pass costs, derived rather than observed.
    ///
    /// Eight for both scenarios' shared work: three to open the repository, one
    /// `rev-parse` for the base revision, one more for the snapshot's `HEAD`
    /// anchor, one `status`, one `hash-object` re-checking the conversion
    /// suspects, and one `hash-object` recording their pinned OIDs.
    ///
    /// The branch scenario pays two more, and both are the union's: a
    /// `diff-tree` over the segment already committed on the branch, and the
    /// `cat-file --batch` that reads the blobs it turns up. The head-at-base
    /// scenario skips the first because there is nothing between the base and
    /// the anchor, and the second because a purely dirty change has no readable
    /// blob at all.
    ///
    /// Written down as an expectation rather than a floor: the number moving is
    /// a design change, and it should fail here and be argued for, not appear in
    /// a graph three phases later. It moved once, from seven, and the argument
    /// is that opening a repository now costs a third spawn: a `git config` read
    /// of the filter drivers this repository defines. Everything after it
    /// carries `-c` pins that stop those drivers executing, and a filter is a
    /// program the repository wrote — one fixed read, at open, buys the
    /// guarantee that no working-tree read runs it. The cost does not scale with
    /// anything: it is one spawn per `Git::open`, whatever the repository holds.
    fn expected_spawns(self) -> u64 {
        match self {
            DirtyScenario::HeadAtBase => 8,
            DirtyScenario::BranchWithCommits => 10,
        }
    }
}

/// What one fast-lane git pass cost.
struct Pass {
    elapsed: Duration,
    spawns: u64,
    files: usize,
    blobs: usize,
    bytes: usize,
    cache_hit: bool,
}

/// One fast-lane git pass, timed from `Git::open`.
///
/// Opening the repository is inside the measurement because a real `andon
/// measure` pays for it. Excluding it would flatter every number by two spawns
/// and whatever `rev-parse` costs on a cold filesystem.
fn pass(
    repo: &Path,
    base: &Revision,
    head: &Revision,
    store: &CacheStore,
    policy: &Policy,
) -> Pass {
    // `ANDON_PERF_STAGES=1` prints where a pass spent its time. Kept in rather
    // than deleted after use: the first thing anyone asks of a breached budget
    // is which stage breached it, and reconstructing this by hand each time is
    // how a perf gate turns into a number nobody investigates.
    let stages = std::env::var_os("ANDON_PERF_STAGES").is_some();
    let started = Instant::now();
    let mut mark = started;
    let lap = |label: &str, mark: &mut Instant| {
        if stages {
            println!("      {label:<22} {:>7.1} ms", ms(mark.elapsed()));
        }
        *mark = Instant::now();
    };

    let git = Git::open(repo).expect("fixture repository opens");
    lap("open", &mut mark);
    let range = ResolvedRange::resolve(&git, base, head).expect("resolves");
    lap("resolve", &mut mark);
    let changed = ChangedSet::enumerate(&git, &range).expect("enumerates");
    lap("enumerate", &mut mark);
    let blobs = changed.read_head_blobs(&git).expect("reads blobs");
    lap("read blobs", &mut mark);

    let key = CacheKey::new(&range, policy, ENGINE_ID, ENGINE_VERSION).expect("key builds");
    lap("key", &mut mark);
    let cache_hit = store.get(&key).expect("cache readable").is_some();
    lap("cache", &mut mark);
    if !cache_hit {
        // The stand-in for an engine result. P1 has no numbers to cache yet, so
        // what is stored is the shape of what will be: something derived from
        // the pass, written under the key the pass computed.
        let summary = format!("{}:{}", changed.len(), blobs.len());
        store.put(&key, summary.as_bytes()).expect("cache writable");
    }

    Pass {
        elapsed: started.elapsed(),
        spawns: git.spawn_count(),
        files: changed.len(),
        blobs: blobs.len(),
        bytes: blobs.iter().map(|(_, c)| c.bytes().len()).sum(),
        cache_hit,
    }
}

/// Whether fsmonitor is actually watching this repository.
///
/// Asked *after* the fsmonitor leg has run, and answered from what the daemon
/// reports rather than from the platform or the git version. The first version
/// of this check tried to infer support by matching git's stderr for "is not a
/// git command", and reported `available` on a Linux runner — the subcommand
/// exists there and declines for a different reason, so the string never
/// matched. A capability probe that guesses from an error message is a probe
/// that will be wrong on the next platform.
///
/// `fsmonitor--daemon status` prints "is watching" when a daemon is genuinely
/// serving this repository, which is the only fact the gate actually needs: not
/// "could this platform do it" but "did it".
fn fsmonitor_is_watching(git: &Git) -> bool {
    git.cmd(["fsmonitor--daemon", "status"])
        .succeeds_with_output()
        .ok()
        .flatten()
        .is_some_and(|out| out.contains("is watching"))
}

/// Nearest-rank p95.
fn p95(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    let index = ((0.95 * samples.len() as f64).ceil() as usize).saturating_sub(1);
    samples[index.min(samples.len() - 1)]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// A fresh, empty cache directory for a cold run.
fn cold_store(name: &str) -> (CacheStore, tempfile::TempDir) {
    let dir = tempfile::Builder::new()
        .prefix(&format!("andon-perf-{name}-"))
        .tempdir()
        .expect("temp dir");
    let store = CacheStore::open(dir.path()).expect("store opens");
    (store, dir)
}

#[test]
#[ignore = "needs the generated 100k-file fixture; run with --ignored in release"]
fn the_fast_lane_stays_inside_its_policy_budgets() {
    if cfg!(debug_assertions) {
        panic!(
            "the perf gate measures a debug build unless run with --release, and a \
             debug build breaches every budget on optimization alone.\n\
             Run: cargo test --release -p andon-core --test perf_gate -- --ignored --nocapture"
        );
    }

    let fixture = fixture_dir();
    let manifest = Manifest::load(&fixture);
    let repo = fixture.join("repo");
    let policy = policy();
    let warm_budget = policy.perf.fast_lane_warm_p95_ms as f64;
    let fallback_budget = policy.perf.fast_lane_warm_fallback_p95_ms as f64;
    let cold_budget = policy.perf.fast_lane_cold_cap_ms as f64;
    let spawn_budget = policy.perf.max_git_spawns_per_measure;

    println!("\nperf gate — budgets from .andon.toml [perf]");
    println!("  warm p95 <= {warm_budget} ms, cold <= {cold_budget} ms, spawns <= {spawn_budget}");
    println!("  warm dirty, no watching fsmonitor daemon: p95 <= {fallback_budget} ms");
    println!("  fixture: {}", repo.display());
    println!(
        "  git: {}\n",
        Git::open(&repo).expect("repo opens").version()
    );
    println!(
        "{:<14} {:>8} {:>7} {:>10} {:>9} {:>7} {:>9}",
        "scenario", "files", "blobs", "bytes", "time ms", "spawns", "headroom"
    );

    let base = Revision::Rev(manifest.commit("base").to_string());
    let mut failures: Vec<String> = Vec::new();
    // (scenario, spawns, changed files) for the committed series, so the
    // structural half of T6 is asserted from the same runs that time it.
    let mut committed: Vec<(&str, u64, usize)> = Vec::new();

    // ---- cold: the worst realistic case, on the largest diff ----------------
    {
        let (store, _keep) = cold_store("cold");
        let head = Revision::Rev(manifest.commit("large").to_string());
        let result = pass(&repo, &base, &head, &store, &policy);
        assert!(!result.cache_hit, "a cold run must not hit the cache");
        report(
            "cold-large",
            &result,
            cold_budget,
            &mut failures,
            spawn_budget,
        );
    }

    // ---- warm: the three committed diffs, p95 of twenty ---------------------
    for name in ["small", "medium", "large"] {
        let (store, _keep) = cold_store(name);
        let head = Revision::Rev(manifest.commit(name).to_string());
        // One pass to populate, then the measured ones.
        let first = pass(&repo, &base, &head, &store, &policy);
        let mut samples = Vec::with_capacity(WARM_PASSES);
        let mut last = first;
        for _ in 0..WARM_PASSES {
            last = pass(&repo, &base, &head, &store, &policy);
            samples.push(last.elapsed);
        }
        assert!(last.cache_hit, "a warm run must hit the cache it populated");
        let summary = Pass {
            elapsed: p95(samples),
            ..last
        };
        committed.push((name, summary.spawns, summary.files));
        report(
            &format!("warm-{name}"),
            &summary,
            warm_budget,
            &mut failures,
            spawn_budget,
        );
    }

    // The structural half of PREMORTEM T6, and the half a stopwatch cannot see.
    // A thousand-file diff and a one-file diff must cost the same number of
    // processes; if they ever stop doing so, the batching regressed and the
    // latency will follow on a repository larger than this one.
    let flat = committed[0].1;
    for (name, spawns, files) in &committed {
        assert_eq!(
            *spawns, flat,
            "{name} ({files} files) cost {spawns} spawns against {flat} for the smallest diff"
        );
    }
    assert!(
        committed[2].2 >= 1000,
        "the large series must actually be large, or the flatness proves nothing"
    );
    println!(
        "
spawn count is flat at {flat} across 1, 50, and 1000 changed files"
    );

    // ---- warm dirty: the incremental keying path, which is T6 proper --------
    //
    // Two arrangements, two budgets, and **both gate**. The earlier shape picked
    // one leg to gate and reported the other, which is how the un-accelerated
    // path came to be 1306.9 ms against a 1000 ms figure on a green gate: the
    // number was printed, and nothing was asserting it.
    //
    // "Which leg gates" was the wrong question. Both arrangements ship — builtin
    // fsmonitor does not exist on Linux and can decline anywhere — so each is
    // held to the budget that describes it, and a leg that genuinely cannot run
    // here says why rather than disappearing.
    // Two scenarios, because the dirty path has two shapes that ship. A tree
    // dirty on top of the base commit is the simple one. A branch that already
    // carries commits *and* is dirty on top is the default `andon measure`
    // shape, and it costs a `diff-tree` and a blob read the simple one does not
    // — so it is measured rather than assumed to be the same.
    let git = Git::open(&repo).expect("repo opens");

    let mut legs: Vec<DirtyLeg> = Vec::new();
    for scenario in [DirtyScenario::HeadAtBase, DirtyScenario::BranchWithCommits] {
        // `--force`: the previous scenario left the tree dirty on purpose, and
        // those edits are what this checkout is meant to discard.
        git.cmd(["checkout", "--force", "--quiet", scenario.branch()])
            .output()
            .expect("check out the scenario's branch");
        dirty_the_worktree(&repo, &manifest.dirty_paths);

        for (suffix, fsmonitor, budget) in [
            ("nofsm", "false", fallback_budget),
            ("fsm", "true", warm_budget),
        ] {
            let label = format!("{}-{suffix}", scenario.label());
            git.cmd(["config", "core.fsmonitor", fsmonitor])
                .output()
                .expect("set fsmonitor");

            let (store, _keep) = cold_store(&label);
            let head = Revision::Worktree;
            // Warm-up passes, untimed. With fsmonitor on, the first invocation
            // *starts* the daemon and the next few race its initial scan —
            // timing those measures the daemon booting rather than the steady
            // state, and reports fsmonitor as a pessimization when it is the
            // opposite.
            let mut last = pass(&repo, &base, &head, &store, &policy);
            for _ in 0..3 {
                last = pass(&repo, &base, &head, &store, &policy);
            }
            let mut samples = Vec::with_capacity(WARM_PASSES);
            for _ in 0..WARM_PASSES {
                last = pass(&repo, &base, &head, &store, &policy);
                samples.push(last.elapsed);
            }
            // The committed series asserts this and the dirty legs did not,
            // which left the warm dirty numbers proving less than they looked
            // like they did: a leg that missed its cache on every pass would be
            // timing a cold path under a warm label.
            assert!(
                last.cache_hit,
                "{label}: a warm run must hit the cache it populated, or the \
                 incremental keying path is not what is being measured"
            );
            if scenario == DirtyScenario::BranchWithCommits {
                // Both segments are there, asserted from the shape rather than
                // from constants. The committed segment is 1000 files and every
                // one of them has a readable blob; the dirty segment is
                // `dirty_paths` and none of them does, because an unstaged edit
                // has no object anyone can read. Composition takes the base side
                // from the first and the worktree side from the second, so every
                // path in both loses its blob and keeps its entry — which makes
                // `blobs == files - dirty` true whatever the overlap happens to
                // be, and false for either segment alone.
                let dirty = manifest.dirty_paths.len();
                assert!(
                    last.files >= 1000,
                    "{label}: the committed segment is missing; got {} files",
                    last.files
                );
                assert_eq!(
                    last.blobs,
                    last.files - dirty,
                    "{label}: expected every one of the {dirty} dirty paths to \
                     carry no readable blob, over {} entries",
                    last.files
                );
                println!(
                    "  {label}: 1000 committed + {dirty} dirty = {} paths, {} shared",
                    last.files,
                    1000 + dirty - last.files
                );
            }
            let watching = fsmonitor == "true" && fsmonitor_is_watching(&git);
            legs.push(DirtyLeg {
                label,
                budget,
                // The fsmonitor leg is only runnable where a daemon actually
                // watches. Asked while it is still configured and warm, which is
                // the only moment the answer means anything.
                runnable: fsmonitor == "false" || watching,
                expected_spawns: scenario.expected_spawns(),
                summary: Pass {
                    elapsed: p95(samples),
                    ..last
                },
            });
        }
    }

    println!();
    for leg in &legs {
        if leg.runnable {
            report(
                &leg.label,
                &leg.summary,
                leg.budget,
                &mut failures,
                spawn_budget,
            );
            // The structural assertion, per scenario rather than "flat across
            // all of them": the union genuinely costs two more processes, and
            // saying so explicitly is what keeps the next one from arriving
            // unannounced.
            assert_eq!(
                leg.summary.spawns, leg.expected_spawns,
                "{}: expected {} git spawns and saw {}. If that is a deliberate \
                 change, move the number in DirtyScenario::expected_spawns and \
                 say why in the commit; if it is not, something stopped batching.",
                leg.label, leg.expected_spawns, leg.summary.spawns
            );
        } else {
            // Not silently skipped. A leg that vanishes from a gate's output is
            // indistinguishable from a leg that passed, and the reason it could
            // not run is the thing a reader needs.
            println!(
                "{:<14} {:>8} {:>7} {:>10} {:>9} {:>7} {:>9}",
                leg.label, "-", "-", "-", "not run", "-", "-"
            );
            println!(
                "  NOTE: {} did not run: `fsmonitor--daemon status` does not report a daemon",
                leg.label
            );
            println!("        watching this repository, so there is nothing to measure here.");
            println!("        Builtin fsmonitor needs git 2.37+ and does not exist on Linux.");
            println!(
                "        Its {} ms budget is therefore untested on this platform, and the",
                leg.budget
            );
            println!("        un-accelerated leg above is what this platform actually pays.");
        }
    }
    assert!(
        legs.iter().any(|leg| leg.runnable),
        "neither dirty leg ran, so the T6 path was not measured at all"
    );

    // Leave no daemon behind: `core.fsmonitor=true` starts a background process,
    // and a CI runner that ends with one still holding the repository open is a
    // flake waiting for the next job.
    git.cmd(["config", "core.fsmonitor", "false"]).output().ok();
    git.cmd(["fsmonitor--daemon", "stop"]).succeeds().ok();
    // And leave the fixture on the branch the manifest describes. CI regenerates
    // it per run; a developer's does not, and a second run that started on
    // `large` would measure a different repository under the same labels.
    git.cmd(["checkout", "--force", "--quiet", "base"])
        .output()
        .ok();

    println!();
    assert!(
        failures.is_empty(),
        "perf budgets breached:\n  {}\n\n\
         Budgets live in .andon.toml [perf]. Raising one is a ledgered policy \
         edit with a reason, not a fix.",
        failures.join("\n  ")
    );
}

fn report(
    label: &str,
    result: &Pass,
    budget_ms: f64,
    failures: &mut Vec<String>,
    spawn_budget: u32,
) {
    let elapsed = ms(result.elapsed);
    let headroom = 100.0 * (1.0 - elapsed / budget_ms);
    println!(
        "{:<14} {:>8} {:>7} {:>10} {:>9.1} {:>7} {:>8.1}%",
        label, result.files, result.blobs, result.bytes, elapsed, result.spawns, headroom
    );
    if elapsed > budget_ms {
        failures.push(format!(
            "{label}: {elapsed:.1} ms exceeds the {budget_ms} ms budget"
        ));
    }
    if result.spawns > u64::from(spawn_budget) {
        failures.push(format!(
            "{label}: {} git spawns exceeds the budget of {spawn_budget}",
            result.spawns
        ));
    }
}

/// Edit the manifest's dirty files, so the working tree differs from `HEAD` in
/// exactly the handful the fixture specifies.
fn dirty_the_worktree(repo: &Path, paths: &[String]) {
    for (i, path) in paths.iter().enumerate() {
        let full = repo.join(path);
        let mut body = std::fs::read(&full).expect("fixture file exists");
        body.extend_from_slice(format!("// dirty edit {i}\n").as_bytes());
        std::fs::write(&full, body).expect("write dirty file");
    }
}
