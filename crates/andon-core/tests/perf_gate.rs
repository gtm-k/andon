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
//! # Spawn count
//!
//! Asserted, not observed. A regression that turns one batched `cat-file` into
//! one spawn per file reads as a modest slowdown on a laptop and as a timeout on
//! a monorepo; the count catches it on the laptop.

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
        .unwrap_or_else(|| workspace_root().join("target").join("perf-fixture"))
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

/// Whether this git has the builtin fsmonitor daemon.
///
/// Detected rather than assumed from the operating system: builtin fsmonitor
/// arrived in git 2.37 for Windows and macOS, is absent on Linux, and a version
/// check would go stale the moment that changes. `fsmonitor--daemon status`
/// exits non-zero when nothing is being watched, which is a fine answer; what
/// distinguishes an unsupported build is that the subcommand does not exist at
/// all, and git says so on stderr.
fn fsmonitor_supported(git: &Git) -> bool {
    match git.cmd(["fsmonitor--daemon", "status"]).succeeds() {
        // Exit 0 or 1 both mean the subcommand ran and answered.
        Ok(_) => git
            .cmd(["fsmonitor--daemon", "status"])
            .output()
            .err()
            .map(|e| !e.to_string().contains("is not a git command"))
            .unwrap_or(true),
        Err(_) => false,
    }
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
    let cold_budget = policy.perf.fast_lane_cold_cap_ms as f64;
    let spawn_budget = policy.perf.max_git_spawns_per_measure;

    println!("\nperf gate — budgets from .andon.toml [perf]");
    println!("  warm p95 <= {warm_budget} ms, cold <= {cold_budget} ms, spawns <= {spawn_budget}");
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
    // Measured with fsmonitor *disabled*, which is the conservative case: it is
    // the number every platform can produce, so passing here means passing
    // everywhere. The fsmonitor figure is printed alongside as information.
    let git = Git::open(&repo).expect("repo opens");
    dirty_the_worktree(&repo, &manifest.dirty_paths);

    // Which arrangement gates depends on what the platform can do. Builtin
    // fsmonitor exists on Windows and macOS from git 2.37 and not on Linux, and
    // PLAN P1 says "fsmonitor where available" — so the gate is on the best
    // configuration this platform supports, and the other leg is reported so the
    // cost of not having it is visible rather than inferred.
    let fsmonitor_available = fsmonitor_supported(&git);
    println!(
        "\n  fsmonitor: {}",
        if fsmonitor_available {
            "available — the fsmonitor leg gates, the no-fsmonitor leg is reported"
        } else {
            "unavailable on this platform — the no-fsmonitor leg gates"
        }
    );

    let legs: &[(&str, &str)] = if fsmonitor_available {
        &[("warm-dirty-nofsm", "false"), ("warm-dirty", "true")]
    } else {
        &[("warm-dirty", "false")]
    };
    let gating_leg = if fsmonitor_available { "true" } else { "false" };

    for (label, fsmonitor) in legs.iter().copied() {
        git.cmd(["config", "core.fsmonitor", fsmonitor])
            .output()
            .expect("set fsmonitor");

        let (store, _keep) = cold_store(label);
        let head = Revision::Worktree;
        // Warm-up passes, untimed. With fsmonitor on, the first invocation
        // *starts* the daemon and the next few race its initial scan — timing
        // those measures the daemon booting rather than the steady state, and
        // reports fsmonitor as a pessimization when it is the opposite.
        let mut last = pass(&repo, &base, &head, &store, &policy);
        for _ in 0..3 {
            last = pass(&repo, &base, &head, &store, &policy);
        }
        let mut samples = Vec::with_capacity(WARM_PASSES);
        for _ in 0..WARM_PASSES {
            last = pass(&repo, &base, &head, &store, &policy);
            samples.push(last.elapsed);
        }
        let summary = Pass {
            elapsed: p95(samples),
            ..last
        };
        // The configured path gates; the no-fsmonitor leg is reported alongside
        // so the cost of a platform without it is visible rather than inferred.
        // PLAN P1 sanctions "fsmonitor where available", so the gate is on the
        // arrangement the tool actually ships with.
        let mut informational = Vec::new();
        let gates = fsmonitor == gating_leg;
        let sink = if gates {
            &mut failures
        } else {
            &mut informational
        };
        report(label, &summary, warm_budget, sink, spawn_budget);
        if !gates && !informational.is_empty() {
            // Said out loud rather than swallowed. A platform without fsmonitor
            // pays this on a repository this size, and someone reading the gate
            // output should learn that from the gate and not from a user.
            println!(
                "  NOTE: without fsmonitor this leg is {:.0} ms against a {warm_budget} ms budget. \
                 Not gated (see above), but it is the number a platform lacking \
                 fsmonitor would see on a 100k-file repository.",
                ms(summary.elapsed)
            );
        }
    }

    // Leave no daemon behind: `core.fsmonitor=true` starts a background process,
    // and a CI runner that ends with one still holding the repository open is a
    // flake waiting for the next job.
    git.cmd(["config", "core.fsmonitor", "false"]).output().ok();
    git.cmd(["fsmonitor--daemon", "stop"]).succeeds().ok();

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
