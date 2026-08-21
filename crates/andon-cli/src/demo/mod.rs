//! `andon demo tamper` — the trust story, one command, zero CI (PLAN P9b, A3).
//!
//! # What it stages and why
//!
//! PREMORTEM A3 is the stranger who only ever sees the commodity half —
//! metrics, thresholds, a report — and never the half that is the point: a
//! self-reported measurement is a *claim*, and the claim is checked by an
//! independent recompute that cannot be argued with. This command stages both
//! halves in a throwaway repository under the system temp directory:
//!
//! - **The legit leg.** An ordinary change is measured, the record lands in
//!   `refs/notes/andon-measure` as a self-report, and the verifier's recompute
//!   confirms it. The record's trust flips from "self-reported, counts
//!   downstream: no" to `confirmed`.
//! - **The gamed leg.** An equally ordinary change is measured and recorded —
//!   and then the note is rewritten by `andon-spike-forge`, the workspace's
//!   adversary binary: every count inflated by one and every per-result digest
//!   re-sealed, so the forged record is internally consistent, correctly
//!   formatted, and false. Inspection cannot catch it. The verifier's recompute
//!   catches it: `divergent`, with the disagreeing metrics named.
//!
//! # Why the forgery is performed by a different program
//!
//! `andon` performs no forgery of its own, and the boundary is stated
//! precisely because prose about a mechanism must not outrun it: every line
//! of forging logic lives in one file compiled only into the adversary
//! binary, and `andon-ledger-min`'s `binary_separation` test fails the build
//! if any of it leaks into that crate's own library. The scan reaches no
//! further — the rest of the workspace this binary links (`andon-core` with
//! its public `seal()`, the engines, this crate) is kept clean by review,
//! and was verified clean at this phase's review, not enforced by a guard.
//! So this demo does what a real attacker does — a different program writes
//! a different note — and when the adversary binary is not present the demo
//! refuses and says why, rather than growing a forging code path of its own
//! to be more convenient.
//!
//! # The outcomes are asserted, not narrated
//!
//! The demo checks that the legit leg confirmed and the gamed leg diverged, and
//! exits 1 naming what it saw otherwise. A demo that narrated success over a
//! wrong outcome would be a false claim about the exact mechanism it exists to
//! demonstrate.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use andon_core::git::Git;
use andon_core::schema::enums::Attestation;

use crate::args::Flags;
use crate::{attest, ledger, measure, render};

/// Fixed identity and clock for the theater's commits, so two runs build the
/// same repository. Same reasoning as the scenario fixtures' `FIXTURE_EPOCH`
/// (2026-01-01T00:00:00Z).
const DEMO_NAME: &str = "Andon Demo";
const DEMO_EMAIL: &str = "demo@andon.invalid";
const DEMO_EPOCH: i64 = 1_767_225_600;

const DEMO_USAGE: &str = "\
andon demo tamper [--keep]

  Stages the trust story locally, in about a minute, in a throwaway repository:
  an honest change whose self-report the verifier confirms, and a forged
  self-report — rewritten by the adversary binary `andon-spike-forge` — that the
  verifier catches as divergent. Nothing outside the temp directory is touched.

  --keep     leave the theater repository on disk and print its path

  Needs `andon-spike-forge` beside this binary (`cargo build --workspace`
  provides it). The demo performs no forgery itself: the forging logic lives
  in one file compiled only into the adversary binary, a build-failing test
  guards that file's crate, and the rest of the workspace this binary links
  is kept clean by review, not by the scan.";

/// `andon demo <story>`.
pub fn cmd_demo(flags: &Flags) -> Result<u8, String> {
    if flags.on("help") {
        println!("{DEMO_USAGE}");
        return Ok(0);
    }
    flags.reject_unknown(&[])?;
    match flags.first() {
        Some("tamper") => {}
        Some(other) => return Err(format!("unknown demo '{other}'; the demos are: tamper")),
        None => return Err(format!("which demo? the demos are: tamper\n\n{DEMO_USAGE}")),
    }
    let narrative = run_tamper(flags.on("keep"))?;
    print!("{narrative}");
    Ok(0)
}

/// The whole story, returned as one narrative so a test can read exactly what a
/// person reads.
fn run_tamper(keep: bool) -> Result<String, String> {
    // The adversary is located before anything is built: a refusal after a
    // half-built theater would leave litter for no benefit.
    let forge = forge_binary()?;

    let mut theater = Theater::create()?;
    let mut out = String::new();
    let say = |out: &mut String, text: &str| {
        let _ = writeln!(out, "{text}");
    };

    say(&mut out, "");
    say(
        &mut out,
        "  ANDON DEMO — a forged measurement, caught. Everything below happens in a",
    );
    let _ = writeln!(
        out,
        "  throwaway repository under {}; nothing else is touched.\n",
        theater.dir.display()
    );

    // ---- The stage: one base commit both changes build on. ----
    theater.write("src/orders.ts", BASE_TS)?;
    let base = theater.commit("base: the ordering module")?;

    // ---- Leg 1: an honest change, self-reported, then confirmed. ----
    say(&mut out, "  LEG 1 — an honest change.\n");
    let legit = theater.branch_and_commit(
        "improve",
        &base,
        "src/orders.ts",
        LEGIT_TS,
        "improve: validate quantities before totalling",
    )?;
    let record = theater.measure_and_record(&base, &legit)?;
    let _ = writeln!(
        out,
        "  The agent measured its change ({}) and recorded the result as a git note —",
        crate::resolve::change_line(&record.compare_context).trim()
    );
    let _ = writeln!(
        out,
        "  a self-report. Verdict: {}, {} finding(s). Trust so far: {} — counts",
        render::verdict_word(record.verdict.verdict),
        render::findings(&record).len(),
        attestation_word(record.attestation.value),
    );
    say(
        &mut out,
        "  downstream: no. A self-report is a claim; nothing has checked it yet.\n",
    );
    say(
        &mut out,
        "  Now the verifier recomputes the same change from the repository's own",
    );
    say(&mut out, "  objects and compares per-result digests:");
    let attested = attest::attest(&attest::Request {
        repo: theater.dir.clone(),
        head: legit.clone(),
        trusted_branch: "main".to_string(),
        fork_tier: false,
    })?;
    out.push_str(&attest::render(&attested));
    if attested.classification.attestation != Attestation::Confirmed {
        return Err(demo_defect("legit", "confirmed", &attested, &out));
    }

    // ---- Leg 2: an equally ordinary change, then the note is forged. ----
    say(&mut out, "  LEG 2 — a forged self-report.\n");
    let gamed = theater.branch_and_commit(
        "gamed",
        &base,
        "src/orders.ts",
        GAMED_TS,
        "extend: bulk pricing for large orders",
    )?;
    let gamed_record = theater.measure_and_record(&base, &gamed)?;
    let _ = writeln!(
        out,
        "  The second change is just as ordinary ({} finding(s) when measured honestly).",
        render::findings(&gamed_record).len()
    );
    say(
        &mut out,
        "  The lie is not in the diff — it is about to be written into the ledger.\n",
    );
    let forged_line = run_forge(&forge, &theater.dir, &gamed)?;
    let _ = writeln!(
        out,
        "  A DIFFERENT program — the adversary binary, {} —",
        forge
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "andon-spike-forge".to_string())
    );
    say(
        &mut out,
        "  rewrote the note: every count one higher than measured, every digest",
    );
    say(
        &mut out,
        "  re-sealed. The forged record is internally consistent and false; no",
    );
    say(
        &mut out,
        "  inspection of the record alone can catch it. (`andon` ships no forging",
    );
    say(
        &mut out,
        "  path of its own: the forging logic lives in one file compiled only into",
    );
    say(
        &mut out,
        "  the adversary, a build-failing test guards that file's crate, and the",
    );
    let _ = writeln!(
        out,
        "  rest of the workspace this binary links is kept clean by review, not by \
         the scan.)\n"
    );
    let _ = writeln!(out, "    adversary: {}\n", forged_line.trim());
    say(&mut out, "  The same verifier, on the forged report:");
    let gamed_attested = attest::attest(&attest::Request {
        repo: theater.dir.clone(),
        head: gamed.clone(),
        trusted_branch: "main".to_string(),
        fork_tier: false,
    })?;
    out.push_str(&attest::render(&gamed_attested));
    if gamed_attested.classification.attestation != Attestation::Divergent {
        return Err(demo_defect("gamed", "divergent", &gamed_attested, &out));
    }

    // ---- The point, stated once, from what just happened. ----
    say(&mut out, "  WHAT THIS SHOWED");
    say(
        &mut out,
        "  Both legs wrote the same kind of self-report. Inspection could not tell",
    );
    say(
        &mut out,
        "  them apart — the forged one is correctly formatted and self-consistent.",
    );
    say(
        &mut out,
        "  The independent recompute told them apart: confirmed on the honest one,",
    );
    say(
        &mut out,
        "  divergent on the forged one, with the disagreeing metrics named. Until",
    );
    say(
        &mut out,
        "  that recompute runs, a measurement is self-reported and counts for",
    );
    say(
        &mut out,
        "  nothing downstream. In real use the recompute is CI's job — `andon init",
    );
    say(
        &mut out,
        "  --ci` prints the recipe — and this command exists so you can watch the",
    );
    say(
        &mut out,
        "  distinction work without setting any of that up.",
    );
    say(&mut out, "");

    if keep {
        let _ = writeln!(
            out,
            "  The theater repository is kept at {}\n",
            theater.dir.display()
        );
        std::mem::forget(theater);
    }
    Ok(out)
}

/// A demo whose outcome contradicts its own story is a defect, loudly.
fn demo_defect(leg: &str, expected: &str, attested: &attest::Attested, so_far: &str) -> String {
    format!(
        "{so_far}\n  DEMO DEFECT: the {leg} leg was expected to attest `{expected}` and \
         attested `{}` instead. The narrative above is what actually happened; this exit \
         is the demo refusing to claim otherwise. Please report this.",
        attestation_word(attested.classification.attestation)
    )
}

/// The wire spelling of an attestation value, read off the serializer so a
/// schema rename cannot leave this printing the old word.
fn attestation_word(value: Attestation) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{value:?}"))
}

/// Where the adversary binary lives: an explicit override, or beside this
/// executable. The same two-candidate rule as the scenario runner — beside the
/// exe covers `cargo run` and an installed workspace build; one directory up
/// covers `cargo test`, whose harness lives in `target/<profile>/deps/`.
fn forge_binary() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("ANDON_SPIKE_FORGE_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "ANDON_SPIKE_FORGE_BIN is set to {} but nothing is there.",
            path.display()
        ));
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let name = format!("andon-spike-forge{}", std::env::consts::EXE_SUFFIX);
    let mut tried = Vec::new();
    for dir in exe.parent().into_iter().chain(
        exe.parent()
            .and_then(Path::parent)
            .filter(|_| exe.parent().is_some_and(|p| p.ends_with("deps"))),
    ) {
        let candidate = dir.join(&name);
        if candidate.is_file() {
            return Ok(candidate);
        }
        tried.push(candidate.display().to_string());
    }
    Err(format!(
        "the demo needs the adversary binary `{name}` and did not find it (tried: {}).\n\
         The forging logic deliberately lives in one file compiled only into the \
         adversary, guarded there by a build-failing test, and this demo does not grow \
         a forging path of its own. Build it with `cargo build --workspace` in the \
         Andon checkout, or point ANDON_SPIKE_FORGE_BIN at it.",
        tried.join(", ")
    ))
}

/// Run the adversary against one commit's note.
fn run_forge(forge: &Path, repo: &Path, commit: &str) -> Result<String, String> {
    let output = std::process::Command::new(forge)
        .arg("--repo")
        .arg(repo)
        .args(["--commit", commit, "--op", "inflate-metric"])
        .output()
        .map_err(|e| format!("could not run {}: {e}", forge.display()))?;
    if !output.status.success() {
        return Err(format!(
            "the adversary binary failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The throwaway repository. Dropping it removes the directory.
struct Theater {
    dir: PathBuf,
    git: Git,
    commits: i64,
}

impl Drop for Theater {
    fn drop(&mut self) {
        // Best-effort: a leftover under the system temp dir is what temp dirs
        // are for, and a cleanup failure must not overwrite the demo's exit.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Theater {
    /// A fresh repository under the system temp directory.
    fn create() -> Result<Self, String> {
        let dir = std::env::temp_dir().join(format!(
            "andon-demo-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        // A raw spawn, like `init::git_hook_path`'s and for a related reason:
        // `Git::open` insists on being inside a repository and the destination
        // is not one yet. Everything after this line goes through `Git::cmd`
        // and its pinned config.
        let output = std::process::Command::new("git")
            .args(["init", "--quiet", "--initial-branch", "main"])
            .arg(&dir)
            .output()
            .map_err(|e| format!("git could not be run: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "git init failed in {}: {}",
                dir.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let git = Git::open(&dir).map_err(|e| e.to_string())?;
        for (key, value) in [
            ("user.name", DEMO_NAME),
            ("user.email", DEMO_EMAIL),
            ("core.autocrlf", "false"),
        ] {
            git.cmd(["config", key, value])
                .output()
                .map_err(|e| e.to_string())?;
        }
        Ok(Theater {
            dir,
            git,
            commits: 0,
        })
    }

    fn write(&self, path: &str, text: &str) -> Result<(), String> {
        let full = self.dir.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        std::fs::write(&full, text).map_err(|e| format!("{}: {e}", full.display()))
    }

    /// Commit everything staged-or-not, with the pinned identity and clock.
    fn commit(&mut self, message: &str) -> Result<String, String> {
        self.git
            .cmd(["add", "--all", "."])
            .output()
            .map_err(|e| e.to_string())?;
        let stamp = format!("{} +0000", DEMO_EPOCH + self.commits * 60);
        self.commits += 1;
        self.git
            .cmd(["commit", "--quiet", "-m", message])
            .env("GIT_AUTHOR_NAME", DEMO_NAME)
            .env("GIT_AUTHOR_EMAIL", DEMO_EMAIL)
            .env("GIT_COMMITTER_NAME", DEMO_NAME)
            .env("GIT_COMMITTER_EMAIL", DEMO_EMAIL)
            .env("GIT_AUTHOR_DATE", &stamp)
            .env("GIT_COMMITTER_DATE", &stamp)
            .output()
            .map_err(|e| e.to_string())?;
        let oid = self
            .git
            .cmd(["rev-parse", "--verify", "HEAD^{commit}"])
            .text()
            .map_err(|e| e.to_string())?;
        Ok(oid.trim().to_string())
    }

    /// A branch off `from`, one file rewritten, committed.
    fn branch_and_commit(
        &mut self,
        name: &str,
        from: &str,
        path: &str,
        text: &str,
        message: &str,
    ) -> Result<String, String> {
        self.git
            .cmd(["checkout", "--quiet", "-b", name, from])
            .output()
            .map_err(|e| e.to_string())?;
        self.write(path, text)?;
        self.commit(message)
    }

    /// Measure `base..head` the way `andon measure` does, and file the note the
    /// way `--record` does. The record is a self-report: `attestation:
    /// unwitnessed` until a verifier says otherwise.
    fn measure_and_record(
        &self,
        base: &str,
        head: &str,
    ) -> Result<andon_core::schema::payload::MeasurementRecord, String> {
        let measurement = measure::measure(&measure::Request {
            repo: self.dir.clone(),
            base: Some(base.to_string()),
            head: Some(head.to_string()),
            no_fallback: true,
            ..measure::Request::default()
        })
        .map_err(|e| e.to_string())?;
        ledger::record(&self.git, &measurement.record, &measurement.ledger_anchor)?;
        Ok(measurement.record)
    }
}

const BASE_TS: &str = "\
export interface Order {
  quantity: number;
  unitPrice: number;
}

export function orderTotal(order: Order): number {
  return order.quantity * order.unitPrice;
}
";

const LEGIT_TS: &str = "\
export interface Order {
  quantity: number;
  unitPrice: number;
}

export function validateOrder(order: Order): boolean {
  return Number.isFinite(order.quantity) && order.quantity > 0 && order.unitPrice >= 0;
}

export function orderTotal(order: Order): number {
  if (!validateOrder(order)) {
    throw new RangeError('order quantities must be positive and finite');
  }
  return order.quantity * order.unitPrice;
}
";

const GAMED_TS: &str = "\
export interface Order {
  quantity: number;
  unitPrice: number;
}

export function bulkDiscount(quantity: number): number {
  if (quantity >= 100) {
    return 0.9;
  }
  return 1;
}

export function orderTotal(order: Order): number {
  return order.quantity * order.unitPrice * bulkDiscount(order.quantity);
}
";
