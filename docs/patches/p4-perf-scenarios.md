# P4 → the perf gate: what the process family costs

**Status:** informational now, **required at P5a.**
**Why it is a patch and not an edit:** `.github/workflows/perf.yml` and
`crates/andon-core/tests/perf_gate.rs` are P1-owned. PLAN P4's instruction is
explicit — if the history cache adds spawns to `measure_change`'s path, extend
the fixtures and expectations through a documented patch rather than editing
P1's files.
**Owner at apply time:** the orchestrator, at P5a, when the engines are first
wired into `measure_change`.

---

## The finding: nothing on the gated path has changed today

P4 ships two engine crates. Neither is called by `measure_change` — P5a builds
that assembly — so the fast-lane path P1's perf gate measures is
**byte-for-byte the path it measured before this phase**, and the existing
budgets are unaffected. There is nothing to add to `perf.yml` yet, and adding a
scenario for a code path nothing calls would gate a number that means nothing.

What follows is the cost model, measured rather than estimated, so that P5a's
integration starts from data.

## Measured cost

Asserted in `crates/engines/process/tests/spawn_budget.rs`, which fails the build
if any of it changes:

| | spawns | what they are |
|---|---|---|
| cold, no cache | 2 | `git log -1 --format=%ct <anchor>`, then one `git log --numstat` bounded by the window |
| cold, cache miss | 2 | the same two; the result is written to the store |
| **warm, cache hit** | **0** | nothing is asked of git at all |
| 40 changed files | 2 | the count does not scale with the changed set — asserted directly |

Wall-clock, measured on Windows against a synthetic 300-commit, 20-file
repository, `andon-p4-probe` end to end (process start, `Git::open`, resolution,
enumeration, history read, and measurement):

| | ms |
|---|---|
| cold | 308–335 |
| warm | 128–140 |
| the history read alone (cold − warm) | ≈ 200 |
| cache entry | 46.8 KB for 300 commits (≈ 156 bytes per path-touch) |

The artifacts engine adds **one** spawn — `git diff --unified=0` for the hunk
headers — and no cache. It is advisory-lane work and is not on the compared path.

## The scaling model, and the number P5a has to decide

Cold cost is linear in **path-touches inside the window**, not in repository
size. A 100k-file repository with a quiet year costs less than a 200-file
repository with a busy one. That is the right shape for PREMORTEM T6 — the cost
follows the history the window asked for — but it has no upper bound: a
monorepo's 365-day window can hold hundreds of thousands of commits, and the
first measurement pays for all of them.

Three properties keep that from being a fast-lane problem, and one question is
left open:

- The entry is keyed by **anchor commit**, which is immutable, so the walk is
  paid once per commit rather than once per measurement.
- A hit costs zero spawns, so the warm path — the one P1's headline budget is
  about — is untouched by the size of the history.
- The window is a policy field. An operator on a very large repository can narrow
  it, and the narrowing is visible in the regime rather than silent.
- **Open for P5a:** whether the *first* measurement on a large repository must
  spill to the async lane with `completeness: partial` rather than block the fast
  lane's 10-second cold cap. The machinery for that is P7's, and the decision
  needs a real large-repository number rather than the 300-commit one above.

## The patch, to apply at P5a

Two steps, once `measure_change` calls the engines.

**1. Add the engine spawn budget to the perf gate's assertions.** The scenario
belongs in the engine crate rather than in `crates/andon-core/tests/perf_gate.rs`:
`andon-core` must not depend on an engine crate, and inverting that dependency to
gate a number would be a worse outcome than running one more test binary. The
assertions already exist in
`crates/engines/process/tests/spawn_budget.rs`; what the patch adds is running
them in the perf job, in release, against the shared 100k fixture:

```yaml
      # In both the linux and windows jobs of .github/workflows/perf.yml, after
      # the existing "Perf gate" step.
      - name: Engine cost model (process family)
        run: |
          set -euo pipefail
          cargo test --release -p andon-engine-process --test spawn_budget -- \
            --nocapture --test-threads=1
```

**2. Raise the assembled spawn expectation, once and explicitly.** P1's
`max_git_spawns_per_measure` is 64 and the plumbing uses at most 9. The
assembled fast lane at P5a adds:

| engine | cold spawns | warm spawns |
|---|---|---|
| process | 2 | 0 |
| artifacts | 1 | 1 |

That leaves the assembled measurement comfortably inside 64 with P2's and P3's
engines still to come, so **no policy edit is expected**. If one turns out to be
needed it is a ledgered `.andon.toml` change with a stated reason, never a
quietly raised number — the ratchet PREMORTEM T6 warns about.

## What must not happen

Neither file is touched by P4. If a reviewer finds `perf.yml` or `perf_gate.rs`
modified on the P4 branch, that is a scope violation and not an oversight.
