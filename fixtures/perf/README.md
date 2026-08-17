# The perf fixture

A generated ~100,000-file git repository with a pinned diff series, and the
subject of the perf gate (`crates/andon-core/tests/perf_gate.rs`).

```sh
./fixtures/perf/generate.sh
cargo test --release -p andon-core --test perf_gate -- --ignored --nocapture
```

Release mode is not optional and the harness refuses to run without it: a debug
build breaches every budget on optimization alone, which would make the gate a
measurement of `-O0`.

## What is here

| File | What it is |
|---|---|
| `series.toml` | The definition: layout, content seed, and the three diff sizes. |
| `expected.toml` | The pinned commit OIDs generation must produce. |
| `generate.sh` | The entry point. Builds into `.perf-fixture/` (git-ignored, and deliberately outside `target/`). |

## Why generated rather than committed

A hundred thousand files do not belong in the repository, and a fixture that is
*regenerated* rather than stored is only useful if it comes out the same every
time. Everything feeding a commit OID is fixed — the seeded content, the paths,
the author and committer identity, and both timestamps — so the fixture has the
same OIDs on Linux, macOS, and Windows. `expected.toml` pins them and the
generator refuses to hand the gate a repository that does not match.

That is what makes "pinned diff series" a hash rather than an intention. If the
pins stop matching, the fixture changed and this run's numbers are not
comparable with the last one's — which is a ledgered budget decision, not a pin
to refresh quietly.

## Why the numbers are shaped this way

PREMORTEM T6 is the claim that fast-lane cost tracks *diff* size and not
*repository* size. A claim about the shape of a curve cannot be tested at one
point, so the series is 1, 50, and 1000 changed files against one fixed
100,000-file repository, and the gate asserts a flat git-subprocess count across
all three. The count is the half a stopwatch cannot see: batching that regresses
into one spawn per file reads as a modest slowdown on a laptop and as a timeout
on a monorepo.

The dirty-tree scenario is the one T6 is really about. Twenty-five uncommitted
files in a hundred thousand: if finding that handful costs a walk of the other
99,975, the fast lane is not fast on the repositories that needed it.

## Budgets

From `.andon.toml` `[perf]`, read at run time and never written in the harness.
A hardcoded budget is a number nobody can ledger a change to, and it enables the
ratchet where the constant gets nudged until the gate goes green.

## Where the time goes

`ANDON_PERF_STAGES=1` prints a per-stage breakdown of every pass. The first
question anyone asks of a breached budget is which stage breached it.

## Two things worth knowing before reading a number

**The gate is one test, not several.** `cargo test` runs test functions in
parallel, and two of them measuring the same repository reported 1400 ms for
work that takes 150 ms alone. A perf gate that races itself measures the race.

**fsmonitor decides the dirty-tree number.** Builtin fsmonitor exists on Windows
and macOS from git 2.37 and not on Linux, so the harness detects it and gates on
the best arrangement the platform supports, reporting the other leg alongside.
On the reference Windows machine the dirty path is 194 ms with fsmonitor and
938 ms without, against a 1000 ms budget — so the leg that is *not* gated is
also the one worth watching.
