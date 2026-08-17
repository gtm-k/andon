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

`.gitattributes` marks `fixtures/**` as `-text`, because fixture data is
byte-exact input and normalizing it would be a trap rather than a tidy-up. The
script is the one exception, on its own later line: it is not fixture data, and
under the byte-exact rule a Windows checkout gave it a CRLF shebang, which is
not executable. The Linux perf leg went red on
`/usr/bin/env: 'bash\r': No such file or directory` before that line existed.

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

It runs in two shapes. `warm-dirty` sits on the base commit, so the whole change
is uncommitted. `warm-branch` sits on the `large` series branch with the same
twenty-five files dirty on top — a branch with a thousand committed files behind
it and edits in front of it, which is the default `andon measure` shape and what
an agent measuring its own change mid-loop always looks like. The second costs
two processes more than the first: a `diff-tree` over the committed segment and
the `cat-file` batch that reads the blobs it turns up.

The spawn counts are asserted differently on purpose. The committed series
asserts *flatness* across 1, 50, and 1000 files, which is T6's shape claim. The
dirty legs assert an *exact number per scenario*, because they legitimately
differ from each other and demanding flatness across them would be demanding the
wrong property.

## Budgets

From `.andon.toml` `[perf]`, read at run time and never written in the harness.
A hardcoded budget is a number nobody can ledger a change to, and it enables the
ratchet where the constant gets nudged until the gate goes green.

| Key | What it bounds |
|---|---|
| `fast_lane_warm_p95_ms` | The warm passes, and the dirty-tree path with a watching fsmonitor daemon. |
| `fast_lane_warm_fallback_p95_ms` | The dirty-tree path with no watching daemon. |
| `fast_lane_cold_cap_ms` | The cold pass on the largest diff. |
| `max_git_spawns_per_measure` | Every pass, asserted rather than observed. |

## Where the time goes

`ANDON_PERF_STAGES=1` prints a per-stage breakdown of every pass. The first
question anyone asks of a breached budget is which stage breached it.

## Two things worth knowing before reading a number

**The gate is one test, not several.** `cargo test` runs test functions in
parallel, and two of them measuring the same repository reported 1400 ms for
work that takes 150 ms alone. A perf gate that races itself measures the race.

**fsmonitor changes the dirty-tree number, and both numbers are gated.** Builtin
fsmonitor exists on Windows and macOS from git 2.37 and not on Linux, so the
harness measures the dirty path both ways and holds each to its own budget:
`fast_lane_warm_p95_ms` for the accelerated arrangement,
`fast_lane_warm_fallback_p95_ms` for the one without a watching daemon. On a
reference Windows run the four legs are 146 ms and 887 ms for `warm-dirty`, and
257 ms and 983 ms for `warm-branch`, against 1000 ms and 2000 ms.

The harness used to gate one leg and merely print the other, picking which from
what the daemon reported. That is a ratchet with no constant to nudge, and it
had already fired: the un-accelerated path was measured at 1306.9 ms while the
gate stayed green, because the budget it breached was the one nothing asserted.
Now a leg either gates or explains, in the results table, why it could not run
at all — which on Linux is the fsmonitor leg, every time.

`fsmonitor--daemon status` is what decides "could not run", and the question it
answers is "did a daemon watch this repository", not "does this platform support
one". An earlier version inferred support by matching git's stderr for
"is not a git command" and reported `available` on a Linux runner, where the
subcommand exists and declines for a different reason.
