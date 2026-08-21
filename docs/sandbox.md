# The sandbox, and the async lane it serves

Andon's only `code-exec` engine is the user's own test command, declared in
`.andon.toml`:

```toml
[sandbox]
enabled = true                 # the async lane's feature flag; off by default
test_command = "npm test"      # run through `sh -c` / `cmd /C`
test_timeout_ms = 600000       # generous: a fresh worktree pays a cold build
env_allow = []                 # names passed through beyond the base allowlist
# memory_limit_mb = 4096       # best-effort cap; unset means no cap
```

Everything defaults off. A repository that never touches `[sandbox]` measures
exactly as it did before the lane existed — that is the rollback path.

## Why the command is policy

Codex finding #19: builds, test suites and hooks execute repository-controlled
code, and an agent invoking them in a developer environment exposes
credentials, the network, and the machine. Andon's answer has two halves. The
*trusted-command* half is that the command is **policy**: the verifier reads it
from the base commit, an edit to it inside the change under measurement
surfaces as a `policy-change` finding with a direction (removing the command or
shortening the timeout is a loosening), and declaring one at all is a visible,
reviewable act. The *containment* half is the sandbox below.

## What the sandbox provides

- **A temporary worktree.** The suite runs in a throwaway checkout of the
  measured snapshot, materialized from git objects — the anchor commit plus
  the measured change's blobs. It never runs in the operator's tree, and it
  never runs against bytes other than the ones that were measured, even when
  the operator has kept editing since.
- **A default-deny environment.** The child receives a documented base
  allowlist (`andon_sandbox::BASE_ENV_ALLOW` — PATH, HOME/USERPROFILE, the
  temp variables, and per-OS process-start necessities), anything
  `env_allow` adds, and `ANDON_SANDBOX=1`. Nothing else crosses: tokens and
  keys in the invoking environment never reach repository code.
- **A wall-clock timeout with a process-tree kill.** At `test_timeout_ms` the
  whole tree is killed — a job object with kill-on-close on Windows, a
  process-group `SIGKILL` on Unix — and the tree is also swept when the
  command exits normally, so a daemon a test spawned does not outlive the
  measurement.
- **Best-effort resource limits.** `memory_limit_mb` maps to a job-object
  memory limit on Windows and an address-space rlimit on Unix.

## What the sandbox deliberately does not provide

Stated here because prose about a mechanism must not outrun it:

- **No network isolation.** The suite reaches anything the invoking user can.
  Every tests-family result carries `sandbox: no-net-isolation` inside its
  `measurement_regime`, so the payload discloses this wherever the record
  travels (VISION §5's disclosed limitation).
- **No filesystem isolation beyond the working directory.** The suite runs as
  the invoking user. The temp worktree is where it is pointed, not where it is
  confined.
- **Not a security boundary against a hostile repository.** The environment
  deny keeps secrets out of the child's *environment*; it does not stop code
  that reads files the user can read. The limits are best-effort. An operator
  who does not trust a repository should not declare a `test_command` for it.
- **On Unix, the group kill has a named gap:** a grandchild that calls
  `setsid` leaves the process group and survives the sweep. The Windows job
  object has no equivalent escape short of breakaway rights, which are not
  granted.

## The async lane: deferred execution, not a daemon

`andon measure` never blocks on slow work. The test command always runs on the
async lane, and past the cold cap (`perf.fast_lane_cold_cap_ms`, enforced when
the lane is enabled) the content engines spill to it too — the cap bounds when
an engine may *start*; an engine already running is not interrupted mid-file.
The measurement returns with its completeness honestly below `complete`, the
verdict carries an `engine-spilled-async` reason, and a job file waits in the
state directory.

**`andon wait` is what executes the job** — in the foreground, under the
policy snapshot the measurement was taken with — then merges the results in
with `lane: async` freshness stamps, re-reaches the verdict, and consumes the
job. The MCP `await_results` tool runs the same completion. No background
process exists at any point: a daemon would race the agent's next edit and die
unobserved with its session, and "is the suite still running?" must always be
answerable by looking.

A failed suite blocks through `severity.block_on_test_failure` (default on),
keyed on the failure flag itself — the suite's claims are tier N, honestly, so
severity alone could never block. A suite killed at the timeout is an
**unanswered question**: the record stays incomplete with an
`engine-unavailable` reason that says so, and it is never reported as a test
failure. The suite's output tails are saved to
`.git/andon/test-suite-output.log` for whoever has to act on the verdict.

## Costs worth knowing

- A fresh worktree means compiled suites pay a cold build every run; the
  default timeout is sized for that, and the worktree is removed when the run
  ends (a crash leaves a directory under the system temp dir and a
  registration the next run prunes).
- Suite results are timing- and environment-dependent, so nothing the tests
  engine emits is `deterministic`: none of it enters the digest compare, and
  the v1 verifier does not execute the code-exec lane at all — the CI-side
  execution design belongs to the P9 verifier.
- Under `--self-measure`, paths the policy withholds are not replayed into the
  sandbox; the suite sees them as of the anchor commit.
