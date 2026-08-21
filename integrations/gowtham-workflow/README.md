# Andon in the gowtham-workflow: the post-code gate measures its phase

Andon's first real consumer (PLAN P9b). The gowtham-workflow's post-code
ensemble review rules on a phase diff; this integration puts an Andon
measurement of that exact diff beside the reviewers' briefs and files the
record in the repository's ledger, so every gated phase becomes part of the
false-positive evidence base the flip gate reads.

Everything here is a consumer of shipped surfaces — `andon measure`,
`andon ledger fp-window`, `andon init` — and can be removed without touching
the product.

## The recipe

At the workflow's post-code gate, after the phase tip is verified and before
the ensemble reviewers are dispatched, the orchestrator runs:

```sh
integrations/gowtham-workflow/measure-phase.sh <worktree> <base-sha> <head-sha> [model-id]
# Andon measuring Andon itself: append --self-measure
```

which is exactly:

```sh
andon measure --repo <worktree> --base <base-sha> --head <head-sha> \
  --source agent-initiated --harness claude-code [--model <id>] --record
```

- **The SHAs are the verified ones** — the same commits the reviewers rule on,
  never a branch name (the P8 merge incident's rule: the pointer you verify
  must be the pointer you use).
- **The report goes into the review brief.** Reviewers receive the terminal
  report (or `--profile agent-mode` for an agent reviewer) beside the diff;
  the measurement is evidence for their verdict, not a substitute for it.
- **The exit code is Andon's own gate contract** (`andon --help` is
  authoritative): 0 pass/advise, 2 block, 3 escalate to human, 1 the tool or
  the read failed. A 2 or 3 at this gate is a finding for the ensemble round,
  not an automatic phase failure — the ensemble owns the verdict; Andon owns
  the evidence.
- **`--source agent-initiated`, deliberately not `hook`:**
  `InvocationSource::Hook` means "a harness hook fired", and this command is
  run by the orchestrator agent at a playbook gate. Recording `hook` would be
  a claim the mechanism does not prove.
- **`--record` is the point.** The note lands in `refs/notes/andon-measure`,
  where the FP-budget window (below) and `andon ledger stats` read it.

### Wiring it into the workflow playbook

The line the workflow's SKILL.md post-code phase gains (adoption in the
`gowtham-workflow` plugin repo is an orchestrator/user step — this repository
only documents the snippet):

> Before dispatching the post-code ensemble, run
> `integrations/gowtham-workflow/measure-phase.sh <worktree> <base> <head>
> <model>` in the measured repository and attach its report and exit code to
> every reviewer brief.

## Reading the output (the parts a first user stumbles on)

The report is designed to be read without this section; these are the fields
that carry a contract a consumer must not guess at (P6/P7 routed the gaps
here — PLAN F5):

- **`advise` keeps the line moving.** It is findings worth reading, not a
  softer block. Act on findings whose `diff_actionable` is `true`; a `false`
  there marks context — "do not grind on it" is the designed reading, and the
  loop cap escalates a grinder to a human regardless.
- **`counts_downstream: false` is the trust story, not an error.** Every
  fresh measurement is a self-report; nothing it says counts as attested
  evidence until a verifier recomputes it (`attestation: unwitnessed` →
  `confirmed`/`divergent`). A reviewer citing Andon numbers cites a
  self-report and should say so.
- **`verdict_invalid: true` overrides `verdict`.** The stored verdict is
  contradicted by the record's own coverage; re-measure instead of branching
  on the verdict word.
- **`unread_paths > 0` (agent profile) / `NOT READ` (report) exits 1.** A
  change nobody could fully read does not pass the gate, whatever the verdict
  says; the report names the paths.
- **`truncated: true` is a budget cut, not the whole answer.**
  `total_findings` says how many exist; findings are worst-first, so what was
  cut ranks below what was shown. `andon report --full` prints everything.
- **A test suite killed at its timeout is an unanswered question.** The
  record stays incomplete with an `engine-unavailable` reason; it is never
  reported as a test failure. Next step: read the suite's tail in
  `.git/andon/test-suite-output.log`, raise `[sandbox] test_timeout_ms` (a
  ledgered policy edit — a *shorter* timeout is the loosening direction), and
  measure again.

## The FP-budget window (PREMORTEM S6, PLAN R2-3)

The flip's entry gate (P10b) checks a numeric budget set ex ante: **≥30
honest changes over ≥14 days; MED+ findings on <10% of them; escalations
<1/week** — with the P2 rider that cognitive/cyclomatic-driven MED+ is
counted separately, and the round-1 B8 anti-gaming check that any policy
loosening relative to the conservative defaults carries a ledgered
justification.

The instrumentation is one command over the ledger the recipe above feeds:

```sh
andon ledger fp-window --since <window-start> [--until <stamp>]
```

It reports: distinct measured changes (by head identity), the MED+ change
rate with the cognitive/cyclomatic split, escalation records per week, the
policy hashes the window's records carried, and the field-by-field diff of
the policy in force against the conservative defaults with each delta's
direction. It deliberately does not say pass or fail — the gate that owns
the budget does the comparing.

**Window protocol:** the window START is the ledgered fact — the landing
time (notes-history committer date) of the first record after the
instrumentation went live, recorded in the project ledger by the
orchestrator. At window end, the same command's output — quantities plus the
B8 policy diff — is the artifact the P10b entry gate checks. Records carry
no wall-clock field by design (the ledger's note carries when a record
landed), so the window is "what entered this repository's ledger in the
interval"; `fp-window`'s own output counts anything it could not date rather
than dropping it.

## The cross-harness ledger

One repository's ledger holding hook-driven measurements from more than one
harness integration is the artifact a single harness structurally cannot
produce (PREMORTEM A6). The executed story — both shipped integrations, both
gates fired for real, the slices, and exactly what each leg does and does not
prove — is in [`cross-harness-story.md`](cross-harness-story.md).

## First real consumption

The recipe's first run was on Andon's own P7 phase diff
(`8d6a5f8 → b088142`, the async-sandbox phase, 66 files, 5 engines, 473
results): verdict `advise`, self-measure provenance disclosed (bootstrap
exception named, 2 golden expectation files withheld by policy), recorded to
`refs/notes/andon-measure`. The `fp-window` run over that ledger produced the
first live B8 diff — it reported Andon's own ratified `self_measure.excluded_paths`
widening (3 defaults → 6 declared entries) as a loosening, which is the
mechanism working: that widening is exactly the class of edit the gate
demands a ledgered justification for, and this one has it (the wave-1 close
ratification; the justification is quoted in `.andon.toml` itself beside the
list).
