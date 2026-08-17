# Self-measurement

Andon must pass its own measurement. That constraint is worth having and it
creates a circularity worth naming: if the working tree's build measures the
working tree, then a change that breaks a detector is judged by the broken
detector, and a fixture that exists to trip the tamper suite trips it on every
commit.

This document is the contract. The enforceable parts live in
`andon_core::selfmeasure` and the `[self_measure]` section of `.andon.toml`;
prose that no code reads is how a rule quietly stops applying.

## The rule

**Self-measurement runs the last attested release binary.**

Not the working tree's build, and not the last release — the last release whose
own measurement CI attested. A detector cannot bless the change that alters it,
because the binary doing the judging predates the change.

## The bootstrap exception

No attested release exists yet, so there is nothing to measure with. Until the
first one ships, `[self_measure] binary` reads `current-build` and every
self-measurement carries the override reason
`bootstrap-no-attested-release`.

The exception is self-expiring: it stops being available the moment the first
attested release exists, because the condition it names stops being true. It is
not a grace period anyone has to remember to end.

Dogfood switch-on is P5b. Phases P0 through P5a carry a placeholder in CI —
`scripts/self-measure.sh`, which announces that no measurement was performed.
The placeholder is deliberately loud: a self-measure step that silently exits
zero is worse than no step, because the CI log then shows a green check for work
that did not happen.

## Overrides

Skipping the gate is sometimes legitimate and must never be quiet. An override
carries a reason code from a closed set, and lands in the ledger:

| Reason code | When it applies |
|---|---|
| `bootstrap-no-attested-release` | No attested release exists. Self-expiring. |
| `engine-change-under-review` | The change is to an engine, so the attested binary's verdict describes the old detector. Pairs with the two-binary comparison below. |
| `known-detector-defect` | A detector defect is filed and firing on this change. The issue reference is required. |
| `infrastructure-unavailable` | The attested binary could not be fetched or run. Infrastructure, not judgement. |
| `reviewed-false-positive` | A finding was reviewed and found false. Feeds the PREMORTEM S6 false-positive budget. |

Every field of `SelfMeasureOverride` is required — justification, issue
reference, named approver, and the head OID it applies to. An override with no
reference and no approver is indistinguishable from a silent bypass, which is
the thing being prevented. Overrides do not carry forward: they are pinned to
one commit.

`SelfMeasureProvenance::is_clean()` answers false whenever an override is
present, so an overridden run can never be counted as a clean one.

## Fixture exclusion, and its drift signal

`fixtures/gamed/**`, `fixtures/adversarial/**`, and the registry-lint fixtures
exist to fire the tamper suite. Measuring them would block every build on
findings that are the point of the files.

They are excluded by **declared policy**, in `[self_measure] excluded_paths`, and
not by a rule inside the runner. Two reasons: the exclusion is reviewable in a
diff, and it has a baseline to drift from.

The drift signal is the second half. An exclusion list that quietly widens is how
a dogfood gate stops meaning anything — each addition is individually reasonable
and the sum is a tool that measures nothing. When the excluded set grows relative
to the last attested run, `exclusion_drift` is set, the run is not clean, and the
growth is a finding rather than a silence.

## The two-binary comparison, and the gate that owns it

When a change touches `crates/engines/**`, the attested binary and the working
tree's binary measure the same golden fixtures and their results are compared. A
difference is the *intended* output of an engine change; the comparison makes it
explicit and reviewable instead of leaving reviewers to guess which numbers
moved on purpose.

**Owning gate:** the `engines-change` job in `.github/workflows/ci.yml`. It runs
whenever `crates/engines/**` changes and needs no manual enabling.

**Activation:** the comparison needs a golden set, which P5b creates at
`fixtures/golden/`. The job checks for it and does the right thing either way:

- **Before P5b** — no `fixtures/golden/`: compile and unit tests only, and the
  job says which of the two modes it ran.
- **From P5b** — `fixtures/golden/` present: the full two-binary comparison.

The bridge is wired now rather than at P5b so that the first engine change
cannot land before anyone has remembered to add the gate. A job that reports
which mode it took also makes the transition visible in the CI log, rather than
leaving "did the real comparison run?" as a question someone has to answer by
reading the workflow file.

## Dogfood switch-on

At P5b, Andon's CI measures Andon. The gate asserts **non-empty results and the
expected engine count**, not merely that the command exited zero — a measurement
that silently produced nothing would otherwise pass as a green check. The
switch-on itself is a ledgered event.
