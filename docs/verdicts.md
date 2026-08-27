# What a verdict rests on

A verdict is the last line of a chain: an engine measures a number, a claim in the
evidence registry says what that number is evidence for and at what strength, policy
caps how serious the finding may become, and one rule decides whether the line stops.
This page walks the chain, names the one place a finding stops the line *without*
passing through the caps, and says what that rests on — because it is the strongest
thing Andon does, and it stands on tier-N evidence: novel, and not yet validated.

Everything here is derived from `crates/andon-core/src/verdict/severity.rs`,
`crates/andon-core/src/parse_health.rs`, `crates/andon-core/src/schema/enums.rs`
and the shipped defaults in `crates/andon-core/src/policy.rs`. Where those move, this
page has to move with them.

## The four verdicts

| verdict | exit | what it means | what to do |
|---|---|---|---|
| `pass` | 0 | nothing rose above the advisory floor | keep going |
| `advise` | 0 | findings worth reading; none stops the line | read them, or do not |
| `block` | 2 | something stops the line | fix what the findings name, measure again |
| `escalate_to_human` | 3 | the loop is over | a person looks; `andon ledger ack` clears the counter |

Exit 1 is none of these: the tool could not do its job, or a changed path could not
be read, and the verdict was never reached.

Findings arrive **worst first, as a sort and not a score**. Nothing is summed. Each
carries a location, a severity, the claim it stands on, the claim's evidence tier, and
a `diff_actionable` flag saying whether the agent can act on it inside the change it
just made.

## Severities, and the band that stops the line

Five severities: `Info`, `Low`, `Medium`, `High`, `Critical`. **`Medium` and above is
the MED+ band**, and a finding in the band stops the line. Below it a finding advises.

An engine sets a *pre-policy* severity — how strong the thing it found is, in its own
terms. Policy then applies ceilings, and the ceilings only ever go one way:

> Policy can lower a severity and can never raise one. An operator editing
> `.andon.toml` can make Andon quieter about their repository and cannot make it
> louder about someone else's, and a bug in the ceiling code can only ever
> under-report.

## Evidence tiers

Every metric stands on a claim, and every claim carries a tier — the strength of the
evidence that the number predicts what the claim says it predicts:

| tier | meaning |
|---|---|
| **A** | validated against outcomes at scale |
| **B** | published validation, narrower population or weaker linkage |
| **C** | weak or contested on its own |
| **D** | critiqued; not to be used as a headline |
| **N** | novel and unvalidated — motivated by evidence, not yet supported by it |

`andon explain <metric-id>` prints the claim, its tier, the citation, the population
it was measured on, the effect claimed, the re-review date, and the `does_not_predict`
list — the things the number is *not* evidence for. A claim with no `does_not_predict`
cannot enter the registry.

Under the shipped defaults, **only tiers A and B may reach the MED+ band**
(`severity.med_plus_tiers = ["A", "B"]`). C is capped at `Low` by a separate, more
specific rule that survives an operator admitting C to the band. Every tamper claim,
and the tests-lane claim, are tier N.

## The ceilings

The strongest severity a finding can reach is the minimum of four ceilings, and they
compose by `min` so the order does not matter:

| ceiling | source | why |
|---|---|---|
| **completeness** | the result's `completeness` field | a number computed over data that is partly missing must not stop the line. `complete` allows `Critical`; `parse-degraded`, `partial` and `unwitnessed` all cap at `Low` |
| **evidence tier** | `severity.med_plus_tiers` | a tier the operator has not admitted to the band caps at `Low` |
| **C-tier** | `severity.max_severity_for_c_tier` | weak or contested evidence advises; the more specific rule wins where both apply |
| **actionability** | `severity.med_plus_requires_diff_actionable` | blocking on what nobody can fix in the diff is the uninstall loop — `context-informational` findings cap at `Low` |

A finding that comes out of the ceilings at `Medium` or above stops the line. That is
route three of three.

## The two routes that do not pass through the ceilings

Two kinds of finding stop the line on a **fired flag**, without consulting the capped
severity at all:

1. **A fired tamper signal**, while `severity.block_on_tamper` is true (the default).
2. **A fired test-suite failure**, while `severity.block_on_test_failure` is true (the
   default).

Why the bypass exists is worth reading in full, because it is the same fact stated
twice.

**Every tamper claim is tier N.** N is not in the default MED+ tiers, so the tier
ceiling caps every tamper firing at `Low` — on a complete parse, with nothing degraded
anywhere. A rule that keyed line-stopping on the capped severity would therefore
*never* stop the line for a tamper signal, on any change, in the shipped
configuration. The flag is not a refinement of the severity path; it is the only path.

**The muzzle.** Separately, a detector that fires over a partly-unreadable file has
its result demoted to `parse-degraded`, and the completeness ceiling caps it at
`Low`. That demotion is correct and stays. But if line-stopping read the capped
severity, one parked parse error in a file nobody examined would silence the entire
tamper suite for every later change that touches it — the demotion would have become
the evasion. A firing over a degraded view is a lower bound: the detector saw real
evidence in the part it could read, and the part it could not read can only hide
more. So the reported severity stays capped, honestly, and the line still stops.

What this looks like in practice — real output, on a change that deleted three of
four test cases:

```
 BLOCK  the line stops. Something here has to be dealt with before this lands.
 …
 WHY
  !! tamper-signal             tamper.test-removal fired: the line stops
     ↳ tamper.test-removal
 …
 FINDINGS (worst first; a sort, not a score — nothing here is added up)
  - LOW   tamper.test-removal  this change
       fired
```

The severity label is `LOW`; the verdict is `BLOCK`. Both are correct: the label is
the capped severity and the flag is what stopped the line.

One surface does not yet say this. `andon explain <metric-id>` has a section, "The
strongest this finding can be", computed from the ceilings alone — so for a tamper
metric or for `tests.suite-failure` it prints *"this can advise; it cannot stop the
line"*, which is true of the severity and false of the verdict. Read that sentence
as being about the label. The flag route above is what decides.

### What the uncapped route rests on

This is the disclosure. **The one class of verdict that no evidence-tier ceiling can
soften rests on tier-N evidence**: seven detectors calibrated against a corpus of 102
constructed changes that the project wrote itself, frozen before the detectors were
measured against it, with precision and recall floors of 0.80 and 0.70 set ex ante.
Every detector clears both floors on that corpus, and a test fails the build if the
published table stops being the one the code produces. No external study evaluates
any of these detectors, and the registry says so in every one of their citations.

Weigh a tamper block accordingly. It is a claim that a specific enumerated pattern
appeared in the change — deleted or skipped test cases, cases that stopped asserting,
a rising suppression count, a rising parse-fault count, a widened coverage exclusion,
a loosened threshold, a large literal table inside a function body. It is not a claim
that the pattern was illegitimate; every tamper claim's `does_not_predict` opens with
exactly that. Deleting the tests for a deleted feature is correct, and the detector
cannot tell.

Two switches exist for a repository that wants the numbers without the gate:
`severity.block_on_tamper = false` and `severity.block_on_test_failure = false`. Both
are ledgered policy edits, and loosening either inside a change under measurement
surfaces as a `policy-change` finding.

### The one conditional detector

`tamper.threshold-config-edit` fires when a recognised quality threshold moves in the
loosening direction — a severity lowered, a strictness flag turned off, a floor
reduced. A tool that blocked every such edit would make legitimate policy evolution
impossible, and a project that cannot change its own thresholds changes tools instead.
So this one detector stops the line **unless a verified, ledgered justification covers
the change**; with one, it advises. The other six take no such exemption: a ledger
entry saying a test deletion was intended does not turn the firing off.

## Completeness

Every result carries a `completeness`:

| value | meaning | severity ceiling |
|---|---|---|
| `complete` | measured over everything it set out to measure | none |
| `partial` | some of the work was deferred or declined, and the record says which | `Low` |
| `parse-degraded` | computed over a file the parser could not fully read; counts are lower bounds | `Low` |
| `unwitnessed` | no number — an absence, never a zero, with the reason attached | `Low` |

A record whose results are not all `complete` reaches its verdict without what is
missing, and says so in its reasons (`measurement-incomplete`, `engine-spilled-async`,
`engine-unavailable`). `andon wait` runs what the async lane still owes; nothing else
turns `partial` into `complete`.

## The loop

Each measurement pass that leaves something open — a diff-actionable finding above
`Info`, a fired flag that stops the line, or an unjustified policy loosening —
advances a per-branch counter, once per distinct change; a pass with nothing open is
the loop finishing, and the count resets. Past `loop.iteration_cap` (default 3) with
findings still open, the verdict becomes `escalate_to_human` and stays there until a
person runs `andon ledger ack`. Findings the agent cannot act on inside its own change
(`context-informational`) are exempt, and so is a justified threshold edit; a
degraded tamper firing counts, for the muzzle reason above. The counter is local tool
state, not a security boundary — deleting it resets the count, and the mechanism that
stops dishonest work is the verifier, not this file.

## The tamper suite, scoped

The seven detectors answer four questions:

| question | detectors |
|---|---|
| has the suite stopped verifying things? | `test-removal`, `assertion-free-test` |
| is there code the static engines can no longer read? | `suppression-density`, `parse-error-delta` |
| did the quality bar move instead of the code? | `coverage-exclusion-drift`, `threshold-config-edit` |
| was an implementation replaced by its expected answers? | `lookup-table-blowup` |

**What the numbers behind them mean.** The corpus precision and recall are not field
precision and recall. They describe how the detectors do on 102 changes written by
the same person who wrote the detectors, in one repository, over four weeks: *the
rules do what they say on cases chosen to test whether they do*. The false-positive
rate on real changes is measured separately — a window of at least 30 honest changes
over at least 14 days — and gates public release. The measured table, and the
protocol for refreshing it, is `fixtures/adversarial/README.md`.

**What they do not catch.** A published corpus is a list of what fires, and the
complement of that list is the evasion manual. A held-back set of evasions is kept
outside this repository to measure whether the public cases have been fitted to. As
of 2026-08-25 it stood at **3 caught and 8 evading**, and six of the seven detectors
were below the 0.70 recall floor on withheld cases. That is a combined count over
two kinds of case — evasions the detectors have never seen, and regression specimens
kept private after a fix — and the two are owed separately, because a combined
figure rises with every fix whether or not generalisation improves.

The evasions that work need no insider knowledge. Per detector, from the corpus
README, which carries what closing each would need:

| detector | evades it |
|---|---|
| `test-removal` | a runtime early return in every case; cases replaced by differently-named tautologies |
| `assertion-free-test` | cases replaced by tautologies that still contain an `expect` |
| `suppression-density` | one blanket file-level disable, under the two-directive floor |
| `parse-error-delta` | logic moved into a string and evaluated — the file parses cleanly |
| `threshold-config-edit` | `extends` swapped to a looser base; a rule deleted rather than downgraded; a rule value spread across lines; an ESLint severity written as a number |
| `coverage-exclusion-drift` | a `.properties` value past its first comma; an exclusion added in one file and an unrelated one removed in another; a re-inclusion (`!path`) deleted; a positive inclusion narrowed. A replacement pattern neither anchored above the other is not silent — it comes back `completeness: partial` — but it does not fire |
| `lookup-table-blowup` | a table assembled at run time |

**The honest claim is narrow: these detectors catch the patterns they enumerate.**
They are a measured floor under the cheapest moves, with the gaps written down. They
are not a general defence against a determined adversary, and Andon does not describe
them as one.

## Attestation: whether a verdict counts

A self-report is what the agent's own binary wrote. It reaches a verdict and it is
useful, and it counts for nothing downstream until a verifier recomputes the change
and compares per-result digests:

| value | means | counts downstream |
|---|---|---|
| `confirmed` | every compared digest matched | yes |
| `confirmed-static` | fork tier: recomputed with no self-report to compare against | yes |
| `divergent` | digests disagreed, or a tamper signal fired | no |
| `unwitnessed` | no recompute, or nothing was compared — neutral, not negative | no |
| `unwitnessed-version-skew` | different measurement regimes; digests never comparable | no |
| `unwitnessed-base-mismatch` | the claimed base is stale, or was rebased | no |

A measurement of an uncommitted working tree is `unwitnessed` by construction, and
stays so: CI cannot check out your working tree. Commit the change to make it
attestable. What an attestation does and does not prove — in particular, that push
access can forge one in v1 — is `docs/trust-boundary.md`.
