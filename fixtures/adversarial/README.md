# The adversarial corpus

102 changes, each one a small repository's worth of before-and-after files, each
one either a deliberate attempt to move a number without improving the code or a
legitimate change that looks like one. The tamper suite is measured against it,
and the measurement is a gate: PLAN.md P3 sets a precision floor of **0.80** and
a recall floor of **0.70** per detector, ex ante, and a detector below either
fails the phase.

Two directories:

| Directory | Cases | Purpose |
|---|---:|---|
| `fixtures/adversarial/<detector>/<case>/` | 51 | should fire — the source of **recall** |
| `fixtures/honest/corpus/<detector>/<case>/` | 51 | should not fire — the source of **precision**'s false positives |

The should-pass corpus is not an afterthought. A detector that fires on
everything has perfect recall, and the only thing that distinguishes it from a
useful one is the false-positive count. PLAN.md B5/B6 names this directly:
legitimate suppressions, test deletions, and policy edits must not fire.

## The measurement

Regenerate with:

```
cargo run -p andon-engine-tamper --bin andon-corpus-report -- --check-freeze --check-floors --markdown
```

Corpus v1, frozen 2026-08-17, digest `9aa97c6d5b8289b2`, refresh due
2026-11-17. Measured against `andon-engine-tamper` 0.1.0 at rule pack 2 (repair
round 1) with the grammar pins in `crates/engines/tamper/src/syntax.rs`.

| detector | TP | FN | FP | TN | precision | recall |
|---|---:|---:|---:|---:|---:|---:|
| `test-removal` | 8 | 0 | 0 | 51 | 1.00 | 1.00 |
| `suppression-density` | 7 | 0 | 0 | 51 | 1.00 | 1.00 |
| `assertion-free-test` | 7 | 0 | 0 | 51 | 1.00 | 1.00 |
| `coverage-exclusion-drift` | 7 | 0 | 0 | 51 | 1.00 | 1.00 |
| `threshold-config-edit` | 7 | 1 | 0 | 51 | 1.00 | 0.88 |
| `lookup-table-blowup` | 7 | 0 | 0 | 51 | 1.00 | 1.00 |
| `parse-error-delta` | 7 | 0 | 1 | 50 | 0.88 | 1.00 |

Every detector clears both floors. `tests/corpus_floors.rs` asserts it, asserts
the freeze digest still matches, asserts each detector has at least five
should-fire cases, and asserts this table is the one the code produces — a
published precision figure that has stopped describing the build is the
registry-rot failure of PREMORTEM S2 arriving in the one table this phase is
judged on.

### What the numbers do not mean

**These are not field precision and recall.** They describe how the detectors do
on 102 changes written by the same person who wrote the detectors, over four
weeks in one repository. The honest reading is narrow: *the rules do what they
say on cases chosen to test whether they do*. The number that would mean
something is the false-positive rate on real changes, which is what PLAN.md's
P9b instrumentation and P10b entry gate measure, over at least 30 honest changes
and at least 14 days.

**One false negative and one false positive are real, and neither is a
defect.**

`threshold-config-edit` misses `eslint-rule-deleted`: a rule removed from a
config file rather than downgraded leaves no head-side value to compare against,
and the detector only compares keys present on both sides. Deleting a rule
loosens as surely as setting it to `off`. The case is in the corpus so that the
gap appears in the recall column rather than in a footnote. Closing it means
comparing the base's key set against the head's, which is a v1.1 change.

`parse-error-delta` fires on `pre-existing-errors-left-alone`, a should-pass
case. That is a **contract change**, not a regression. Repair round 1 added a
second arm to the detector: a *changed* file that is parse-degraded fires at
`Low` even when the delta is zero, because parking the faults in one commit and
adding the evasive code in the next reads as a zero delta (P2's adversarial lens
found the shape). Under the new contract that case *should* fire softly — an
honest legacy file with an old syntax error and a deliberately parked one are the
same bytes, and no static rule separates them. The corpus is frozen, so the case
moves to the adversarial side at the v1.1 refresh rather than being edited now.
Precision 1.00 → 0.88, above the 0.80 floor.

**The perfect columns are the weakest evidence here.** A first pass of this
corpus scored 1.00/1.00 on all seven detectors with no cross-fires, which was not
a result — it was a corpus restating its own implementation. The boundary cases
added before the freeze found four real bugs:

- `it.each(table)(name, fn)` counted as two calls and none of its rows, so the
  ordinary `it` → `it.each` refactoring read as tests removed;
- `describe.skip` took a whole suite out of the run and nothing noticed;
- should-style assertions (`result.should.equal(3)`) read as no assertion at all;
- `True`/`False` in an INI file compared as strings, so mypy's strictness flags
  could be turned off silently.

That is what the corpus is for. Repair round 1 then found five more that the
corpus had not — see the known limitations below — which is the ensemble doing
what the corpus alone could not.

## Known limitations

Written down rather than discovered. Each is a shape the suite does not catch, or
catches in a way worth knowing about; the frontier ones have a specimen in the
held-back set (`gtm-k/andon-evasion`) so that they keep being re-run.

### Evasions the suite does not catch

| shape | detector | why, and what closing it needs |
|---|---|---|
| `extends` swapped to a loose base config | `threshold-config-edit` | Every value in the file is untouched; the strictness profile changes by inheritance. Closing it means resolving and diffing another config graph. |
| Real cases replaced by differently-named tautologies | `assertion-free-test`, `test-removal` | The case count is preserved and every replacement contains an `expect`, so both detectors stay quiet while three behaviours stop being checked. Closing it means relating an assertion's arguments to the code under test — a data-flow question, not a syntactic one. |
| A rule deleted rather than downgraded | `threshold-config-edit` | Scored: it is the false negative in the table above. |
| An option raised inside an array-form rule (`["error", 10]` → `["error", 40]`) | `threshold-config-edit` | Only the severity is read out of the array form. Knowing which option is a threshold means knowing the rule, which is a per-linter rule table this detector does not have. |
| A runtime early return in every case | `test-removal` | No skip marker, no deleted case. Needs reachability. |
| One blanket file-level `eslint-disable` | `suppression-density` | Walks under the floor of two added directives, which exists for precision. Closing it means weighting blanket directives above targeted ones. |
| An exclusion pattern widened rather than added | `coverage-exclusion-drift` | Entry count is the metric and it does not move. Needs globs compared by breadth. |
| A lookup table assembled at run time | `lookup-table-blowup` | No literal collection node exists. Needs constant folding. |
| Logic moved into a string and evaluated | `parse-error-delta` | The file parses cleanly on both sides. Needs dynamic-evaluation detection. |

### Bounds that can change an answer

- **Suppression markers are an enumerated list**, not a general rule. A linter
  absent from `detectors::suppression_density::MARKERS` is not detected. Adding
  one moves `RULE_PACK_VERSION` and therefore the measurement regime, which is
  the correct consequence: what counts as a suppression has changed.
- **Ancestor walks stop at 256 levels.** `Node::parent()` costs O(depth) in
  tree-sitter, so an unbounded walk is quadratic — this was a five-second-per-
  detector hang on a 10 KB file before repair round 1. A construct nested deeper
  than 256 is not classified.
- **Clone detection saturates above 32 occurrences of one window hash.** In a
  saturated bucket a longer match between two far-apart occurrences can be missed
  when a nearer partner offers a shorter one. The alternative is quadratic.
- **The clone group list is not a partition of the per-file token counts.** Five
  files can hold a copy while the group list names two of them, because a longer
  clone between that pair won the region. The counts are the coverage; the groups
  are the description.

### Corpus errata, to fix at the v1.1 refresh

- `honest/lookup-table-blowup/module-level-reference-data` is titled "a
  forty-entry country list" and contains a table of squares. The case exercises
  what it should — a large literal at module scope — and only the label is wrong.
  Not corrected now: the corpus is frozen, and a re-freeze to fix a title would
  spend the discipline that makes the floors meaningful on a cosmetic edit.
- `honest/parse-error-delta/pre-existing-errors-left-alone` moves to the
  adversarial side, for the contract reason given above.

## Writing a case

```
<detector>/<case-name>/
  case.toml      title, expected signals, and why
  base/          the files before the change
  head/          the files after
```

A path in `base/` and not in `head/` is a deletion; the reverse is an addition.
A side with no files has no directory at all, because git does not track empty
ones. Renames need saying out loud, since two directories cannot express one:

```toml
title = "a spec file renamed, byte for byte"
expect = ["test-removal"]
note   = "why this is gaming, or why it is legitimate"

[[rename]]
from = "test/cart.spec.ts"
to   = "test/checkout-cart.spec.ts"
```

`expect` is empty for a should-pass case and lists one or more tamper-signal
names for a should-fire one. `note` is required: a case nobody can justify is a
case nobody can re-review, and at the next refresh the note is the only thing
that says what the case was for.

### Cross-fires

An adversarial case for one detector can legitimately trip another — a change
that deletes tests *and* adds suppressions is both, and both detectors are right
to say so. Cross-fires are counted and printed, and they do not enter any floor.
Counting them as false positives would penalize a detector for working.

## Refresh, and why it is scheduled rather than intended

PREMORTEM S1: an adversarial corpus that never changes becomes the evasion
training set for anyone who reads it, and this one is public. So the corpus
carries a `refresh_due` date in `CORPUS-v1.toml` and
`.github/workflows/corpus-refresh.yml` runs quarterly and goes red past it. A
refresh means:

1. Read the ledger's distribution for values clustering under thresholds
   (`andon ledger stats --distribution`, P8) and write cases for what it shows.
2. Add the evasions found since — from issues, from dogfood, from the held-back
   set below.
3. Move the boundary: any case every detector now aces contributes nothing, and
   should be replaced rather than kept for the count.
4. Re-freeze (`andon-corpus-report freeze`) and re-measure, **in that order**.
   The digest is what makes the order enforceable.

### The held-back set

A subset of evasions is deliberately **not** in this repository. It lives in
`gtm-k/andon-evasion`, private, never flipped — because a public corpus is a
published list of what the detectors catch, and the complement of that list is
the answer key. The held-back set is what measures whether the published corpus
has become the training set: if a detector scores well here and badly there, the
public cases have been fitted to.

The private set is refreshed on the same quarterly cadence, is never used to
tune a detector without a corresponding public case being added, and never
appears in a public report as anything but a hit rate.

## The freeze

`CORPUS-v1.toml` records a SHA-256 over every case file and manifest in both
corpora, sorted by path. `--check-freeze` recomputes it and refuses to publish a
report for a corpus that has moved.

The reason is the order of operations. PLAN.md P3 requires the corpus to be
frozen and reviewed **before** the floors are measured against it, so the test
and its subject are not authored in one motion — and the git history shows the
freeze commit landing ahead of the measurement. Fixing a detector after the
freeze is the intended workflow; the corpus is the test and the detector is the
subject. Editing a case after the freeze is not, and needs a deliberate
re-freeze, a review, and a re-measurement.
