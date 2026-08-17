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
2026-11-17. Measured against `andon-engine-tamper` 0.1.0 with the grammar pins
in `crates/engines/tamper/src/syntax.rs`.

| detector | TP | FN | FP | TN | precision | recall |
|---|---:|---:|---:|---:|---:|---:|
| `test-removal` | 8 | 0 | 0 | 51 | 1.00 | 1.00 |
| `suppression-density` | 7 | 0 | 0 | 51 | 1.00 | 1.00 |
| `assertion-free-test` | 7 | 0 | 0 | 51 | 1.00 | 1.00 |
| `coverage-exclusion-drift` | 7 | 0 | 0 | 51 | 1.00 | 1.00 |
| `threshold-config-edit` | 7 | 1 | 0 | 51 | 1.00 | 0.88 |
| `lookup-table-blowup` | 7 | 0 | 0 | 51 | 1.00 | 1.00 |
| `parse-error-delta` | 7 | 0 | 0 | 51 | 1.00 | 1.00 |

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

**One false negative is real and deliberate.** `threshold-config-edit` misses
`eslint-rule-deleted`: a rule removed from a config file rather than downgraded
leaves no head-side value to compare against, and the detector only compares keys
present on both sides. Deleting a rule loosens as surely as setting it to `off`.
The case is in the corpus so that the gap appears in the recall column rather
than in a footnote. Closing it means comparing the base's key set against the
head's, which is a v1.1 change.

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

That is what the corpus is for. The current table is what it looks like after
those were fixed, and the next refresh should expect to find more.

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
