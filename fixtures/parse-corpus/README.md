# The parse-health corpus

Pinned real-world source in every language the static family measures, scored
against an ex ante parse-health budget.

- `corpus.toml` — the repositories, their pinned commit SHAs, and the budgets.
- `baseline.toml` — what the last green run measured, and the regime it measured
  it under. Generated; commit what the CI job uploads.

Run it: dispatch `.github/workflows/parse-corpus.yml`. Locally:

```sh
andon-static corpus plan                 # name, url, rev — one line per repo
andon-static corpus check --root <dir>   # after fetching each at its pinned SHA
```

## What it is for

`tree-sitter` recovers from anything. A grammar that predates a widely-used
syntax still returns a tree, still yields numbers, and still yields numbers that
look exactly like numbers from a file it understood completely. The unit tests
prove parse health is *reported*; only real source proves the grammars are
adequate (PREMORTEM T3).

## What the first run found

It found something on first contact, which is the argument for the corpus
existing.

**TypeScript: 4 files of 221 degraded (1.81%), 29 ERROR and 4 MISSING nodes of
70,045.** Within the 2% budget, and not creeping rot — two named upstream gaps in
`tree-sitter-typescript` 0.23.2:

| File | Cause |
|---|---|
| `type-fest source/internal/index.d.ts` | `export type * from './x'` — TypeScript 5.0's type-only `export *`. The grammar does not know the form. |
| `swr src/{_internal,infinite,mutation}/types.ts` | Conditional types with `infer` in a function-return position, e.g. `K extends () => infer Arg \| null ? … : …`. |

Neither is fixable by choosing a better pin: **0.23.2 is the latest release of
`tree-sitter-typescript`.** Every other language measures zero degraded files.

The consequence is bounded and visible by design rather than by luck. Results
from those files are `completeness: parse-degraded`, cannot reach MED+, and carry
the caveat naming their ERROR and MISSING counts — so a number computed over a
partially-understood type declaration is reported, and is reported as what it is.

Worth re-checking at each grammar bump: if a later `tree-sitter-typescript`
supports `export type *`, the rate should drop and the baseline should say so.

## Why the budgets are what they are

Both were chosen before the first run, from a principle rather than from an
observation. The reasoning is in `corpus.toml` beside the numbers.

Rates, not counts: a pinned repository grows between refreshes, and a gate that
fails on arithmetic is a gate somebody eventually raises to make it stop.

## How "re-run per grammar bump" is enforced

Not by a workflow trigger. `baseline.toml` records the regime its numbers were
taken under — every grammar version, the tree-sitter runtime, and the metric
spec revision — and `crates/engines/static-metrics/tests/corpus_baseline.rs`
fails when that stamp and the engine's current regime disagree.

So bumping a grammar turns the ordinary `cargo test` red on every push until the
corpus job has been dispatched and its fresh baseline committed. The expensive
job stays on `workflow_dispatch`, which is user decision D2, and the requirement
is enforced where it costs nothing.

A path filter on the workflow would have been weaker in both directions: it fires
on every commit that touches the engine crate, it does not fire when a transitive
change moves the grammar, and it cannot tell whether anybody looked at the result.

## Adding a repository

Pin a full commit SHA — never a tag, which is a mutable pointer — declare which
languages it is there to exercise and why, and give it a budget. `corpus check`
fails when a repository claims a language and contributes no files in it, which
is how an `include` prefix that stopped matching after an upstream reorganisation
is caught instead of silently shrinking the corpus.

Nothing here is redistributed: the corpus is URLs and SHAs, fetched at run time.
The licence column is provenance.
