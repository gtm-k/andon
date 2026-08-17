# The cross-OS matrix specimen

One change, engineered so that **every one of the seven tamper detectors fires
and the clone engine finds a real clone group**. It is the fixture the standing
cross-OS determinism matrix measures (PLAN.md B4, R2-1).

## Why a fixture that fires everything

A digest comparison over results that are all `false` and all `0` is green
whatever the engines do. It would prove that three operating systems agree about
nothing, and "the detectors agreed" would be indistinguishable from "the
detectors did not run". So the specimen is chosen to make every value non-trivial
on every leg:

| detector or engine | what fires it here |
|---|---|
| `test-removal` | two cases deleted from `test/cart.spec.ts`, one of the survivors `.skip`ped |
| `suppression-density` | three suppressions added to `src/cart.ts` |
| `assertion-free-test` | a new case that calls `subtotal` and asserts nothing |
| `coverage-exclusion-drift` | two paths added to `.coveragerc`'s omit list |
| `threshold-config-edit` | `strict` turned off in `tsconfig.json` |
| `lookup-table-blowup` | a thirty-row table inside `rate()` in `src/rates.ts` |
| `parse-error-delta` | `src/adapter.ts`, added and unparseable |
| `clones` | the `subtotal` body duplicated into `src/checkout.ts` with every identifier renamed |

The clone is deliberately a Type-2 one — same structure, every name changed —
because a byte-identical copy would be found by a `diff` and proves nothing about
token normalization.

## Some of what it measures is `parse-degraded`, and that is correct

`src/adapter.ts` is unparseable on purpose, which is what makes
`parse-error-delta` fire — and it also means this specimen is not a change both
engines read completely. Results computed over that file, or over a set
containing it, therefore arrive marked `parse-degraded` rather than `complete`,
and both records take the weakest completeness of their results:

| result | completeness | why |
|---|---|---|
| `clones.file-duplicated-tokens` on `src/adapter.ts` | `parse-degraded` | the token stream stops where the grammar does |
| the four change-scoped `clones.*` | `parse-degraded` | each is computed over the whole measured set, `adapter.ts` included |
| `clones.file-duplicated-tokens` on the other four files | `complete` | demotion follows the file, not the run |
| `tamper.lookup-table-blowup` and its magnitude | `parse-degraded` | `adapter.ts` is a non-test source file in that detector's view |
| the other five detectors | `complete` | three read bytes, and the two that parse read only test files, which are clean here |
| `tamper.parse-error-delta` | `complete` | it *reports* the degradation; counting ERROR nodes over a tree full of them is exact |

Nothing about the matrix changes: the legs compare digests against each other
rather than against stored values, `completeness` is derived from the bytes and
so is identical on every leg, and the result counts the join asserts — 14 and 9 —
are unaffected.

## Why it is not a corpus case

`fixtures/adversarial/` is frozen and its digest is what makes the precision and
recall floors a test rather than a self-assessment. A specimen engineered to fire
everything at once is a poor precision/recall case anyway: it says nothing about
whether a detector fires on the *right* thing. It lives here instead, is loaded
by nothing that scores, and is measured by `andon-tamper-probe` and
`andon-clones-probe` only.

## Building it

```
andon-tamper-probe build-fixture --case fixtures/matrix/all-seven --dest work --json shas.json
andon-tamper-probe --repo work --base <base> --head <head> --out tamper.json
andon-clones-probe --repo work --base <base> --head <head> --out clones.json
andon-spike compare-records --leg linux=... --leg macos=... --leg windows=...
```

The fixture is built **once** and shipped to the legs as a bare repository, for
the reason `spike-matrix.yml` gives about its own: a per-result digest binds
`(base_oid, head_oid)`, so building separately per leg would nest a second
determinism claim inside the one under test.

## Line endings

`fixtures/**` is `-text` in `.gitattributes`, so these bytes are checked out
exactly as committed on every platform. That is deliberate: the specimen is the
control, and a fixture whose bytes changed with the checkout could not tell a
broken engine from a broken checkout.
