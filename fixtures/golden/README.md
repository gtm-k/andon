# The golden set

Frozen fixture repositories and the reference payloads Andon produced for them.
Two cases: one an honest author would make, one a tool that wanted better numbers
would make.

## What it is for

1. **The two-binary comparison** (`docs/self-measure.md`). When a change touches
   `crates/engines/**`, the engine output over these fixtures is compared. A
   difference is the *intended* result of an engine change; the comparison makes
   it explicit and reviewable rather than leaving a reviewer to guess which
   numbers moved on purpose. Owned by the `engines-change` job in
   `.github/workflows/ci.yml`.
2. **The cross-environment determinism study** (VISION §6): byte-identical
   per-result digests over the deterministic compare set, across operating
   systems, *within one measurement regime*. The process family names the git
   version it ran under as its regime; a run under a different git is compared
   by reconstruction — substitute the recorded git version, re-hash, and the
   recorded digest must come back — rather than by equality. Every other family
   has no regime to substitute, and an unequal digest there is a real
   difference. `crates/andon-cli/tests/golden.rs` is the rule, with a control
   test for each branch.
3. **P10a's stability study.**

## Layout

```
<case>/
  case.toml        the repository as committed data: ordered steps, and which
                   two are the base and the head
  steps/<id>/      the files that step writes, as real files a reviewer reads
  expected.json    the reference payload
```

The repository is **built**, not committed: a git repository cannot live inside a
git repository, and a bundle is opaque in a diff. Author, committer, both dates,
the messages and the trees are fixed, and the object format is pinned to SHA-1,
so the commit OIDs are byte-for-byte reproducible on every machine. That matters
because `base_oid` and `head_oid` are inside `ResultDigestInput`: every digest in
a reference payload is a function of them.

## The tolerance, fixed before any number was recorded

From PLAN.md's P5b acceptance criteria and round-2 fold R2-4. A tolerance chosen
after seeing a diff is a tolerance chosen to make the diff pass, so these were
set ex ante:

| What | Tolerance |
|---|---|
| Verdict, attestation, completeness, severity, metric class, engine roster, tamper signals, verdict reason codes | **100% agreement.** No band. |
| `Count`, `Integer`, `Flag`, `Text` | **Exact.** Counts are always exact. |
| `Ratio`, `Duration` on a metric outside the compare set | within **max(1 absolute unit, 10% relative)** |
| Anything the registry marks `deterministic` | **the per-result digest is pinned**, which is stronger than any band on the value |

Exactly one shipped metric is outside the compare set today —
`artifacts.uncovered-changed-lines`, because a coverage report is an untracked
build output no verifier can reproduce — and its value is a count, so it is
compared exactly as well. The relative band is implemented and tested and
currently unreached. That is worth saying rather than leaving to be discovered:
this suite has less slack than the table suggests.

## Running it

```
cargo test -p andon-cli --test golden
```

## Re-recording

Only ever a deliberate act, and only when an engine change is *meant* to move
numbers:

```
ANDON_RERECORD_GOLDEN=1 cargo test -p andon-cli --test golden
```

Then read the diff before committing it. A re-record with no explanation in the
commit message is a golden set that has stopped being evidence — the point of the
comparison is that somebody looked at what moved and said why.

## Adding a case

A case must be one somebody can explain in a sentence: what would have to break
for it to fail. `every_case_describes_what_it_is_for` enforces that the sentence
exists; only review enforces that it is true.
