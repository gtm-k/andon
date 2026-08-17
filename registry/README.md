# The evidence registry

Every number Andon reports cites a claim, and every claim says what it does
**not** predict. That is the product, not a documentation habit: a measurement
tool that cannot tell you how much to trust each number is asking you to trust
all of them equally.

Schema: `schemas/registry-v1.schema.json`. Lint: `andon-registry-lint`.

## Layout

One file per engine, named for the engine, each owned by the phase that builds
it:

| File | Engine | Phase |
|------|--------|-------|
| `static.toml` | static-metrics | P2 |
| `clones.toml` | clones | P3 |
| `tamper.toml` | tamper | P3 |
| `process.toml` | process | P4 |
| `artifacts.toml` | artifacts | P4 |

Files are disjoint so phases running in parallel never edit the same one
(PLAN.md R2-2). P5a's loader merges them.

*This directory is empty of engine files until P2.* The lint passes over an
empty registry and says so.

## A claim tuple

A claim is scoped to **one implementation, at one version, in one language,
predicting one outcome**. "Cyclomatic complexity predicts defects" is not a
claim this registry can express, and that is deliberate: the literature supports
statements about a specific measurement of a specific thing, and family-wide
claims are how evidence gets overstated.

```toml
schema_version = 1
engine = "static-metrics"
family = "static"

[[metric]]
metric_id = "static.cognitive-complexity"
claim_id = "andon.static.cognitive@1|typescript|comprehension-time"
class = "diff-actionable"
deterministic = true

[[claim]]
# claim_id is always implementation@version|language|outcome, so the id and the
# tuple cannot drift apart. The lint enforces it.
claim_id = "andon.static.cognitive@1|typescript|comprehension-time"
implementation = "andon.static.cognitive"
implementation_version = "1"
language = "typescript"
outcome = "comprehension-time"
tier = "B"
citation = "Munoz Baron, Wyrich & Wagner, ESEM 2020"
citation_ref = "10.1145/3382494.3410636"
population = "427 snippets, ~24k human ratings across 27 studies"
effect = "correlates with time-to-comprehend and with subjective ratings"
does_not_predict = ["defect density", "correctness", "review effort"]
owner = "gtm-k"
expiry = "2027-03-15"
```

`tier` follows the grading in `docs/metric-families.csv`: **A** validated
against outcomes at scale, **B** published validation on a narrower population,
**C** weak or contested alone, **D** critiqued and not to be used as a headline,
**N** novel and unvalidated.

## What the lint enforces

Structural problems fail the build:

- a metric citing a claim that does not resolve — the rule the whole registry
  exists for;
- a `claim_id` that disagrees with its own tuple;
- an empty `does_not_predict`, or an empty citation, population, effect, or
  owner;
- duplicate claim or metric ids;
- more than `registry.claim_budget` claims (24);
- more than `registry.max_claims_expiring_per_month` claims falling due in one
  month (3).

Run it: `cargo run -p andon-registry-lint -- --as-of 2026-08-17 registry/`

## Expiry, and why it demotes instead of blocking

Every claim carries a re-review date. Past it the claim **auto-demotes**:
`evidence: stale` appears on every number citing it, in the payload, the report,
and the agent profile. The build stays green.

Both halves matter. Silent expiry means stale claims keep being cited at full
confidence and the registry rots while looking healthy. Expiry that *fails* the
build means an aged citation stops the release train — the same bottleneck, with
the moat rotting in public during the window adoption is measured in (PREMORTEM
S2, Story 3).

### Why the budget and the stagger exist

Twenty-four claims is not a modesty figure, it is a capacity one: what a single
owner can genuinely re-review in a week, once a year. Review cost scales with
adoption while review capacity stays at one person, so the budget is enforced as
a count and the expiries are spread — at most three in any calendar month — so
the load arrives evenly rather than as a cliff.

Initial expiries should therefore be staggered when a claim is added, not
assigned the same date as its neighbours. The lint rejects a cluster.

## Contributing a claim, or a re-review

Both are pull requests against the engine's registry file.

- **New claim.** Needs a primary source, not a citation of a citation:
  `citation_ref` must resolve, `population` and `effect` must be the source's own
  terms, and `does_not_predict` must be specific. Adding a claim at the budget
  means retiring one — say which, and why.
- **Re-review at expiry.** Confirm the claim still holds against current
  literature, or downgrade its tier, or retire it. Move `expiry` forward into a
  month with room under the stagger limit. A re-review that only moves the date
  is not a re-review, and the diff should show what was checked.

From P10a the schema, DOI resolution, quoted-passage existence, and fingerprint
consistency are checked automatically, and human review becomes a sampling
audit. That automation is a flip precondition rather than a nicety: it is the
answer to the contribution funnel dying under its own review ethos.
