# Registry review policy

How a change to `registry/*.toml` is reviewed: what the machine checks, what a
person checks, who has to approve, how long it takes, and what gets a change
sent back. `registry/README.md` explains what the registry *is*; this page is
the process.

## What a registry change is

A change to one of two kinds of entry:

- **A claim tuple** — `[[claim]]`: one implementation, at one version, in one
  language, predicting one outcome, with its evidence `tier` (A, B, C, D, or N
  as graded in `docs/metric-families.csv`), a `citation` and optional
  `citation_ref`, the studied `population`, the measured `effect`, the
  `does_not_predict` list, an `owner`, and an `expiry`.
- **A metric entry** — `[[metric]]`: a `metric_id` an engine emits, the
  `claim_id` it cites, its `class` (`diff-actionable` or
  `context-informational`), and whether it is `deterministic`.

Three facts make this code review rather than documentation review:

1. **The registry is compiled into the binary.** Each engine includes its
   registry file with `include_str!`, so a merged change to `registry/` changes
   what every build reports as the evidence behind its numbers.
2. **A metric entry cannot change alone.** Every engine has a drift test
   (`Registry::check_engine`) asserting that the metric set it emits equals its
   registry file. Adding or removing a `[[metric]]` without the matching engine
   change fails `cargo test`.
3. **`deterministic` is a trust-boundary flag.** The verifier's copy of the
   registry decides which results enter the digest compare
   (`docs/trust-boundary.md`, "The flag nobody signs"). Flipping it moves a
   metric between channels, and that document says it changes first.

## What the lint checks

`andon-registry-lint` runs in CI on every push (`ci.yml`, job `registry-lint`)
and on registry pull requests (`registry-pr.yml`). Run it locally:

```sh
cargo run -p andon-registry-lint -- --policy .andon.toml registry/
```

Exit 0 is clean (notices allowed), 1 is a lint failure, 2 is bad usage, an
unreadable registry, or a file that does not parse. What it enforces, by
diagnostic code:

| Fails the build | Meaning |
|---|---|
| parse error (exit 2) | the file is not valid TOML, or does not match the registry schema — a missing field, an unknown field, a `tier` outside A–D/N, a malformed date |
| `registry.schema-version` | `schema_version` is not 1 |
| `registry.claim-id-format` | `claim_id` is not `implementation@version\|language\|outcome` for its own tuple |
| `registry.missing-field` | `does_not_predict` is empty, or `citation`, `population`, `effect`, or `owner` is blank |
| `registry.duplicate-claim`, `registry.duplicate-metric` | the same id declared twice, across all files |
| `registry.unmapped-metric` | a metric cites a claim no file declares — the rule the registry exists for |
| `registry.claim-budget` | more claims than `[registry] claim_budget` in `.andon.toml` |
| `registry.expiry-stagger` | more claims falling due in one calendar month than `[registry] max_claims_expiring_per_month` |

| Reported, never fails | Meaning |
|---|---|
| `registry.evidence-stale` | a claim's `expiry` has passed; it is demoted to `evidence: stale` on every number citing it, and the build stays green |
| `registry.unused-claim` | a claim no metric cites — budget spent on nothing |

## What the lint does not check

The lint has no network and no judgement. Everything below is the reviewer's,
and a green lint says nothing about it:

- that `citation_ref` **resolves**, and to the work the `citation` names;
- that the source is **primary** — the study, not a survey or a post that
  cites it;
- that `population` and `effect` are **the source's own terms**, not a
  paraphrase that strengthens them;
- that `tier` matches the grading in `docs/metric-families.csv` for evidence
  of that kind;
- that `does_not_predict` is **specific** to this claim — "everything else" and
  a copy of a neighbouring claim's list are both empty in the way that matters;
- that a moved `expiry` reflects a **re-review** — the diff should show what
  was checked, not only a date;
- that a new claim at the budget names **which claim it retires**, and why.

## Who reviews

Approval is by the change's effect on what Andon can say, not by its size.

| Change | Approvals | Why |
|---|---|---|
| A tier **N**, **C**, or **D** claim — new, re-reviewed, or retired; a re-review that keeps or lowers any tier; a metric entry with `deterministic` unchanged | **one** maintainer | Under `.andon.toml`, only tiers in `med_plus_tiers` (A and B) can carry a finding above LOW, and C is capped separately by `max_severity_for_c_tier`. These claims can advise; they cannot block. |
| A tier **A** or **B** claim — new, or a re-review that **raises** a claim into A or B | **two** reviewers | This is the only change that raises what a metric can block on. The second reviewer's job is the source: does it say what the tuple says, about that population, at that strength. |
| Any change to a metric's `deterministic` flag | **two** reviewers, and the pull request updates `docs/trust-boundary.md` in the same change | A channel move. The compare set changes for every verifier built from the commit. |

This project has one maintainer today. A change that needs two reviewers is
not merged with one: the second is a named reviewer with domain knowledge of
the source, asked on the pull request, and the change waits for them. The row
exists so that the wait is the rule and not the exception.

## Response time

The same numbers `SECURITY.md` gives, because they describe the same person:

- **First response within 7 days** of the pull request being opened — a
  review, a question, or a note saying when review will happen.
- **A decision within 14 days** for a one-approval change: merged, changes
  requested, or declined with the reason.
- **A decision within 30 days** for a two-reviewer change, which includes the
  time to find the second reviewer.

A pull request with no response after 7 days may be bumped with a comment; that
is the process working, not an imposition.

## What gets a change declined

- A `claim_id` that does not match its tuple, or a tuple broadened past what
  the source studied — the lint catches the first; a reviewer catches the
  second.
- A `does_not_predict` that is empty, generic, or copied.
- A `citation_ref` that does not resolve, resolves to something other than the
  citation, or points at a secondary source when a primary one exists.
- `population` or `effect` stated more strongly than the source states them.
- A claim over budget with no retirement named.
- An expiry landing in a month already at the stagger limit.
- A re-review that moves only the date.
- A metric entry with no matching engine change — this one fails `cargo test`
  before a reviewer sees it.
- A `deterministic` change without the trust-boundary edit beside it.

## Submitting a change

1. Edit the engine's file in `registry/` — one file per engine, and a claim
   lives in the file of the engine that cites it.
2. Run the lint with a pinned date, so the result does not depend on the day:
   `cargo run -p andon-registry-lint -- --as-of YYYY-MM-DD --policy .andon.toml registry/`.
3. Run `cargo test --workspace` — the drift tests and the shipped-registry load
   test run there.
4. In the pull request: the source (`citation_ref` or a URL), what was checked
   against it, the retirement if at budget, and the expiry month chosen and why
   it has room.
