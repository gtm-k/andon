# Andon

Agent-callable code measurement: evidence-carrying, delta-first, tamper-aware.

Private during development. See `gtm-k/prd/andon` for the vision and plan.

---

## What it does

Measures a code change and returns a verdict — `pass`, `advise`, `block`, or
`escalate_to_human` — with the evidence behind it. An agent calls it over MCP after
making a change; a person runs `andon measure`. Findings come back worst-first, each
with a location and a `diff_actionable` flag saying whether the agent can fix it inside
the change it just made.

Every number carries the claim it stands on, and every claim carries an honesty field
naming what the number is **not** evidence for. `andon explain <metric-id>` prints both.

## What it measures, and in which languages

**This is the first thing to check before running it against your repository.**

39 metrics across six engine families. `andon explain --list` prints every one.

| Engine family | Metrics | Languages |
|---|---|---|
| `tamper` — seven detectors, see below | 14 | JavaScript, TypeScript, TSX, Python |
| `static` — size, complexity, parse health | 11 | those four, plus **Rust at size only** — no complexity, no parse health |
| `process` — history and hotspots | 6 | language-independent (reads git) |
| `clones` — duplicated regions | 5 | the same four grammars |
| `tests` — the repository's own suite, sandboxed | 2 | whatever the suite itself runs |
| `artifacts` — coverage and reports | 1 | language-independent (reads report files) |

**A file in a language not listed above is not measured.** Go, Java, Ruby, PHP, C, C++,
C#, Swift and Kotlin have no model here — a change touching only those files can return
`pass` because nothing looked at it, not because nothing was wrong. Andon is not a
security scanner and ships no SAST family; it will not find an injection or a hardcoded
credential in any language.

## What the tamper suite is, and what it is not

Seven detectors answer four questions: has the suite stopped verifying things, is there
code the static engines can no longer read, did the quality bar move instead of the
code, was an implementation replaced by its expected answers.

They are measured against a frozen corpus of 102 constructed changes — 51 that must
fire, 51 that must not — with per-detector precision and recall floors set **before**
measurement at 0.80 and 0.70. Every detector clears both.

**Read `fixtures/adversarial/README.md` before believing that means much.** It states,
in the project's own words, that these "are not field precision and recall", and it
enumerates every evasion the suite is known to miss, per detector, with what closing
each one would require. A published adversarial corpus is a specification for evading
the detectors it describes, so a held-back set exists precisely to measure whether the
public cases have been fitted to — and it scores materially lower.

The honest claim is narrow: **these detectors catch the patterns they enumerate.** They
are not a general defence against a determined adversary, and the project does not claim
they are.

## What a verdict does and does not mean

- A **`block`** on a tamper signal is not capped by evidence tier the way metric
  findings are. That is deliberate — a gaming signal that could only advise would not be
  a gaming signal — but it means the one uncapped verdict class rests on the project's
  own constructed corpus rather than on external study. Weigh it accordingly.
- **`completeness`** is not decoration. A result marked `partial` or `unwitnessed`
  covers less than the change, and the verdict was reached without what is missing.
- An **attestation** is what makes a measurement more than a self-report. Until CI
  recomputes a change independently, `andon report` says so on every rendering.

## Getting the honest version

| Question | Where it is answered |
|---|---|
| What does this number not predict? | `andon explain <metric-id>` |
| What does the tamper suite miss? | `fixtures/adversarial/README.md` |
| What can an attestation actually prove? | `docs/trust-boundary.md` |
| What does the sandbox isolate? | `docs/sandbox.md` — it is **not** a security boundary against a hostile repository |
| Does Andon measure itself? | `docs/self-measure.md` |

## Building

```
cargo build --workspace
cargo test --workspace
```

Gates, mirroring `.github/workflows/ci.yml`:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
cargo deny check licenses bans sources
```
