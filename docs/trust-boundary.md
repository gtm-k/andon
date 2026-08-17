# The trust boundary

Andon's measurements come from two channels, and the difference between them is
the whole design. This document says which numbers live in which channel, why
the split is drawn where it is, and — plainly — what the attestation does *not*
prove.

It is the contract P9 builds the hardened verifier against. If a phase needs to
move a metric from one channel to the other, this file changes first.

---

## The two channels

### Channel 1 — digest-compared

**Deterministic and seed-free.** The agent measures, the verifier recomputes,
and the two per-result digests are compared byte for byte. A disagreement here
is `divergent`: the first-class tamper outcome.

A result may enter this channel only if it satisfies all four:

1. **Its inputs are git blob bytes.** Named by OID, read through
   `git cat-file --batch`, never from the working tree. A blob's bytes are fixed
   by its OID, so a CRLF checkout on Windows and an LF checkout on Linux produce
   the same number from the same blob. This is the mechanism, not a convention:
   `andon_core::git::BlobBatch::read` takes an OID and has no path argument, and
   `Content::from_worktree` stamps its output advisory. There is no constructor
   that produces compared-lane bytes from a path.
2. **No seed, no clock, no sampling.** Nothing whose value depends on when it
   ran or on a random draw.
3. **No iteration order that is not fixed by a type.** `BTreeMap` throughout the
   schema; enumeration output sorted in Rust rather than trusted from git, whose
   `diff.orderFile` cannot be neutralized by pinning.
4. **Its registry entry says `deterministic = true`.** And the *verifier's* copy
   of the registry decides, never the record's. See "The flag nobody signs".

### Channel 2 — CI-authoritative only

**Seeded, sampled, or held out.** Computed by the verifier, reported by the
verifier, and **excluded from the digest compare** — because there is nothing
for an agent's number to be compared against, by construction.

Its v1 occupant is **HMAC-seeded verification sampling** (user decision D1,
owned by P9): a per-run-unpredictable selection of which files receive a full
deep recompute beyond the standard set, which clone-window offsets are used, and
which prior results get spot re-verified. The seed is derived from a repository
secret and a run nonce.

The point of channel 2 is the one thing channel 1 cannot do. Every check in
channel 1 is published — an adversary knows exactly what will be recomputed and
can craft a change that passes all of it. Channel 2 is the part they cannot
predict. P9's acceptance criterion states the bar ex ante: a gamed change
crafted to pass every published deterministic check must be caught by the seeded
pass in at least one of five seeded runs, *and* must pass the deterministic-only
pass — proving it was the seeded channel that made the catch.

### What is in neither channel

Values that legitimately differ between two honest machines measuring the same
change. They are recorded and never compared:

| Field | Why it cannot be compared |
|---|---|
| `freshness.*` | Wall-clock timings and cache state differ by construction. |
| `compare_context.git_version` | Three runner images ship three gits. |
| `tool.build_oid`, `tool.version` | Depend on how each side was built. |
| `invocation.*` | Harness, model, and author differ between agent and verifier. |
| `policy_hash`, `severity` | The verifier loads policy from the **base** commit while the agent measured under the head's. Comparing them would make every PR that edits `.andon.toml` read as tampering — a designed-in false positive on precisely the case PLAN B6 rules *advisory*. Nothing is laundered: P9's two-axis rule has the verifier compute its own verdict from its own recompute. |
| `evidence.stale` | Derived from the run date, so yesterday's digest would not reproduce today. |
| `deterministic`, `digest` | Metadata about the compare, not facts about the measurement. |

The authoritative list is the field set of
`andon_core::schema::payload::ResultDigestInput`, and its doc comment carries
the same reasoning. This table is the summary; the type is the contract.

---

## The compare, in order

The order is the contract, because reordering it produces false tamper
accusations.

1. **Tuple equality.** An unequal `(base_oid, head_oid)` means the two sides
   measured different things and their digests were never expected to agree. The
   mismatch is **classified, not merely detected** (PLAN R2-4):
   - claimed base is an **ancestor** of the trusted branch → a stale base or a
     rebase → `unwitnessed-base-mismatch`. Not a tamper signal, and **not a
     pass**: the record stays self-reported and never counts downstream.
     Repeated mismatches on one PR escalate.
   - claimed base is **not an ancestor, or is an OID this repository has never
     seen** → tamper signal `base-fabrication` → `divergent`.

   The base relation is settled before the head is looked at, so fabricating
   both halves of the tuple cannot earn the gentler outcome that fabricating one
   earns.
2. **Regime equality.** Different engine, grammar, or git versions produce
   legitimately different numbers → `unwitnessed-version-skew`, never
   `divergent` (PREMORTEM S4).
3. **Digest compare**, over the deterministic results as the *verifier* marks
   them.
4. **A confirmation has to be earned.** Every check above is phrased over the
   results the two sides have in common, so a self-report that pairs nothing
   passes all of them vacuously. `confirmed` additionally requires that a
   comparison actually happened and that every deterministic result the verifier
   produced was witnessed. Both failures demote to `unwitnessed`, never to
   `divergent`: an omission is not an accusation.

The verifier resolves the base **for itself**, as
`merge-base(trusted_branch, head)`. Not the trusted branch's tip — main
advancing does not move a fork point, and resolving the tip instead would turn
every PR in a busy repository into a mismatch.

The checkout is pinned to the **PR head SHA**. GitHub's `pull_request` event
checks out a synthetic merge commit by default; that commit exists in no branch,
the agent never measured it, and verifying it would make every honest PR a tuple
mismatch. `andon-spike verify` refuses to run when `HEAD` is not the commit it
was asked about, so a workflow that gets this wrong fails loudly instead of
attesting wrongly.

---

## The flag nobody signs

`deterministic` decides compare-set membership and sits **outside**
`ResultDigestInput`, so nothing signs it and a self-report can say anything it
likes about it.

Compare-set membership is therefore keyed on the **verifier's** flag alone,
resolved from the registry compiled into the verifier's own binary. Honouring
the report's `false` would let any result buy its way out of the compare for the
price of one boolean: flip the flags, forge the numbers, write garbage digests,
and the comparison loop walks past all of it leaving matched, mismatched, and
unpaired empty — a `confirmed` with no trace of what was never checked.

Where the two sides disagree, the verifier's answer is used and the
disagreement is recorded in `CompareOutcome.flag_disagreements`. It is not an
accusation — an engine upgrade can legitimately change whether a metric is
seed-free — but a signal nobody can see is a signal that does not exist.

Fixture: `fixtures/gamed/flipped-deterministic/`.

---

## The attestation values

| Value | Means | Counts downstream |
|---|---|---|
| `confirmed` | CI recomputed the deterministic set; every digest matched. | yes |
| `confirmed-static` | Fork tier: CI recomputed from an unprivileged job with no self-report to compare against. A pass, labelled as the weaker one it is. | yes |
| `divergent` | Digests disagreed on an equal tuple at an equal regime, or a tamper signal fired. | no |
| `unwitnessed` | No CI recompute, or nothing was actually compared. Neutral, not negative. | no |
| `unwitnessed-version-skew` | The regimes differed, so the digests were never comparable. | no |
| `unwitnessed-base-mismatch` | The claimed base is an ancestor of the trusted branch — a stale base or a rebase. | no |

Mapping these onto CI check conclusions, and composing them with the verdict CI
computes from its own recompute (the two-axis rule: the conclusion is the
**worse** of the two, so an absent self-report can never launder a CI-computed
tamper finding into a neutral notice), is **P9's** acceptance criterion. The
P1.5 action reports the value and lets the workflow decide.

### Several self-reports on one commit

`git notes append` and `cat_sort_uniq` both admit more than one record per
commit — two engines, a re-run, a merged ledger. The verifier classifies every
self-report it finds and takes the **worst** outcome. Taking the best, the
first, or the newest would each hand an attacker the same move: append one
honest record beside the forged one and let the verifier pick the flattering
half.

---

## What the attestation does not prove (advisor F4)

**v1 attestation trust is GitHub Actions provenance, not cryptography.**

`refs/notes/andon-attest` is an ordinary git ref. **Anyone with push access to
the repository can write an attestation by hand**, claiming any value including
`confirmed`, and nothing in v1 can tell that record from one a workflow
produced. `AttestationBlock.verifier` records a provider and a workflow-run URL,
and both are self-declared strings.

What the attestation *does* establish, when it was in fact produced by the
action:

- the numbers were recomputed by a process the measured party did not control;
- from a clean checkout pinned to the PR head SHA;
- against a base the verifier resolved itself.

What it does not establish: that the record you are reading is the one that
process produced.

**Sigstore signing is the named v1.5 hardening** — keyless signing of the attest
record with the workflow's OIDC identity, so the record carries its own
provenance rather than borrowing the ref's. It is out of v1 scope by decision,
not by oversight, and this limitation is disclosed in VISION §5 as well as here.

Practical consequence for a consumer: an attestation is evidence in a repository
whose push access you already trust. It is not evidence to a stranger. Treat
`confirmed` from an untrusted repository as unverified until v1.5.

---

## Fork transport (placeholder — P9 owns this)

Notes refs do not travel with fork pull requests. A fork PR's job is
unprivileged by design (PREMORTEM T5: `pull_request_target` with a writable
token running PR code is a secret-leak vector), so there is frequently no
self-report available on the verifier's side at all.

The shape P9 implements, stated here so the two documents cannot drift:

- **Notes when available.** The normal path.
- **Commit-trailer digest when notes are unavailable.** The self-report's
  per-result digests are carried in a commit trailer, which travels with the
  commit and therefore with the fork PR. The compare runs against the trailer.
- **Neither available → `confirmed-static`**, emitted without a compare and
  labelled as the weaker tier it is. The verifier still recomputed; nobody
  attested the agent's claim because the agent's claim never arrived.

P1.5 wires the fork tier as a representable outcome (`--fork-tier`) and stops
there. The transport, the workflow-configuration assertion that no
secret or writable token is reachable from any job executing PR code, and the
simulated fork-PR exercise in a scratch repository are all P9's acceptance
criteria.

---

## The P1.5 spike metrics

The three metrics the trust spike measures — `spike.changed-files`,
`spike.file-bytes`, `spike.file-lines` — are instrument scaffolding. They are
byte counts, tier `N`, and their claims say in words that they predict nothing.

Their evidence registry lives at `crates/andon-ledger-min/registry/spike.toml`,
**beside the crate rather than in the repository-root `registry/`**, so they are
not counted against the shipped claim budget of 24 (PREMORTEM S2). P2's
`registry/static.toml` brings the first metrics with an evidence story, and the
spike metrics are replaced rather than promoted.

They exist so the trust kernel has something real to digest-compare before any
engine exists — and so that a red cross-OS matrix means the kernel is broken
rather than leaving anyone to wonder whether a tree-sitter grammar was at fault.

---

## Where the claims are tested

| Claim | Evidence |
|---|---|
| Honest change → `confirmed`, on every OS | `fixtures/honest/determinism/`, run on all three matrix legs |
| Byte-identical digests across Win/macOS/Linux | `.github/workflows/spike-matrix.yml`, `verifier-recompute` job |
| Main advancing does not move the base | `fixtures/honest/moving-main/` |
| Rebase → demotion, not accusation | `fixtures/honest/rebased-pr/` |
| Version skew → skew, not divergence | `fixtures/honest/version-skew/` |
| Forged numbers → `divergent` | `fixtures/gamed/inflated-metric/` |
| Flipped `deterministic` cannot escape the compare | `fixtures/gamed/flipped-deterministic/` |
| Fabricated base → `base-fabrication` → `divergent` | `fixtures/gamed/fabricated-base/` |
| Concurrent attestations survive a notes merge | `crates/andon-ledger-min/tests/concurrency_and_squash.rs` |
| Squash-migrated records survive on what landed | same |
| A shallow clone still gets the whole ledger | same |
| The measuring binary cannot forge a record | `crates/andon-ledger-min/tests/binary_separation.rs` |
| The verifier refuses a merge-ref checkout | `crates/andon-ledger-min/tests/verdict_set.rs` |
