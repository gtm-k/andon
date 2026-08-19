# The published contract

Four surfaces come out of one measurement — CLI, MCP, JSON payload, human report
— and a fifth actor, the CI verifier, checks the result. The versioned payload
schema is what holds still for all five (VISION §3.4).

| Artifact | Type | What it describes |
|---|---|---|
| `payload-v1.schema.json` | `MeasurementRecord` | A full measurement, self-reported or attested |
| `agent-profile-v1.schema.json` | `AgentProfile` | The bounded agent-mode view |
| `policy-v1.schema.json` | `Policy` | `.andon.toml` |
| `registry-v1.schema.json` | `EngineRegistryFile` | One engine's evidence registry file |

All four are generated from the Rust types in `andon-core` and pinned by
`crates/andon-core/tests/schema_drift.rs`. After an intentional change:

```bash
ANDON_UPDATE_SCHEMAS=1 cargo test -p andon-core --test schema_drift
```

Field descriptions in the artifacts come from doc comments on the Rust types,
which is why `andon-core` denies `missing_docs`: documenting a field is
documenting the contract someone integrates against.

## Canonical serialization

Digest equality is the trust mechanism, so there is exactly one way to produce
bytes for hashing (`andon_core::canonical`):

1. Object keys sorted by **UTF-16 code unit**, per RFC 8785 (JCS).
2. No insignificant whitespace.
3. Minimal string escaping — `"`, `\`, and control characters below `0x20`.
   Non-ASCII is emitted as UTF-8, never `\u`-escaped.
4. `i64`/`u64` emitted as exact decimal digits.
5. Floats formatted as ECMAScript `Number::toString`: shortest round-tripping
   decimal, ES6 exponent placement, `-0` normalized to `0`. Non-finite floats
   are an error.

**This is JCS-style, not JCS-conformant.** JCS routes every number through the
ES6 double path, which loses precision above 2^53; Andon emits integers exactly,
because counts are compared and must stay exact. Both sides of every digest
compare run the same binary, so self-consistency is what carries the property.
Wire-compatibility with third-party JCS implementations is not claimed.

### Ratios are quantized, and why

`MetricValue::Ratio` rounds to six decimal places on serialization and on
deserialization. The reason is empirical rather than aesthetic: `serde_json`'s
float parser is not correctly rounded for every input — it reads the canonical
text of `1.2689392828653361e-47` back one ULP low. A raw `f64` in the compare set
could therefore be written by the agent, re-read by a consumer, and re-hash to a
different digest, producing `divergent` on an honest change. Quantized values are
short enough to land on the exact path of any conforming parser. The asymmetry is
pinned by a regression test that fails if `serde_json` is fixed.

Six places is far more resolution than a code metric carries. Counts and integers
are never quantized.

## Per-result digests, and the compare set

Digests are **per result**, not one digest over the record. A single monolithic
digest cannot tell you *which* number disagreed, and a verifier that can only say
"something differs" cannot distinguish a tampered metric from a metric the two
sides were never going to agree on.

A digest covers `ResultDigestInput`: schema version, the `(base_oid, head_oid)`
tuple, engine and metric and claim ids, family, scope, value, delta,
completeness, and the measurement regime.

**Deliberately outside it:**

| Excluded | Why |
|---|---|
| `policy_hash` | The verifier loads policy from the **base** commit while the agent measured under head policy. Including it would flip every digest on any PR touching `.andon.toml` — a designed-in false tamper on exactly the case ruled advisory (PLAN B6). |
| `severity` | Derived from policy; same problem one level down. |
| `freshness` | Timings and cache state differ by construction. |
| `invocation` | Harness, model, and author differ between agent and verifier by construction. |
| `evidence` | Carries a staleness flag derived from the current date, so including it would make yesterday's digest fail to reproduce today. |
| `deterministic`, `digest` | Metadata about the compare, not facts about the measurement. |

Nothing is laundered by these exclusions. P9's two-axis rule has the verifier
compute its own verdict from its own recompute and take the worse of the two, so
a lied-about severity cannot turn a CI-computed `block` into a pass.

Only results marked `deterministic` enter the compare at all. Seeded and
timing-dependent checks are CI-authoritative and excluded by design — see
`docs/trust-boundary.md` from P1.5.

**Whose `deterministic` flag decides is the verifier's.** The field is in the
table above — outside the digest input, and so unsigned. If a self-report's
`false` excused a result from the compare, every result would carry its own
opt-out: flip the flags, forge the numbers, and the compare walks past all of
them and reports a pass over nothing. So membership is read off the verifier's
own copy, which it can vouch for because it produced it, and a pair the verifier
calls deterministic is compared whatever the report claims. Where the two sides
disagree, the metric id appears in `compare.flag_disagreements` — visible, but
not an accusation on its own, since an engine upgrade can legitimately change
whether a metric is seed-free.

## The compare pipeline

The **order of these three checks is the contract**, because reordering them
manufactures false tamper accusations. Implemented in `andon_core::compare`, so
P1.5 and P9 build against a function rather than re-deriving it from prose.

1. **Tuple equality.** Unequal `(base_oid, head_oid)` means the two sides
   measured different things and their digests were never expected to agree.
   Classified, not merely detected:
   - claimed base **is an ancestor** of the trusted branch — a stale base or a
     rebase → `unwitnessed-base-mismatch`. A non-tamper outcome that is still
     **not a pass**: the record stays self-reported and never counts downstream.
   - claimed base **is not an ancestor, or is unknown** → tamper signal
     `base-fabrication` → `divergent`.
2. **Regime equality.** Different engine, grammar, or git versions produce
   legitimately different numbers → `unwitnessed-version-skew`, never
   `divergent`.
3. **Digest compare**, over the results the *verifier* marks deterministic.
   Reaching this step means both sides measured the same change with the same
   tooling, so a disagreement is a real one → `divergent`.
4. **Confirmation is earned, not defaulted to.** Every check above is phrased
   over the results the two sides have in common, so a report with nothing in
   common passes all three vacuously. `confirmed` additionally requires that at
   least one pair was compared, and that no deterministic result the verifier
   produced was left unpaired. Failing either demotes to `unwitnessed` — never
   `divergent`, because unpaired results have honest causes (an async lane still
   running, `completeness: partial`).

The verifier resolves the base itself and never takes the record's word for it —
for the base, for the regime, or for what belongs in the compare set.

**Step 0, before the tuple: `head_kind`.** A head can be a commit or an
uncommitted tree, and only the first is something a verifier can check out. A
record measured against a working tree carries the content hash of its snapshot
in `head_oid` — never `HEAD`'s commit OID, which would pass the tuple check while
describing bytes that were never committed. `classify` reads `head_kind` before
anything else and returns `unwitnessed-uncommitted` without attempting a compare;
reaching the tuple check with a content hash would report
`unwitnessed-base-mismatch`, or `base-fabrication` and `divergent` if the base had
also moved, which is a tamper accusation against somebody who forgot to commit.

`head_kind` is inside `ResultDigestInput`, so it is a measurement fact rather
than compare metadata: "these numbers came off an uncommitted tree" is part of
what was measured, and a record that lied about it sealed its results against the
lie.

## Vocabularies

`verdict`: `pass | advise | block | escalate_to_human`

`attestation`: `confirmed | confirmed-static | divergent | unwitnessed |
unwitnessed-version-skew | unwitnessed-base-mismatch | unwitnessed-uncommitted`.
Only the first two count downstream (`Attestation::counts_downstream`).

The `unwitnessed-*` family is four specific causes kept out of one generic
bucket, and `unwitnessed-uncommitted` is the one that can never improve: the
other three describe a recompute that has not happened or did not line up, while
this one describes a head no verifier can ever check out. Telling an operator to
wait for an attestation that is not coming is the actor-observability defect the
family exists to avoid.

`completeness`: `complete | partial | parse-degraded | unwitnessed`. Missing data
is said out loud, never reported as a zero.

`tamper_signals`: `suppression-density | test-removal | coverage-exclusion-drift
| assertion-free-test | threshold-config-edit | lookup-table-blowup |
parse-error-delta | base-fabrication`. The first seven are the P3 detector suite;
`base-fabrication` is raised by the verifier, not by a content detector.

`invocation_source`: `hook | agent-initiated | human-cli | ci-verifier`.

`measurement_regime` is tagged by `family` and defined for all five:
`static | clones | tamper | process | artifacts`.

### A note on spelling

`escalate_to_human` is snake_case while `confirmed-static` and `parse-degraded`
are kebab-case. This is inconsistent and it is deliberate — the spellings are
copied verbatim from PLAN.md's acceptance criteria, which is the contract these
types implement. Reproducing the inconsistency is cheaper than a schema version
bump to fix an aesthetic problem.

## Reserved fields

`run_id`, `workspace_id`, and `package_scope` are always serialized, `null` when
unset, so the shape of a record never varies with content. They exist so
orchestrator and monorepo support (VISION §3.3) can land without a breaking
change.

## Versioning

`schema_version` is `2`. A change to any published type is a plan change, not a
phase decision: `schemas/*` is P0-owned, and later phases touch it only where
their PLAN.md row says so, serialized, with a version bump and a changelog line.

Pre-release, "v1" is still being defined rather than maintained, so an additive
field with a default is a v1 definition change and not a v1 → v2 migration. That
is the precedent P0 set with `CompareOutcome.flag_disagreements` (decision log,
2026-08-17). It ends at the first release, after which the sentence above is the
whole rule.

### v1 → v2

| Schema | Change | Phase | Why |
|---|---|---|---|
| `payload-v1` | `CompareContext.head_kind` added, required; `head_oid` widened from "a commit OID" to "the head's identity, of the kind `head_kind` names"; `Attestation::unwitnessed-uncommitted` added; `head_kind` bound into `ResultDigestInput` | P5b (mini-G2 ruling) | The state the product exists for is an agent that has written a change and not committed it, and it could not be represented: the working tree has no commit OID, and writing `HEAD`'s in its place is the R2-4 laundering path that produces false `divergent` verdicts on honest work. So the head says what it is. |

**Why this is a migration and not a v1 definition change.** The carve-out below
covers *an additive field with a default*, which is what
`CompareOutcome.flag_disagreements` was: nothing that already existed changed
meaning. Here an existing required field did. A v1 consumer that read `head_oid`
and handed it to `git cat-file` was correct at v1 and is wrong at v2, and telling
it so is what a version number is for. Every per-result digest moves, because
`schema_version` and `head_kind` are both inside `ResultDigestInput`; the golden
set was re-recorded in the same commit.

### Changes to the v1 definition

| Schema | Change | Phase | Why |
|---|---|---|---|
| `payload-v1` | `CompareOutcome.flag_disagreements` added, required, always present | P0 | Verifier-authoritative compare membership (decision log E2). |
| `agent-profile-v1` | `AgentProfile.verdict_invalid` added, default `false` | P5b | Records sealed before "a change nobody read cannot pass" carry `verdict: pass` beside a non-zero `unread_paths`. The two cannot both be true, and the machine surface has to be able to say so in a field rather than in prose. The record itself is untouched: it is served exactly as sealed, and every renderer labels the stored verdict rather than recomputing or rewriting it. |
| `payload-v1` | `MeasurementRecord.self_measure` added, default `null` | P5b | `SelfMeasureProvenance` existed with no caller, so which binary judged, under which override, and what `[self_measure] excluded_paths` withheld all lived for one process: the terminal named eighteen withheld paths and the saved record, the read-back report, `wait`, `--json` and the agent profile named none — including the dogfood job's own payload. A record-level field, outside `ResultDigestInput` for the same reason as `policy_hash`: it describes how the measurement was arrived at, not what was measured. |
| `agent-profile-v1` | `AgentProfile.withheld_paths` added, default `0` | P5b | The count half of the above, for the surface with a byte budget. Zero for every repository that is not this one. |
| `policy-v1` | `[perf] fast_lane_warm_fallback_p95_ms` added, default `2000` | P1 | The dirty-tree path without a watching fsmonitor daemon is a shipped arrangement with its own cost, and it needs a budget of its own to be gated rather than merely printed. Ledgered policy decision, orchestrator pre-approved. |
