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

## Vocabularies

`verdict`: `pass | advise | block | escalate_to_human`

`attestation`: `confirmed | confirmed-static | divergent | unwitnessed |
unwitnessed-version-skew | unwitnessed-base-mismatch`. Only the first two count
downstream (`Attestation::counts_downstream`).

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

`schema_version` is `1`. A change to any published type is a plan change, not a
phase decision: `schemas/*` is P0-owned, and later phases touch it only where
their PLAN.md row says so, serialized, with a version bump and a changelog line.
