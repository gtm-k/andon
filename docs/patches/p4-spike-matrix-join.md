# P4 → `spike-matrix.yml`: the process family's join

**Status:** ready to apply, **serialized after P2's join.**
**Why it is a patch and not an edit:** `.github/workflows/spike-matrix.yml` has a
single writer this wave — P2 — by the wave rule in PLAN.md's decision log
(P1.5 execution, item (g)). P3 and P4 deliver their joins as documented patches
applied after the merge, in P2 → P3 → P4 order.
**Owner at apply time:** the orchestrator.
**Everything this patch needs already exists on `main`:** the logic lives in
`crates/engines/process/src/probe.rs` and the `andon-p4-probe` binary, both
covered by unit tests. The YAML below only calls it.

---

## What this join asserts, and what it deliberately does not

`MeasurementRegime::Process` binds `git_version` — P0's schema requires it and
PLAN P4's acceptance criterion names it explicitly ("history_window + git version
in the tuple"). It is bound because git's date-limited traversal and its diff
machinery are part of how these numbers were produced, and PREMORTEM S4 says two
tooling versions are two regimes.

The three matrix runners ship three different gits. So the assertion P2 and P3
make — every leg byte-identical — **would be the wrong assertion here**: legs at
different git versions are different regimes, and `andon_core::compare` stops at
step 2 with `unwitnessed-version-skew` before it examines a single digest. A
green "all legs identical" gate for the process family would either be measuring
nothing or asserting something the product does not claim.

PLAN P4 anticipated exactly this. Its matrix criterion reads "Process + artifact
outputs join the cross-OS matrix **where deterministic**" — the qualifier P2's
and P3's rows do not carry.

So the join asserts two things, both of which are claims rather than concessions:

1. **Within one measurement regime, every leg is byte-identical.** This is the
   determinism claim, and it is what catches a wall clock, a hash-map iteration
   order, or a platform `log2` reaching a value. The Linux agent leg and the
   Linux verifier leg always share a regime — same runner image, same git — so
   the agent-versus-verifier comparison the trust kernel depends on is exercised
   on every run, not only when the runner images happen to agree.
2. **Across regimes, the regimes differ and are reported.** PREMORTEM S4's
   prevention line, demonstrated live rather than asserted in prose: legs whose
   numbers came from different tooling are visibly incomparable instead of
   silently compared.

Neither outcome is a pass by default. `andon-p4-probe compare` fails the job when
legs sharing a regime disagree, when the legs measured different `(base, head)`
tuples, when any leg produced no results, and when any leg reports a **truncated**
window — the last because a shallow clone emits change-scoped markers that agree
with each other perfectly, which is exactly the vacuous green this gate must
refuse.

## Why the artifacts family does not join

Every `artifacts.*` result is `deterministic: false` (see
`registry/artifacts.toml` and `crates/engines/artifacts/src/engine.rs`): a
coverage report is an untracked build output, and no verifier can reproduce one
without executing the repository's test suite. Results outside the compare set
have nothing to be byte-identical about. A matrix leg for them would assert that
two runners parsing the same committed fixture file produce the same numbers,
which is a parser test and already covered by
`crates/engines/artifacts/tests/diff_coverage.rs`.

## The requirement this creates for P9

**The verifier must fetch full history before recomputing.** `actions/checkout`
clones at depth 1 by default. A verifier with a truncated window emits
change-scoped markers instead of per-file process results, and while that can
never produce a false `divergent` — proved in
`crates/engines/process/tests/compare_asymmetry.rs`, in both directions — it does
mean no process metric can ever reach `confirmed`. Either `fetch-depth: 0` on the
verifier's checkout, or an explicit `git fetch --unshallow`, is a P9 acceptance
condition rather than a nicety.

---

## The patch

Add three jobs. Nothing existing is modified, so this applies cleanly whatever
P2 and P3 added before it.

```yaml
  # --------------------------------------------------- P4: process, push tier
  # Linux only, on every push, per D2: the cheap standing check that the process
  # family's agent-side and verifier-side numbers agree on one machine. The
  # cross-OS legs below wait for the dispatch at a phase gate.
  process-linux-self-check:
    name: process determinism (linux self-check)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2

      - name: Build the spike and the probe
        run: cargo build --release -p andon-ledger-min -p andon-engine-process

      - name: Measure the determinism fixture twice, as agent and as verifier
        run: |
          set -euo pipefail
          ./target/release/andon-spike scenario prepare \
            --manifest "$FIXTURE_MANIFEST" --dest fixture-src --json fixture.json
          head="$(jq -r .head fixture.json)"
          branch="$(jq -r .trusted_branch fixture.json)"
          git clone --quiet fixture-src agent-work
          git clone --quiet fixture-src verifier-work
          for side in agent verifier; do
            ./target/release/andon-p4-probe measure \
              --repo "${side}-work" --base "merge-base:origin/${branch}" \
              --head "$head" --window 3650 --no-cache \
              --out "process-${side}.json"
          done
          ./target/release/andon-p4-probe compare \
            --leg agent=process-agent.json \
            --leg verifier=process-verifier.json

  # ------------------------------------------------ P4: process, dispatch tier
  process-determinism:
    name: process metrics (${{ matrix.os }})
    needs: build-fixture
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2

      - name: Build the probe
        run: cargo build --release -p andon-engine-process

      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          name: determinism-fixture

      # Full history, deliberately: `--depth` here would make every leg report a
      # truncated window, the probe would fail the job, and it would be right to.
      - name: Clone the fixture with this runner's own git config
        shell: bash
        run: |
          set -euo pipefail
          tar -xzf determinism.tar.gz
          git clone --quiet determinism.git work
          git --version
          test "$(git -C work rev-parse --is-shallow-repository)" = "false"

      - name: Measure the process family
        shell: bash
        env:
          HEAD_SHA: ${{ needs.build-fixture.outputs.head }}
        run: |
          set -euo pipefail
          probe=./target/release/andon-p4-probe
          [ -x "$probe" ] || probe="${probe}.exe"
          # A window wide enough to hold the whole fixture history whatever its
          # pinned dates are, and identical on every leg because the window is
          # part of the regime.
          "$probe" measure \
            --repo work \
            --base "merge-base:origin/${{ needs.build-fixture.outputs.trusted-branch }}" \
            --head "$HEAD_SHA" \
            --window 3650 \
            --no-cache \
            --out "process-${{ matrix.os }}.json"
          cat "process-${{ matrix.os }}.json"

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: process-${{ matrix.os }}
          path: process-${{ matrix.os }}.json
          retention-days: 7

  process-compare:
    name: process metrics — identical within a regime
    needs: [build-fixture, process-determinism]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2

      - name: Build the probe
        run: cargo build --release -p andon-engine-process

      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          path: legs

      # The verifier leg. Same runner image as the Linux agent leg, so the two
      # always share a regime and the strong assertion always has at least one
      # pair to bite on.
      - name: Recompute as the verifier
        env:
          HEAD_SHA: ${{ needs.build-fixture.outputs.head }}
        run: |
          set -euo pipefail
          tar -xzf legs/determinism-fixture/determinism.tar.gz
          git clone --quiet determinism.git verifier-work
          ./target/release/andon-p4-probe measure \
            --repo verifier-work \
            --base "merge-base:origin/${{ needs.build-fixture.outputs.trusted-branch }}" \
            --head "$HEAD_SHA" \
            --window 3650 \
            --no-cache \
            --out process-verifier.json

      - name: Byte-identical within a regime; skewed across regimes
        run: |
          set -euo pipefail
          ./target/release/andon-p4-probe compare \
            --leg linux=legs/process-ubuntu-latest/process-ubuntu-latest.json \
            --leg macos=legs/process-macos-latest/process-macos-latest.json \
            --leg windows=legs/process-windows-latest/process-windows-latest.json \
            --leg verifier=process-verifier.json
```

## Verifying the patch before dispatching a paid run

The whole comparison runs locally against any repository:

```bash
cargo build --release -p andon-engine-process
./target/release/andon-p4-probe measure --repo . --base HEAD~1 --head HEAD \
  --window 365 --no-cache --out a.json
./target/release/andon-p4-probe measure --repo . --base HEAD~1 --head HEAD \
  --window 365 --no-cache --out b.json
./target/release/andon-p4-probe compare --leg agent=a.json --leg verifier=b.json
```

Exercised on the Andon repository during P4 with all three outcomes: two honest
legs pass; a leg with one digest edited fails and names the row that moved; a leg
with a different `git_version` is reported as a separate regime and is not
compared.
