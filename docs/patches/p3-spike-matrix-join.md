# P3 → `spike-matrix.yml`: the clone and tamper engines join the standing matrix

**Status:** ready to apply, serialized, after `phase/p3-clones-tamper` merges.
**Owner of the target file:** P2 this wave (PLAN.md decision log, P1.5-execution (g)).
**Applies to:** `.github/workflows/spike-matrix.yml` and `.andon.toml`.

P3 does not touch `spike-matrix.yml`. The wave rule gives that file one writer —
P2 — and P3 and P4 deliver their joins as documented patches applied in
`P2 → P3 → P4` order after merge. This is P3's.

---

## What the join proves

PLAN.md B4 and R2-1: clone outputs **and all seven tamper-detector outputs**
produce byte-identical per-result digests on Windows, macOS, and Linux agents
against a Linux verifier. Twenty-three sealed results per leg — nine from the
clone engine, fourteen from the tamper suite — over a specimen engineered so
that none of them is trivially zero.

That last point is the one worth checking when reviewing this patch. A digest
comparison over results that are all `false` and all `0` is green whatever the
engines do; it would prove three operating systems agree about nothing.
`fixtures/matrix/all-seven` fires every detector and contains a real Type-2
clone. Two things keep that true if somebody edits the specimen: the
`7 of 7 detectors fired` check in the measure step below, and
`crates/engines/tamper/tests/matrix_specimen.rs`, which asserts the same thing
in `cargo test` — so the specimen going quiet is caught on a push rather than at
the next dispatched gate.

## Rehearsed locally before this patch was written

The whole join rests on one thing this repository had never actually done:
`andon-spike compare-records` reading a `MeasurementRecord` that an *engine*
probe wrote rather than one the spike wrote. A serialization mismatch there
would surface only in a dispatched matrix run after merge, which is the most
expensive place to find it. So it was run first, on two independent clones of
one fixture standing in for two legs:

```
$ andon-tamper-probe build-fixture --case fixtures/matrix/all-seven --dest mxA --json shas.json
$ git clone --quiet mxA mxB
$ for leg in A B; do
    andon-tamper-probe --repo mx$leg --base $BASE --head $HEAD --out tamper$leg.json
    andon-clones-probe --repo mx$leg --base $BASE --head $HEAD --out clones$leg.json
  done
tamper: 7 changed path(s), 14 result(s), 7 of 7 detectors fired: test-removal,
        suppression-density, assertion-free-test, coverage-exclusion-drift,
        threshold-config-edit, lookup-table-blowup, parse-error-delta
clones: 7 changed path(s), index disabled, 9 result(s), 2 clone group(s)

$ andon-spike compare-records --leg a=tamperA.json --leg b=tamperB.json --expect-results 14
14 result(s) byte-identical across 2 leg(s)                                    # exit 0

$ andon-spike compare-records --leg a=clonesA.json --leg b=clonesB.json --expect-results 9
9 result(s) byte-identical across 2 leg(s)                                     # exit 0
```

Two clones of one fixture is not the cross-OS claim — that is what the matrix
legs are for. It is the claim that the plumbing in this patch works, which is
the part a patch file can be wrong about.

Re-run after repair round 1, which moved both engines' measurement regimes
(clones `rules2`, tamper rule pack 2) and therefore every digest. Same two exit
zeros, same 14 and 9. The counts are exact — `compare-records` treats
`--expect-results` as equality — so if either moves, this patch's numbers move
with it.

---

## Patch 1 — `.github/workflows/spike-matrix.yml`

**Purely additive: three new jobs appended at the end of `jobs:`.** No existing
job, step, or `env` entry changes, which is what keeps this patch from
conflicting with P2's or P4's.

The jobs mirror the shape the file already uses — build the fixture once on
Linux, ship it, measure on each OS, recompute on Linux, compare — for the reason
stated in that file's header: a per-result digest binds `(base_oid, head_oid)`,
so building the fixture per leg would nest a second determinism claim inside the
one under test.

### Append to the end of `.github/workflows/spike-matrix.yml`

```yaml
  # ----------------------------------------------- P3 engines: clones + tamper
  #
  # The clone engine and all seven tamper detectors join the standing matrix
  # (PLAN B4, R2-1). Same argument as `build-fixture` above: the specimen is
  # built once, on Linux, and shipped, because a per-result digest binds
  # `(base_oid, head_oid)` and building it per leg would make this test depend
  # on three operating systems producing identical commit OIDs.
  #
  # `fixtures/matrix/all-seven` is engineered so that every detector fires and
  # the clone engine finds a real Type-2 clone. A matrix over results that are
  # all `false` and all `0` is green whatever the engines do — see that
  # fixture's README.
  engines-build-fixture:
    name: build the P3 engine specimen
    runs-on: ubuntu-latest
    if: github.event_name == 'workflow_dispatch'
    outputs:
      base: ${{ steps.fixture.outputs.base }}
      head: ${{ steps.fixture.outputs.head }}
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2

      - name: Build the engine binaries
        run: cargo build --release -p andon-engine-clones -p andon-engine-tamper

      - name: Build and pack the specimen
        id: fixture
        run: |
          set -euo pipefail
          ./target/release/andon-tamper-probe build-fixture \
            --case fixtures/matrix/all-seven \
            --dest engine-fixture \
            --json engine-fixture.json
          echo "base=$(jq -e -r .base engine-fixture.json)" >> "$GITHUB_OUTPUT"
          echo "head=$(jq -e -r .head engine-fixture.json)" >> "$GITHUB_OUTPUT"
          git clone --quiet --mirror engine-fixture engine-fixture.git
          tar -czf engine-fixture.tar.gz engine-fixture.git

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: engine-fixture
          path: |
            engine-fixture.tar.gz
            engine-fixture.json
          retention-days: 7

  engines-measure:
    name: engine measure (${{ matrix.os }})
    needs: engines-build-fixture
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2

      - name: Build the engine binaries
        run: cargo build --release -p andon-engine-clones -p andon-engine-tamper

      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          name: engine-fixture

      # Cloned with this runner's own git config, exactly as the spike legs are.
      # On Windows that means core.autocrlf=true and a working tree full of CRLF
      # nobody committed — PREMORTEM Story 1's setup. Both engines read blobs, so
      # the digests must not notice.
      - name: Clone the specimen with this runner's own git config
        shell: bash
        run: |
          set -euo pipefail
          tar -xzf engine-fixture.tar.gz
          git clone --quiet engine-fixture.git engine-work
          git config --show-origin --get core.autocrlf || echo "core.autocrlf: unset"

      - name: Did this checkout change the bytes?
        shell: bash
        run: |
          set -euo pipefail
          for path in src/cart.ts test/cart.spec.ts .coveragerc; do
            committed="$(git -C engine-work rev-parse "HEAD:$path")"
            on_disk="$(git -C engine-work hash-object --no-filters "$path")"
            if [ "$committed" = "$on_disk" ]; then
              echo "unchanged  $path  $committed"
            else
              echo "MANGLED    $path  blob=$committed disk=$on_disk"
            fi
          done

      - name: Measure with both engines
        shell: bash
        env:
          BASE_SHA: ${{ needs.engines-build-fixture.outputs.base }}
          HEAD_SHA: ${{ needs.engines-build-fixture.outputs.head }}
        run: |
          set -euo pipefail
          bin() { local p="./target/release/$1"; [ -x "$p" ] || p="${p}.exe"; echo "$p"; }
          # stderr carries "N of 7 detectors fired"; a leg where fewer than seven
          # fire is comparing zeros and is caught by the assertion below.
          "$(bin andon-tamper-probe)" \
            --repo engine-work --base "$BASE_SHA" --head "$HEAD_SHA" \
            --out "tamper-${{ matrix.os }}.json" 2> tamper.log
          cat tamper.log
          grep -q "7 of 7 detectors fired" tamper.log || {
            echo "::error::the matrix specimen no longer fires all seven detectors on ${{ matrix.os }};" \
                 "a digest comparison over results that are all false proves nothing" >&2
            exit 1
          }
          "$(bin andon-clones-probe)" \
            --repo engine-work --base "$BASE_SHA" --head "$HEAD_SHA" \
            --out "clones-${{ matrix.os }}.json"

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: engine-records-${{ matrix.os }}
          path: |
            tamper-${{ matrix.os }}.json
            clones-${{ matrix.os }}.json
          retention-days: 7

  engines-verify:
    name: engine digests must be byte-identical
    needs: [engines-build-fixture, engines-measure]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2

      - name: Build the binaries
        run: |
          cargo build --release -p andon-engine-clones -p andon-engine-tamper
          cargo build --release -p andon-ledger-min

      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          path: legs

      - name: Recompute as the verifier
        env:
          BASE_SHA: ${{ needs.engines-build-fixture.outputs.base }}
          HEAD_SHA: ${{ needs.engines-build-fixture.outputs.head }}
        run: |
          set -euo pipefail
          tar -xzf legs/engine-fixture/engine-fixture.tar.gz
          git clone --quiet engine-fixture.git verifier-engine-work
          ./target/release/andon-tamper-probe \
            --repo verifier-engine-work --base "$BASE_SHA" --head "$HEAD_SHA" \
            --out tamper-verifier.json
          ./target/release/andon-clones-probe \
            --repo verifier-engine-work --base "$BASE_SHA" --head "$HEAD_SHA" \
            --out clones-verifier.json

      # `compare-records` is the spike's, unchanged, and reads a
      # `MeasurementRecord` — which is why the probes emit one and why no engine
      # crate depends on `andon-ledger-min`.
      #
      # `--expect-results` is an exact count, and it is the assertion that makes
      # a green run mean something: fourteen tamper results (seven flags, seven
      # magnitudes) and nine clone results (four change-scoped, five
      # file-scoped, one per measured file). Four legs that each measured
      # nothing agree perfectly about nothing, and every digest row would be
      # vacuously equal without this.
      #
      # The nine is the count for THIS specimen — five of its seven changed
      # paths are files a grammar reads. Changing the specimen changes it.
      - name: Tamper digests across four legs
        run: |
          set -euo pipefail
          ./target/release/andon-spike compare-records \
            --leg linux=legs/engine-records-ubuntu-latest/tamper-ubuntu-latest.json \
            --leg macos=legs/engine-records-macos-latest/tamper-macos-latest.json \
            --leg windows=legs/engine-records-windows-latest/tamper-windows-latest.json \
            --leg verifier=tamper-verifier.json \
            --expect-results 14

      - name: Clone digests across four legs
        run: |
          set -euo pipefail
          ./target/release/andon-spike compare-records \
            --leg linux=legs/engine-records-ubuntu-latest/clones-ubuntu-latest.json \
            --leg macos=legs/engine-records-macos-latest/clones-macos-latest.json \
            --leg windows=legs/engine-records-windows-latest/clones-windows-latest.json \
            --leg verifier=clones-verifier.json \
            --expect-results 9
```

### Note for whoever applies this

If P2's join has already landed and added an `engines-*` job family of its own,
rename this one's three jobs to `p3-engines-*` rather than merging them. The
fixtures are different and one job building both would couple two phases'
specimens into one failure.

---

## Patch 2 — `.andon.toml`, `[self_measure].excluded_paths`

`.andon.toml` is P0-owned and not in P3's shared-files row, so this is a patch
rather than an edit.

**The problem it fixes.** Andon measures Andon from P5b, and the corpus is full
of deliberate tamper specimens — deleted tests, suppression sweeps, unparseable
files. `excluded_paths` already names `fixtures/gamed/**` and
`fixtures/adversarial/**` for exactly that reason. P3 adds two directories it
does not cover: the should-pass corpus (which contains suppressions, deleted
tests, and loosened configs *by design*, since that is what makes it a
false-positive corpus) and the matrix specimen (which fires all seven
detectors on purpose). Left out, Andon's own dogfood run reports its own
fixtures as tampering — PREMORTEM S3's dogfood circularity, in its most literal
form.

```diff
 excluded_paths = [
     "fixtures/gamed/**",
     "fixtures/adversarial/**",
+    # The should-pass corpus is legitimate-looking changes that must NOT fire —
+    # which means it is full of suppressions, deleted tests, and loosened
+    # configs on purpose. Measuring it would report the false-positive corpus as
+    # a true positive (PREMORTEM S3).
+    "fixtures/honest/corpus/**",
+    # The cross-OS matrix specimen fires all seven detectors by construction.
+    "fixtures/matrix/**",
     "crates/andon-registry-lint/tests/fixtures/**",
 ]
```

`exclusion_drift_signal = true` is already set, so this widening is itself
reported rather than silent — which is the point of that flag, and the reason
this is a patch to review rather than a line to slip in.

---

## Verification after applying

```
gh workflow run spike-matrix.yml --ref main
```

Green means: three OS legs and one verifier produced byte-identical per-result
digests over 14 tamper results and 9 clone results, on a specimen where all
seven detectors fired.

Then confirm the registry budget across the merged wave — P3 spends 5 of the 24
claim tuples (1 clones, 4 tamper) against an allocation of 7, and its expiries
occupy one slot each in 2027-03, -05, -07, -08 and -11:

```
cargo run -p andon-registry-lint -- --policy .andon.toml registry/
```
