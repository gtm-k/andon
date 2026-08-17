#!/usr/bin/env bash
#
# Build the perf fixture. The committed entry point for the perf gate.
#
#   ./fixtures/perf/generate.sh                 # build (or reuse) the fixture
#   ./fixtures/perf/generate.sh --print-oids    # print pins for expected.toml
#
# The fixture is ~100,000 files, so it is generated rather than committed, and
# `expected.toml` pins the commit OIDs the generation must produce. Everything
# that feeds a commit OID — content, paths, author, committer, both timestamps —
# is fixed in `series.toml` and in the generator, so the pins hold on every
# machine. If they stop holding, the fixture changed and the perf numbers are no
# longer comparable to the previous run's; that is a ledgered budget decision,
# not a pin to quietly refresh.
#
# Output lands in `.perf-fixture/`, which is git-ignored: a hundred thousand
# generated files must never appear in `git status` of the repository being
# measured.
#
# Deliberately NOT under `target/`. The Rust build cache manages that directory
# and restored a partial copy of the fixture on CI — a `.git` with no refs in it
# — which the generator then tried to reuse. Keeping the fixture outside the
# build tree means no cache has an opinion about it. The generator also verifies
# completeness now rather than trusting that a `.git` directory implies a
# working fixture; both fixes, because either alone would have left the other
# failure mode live.
#
# Re-running is cheap: generation is `git fast-import` and takes seconds.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${ANDON_PERF_FIXTURE:-$root/.perf-fixture}"

# Release mode is not optional. The generator writes tens of megabytes through a
# pipe, and a debug build turns seconds into minutes.
cargo build --release --quiet -p andon-core --example gen_perf_fixture

mkdir -p "$out"
exec "$root/target/release/examples/gen_perf_fixture" "$out" "$@"
