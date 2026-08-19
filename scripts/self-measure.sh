#!/usr/bin/env bash
# Andon measures Andon.
#
# This replaces the P0 bootstrap placeholder, which announced that no
# measurement had been performed and failed the moment `crates/andon-cli`
# existed. That tripwire has now fired and this is what it was waiting for.
#
# WHAT THIS SCRIPT IS, AND WHAT IT IS NOT
#
# It is the driver: it builds the binary, runs one measurement of this
# repository against itself, and writes three artefacts a reader can go and
# look at. It is NOT the gate. The gate is
# `cargo test -p andon-cli --test dogfood`, where the assertions are typed and
# run on a developer's machine before CI sees them — PLAN P5b requires the gate
# to assert non-empty results and the expected engine count rather than a zero
# exit, and a shell script grepping a JSON payload would be a gate with a defect
# class of its own.
#
# THE BOOTSTRAP EXCEPTION IS IN FORCE, AND IT IS RECORDED
#
# docs/self-measure.md: self-measurement runs the LAST ATTESTED RELEASE binary,
# so that a broken detector cannot bless the change that broke it. No attested
# release exists, so this runs the working tree's own build under the override
# reason `bootstrap-no-attested-release`. The exception is self-expiring: it
# names a condition, and `the_bootstrap_exception_is_still_the_state_of_the_world`
# fails the day that condition stops being true.
#
# The consequence, stated rather than buried: the verdict below is an opinion
# this binary formed about itself. It is printed in full and it does not gate.
set -euo pipefail

cd "$(dirname "$0")/.."

REPORT_TXT="andon-self-measure.txt"
REPORT_HTML="andon-self-measure.html"
REPORT_JSON="andon-self-measure.json"

cat <<'BANNER'
================================================================================
  SELF-MEASURE — Andon measuring Andon
================================================================================
  Rule:       self-measurement runs the last attested release binary.
  Status:     no attested release exists yet.
  Override:   bootstrap-no-attested-release (self-expiring — it stops being
              available the moment the first attested release ships).
  Consequence: the verdict below does not gate. What gates is the assertion
              suite: `cargo test -p andon-cli --test dogfood`.
  Contract:   docs/self-measure.md
================================================================================
BANNER

cargo build --release -p andon-cli

ANDON="target/release/andon"
if [ ! -x "$ANDON" ] && [ ! -x "${ANDON}.exe" ]; then
    echo "ERROR: ${ANDON} was not built." >&2
    exit 1
fi
[ -x "$ANDON" ] || ANDON="${ANDON}.exe"

# `--self-measure` applies [self_measure] excluded_paths from .andon.toml: the
# adversarial fixtures exist to fire the tamper suite, and measuring them would
# block every build on findings that are the point of the files. The withheld
# paths are named in the report, because an exclusion nobody can see is how a
# dogfood gate stops meaning anything.
#
# `--exit-zero` because the verdict does not gate here. Without it a blocking
# self-verdict would fail this step for the same reason a crash does, and the
# log could not tell the two apart.
#
# `--record` because PLAN P5b's acceptance criterion says the dogfood switch-on
# is a LEDGERED EVENT, and it was not one: the run printed a report, uploaded an
# artefact, and left nothing behind that anybody could query. A note in
# `refs/notes/andon-measure` is the difference between "we think the gate ran"
# and a record attached to the commit it was taken under, carrying which binary
# measured, under which override, and what the policy withheld.
#
# It needs no git identity: `andon_ledger_min::notes` pins its own, precisely
# because a CI runner has none configured.
"$ANDON" measure \
    --repo . \
    --self-measure \
    --source human-cli \
    --harness github-actions \
    --full \
    --exit-zero \
    --record \
    --html "$REPORT_HTML" \
    | tee "$REPORT_TXT"

"$ANDON" measure \
    --repo . \
    --self-measure \
    --source human-cli \
    --harness github-actions \
    --json \
    --exit-zero \
    > "$REPORT_JSON"

echo
echo "report:  $REPORT_TXT"
echo "html:    $REPORT_HTML"
echo "payload: $REPORT_JSON"
echo
# The ledgered event itself, printed so a reader of the CI log can see that the
# run was filed rather than merely reported. `show` rather than `list` because
# the question a reader has is what was recorded against THIS commit.
echo "ledger:"
git notes --ref=andon-measure show HEAD 2>/dev/null | head -c 400 || \
    echo "  (no note is recorded against HEAD)"
echo
echo "The verdict above is reported, not enforced. Run the gate with:"
echo "  cargo test -p andon-cli --test dogfood"
