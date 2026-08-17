#!/usr/bin/env bash
# Bootstrap self-measure placeholder.
#
# Andon must pass its own measurement, and cannot yet: there is no attested
# release binary to measure with and no measurement CLI to run. This script
# stands in until dogfood switch-on at P5b.
#
# It is loud on purpose. A placeholder that quietly exits zero puts a green
# check in the CI log for work that did not happen, and the next person to read
# that log has no way to tell the difference. See docs/self-measure.md.
set -euo pipefail

cat <<'BANNER'
================================================================================
  SELF-MEASURE: BOOTSTRAP PLACEHOLDER — NO MEASUREMENT WAS PERFORMED
================================================================================
  Rule:       self-measurement runs the last attested release binary.
  Status:     no attested release exists yet.
  Override:   bootstrap-no-attested-release (self-expiring — it stops being
              available the moment the first attested release ships).
  Activates:  P5b, dogfood switch-on. The gate then asserts non-empty results
              and the expected engine count, not merely a zero exit.
  Contract:   docs/self-measure.md
================================================================================
BANNER

# Guard the exception against outliving its condition. Once the measurement CLI
# exists, this placeholder must be replaced rather than left to pass silently.
if [ -d "crates/andon-cli" ]; then
    echo "ERROR: crates/andon-cli exists, so the bootstrap placeholder is obsolete." >&2
    echo "       Replace scripts/self-measure.sh with a real measurement (P5b)." >&2
    exit 1
fi

echo "self-measure: placeholder acknowledged; no measurement claimed."
