#!/usr/bin/env bash
# Regression test for the ledger line at the end of `scripts/self-measure.sh`.
#
# WHAT WENT WRONG, AND WHY A TEST EXISTS FOR IT
#
# The line read the note with `git notes show ... | head -c 400 || echo "(no note
# is recorded against HEAD)"`. Under `pipefail`, `head` closes the pipe at the
# bound; once the note is bigger than the pipe buffer the still-writing `git
# notes show` takes SIGPIPE and dies 141, the pipeline reports 141, and the `||`
# branch fires. The log then showed 400 bytes of a real note with "(no note is
# recorded against HEAD)" spliced onto the end of the truncated line — a false
# statement about the ledger, printed by the script whose only job is to show
# that the run was filed.
#
# A record is one canonical JSON line carrying a whole MeasurementRecord, so a
# real self-measurement note reaches that size. The huge case below is the shape
# a real note has, not a contrivance chosen to break the old code.
#
# HOW IT TESTS THE REAL SCRIPT AND NOT A COPY OF THE PATTERN
#
# `scripts/self-measure.sh` cds to its own parent directory, so it cannot be
# pointed at a sandbox from outside. Each case therefore copies the real script
# into a sandbox repository AT RUN TIME. An edit to the real script is what this
# test measures: reintroduce the old pipeline there and these cases fail.
#
# The expensive steps are stubbed — a `cargo` on PATH that does nothing, a
# `rustc` on PATH that names a fixed host triple, and an `andon` under
# `target/<that triple>/release/` that prints a line — because what is under
# test is the ledger reporting, not the build or the measurement. The script
# builds with `--target` and reads the binary from the per-target directory
# (ruling E72), so the sandbox lays the stub where the real script looks.
# Nothing else is replaced; the script runs top to bottom and the git notes call
# is the real one.
#
# NO PIPELINES IN THE ASSERTIONS, ON PURPOSE
#
# Matching is bash pattern matching rather than `grep -q`, because `printf | grep
# -q` on a 190 KB haystack is the very construct under test: `grep -q` exits at
# the first match and the writer takes SIGPIPE.
set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$PWD"
SCRIPT_UNDER_TEST="$REPO_ROOT/scripts/self-measure.sh"

if [ ! -f "$SCRIPT_UNDER_TEST" ]; then
    echo "ERROR: $SCRIPT_UNDER_TEST is missing; there is nothing to test." >&2
    exit 1
fi

FAILURES=0
SANDBOXES=()
cleanup() {
    local sandbox
    for sandbox in ${SANDBOXES+"${SANDBOXES[@]}"}; do
        rm -rf "$sandbox"
    done
}
trap cleanup EXIT

pass() { printf '    ok    %s\n' "$1"; }
fail() {
    printf '    FAIL  %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
}

# `[[ $hay == *$needle* ]]` — no pipe, no SIGPIPE, no subprocess.
assert_contains() {
    local label="$1" hay="$2" needle="$3"
    if [[ "$hay" == *"$needle"* ]]; then
        pass "$label"
    else
        fail "$label — expected to find: $needle"
    fi
}

assert_lacks() {
    local label="$1" hay="$2" needle="$3"
    if [[ "$hay" == *"$needle"* ]]; then
        fail "$label — should NOT be present but was: $needle"
    else
        pass "$label"
    fi
}

assert_equals() {
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then
        pass "$label"
    else
        fail "$label — expected [$expected], got [$actual]"
    fi
}

# A sandbox repository with the real script in it and the expensive steps stubbed.
# The host triple the stub `rustc` reports; the script derives the binary path
# from it, so the stub binary lives under the same name.
STUB_TRIPLE="x86_64-stub-none"

build_sandbox() {
    local sandbox="$1"
    mkdir -p "$sandbox/scripts" "$sandbox/target/$STUB_TRIPLE/release" "$sandbox/stub-bin"

    cp "$SCRIPT_UNDER_TEST" "$sandbox/scripts/self-measure.sh"

    # `cargo build --release -p andon-cli --target <triple>` — not what is under test.
    cat > "$sandbox/stub-bin/cargo" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB

    # `rustc -vV`, which the script reads the host triple from. Only the line
    # the script's `sed` selects has to be real.
    cat > "$sandbox/stub-bin/rustc" <<STUB
#!/usr/bin/env bash
printf 'rustc 0.0.0-stub\nhost: %s\n' "$STUB_TRIPLE"
STUB

    # The measurement. It does not write the note: each case installs the note it
    # wants first, so the three states are set up rather than hoped for.
    cat > "$sandbox/target/$STUB_TRIPLE/release/andon" <<'STUB'
#!/usr/bin/env bash
echo "stub andon invoked: $*"
STUB

    chmod +x "$sandbox/stub-bin/cargo" "$sandbox/stub-bin/rustc" \
        "$sandbox/target/$STUB_TRIPLE/release/andon"

    git -c init.defaultBranch=main init --quiet "$sandbox"

    # The identity for every git write in the sandbox, in the sandbox's own
    # config rather than inline on the seed commit: `git notes add` writes a
    # commit object on the notes ref exactly as `commit` does, and a CI runner
    # has an identity for neither — the fatal was "empty ident name", from the
    # first notes call, on a runner whose passwd entry has no name to
    # auto-detect. Repo-local config covers every case's writes and touches
    # nothing outside this throwaway repository.
    git -C "$sandbox" config user.name "andon test"
    git -C "$sandbox" config user.email test@andon.invalid
    git -C "$sandbox" config commit.gpgsign false

    echo "seed" > "$sandbox/seed.txt"
    git -C "$sandbox" add seed.txt
    git -C "$sandbox" commit --quiet -m "seed"
}

# Runs the real script in the sandbox. Sets RUN_OUT and RUN_STATUS.
run_script() {
    local sandbox="$1"
    if RUN_OUT="$(PATH="$sandbox/stub-bin:$PATH" bash "$sandbox/scripts/self-measure.sh" 2>&1)"; then
        RUN_STATUS=0
    else
        RUN_STATUS=$?
    fi
}

new_sandbox() {
    local sandbox
    sandbox="$(mktemp -d)"
    SANDBOXES+=("$sandbox")
    build_sandbox "$sandbox"
    printf '%s' "$sandbox"
}

# What the script itself will compute from the note: command substitution strips
# the trailing newline, so this is derived the same way rather than restated.
note_as_the_script_sees_it() {
    git -C "$1" notes --ref=andon-measure show HEAD
}

echo "self-measure ledger reporting"

# ---------------------------------------------------------------------------
# 1. A note far larger than the pipe buffer: the case that printed the false
#    "(no note is recorded)" beneath the note it had just printed.
# ---------------------------------------------------------------------------
echo "  case: a note larger than the pipe buffer is truncated and SAID to be"
sandbox="$(new_sandbox)"
{
    printf 'LEDGER-HEAD-MARKER'
    # One line, because a record is one canonical JSON line. ~190 KB, comfortably
    # past a 64 KB pipe buffer, which is where the old code started lying.
    # shellcheck disable=SC2046  # word splitting is how the repeat count is fed
    printf '%.0s{"engine":"static-metrics","file":"crates/andon-core/src/lib.rs","finding":"none"},' $(seq 1 2000)
    printf 'LEDGER-TAIL-MARKER\n'
} > "$sandbox/huge-note.txt"
git -C "$sandbox" notes --ref=andon-measure add -F "$sandbox/huge-note.txt" HEAD
huge_note="$(note_as_the_script_sees_it "$sandbox")"
echo "        note is ${#huge_note} characters"

run_script "$sandbox"
assert_equals  "the script exits 0"                     "$RUN_STATUS" "0"
assert_contains "the start of the note is printed"      "$RUN_OUT" "LEDGER-HEAD-MARKER"
assert_lacks   "no false claim that the note is absent" "$RUN_OUT" "no note is recorded"
assert_contains "truncation is announced"               "$RUN_OUT" "truncated for display at"
assert_contains "the announcement states the real size" "$RUN_OUT" "of ${#huge_note} characters"
assert_lacks   "it really did truncate"                 "$RUN_OUT" "LEDGER-TAIL-MARKER"

# ---------------------------------------------------------------------------
# 2. A note over the display bound but under the pipe buffer. The old code did
#    not lie here — it truncated in silence, which is the same wrong impression
#    of the record told more quietly.
# ---------------------------------------------------------------------------
echo "  case: a note over the display bound but under the pipe buffer"
sandbox="$(new_sandbox)"
{
    printf 'LEDGER-HEAD-MARKER\n'
    printf 'binary: target/release/andon\noverride: bootstrap-no-attested-release\n'
    # shellcheck disable=SC2046
    printf 'engine-%02d: measured, findings recorded\n' $(seq 1 20)
    printf 'LEDGER-TAIL-MARKER\n'
} > "$sandbox/mid-note.txt"
git -C "$sandbox" notes --ref=andon-measure add -F "$sandbox/mid-note.txt" HEAD
mid_note="$(note_as_the_script_sees_it "$sandbox")"
echo "        note is ${#mid_note} characters"

run_script "$sandbox"
assert_equals  "the script exits 0"                     "$RUN_STATUS" "0"
assert_contains "the start of the note is printed"      "$RUN_OUT" "LEDGER-HEAD-MARKER"
assert_lacks   "no false claim that the note is absent" "$RUN_OUT" "no note is recorded"
assert_contains "truncation is announced"               "$RUN_OUT" "truncated for display at"
assert_lacks   "it really did truncate"                 "$RUN_OUT" "LEDGER-TAIL-MARKER"

# ---------------------------------------------------------------------------
# 3. A note that fits: printed whole, with nothing said about truncation.
# ---------------------------------------------------------------------------
echo "  case: a note that fits is printed whole"
sandbox="$(new_sandbox)"
printf 'LEDGER-HEAD-MARKER\nrecorded one line\nLEDGER-TAIL-MARKER\n' > "$sandbox/short-note.txt"
git -C "$sandbox" notes --ref=andon-measure add -F "$sandbox/short-note.txt" HEAD
short_note="$(note_as_the_script_sees_it "$sandbox")"
echo "        note is ${#short_note} characters"

run_script "$sandbox"
assert_equals  "the script exits 0"                     "$RUN_STATUS" "0"
assert_contains "the start of the note is printed"      "$RUN_OUT" "LEDGER-HEAD-MARKER"
assert_contains "the END of the note is printed too"    "$RUN_OUT" "LEDGER-TAIL-MARKER"
assert_lacks   "nothing is said about truncation"       "$RUN_OUT" "truncated for display at"
assert_lacks   "no false claim that the note is absent" "$RUN_OUT" "no note is recorded"

# ---------------------------------------------------------------------------
# 4. Genuinely no note: the one state in which the absence message is true.
# ---------------------------------------------------------------------------
echo "  case: a genuinely absent note says so, and only then"
sandbox="$(new_sandbox)"
run_script "$sandbox"
assert_equals  "the script exits 0"                  "$RUN_STATUS" "0"
assert_contains "absence is reported"                "$RUN_OUT" "no note is recorded against HEAD"
assert_lacks   "nothing is said about truncation"    "$RUN_OUT" "truncated for display at"
assert_lacks   "no note content is invented"         "$RUN_OUT" "LEDGER-HEAD-MARKER"

echo
if [ "$FAILURES" -ne 0 ]; then
    echo "$FAILURES assertion(s) failed." >&2
    exit 1
fi
echo "all assertions passed."
