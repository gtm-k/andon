#!/usr/bin/env bash
# The ten-minute stranger path (PLAN P10a-adoption; PREMORTEM A1/A3).
#
# Three copy-paste blocks and nothing else: install; a fresh repository with the
# gate-shaped hook and one source file in flight, measured; that change committed,
# measured again, and the claim behind one number read. A stranger who pastes these
# three blocks has, by the end of the second one, seen the thing this tool does that a
# linter does not — a verdict that carries its evidence and says where its trust ends.
#
# THE BLOCKS ARE PRINTED AND EXECUTED FROM THE SAME STRING
#
# Each block is defined once, below, as text. The driver prints that text exactly as a
# reader would paste it, then `eval`s the same variable. So the transcript this script
# writes is proof that the pasted blocks work — not a description that resembles them,
# which is the version that drifts.
#
# LOCAL VALIDATION, BEFORE THE FLIP
#
# The install line in block 1 resolves only once the repository is public and a release
# exists (P10b). Until then:
#
#     ANDON_BIN=/path/to/andon bash scripts/stranger-path.sh
#
# replaces block 1 with a PATH prepend of that binary's directory (the `andon-mcp` the
# hook registers must sit beside it). The real block 1 is still printed, marked as the
# one a stranger runs, and the driver ASSERTS that the `andon` it then executes resolves
# inside that directory — a stale `andon` earlier on PATH would otherwise validate the
# wrong binary and pass. Identity, not just a version string.
#
# Set STRANGER_KEEP=1 to leave the temporary repository behind for inspection.
#
# Exit status: 0 only when every block ran and every assertion held. A failing block
# prints its output and its number; a failing assertion says what it looked for.
set -Eeuo pipefail

# ---------------------------------------------------------------------------------------
# The three blocks. Edit these; nothing below restates them.
# ---------------------------------------------------------------------------------------

# Block 1 — install. `andon` is the CLI and `andon-mcp` is the MCP server the hook
# registers; both installers put their binary in ~/.cargo/bin. The URLs resolve at flip.
BLOCK1=$(cat <<'BLOCK'
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/gtm-k/andon/releases/latest/download/andon-cli-installer.sh | sh
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/gtm-k/andon/releases/latest/download/andon-mcp-installer.sh | sh
export PATH="$HOME/.cargo/bin:$PATH"
andon --version
BLOCK
)

# Block 2 — a fresh repository, the hook, and one source file in flight. The hook goes in
# as its own commit so the first measurement is of the code, not of the hook's config.
BLOCK2=$(cat <<'BLOCK'
mkdir andon-stranger && cd andon-stranger && git init -q -b main
git config user.name stranger && git config user.email stranger@example.com
andon init --claude
git add -A && git commit -q -m "andon: gate-shaped hook, removable"
mkdir src && cat > src/duration.ts <<'EOF'
/** Parse a duration like "10s", "5m", or "2h" into seconds; null when it is not one. */
export function parseDuration(input: string): number | null {
  const text = input.trim();
  if (text.length < 2) {
    return null;
  }
  const unit = text.slice(-1);
  const amount = Number(text.slice(0, -1));
  if (!Number.isInteger(amount) || amount < 0) {
    return null;
  }
  switch (unit) {
    case "s":
      return amount;
    case "m":
      return amount * 60;
    case "h":
      return amount * 3600;
    default:
      return null;
  }
}
EOF
andon measure
BLOCK
)

# Block 3 — commit the change, measure the clean tree, and read the claim behind one
# number. A clean tree measures the last merged change and says so, rather than printing
# nothing or reprinting stale numbers as if they were about work in flight.
BLOCK3=$(cat <<'BLOCK'
git add -A && git commit -q -m "parse durations"
andon measure --full
andon explain tamper.test-removal
BLOCK
)

# ---------------------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------------------

WORK="$(mktemp -d)"
CURRENT=""
CURRENT_OUT=""

on_err() {
    local status=$?
    if [ -n "$CURRENT_OUT" ] && [ -f "$CURRENT_OUT" ]; then
        cat "$CURRENT_OUT"
    fi
    echo "stranger-path: block ${CURRENT:-preflight} failed (exit ${status})" >&2
}
on_exit() {
    if [ "${STRANGER_KEEP:-0}" = "1" ]; then
        echo "stranger-path: kept ${WORK}"
    else
        cd /
        rm -rf "$WORK"
    fi
}
trap on_err ERR
trap on_exit EXIT

# Prints the block as pasted, executes the same string, then prints what it produced.
# Output is captured through a redirection, not a pipe: a pipeline would run the block
# in a subshell and lose the `cd` block 2 performs, which block 3 depends on.
run_block() {
    local n="$1" title="$2" block="$3"
    CURRENT="$n"
    CURRENT_OUT="$WORK/block-$n.out"
    printf '\n==== Block %s: %s ====\n' "$n" "$title"
    printf '%s\n' "$block"
    printf -- '---- output ----\n'
    eval "$block" >"$CURRENT_OUT" 2>&1
    cat "$CURRENT_OUT"
}

# expect FILE FIXED-STRING WHAT-IT-PROVES
expect() {
    if grep -qF -- "$2" "$1"; then
        printf '  ok    %s\n' "$3"
    else
        printf '  FAIL  %s -- expected the output to contain: %s\n' "$3" "$2" >&2
        exit 1
    fi
}

# Both directories resolved to physical absolute paths before comparing, so a Windows
# `C:/...` and its `/c/...` spelling compare equal.
physical_dir() {
    (cd "$1" && pwd -P)
}

echo "==== stranger path ===="
echo "when      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "host      $(uname -s) $(uname -m)"
echo "git       $(git --version)"
if [ -n "${ANDON_BIN:-}" ]; then
    if [ ! -x "$ANDON_BIN" ]; then
        echo "stranger-path: ANDON_BIN=${ANDON_BIN} is not an executable file" >&2
        exit 1
    fi
    BIN_DIR="$(physical_dir "$(dirname "$ANDON_BIN")")"
    export PATH="$BIN_DIR:$PATH"
    RESOLVED="$(command -v andon || true)"
    if [ -z "$RESOLVED" ] || [ "$(physical_dir "$(dirname "$RESOLVED")")" != "$BIN_DIR" ]; then
        echo "stranger-path: 'andon' resolves to '${RESOLVED:-nothing}', not inside ${BIN_DIR}" >&2
        exit 1
    fi
    echo "mode      local validation: ANDON_BIN=${ANDON_BIN}"
    echo "andon     ${RESOLVED} ($(andon --version))"
    echo "andon-mcp $(command -v andon-mcp || echo 'NOT on PATH -- the hook block 2 installs will name it')"
    BLOCK1_RUN=$(cat <<BLOCK
export PATH="${BIN_DIR}:\$PATH"
andon --version
BLOCK
)
    printf '\n==== Block 1 as a stranger runs it (not executed here: resolves at flip) ====\n'
    printf '%s\n' "$BLOCK1"
    run_block 1 "install (local validation: PATH prepend of ANDON_BIN)" "$BLOCK1_RUN"
else
    echo "mode      download (block 1 fetches the latest release)"
    run_block 1 "install" "$BLOCK1"
fi
expect "$CURRENT_OUT" "andon " "block 1: andon runs and reports a version"

cd "$WORK"
run_block 2 "a fresh repository, the hook, one source file in flight" "$BLOCK2"
expect "$CURRENT_OUT" "Claude Code integration installed." "block 2: the gate-shaped hook installed"
expect "$CURRENT_OUT" "file(s) changed"                    "block 2: a non-empty change was read (A1)"
expect "$CURRENT_OUT" "result(s)"                          "block 2: results were produced with zero configuration"
expect "$CURRENT_OUT" "outside the trust boundary by construction" \
    "block 2: differentiator -- the verdict states where its trust ends (A3)"
expect "$CURRENT_OUT" "stands on a claim you can read" \
    "block 2: differentiator -- every number carries its evidence (A3)"

run_block 3 "commit, measure the clean tree, explain one number" "$BLOCK3"
expect "$CURRENT_OUT" "last merged change"     "block 3: a clean tree measures the last merged change and says so (A1)"
expect "$CURRENT_OUT" "src/duration.ts"        "block 3: the source file was measured"
expect "$CURRENT_OUT" "evidence  tier"         "block 3: a number is printed with its evidence tier"
expect "$CURRENT_OUT" "does not predict"       "block 3: every number says what it does not predict"
expect "$CURRENT_OUT" "What this number does NOT tell you" \
    "block 3: the claim behind a tamper detector, and its limits, are readable"

printf '\n==== done in %ss: three blocks, every assertion held ====\n' "$SECONDS"
echo "undo the hook with: andon init --claude --remove"
