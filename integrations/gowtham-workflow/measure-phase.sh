#!/bin/sh
# The gowtham-workflow post-code hook: measure one phase diff with Andon and
# file the record in the repository's ledger (PLAN P9b).
#
# Usage:
#   measure-phase.sh <repo> <base-sha> <head-sha> [model-id] [extra andon flags...]
#
#   <repo>      the phase worktree (any path inside it)
#   <base-sha>  the commit the phase branched from (the merge target's tip)
#   <head-sha>  the verified phase tip — the SHA the reviewers rule on,
#               never a branch name (the P8 merge incident: the pointer you
#               verify must be the pointer you use)
#   [model-id]  the orchestrator's model identifier, recorded as a ledger
#               dimension when known
#   extras      passed through to `andon measure` — Andon measuring Andon
#               adds --self-measure
#
# The exit code is Andon's own contract, so a gate can key on it directly:
#   0 pass/advise · 2 block · 3 escalate to human · 1 the tool or the read
#   failed (including changed paths nobody could read — a change nobody read
#   does not pass a gate).
#
# `--source agent-initiated`, not `hook`: InvocationSource::Hook's contract is
# "a harness hook fired", and this script is run by the workflow orchestrator
# (an agent following its playbook), not by a harness hook. Recording `hook`
# here would be a claim the mechanism does not prove.
#
# `--record` appends the record to refs/notes/andon-measure — the same ledger
# the FP-budget window reads (`andon ledger fp-window`), so every gated phase
# diff becomes part of the S6 evidence base.

set -eu

if [ "$#" -lt 3 ]; then
  echo "usage: measure-phase.sh <repo> <base-sha> <head-sha> [model-id] [extra andon flags...]" >&2
  exit 1
fi

repo="$1"; base="$2"; head="$3"
shift 3

model_args=""
if [ "$#" -ge 1 ]; then
  case "$1" in
    --*) ;; # no model given; the next argument is already an andon flag
    *) model_args="--model $1"; shift ;;
  esac
fi

# The verdict must come from exactly the SHAs the reviewers will rule on.
git -C "$repo" rev-parse --verify --quiet "$base^{commit}" > /dev/null ||
  { echo "measure-phase: base '$base' is not a commit in $repo" >&2; exit 1; }
git -C "$repo" rev-parse --verify --quiet "$head^{commit}" > /dev/null ||
  { echo "measure-phase: head '$head' is not a commit in $repo" >&2; exit 1; }

# shellcheck disable=SC2086 # model_args is deliberately word-split
exec andon measure \
  --repo "$repo" \
  --base "$base" \
  --head "$head" \
  --source agent-initiated \
  --harness claude-code \
  $model_args \
  --record \
  "$@"
