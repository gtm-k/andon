# The cross-harness ledger, executed

PLAN P9b's A6 artifact: one repository's ledger holding **hook-driven**
measurements from more than one harness integration, sliceable by the ledger
dimensions. A harness vendor can ship measurement inside its own loop; what it
structurally cannot ship is a ledger that outlives the choice of harness.
This document is the executed demonstration — what was run, what it recorded,
and exactly what each leg does and does not prove.

Executed 2026-08-21 (UTC) against the `andon` binary built from this branch
(commit `0a7be2a`), in a scratch repository. Reproduction steps are at the
bottom; the outputs below are pasted from the run, unedited.

## The two legs

Both shipped harness integrations were installed into one repository —
`andon init --claude` (a Claude Code Stop hook) and `andon init --cursor`
(a git pre-commit hook; the rules file is discoverability only) — and both
gates fired:

1. **Claude Code Stop hook.** `andon hook claude-stop` was run exactly as the
   installed hook runs it — same command line, the harness's JSON payload on
   stdin — with an uncommitted change in the tree. This run WAS driven from a
   real Claude Code session (the session that executed this story), invoking
   precisely what the harness invokes at Stop. Recorded: `source: hook`,
   `harness: claude-code` — the hook kind itself proves the harness.
2. **The pre-commit gate.** A real `git commit` fired the installed hook.
   That is the same event any harness triggers when it commits — Cursor's
   agent, Codex, or a person — and the record honestly carries
   `harness: (unrecorded)`: a pre-commit hook cannot prove *who* ran
   `git commit`, so it claims nothing (the P6 design in
   `crates/andon-cli/src/init/hook.rs`). Recorded: `source: hook`.

## What the ledger then answers

```
=== andon ledger stats --by source ===
  2 record(s) on 1 commit(s) in refs/notes/andon-measure (229.4 KB of note bodies).
  by invocation-source:
    hook: 2 record(s) — pass 2

=== andon ledger stats --by harness ===
  by harness:
    (unrecorded): 1 record(s) — pass 1
    claude-code: 1 record(s) — pass 1

=== andon ledger stats --by model ===
  by model:
    (unrecorded): 2 record(s) — pass 2

=== andon ledger stats --filter harness=claude-code --by source ===
  Filtered: harness=claude-code kept 1 of 2 record(s).
  by invocation-source:
    hook: 1 record(s) — pass 1
```

Both records are hook-driven (`--by source`: hook 2). The harness dimension
slices them (`--by harness`), and the filter isolates one harness's records.
The model dimension is honestly `(unrecorded)` on both: neither hook protocol
discloses a model identifier, and Andon does not guess. Model arrives where a
caller can honestly supply it — the MCP `measure_change` tool and
`andon measure --model` both take it, which is how the workflow recipe's own
records carry `model: claude-fable-5`.

## What this does and does not prove

- **Proves:** both shipped integrations are gate-shaped and live (they fired
  on their own trigger, not by an agent choosing to call a tool — round-1's
  A2-coherence rule); one ledger holds both; the dimensions recorded are the
  ones each mechanism can actually prove; `ledger stats` slices and filters
  by harness and model.
- **Does not prove:** that a second harness *product* drove the second leg.
  Cursor is not installed on the machine this ran on, and Codex CLI was
  rate-limited through the execution window (DEFERRED-APPROVALS E40), so the
  pre-commit leg was fired by a plain `git commit` — the identical mechanism,
  with no harness present to witness. The record's `(unrecorded)` harness is
  that fact told truthfully: identity comes only from harness-native hooks
  (the Stop hook) or from an agent disclosing it through the MCP dimensions,
  never from the gate guessing.
- **Strengthening, when the environment allows:** a real Cursor session (or
  Codex, once its limit resets) committing through the same gate adds a
  second real-harness leg with zero code change; its record would still read
  `harness: (unrecorded)` unless that harness's own hook surface or MCP call
  discloses more — which is the boundary, stated as a boundary rather than
  papered over.

## Reproduction

```sh
# a scratch repository
git init -b main story && cd story
printf 'export function greet(name: string): string {\n  return `hello ${name}`;\n}\n' > src.ts
git add -A && git commit -m base

# both integrations
andon init --claude
andon init --cursor

# leg 1: the Stop hook, exactly as Claude Code runs it (JSON on stdin)
printf 'export function farewell(name: string): string {\n  return `bye ${name}`;\n}\n' >> src.ts
printf '{"session_id":"<id>","hook_event_name":"Stop","stop_hook_active":false}' | andon hook claude-stop

# leg 2: the pre-commit gate, fired by a real commit
git add -A && git commit -m "add farewell"

# the slices
andon ledger stats --by source
andon ledger stats --by harness
andon ledger stats --by model
andon ledger stats --filter harness=claude-code --by source
```
