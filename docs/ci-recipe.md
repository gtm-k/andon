# The generic CI recipe

`andon init --ci` prints this document, so the recipe in your terminal is the
one committed here.

Andon's exit code carries the verdict, which is what makes a CI step out of
it with no wrapper:

| exit | meaning | typical CI handling |
|---|---|---|
| 0 | `pass` or `advise` — the line keeps moving | step succeeds |
| 2 | `block` — the line stops | step fails, report in the log |
| 3 | `escalate_to_human` — the loop is over | step fails, a person looks |
| 1 | the tool could not do its job, or a changed path could not be read | step fails as an error |

The step, on any CI system:

```sh
# Fetch enough history for a base to exist. A depth-1 checkout has no parent
# to compare against, and Andon refuses to invent one (it will tell you to
# run exactly this):
git fetch --unshallow 2>/dev/null || true

# Measure the change this build is about. --source hook records that the
# gate, not a person, asked; --record files the measurement in
# refs/notes/andon-measure so the ledger keeps it; --no-fallback refuses to
# measure the last merged change when the range resolves to nothing, which
# in CI means a misconfigured checkout you want to hear about:
andon measure --base "$BASE_REF" --head "$HEAD_REF" \
  --source hook --record --no-fallback
```

- **`$BASE_REF` / `$HEAD_REF`** come from your CI's pull-request context (on
  GitHub Actions, `github.event.pull_request.base.sha` and
  `.head.sha` — check out the head SHA itself, not the synthetic merge ref).
  For push builds, omit `--base` and `--head` and Andon resolves the working
  change the way it does locally.
- **Advisory instead of blocking:** append `--exit-zero` and the report still
  prints while the step always succeeds.
- **The agent-facing payload** (bounded JSON instead of the human report):
  append `--profile agent-mode`.
- **Pushing the notes:** `--record` writes to the local clone; add
  `git push origin refs/notes/andon-measure` after it if the ledger should
  live on the remote. The full notes machinery (merge, retry, squash
  migration) ships with the ledger phase (PLAN P8).

This recipe is measurement only — the self-report lane. The verifying lane
(recompute in CI, compare digests, attest) is the `attest` composite action,
which hardens in PLAN P9; until then `andon attest-stub` shows its shape.
