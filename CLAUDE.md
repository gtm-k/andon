# Andon

Rust workspace (`gtm-k/andon`). Members are two globs only — `crates/andon-*` and
`crates/engines/*` — and the root `Cargo.toml` is P0-owned: **do not edit it** to add a crate,
name the directory to match a glob instead.

**Gates** (mirror `.github/workflows/ci.yml`; run before committing):
`cargo fmt --all --check` · `cargo clippy --workspace --all-targets -- -D warnings` ·
`cargo test --workspace --no-fail-fast` · `cargo deny check licenses bans sources`

**Canonical docs:** `README.md`, `docs/trust-boundary.md`, `docs/self-measure.md`,
`docs/sandbox.md`, `docs/ci-recipe.md`, `schemas/README.md`.

**Internal docs go to `Documents\prd\andon`** — PLAN, VISION, ledger, phase decisions,
review reports. Never this repo: it holds code, tests, and user-facing docs only.

**Layout:** this repo is at `Documents\andon` with sibling `Documents\andon-wt-*` worktrees —
the pre-convention shape. Migration to `dev\andon\main` + `wt\` is deliberately deferred; the
prereqs andon is waiting on are tracked in `prd\andon\MIGRATION-PREREQS.md`, and the convention
itself is `gowtham-workflow\docs\PROJECT-LAYOUT.md`.
