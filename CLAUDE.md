# Andon

Rust workspace. Members are two globs — `crates/andon-*`, `crates/engines/*` — and the root `Cargo.toml` is P0-owned: name a new crate's directory to match a glob, never edit it.

Gates (mirror `.github/workflows/ci.yml`): `cargo fmt --all --check` · `cargo clippy --workspace --all-targets -- -D warnings` · `cargo test --workspace --no-fail-fast` · `cargo deny check licenses bans sources`

Docs: `README.md`, `docs/trust-boundary.md`, `docs/self-measure.md`, `docs/sandbox.md`, `docs/ci-recipe.md`, `schemas/README.md`.

Internal docs — PLAN, VISION, ledger, phase reviews — go to `Documents\prd\andon`, never this repo.

Layout: still at `Documents\andon` with sibling `andon-wt-*` worktrees; the move to `dev\andon\main` is deferred on named blockers — `prd\andon\MIGRATION-PREREQS.md`, convention in `gowtham-workflow\docs\PROJECT-LAYOUT.md`.
