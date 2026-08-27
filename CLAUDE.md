# Andon

Rust workspace. Members are two globs — `crates/andon-*`, `crates/engines/*` — and the root `Cargo.toml` member list is closed: name a new crate's directory to match a glob, never edit it.

Gates (mirror `.github/workflows/ci.yml`): `cargo fmt --all --check` · `cargo clippy --workspace --all-targets -- -D warnings` · `cargo test --workspace --no-fail-fast` · `cargo deny check licenses bans sources`

Docs: `README.md`, `docs/trust-boundary.md`, `docs/self-measure.md`, `docs/sandbox.md`, `docs/ci-recipe.md`, `schemas/README.md`. Contributing: `CONTRIBUTING.md` · registry changes: `registry/REVIEW-POLICY.md` · detector evasions: `SECURITY.md`, privately, never as an issue.

Internal docs — plans, vision, ledgers, phase reviews — live in a private repository, never here.
