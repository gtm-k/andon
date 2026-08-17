# Engine crates

Engine crates live here, one directory each, matched by the root manifest's
`crates/engines/*` member glob:

| Crate | Phase | Family |
|-------|-------|--------|
| `static-metrics` | P2 | `static` |
| `clones` | P3 | `clones` |
| `tamper` | P3 | `tamper` |
| `process` | P4 | `process` |
| `artifacts` | P4 | `artifacts` |

Adding one is a self-contained act: create `crates/engines/<name>/`, implement
`andon_core::engine::MeasureEngine`, and commit `registry/<name>.toml` declaring
every metric the engine emits together with the claim tuples those metrics cite.
The root `Cargo.toml` does not change (PLAN.md R2-2).

**This file is load-bearing.** A cargo members glob that expands to nothing falls
back to the literal path and fails the build, so `crates/engines/` must never be
empty. Cargo skips non-directory glob matches, so this README keeps the glob
valid until the first engine crate lands.
