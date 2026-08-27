# Contributing

Andon is a Rust workspace. This page is the five-minute version: how to build
it, what has to be green before a change is reviewed, and the two rules that are
specific to this project — the corpus rule for detector changes and the review
policy for evidence-registry changes.

## Build and test

`rust-toolchain.toml` pins the toolchain; `rustup` picks it up on first build.

```sh
git clone https://github.com/gtm-k/andon.git
cd andon
cargo build --workspace
cargo test --workspace
```

## The four gates

Every change is held to the same four commands CI runs
(`.github/workflows/ci.yml`). Run them locally before opening a pull request;
a red gate is a red review.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
cargo deny check licenses bans sources
```

`cargo-deny` is a separate install (`cargo install cargo-deny --locked`). CI
pins a specific version and its checksum in `ci.yml`; a local run with a newer
version is fine, a local run that is skipped is not.

Two more checks run in CI and are worth running when they apply:

- **Registry lint** — `cargo run -p andon-registry-lint -- --policy .andon.toml registry/`
  — on any change under `registry/`. See "Registry changes" below.
- **Self-measure** — `bash scripts/self-measure.sh` — Andon measuring its own
  change with the working tree's binary. `docs/self-measure.md` explains the
  bootstrap state it runs in.

## Branches and worktrees

- Never commit on `main`. One branch per change, named for its kind and its
  subject: `fix/<what>`, `feat/<what>`, `test/<what>`, `docs/<what>`.
- A git worktree per branch is how the maintainers work, and is recommended:
  `git worktree add <path> -b fix/<what>` gives each branch its own checkout
  and its own `target/`, so switching branches never invalidates a build.
  Remove the worktree when the branch merges.

## Commits

Read `git log` before writing one. The subject says what changed, in the
imperative; the body says why, what was observed, and what the gates reported —
not which files were touched, which the diff already says. A commit that fixes a
finding names it.

## Pull requests

State what the change does, why, and how you verified it. CI runs the gates
above on every push. Review looks for:

- the gates green, with no `#[allow]` added to make them so;
- a test that fails without the change, where the change is a fix;
- documentation that still describes the behaviour — `README.md`, `docs/`, and
  `schemas/README.md` are part of the change when they are affected;
- nothing internal. This repository holds code, tests, and user-facing
  documentation only. Plans, ledgers, and reviews live in a private repository
  and are not quoted here.

Adding a crate: name its directory to match one of the two workspace globs,
`crates/andon-*` or `crates/engines/*`. The root `Cargo.toml` member list is
not edited.

## The corpus rule — detector changes

The seven tamper detectors are measured against a frozen public corpus:
`fixtures/adversarial/` holds the changes that must fire,
`fixtures/honest/corpus/` the ones that must not, and
`fixtures/adversarial/README.md` publishes the precision and recall each
detector reaches on them, against floors set before measurement. A private
held-back set of evasions exists alongside it, and is the only instrument that
can tell whether the public corpus has been fitted to.

The rule that keeps both of those meaning what they claim:

> **Never tune a detector against a private case without first landing a
> public fixture for it.**

A detector change made to catch an evasion — one reported privately, one found
in dogfood, one from the held-back set — is not complete until the evasion has a
public case the change catches. Concretely, a pull request that touches
`crates/engines/tamper/` to change what fires:

1. adds `fixtures/adversarial/<detector>/<case>/` with a `case.toml` (a
   `title`, the `expect` list, and a `note` saying what the change pretends to
   be), a `base/` tree, and a `head/` tree;
2. adds the should-not-fire twin under
   `fixtures/honest/corpus/<detector>/<case>/` when the same shape can be
   legitimate, so the fix is measured for the false positives it introduces and
   not only the true positives it gains;
3. re-freezes, then re-measures, **in that order**:

   ```sh
   cargo run -p andon-engine-tamper --bin andon-corpus-report -- freeze
   cargo run -p andon-engine-tamper --bin andon-corpus-report -- --check-freeze --check-floors --markdown
   ```

   and puts the regenerated table into `fixtures/adversarial/README.md`.
   `crates/engines/tamper/tests/corpus_floors.rs` fails if the table, the
   freeze digest, or a floor stops describing the build.

A detector change without a corpus case will be asked for one before review
continues. An evasion the suite misses and no fix yet closes is recorded as a
row in that README's "Evasions the suite does not catch" table — the shape, the
detector, why it is missed, and what closing it needs — and not as a fixture: a
should-fire case the suite misses lowers recall against the floors, and the
corpus is frozen between refreshes.

Found an evasion that is **not** on that list? Do not open a pull request or an
issue for it. See `SECURITY.md`. It becomes a public row, or a public case the
suite catches, once a disclosure or a fix lands.

## Registry changes

Every number Andon reports cites a claim in `registry/*.toml`, and the registry
is compiled into the binary — a change to it is a change to what every build
reports as its evidence. `registry/REVIEW-POLICY.md` says what the lint checks
automatically, what a reviewer checks by hand, who has to approve a change of
each kind, and how long a decision takes. Read it before editing a registry
file; `registry/README.md` explains the claim tuple itself.

## Engine changes

A change under `crates/engines/` triggers the golden-set comparison in CI
(`engines change gate` in `ci.yml`): the working tree's binary measures
`fixtures/golden/` and the result is compared with the committed reference
payloads. A number that moves is expected to move — say why in the pull request
and re-record the reference in the same change.

## Reporting

- A measurement that fired when it should not have: open an issue with the
  **false positive** template. It asks for `andon doctor`'s output.
- A measurement that should have fired and did not, or anything that gets a
  change past the tool: `SECURITY.md`, privately.

## Licence

Apache-2.0 (`LICENSE`). Its section 5 applies to contributions: a change
submitted for inclusion is licensed under the same terms, and there is no
separate agreement to sign.
