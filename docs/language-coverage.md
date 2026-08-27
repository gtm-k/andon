# Language coverage

What Andon measures depends on the file extension, and a file in a language it has
no model for is **not measured** — not measured badly, not measured at zero, not
counted anywhere. This page is the table to check before trusting a verdict on your
repository, and it opens with the failure the table exists to disclose.

Everything below is derived from the extension tables in the engines
(`crates/engines/static-metrics/src/lang.rs`, `crates/engines/clones/src/syntax.rs`,
`crates/engines/tamper/src/syntax.rs`) and from how each detector chooses its files.
Where the code moves, this page is what has to move with it.

## The failure this page discloses

A Go repository. The head turns a parameterised query into string interpolation and
adds a hard-coded backdoor:

```go
func find(db *sql.DB, id string) (*sql.Rows, error) {
	if id == "backdoor-9f2c" {
		return db.Query("SELECT * FROM users")
	}
	return db.Query("SELECT * FROM users WHERE id = " + id)
}
```

`andon measure --full`, on the shipped binary, trimmed to the lines that matter:

```
 PASS  nothing above the advisory floor. The line keeps moving.
 change   9e120ec31fd9 → your uncommitted working tree (fork point against main)
 reading  1 file(s) changed · 5 engine(s) · 26 result(s) · record unwitnessed
 …
  · INFO  static.unmeasured-files  this change
       0
       evidence  tier N · None. An instrument reading, introduced by PREMORTEM T3.
       does not predict  code quality, in any direction

 NOT MEASURED (an absence, never a zero)
  artifacts.uncovered-changed-lines  this change
       unwitnessed: no coverage report found
  process.hotspot  main.go
       unwitnessed: no complexity input for this path
```

Two things are wrong with reading that as a clean bill, and only one of them is the
miss. Andon ships no SAST family and would not have found the injection in any
language; that is stated below and in the README. The misleading part is the silence:
**`static.unmeasured-files` reports `0`** because it counts files in a *recognised*
language that could not be read (an uncommitted path with no blob, or bytes that are
not UTF-8) — it does not count files in a language with no model at all. A `.go` file
is therefore indistinguishable in the output from a file correctly out of scope. The
only trace is `process.hotspot main.go — unwitnessed: no complexity input for this
path`, which says the static family had no complexity number for that file — the same
line a Rust file gets, since the tokenization tier has none either.

So: read the table, compare it with the extensions in your change, and treat a
`pass` on a change made of unlisted files as *nothing looked*.

## The table

Extensions are matched case-sensitively against the path git records — `A.TS` is not
TypeScript, because a case-folding host would measure a different set from a
case-preserving one, and the path is inside the digest.

| language | extensions | `static` | `clones` | `tamper` (grammar detectors) | `process` | `artifacts` | `tests` |
|---|---|---|---|---|---|---|---|
| TypeScript | `.ts` `.mts` `.cts` | parsed: size, cyclomatic, cognitive, parse health | yes | yes | yes | yes | yes |
| TSX | `.tsx` | parsed, as above | yes | yes | yes | yes | yes |
| JavaScript | `.js` `.jsx` `.mjs` `.cjs` | parsed, as above | yes | yes | yes | yes | yes |
| Python | `.py` `.pyi` | parsed, as above | yes | yes | yes | yes | yes |
| Rust | `.rs` | **size only** — `static.sloc`; no complexity, no parse health | **no** | **no** | yes | yes | yes |
| anything else | — | **not measured** | **no** | **no** | yes | yes | yes |

What "yes" means in the last three columns:

- **`process`** reads git history, not content, so churn, code age, ownership and
  change coupling exist for every changed path. `process.hotspot` is the exception:
  it needs a complexity number, which only the parsed tier produces, so a Rust or Go
  path reports `unwitnessed: no complexity input for this path`.
- **`artifacts`** reads a coverage report from a fixed set of paths (`lcov.info`,
  `coverage/lcov.info`, `coverage.xml`, `cobertura.xml`, and the common `coverage/`
  and `target/coverage/` spellings) and maps uncovered lines onto the changed ones.
  Whatever produced the report is your business; the engine reads the report.
- **`tests`** runs the command `.andon.toml` declares, on the async lane, inside the
  sandbox. It measures whatever the suite measures and is off unless declared.

### Rust is the tokenization tier

A Rust file yields `static.sloc` from a hand-written scanner and **nothing else from
the static family**: no cyclomatic or cognitive complexity, and no parse-health
results — not zeros, an absence. There is no parser, so "zero parse errors" would be
a number about something that never happened. Rust is also outside the clone
engine and outside the four grammar-bound tamper detectors. The reason is the
project's own history — Andon is written in Rust and had to pass its own measurement
before a Rust grammar was on the roadmap — and the complexity decision for Rust is
still open rather than silently shipped as size.

## The tamper detectors, one by one

The seven detectors do not select files the same way, and the difference matters for
what a non-listed language gets.

| detector | selects files by | languages it can fire on |
|---|---|---|
| `test-removal` | test-shaped path, then a grammar | TS, TSX, JS, Python |
| `assertion-free-test` | test-shaped path, then a grammar | TS, TSX, JS, Python |
| `parse-error-delta` | a grammar | TS, TSX, JS, Python |
| `lookup-table-blowup` | a grammar, excluding test and data paths | TS, TSX, JS, Python |
| `suppression-density` | **every changed text file**, matched textually | any language — for the markers it knows |
| `threshold-config-edit` | recognised tool configuration files | any language — for the tools it knows |
| `coverage-exclusion-drift` | recognised tool configuration files | any language — for the tools it knows |

**Grammar-bound.** The first four parse the file, and a file no grammar reads is
skipped without a trace: a deleted `foo_test.go` or a `test_thing.rb` emptied of
assertions is a test file by path and is never opened. A test-shaped path is one
under `test/`, `tests/`, `__tests__/`, `spec/`, `specs/`, `e2e/` or `testing/`, or
named `test_*`, `*.test.*`, `*.spec.*`, `*_test.*`, `*-test.*` or `*.steps.*`.

**Text-bound.** `suppression-density` counts recognised directives in any changed
file, whatever its language, because a suppression lives in a comment and a comment
is the one thing every grammar agrees to ignore. The list is an enumeration, not a
rule: ESLint, `@ts-ignore`/`@ts-expect-error`/`@ts-nocheck`, Biome, oxlint, deno-lint,
Prettier, istanbul/c8/v8 ignore, `noqa`, `type: ignore`, pylint, pyright, ruff,
flake8, `mypy: ignore-errors`, `nosec`, Rust's `#[allow(`, `sonarignore`, and
`no-inspection`. A Go `//nolint`, a Java `@SuppressWarnings` or a C# `#pragma warning
disable` is not on it and is not counted. It also fires only at two or more added
directives with the per-line density rising — one suppression is a Tuesday.

**Config-bound.** The two gate-loosening detectors read configuration files by the
tool's stem, in every syntax that tool reads, regardless of what language the
repository is written in. `threshold-config-edit` opens `.andon.toml`, `tsconfig*`,
`.eslintrc*`, `eslint.config.*`, `biome.json[c]`, `.flake8`, `pyproject.toml`,
`mypy.ini`/`.mypy.ini`, `ruff.toml`/`.ruff.toml`, **`clippy.toml`**,
**`.golangci.*`**, `sonar-project*.properties`, `jest.config.*`, `vitest.config.*`,
`.coveragerc`, `.nycrc*`, `.c8rc*`, `codecov.yml`/`.codecov.yml`, `tarpaulin.toml`,
`setup.cfg`, `package.json` and `tox.ini`. `coverage-exclusion-drift` opens
`.coveragerc`, `codecov.yml`/`.codecov.yml`, `.nycrc*`, `.c8rc*`, `tarpaulin.toml`,
`pyproject.toml`, `sonar-project*.properties`, `jest.config.*`, `vitest.config.*`,
`nyc.config.*`, `setup.cfg`, `package.json` and `tox.ini`. So a Go repository's golangci
thresholds and a Rust repository's Clippy ceilings *are* watched; the Go source next
to them is not.

## What no language gets

- **No SAST family.** Injection, hard-coded credentials, unsafe deserialisation,
  path traversal — nothing in the registry looks for any of them, in any language.
  Andon measures size, complexity, duplication, history, coverage, suite outcome and
  seven gaming patterns. It is not a security scanner and does not stand in for one.
- **No semantic analysis.** No detector resolves an import, follows a symbol, or
  executes anything on the fast lane. Every answer is a function of the bytes.
- **No zero for an absence.** A family that did not measure a file emits nothing for
  it, and the record's `completeness` and `NOT MEASURED` block name what it could
  not do — but only for work it set out to do. A language outside the table was
  never set out for.

## Checking your own repository

`andon measure --full` prints every result, including absences. The static family
emits `static.sloc` per file for every language it knows, Rust included, so a changed
file with no `static.sloc` result was in no language the static family reads — and
the clone engine and the four grammar-bound tamper detectors read the same four
languages minus Rust. Tamper and clone results are scoped to the change as a whole,
so they cannot tell you per file; the `sloc` line can. `andon explain --list` prints
every metric the build you have can produce, so the table above can be checked
against the binary rather than believed.
