# Packaging

How Andon's binaries reach a machine that has never built them: the installers cargo-dist
generates, what each one is, which names are still late-bound, which acts belong to the
flip, and how to re-run the stranger path that proves the whole thing works end to end.

Everything here is driven by one file, `dist-workspace.toml` at the repository root. It
is the source of truth for targets, installers, triggers, and pins; `dist generate`
renders `.github/workflows/release.yml` from it, and `dist plan` refuses to run while the
two disagree. The workflow is never hand-edited.

## The two apps

cargo-dist names an app after its Cargo package, so the workspace ships two:

| package     | binary      | why it ships                                                      |
|-------------|-------------|-------------------------------------------------------------------|
| `andon-cli` | `andon`     | the command line: `measure`, `explain`, `init`, `demo`, ...       |
| `andon-mcp` | `andon-mcp` | the MCP server `andon init` registers; the hook needs it on PATH  |

Every other binary in the workspace (probes, spikes, the registry lint) stays out. The
selection is `[workspace] packages` in `dist-workspace.toml`, which overrides the
`publish = false` every crate inherits — without a `dist = true` in any crate manifest.

The consequence for names: artifacts are `andon-cli-installer.sh`, `andon-cli.rb`,
`@gtm-k/andon-cli`, `andon-cli-<target>.tar.xz`, and the `andon-mcp-` equivalents. The
brand is `andon`; the artifact prefix is `andon-cli`. Changing that is a decision about
the Cargo package name (or a paired per-package `dist.toml`), not about this directory —
see *Late-bound* below.

Both apps share the workspace version, so one tag (`v0.1.0`) releases both.

## Installers

### Shell (curl) — primary

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/gtm-k/andon/releases/latest/download/andon-cli-installer.sh | sh
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/gtm-k/andon/releases/latest/download/andon-mcp-installer.sh | sh
```

Detects the platform, downloads the matching archive from the GitHub Release, verifies
its checksum, and installs into `$CARGO_HOME/bin` (`~/.cargo/bin`; `install-path =
"CARGO_HOME"`), adding that directory to the shell's PATH files unless told not to.
Overrides the generated script honours: `ANDON_CLI_INSTALL_DIR=<dir>` (install
somewhere else), `ANDON_CLI_NO_MODIFY_PATH=1` (touch no rc files), and the same with the
`ANDON_MCP_` prefix for the second script. These URLs resolve only once the repository is
public and a release exists — at the flip.

### PowerShell

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/gtm-k/andon/releases/latest/download/andon-cli-installer.ps1 | iex"
powershell -ExecutionPolicy Bypass -c "irm https://github.com/gtm-k/andon/releases/latest/download/andon-mcp-installer.ps1 | iex"
```

The same installer for Windows: `x86_64-pc-windows-msvc` archive, `%USERPROFILE%\.cargo\bin`.

### Homebrew — formula generation only

`dist build` renders a formula per app, `andon-cli.rb` and `andon-mcp.rb`, into the
release artifacts. The tap they are destined for is `gtm-k/homebrew-tap`
(`tap = "gtm-k/homebrew-tap"`), and once it exists the install line is:

```sh
brew install gtm-k/tap/andon-cli gtm-k/tap/andon-mcp
```

Nothing pushes the formula there yet. Creating the tap repository, adding its
`HOMEBREW_TAP_TOKEN` secret, and adding `"homebrew"` to `publish-jobs` are flip acts.
Until then every `dist plan` prints `A Homebrew tap was specified but the Homebrew publish
job is disabled` — that warning is the staged state and is expected. (It also prints
`no homepage was specified`: the formula's `homepage` falls back to `repository`; a
`homepage =` in the two crate manifests would silence it, and that is the crate owner's
line, not this directory's.)

### npm — late-bound name, no publish job

`dist build` renders one npm package per app: `@gtm-k/andon-cli` (bin `andon`) and
`@gtm-k/andon-mcp` (bin `andon-mcp`), as `andon-cli-npm-package.tar.gz` and its sibling.

**The name is not final.** The bare `andon` on npm is dormant and needs a user claim or
dispute before any artifact may embed it (PREMORTEM A5). Until that lands the packages
carry the scope in `npm-scope = "@gtm-k"` — the single line in `dist-workspace.toml` to
change when the name is bound. The unscoped bare-name form is `npm-package`, a
per-package setting that lives in the crate's own manifest. The pre-round fallback
ladder was `@andon/cli` → `@andon-dev/cli` → `andon-cli`; all three, and the scoped
placeholder, behave the same under `npx`: `npx <name> measure` installs the package into
npm's cache, the package's `postinstall` downloads the platform binary, and `run-andon.js`
executes it. There is no separate "npx mode".

**Shape delta, routed to P10a-dist.** PLAN P10a's criterion asks for *platform wrappers
via `optionalDependencies`, no postinstall*. cargo-dist's npm installer is the other
shape: one package whose `postinstall` (`node ./install.js`) fetches the archive from the
GitHub Release at install time, checked against `supportedPlatforms` in its
`package.json`. That is what ships from this configuration. Replacing it with
hand-rolled per-platform packages, or accepting postinstall, is P10a-dist's call — it
owns `packaging/npm/**` and the publish. No `"npm"` in `publish-jobs`; no `NPM_TOKEN`.

Note that a *host-mode* `dist build` (see below) lists only the host's platforms in
`supportedPlatforms`, because only the host's archive exists locally. The CI run lists
all four.

## The release workflow

`.github/workflows/release.yml` is generated. Its trigger during development is
`workflow_dispatch` only:

- `dispatch-releases = true` renders `on: workflow_dispatch` with a `tag` input. The
  default input, `dry-run`, plans and builds everything and publishes nothing; a real
  tag such as `v0.1.0` builds, creates the GitHub Release, and uploads. The tag-push
  trigger is not rendered at all.
- `pr-run-mode = "skip"` renders no `pull_request` trigger.

This is the project's Actions rule while the repository is private, done by config
rather than by commenting out a block: `dist plan` byte-compares the workflow against
its template, so a hand edit would force `allow-dirty = ["ci"]` and switch off the only
check that the workflow still matches the configuration.

Every `uses:` in the workflow is pinned by commit SHA, matching `ci.yml`'s convention,
through `[dist.github-action-commits]`; the tag each SHA was recorded from is the comment
beside it.

The build profile the workflow uses is `dist`, which cargo-dist hard-codes. It is
defined in the root `Cargo.toml` as `inherits = "release"` and nothing else (ruling E70):
the shipped and attested binary is the same profile `scripts/self-measure.sh` builds.

The profile is not the whole recipe on Windows. cargo-dist also appends
`-Ctarget-feature=+crt-static` to RUSTFLAGS for MSVC targets (`msvc-crt-static`, true by
default and set explicitly in `dist-workspace.toml`), and RUSTFLAGS lives outside any
profile — so an identical profile still produced a shipped `andon.exe` with the C runtime
linked in and a self-measured one that loaded it from the system: different bytes.
`.cargo/config.toml` pins the same flag for every build of `x86_64-pc-windows-msvc`,
which is what makes `dist build`, CI, and `scripts/self-measure.sh` link the same runtime
(ruling E71). Static is the side to pin: a dynamic CRT would make a stranger's install
depend on the Visual C++ redistributable already being present. The two declarations
must agree — dist sets RUSTFLAGS in the environment, which replaces the config table
rather than merging with it, so turning `msvc-crt-static` off would bypass the pin for
the release build alone and reopen the drift.

## Late-bound

| what                         | where it changes                                                 | bound by                |
|------------------------------|------------------------------------------------------------------|-------------------------|
| npm scope / name             | `npm-scope` in `dist-workspace.toml` (bare name: `npm-package` per crate) | user claim or dispute for `andon` (A5) |
| app / artifact prefix        | the `andon-cli` package name, or a paired `crates/andon-cli/dist.toml` `[package] name` | crate owner decision    |
| Homebrew `homepage` warning  | `homepage =` in the two crate manifests                          | crate owner             |

## Flip acts (P10b) — none of these happen here

1. Create `gtm-k/homebrew-tap`; add `HOMEBREW_TAP_TOKEN`; add `"homebrew"` to
   `publish-jobs`; `dist generate`; commit.
2. npm: claim the name; add `NPM_TOKEN`; add `"npm"` to `publish-jobs`; regenerate
   (P10a-dist, after the wrapper-shape decision above).
3. Re-enable push triggers: `dispatch-releases = false` (restores the tag-push trigger)
   or keep dispatch and release by dispatching with the real tag; `pr-run-mode =
   "plan"`; `dist generate`; commit.
4. Dispatch the workflow with the release tag. The `releases/latest/download/...` URLs
   in the install blocks resolve from that moment.
5. Re-run the stranger path in a clean container (below) as the uncredentialed smoke.

## Building locally

```sh
cargo install cargo-dist --locked     # the config pins cargo-dist-version = "0.32.0"
dist plan                             # exit 0 is the gate: config, workflow, and packages agree
dist build                            # host mode: this machine's archive plus every global artifact
```

`dist build` writes to `target/distrib/`. On a Windows host, 2026-08-27, from this
configuration: `andon-cli-x86_64-pc-windows-msvc.zip` (2,490,323 bytes; `andon.exe`
inside is 9,057,280 bytes), `andon-mcp-x86_64-pc-windows-msvc.zip` (3,123,329 bytes),
both installers for each app, both formulas, both npm tarballs, `source.tar.gz`, and
`sha256.sum`. Extracted, `andon.exe --version` printed `andon 0.1.0`. The macOS and
Linux archives are built by the workflow's matrix, not locally.

## The stranger path

`scripts/stranger-path.sh` is the ten-minute path a stranger takes, as three copy-paste
blocks: install; a fresh repository with the gate-shaped hook and one TypeScript file in
flight, measured; that change committed, measured again, and the claim behind one
number read. Each block is defined once, printed exactly as pasted, and executed from
the same string, so the transcript it writes is proof the blocks work rather than a
description of them. Eleven assertions check the output for the A1 contract (a
non-empty, zero-configuration measurement; a clean tree measures the last merged change
and says so) and the A3 differentiators (the verdict states where its trust ends; every
number carries its evidence and says what it does not predict).

Run it:

```sh
# Once a release exists (download mode — block 1 fetches the latest release):
bash scripts/stranger-path.sh

# Before that, against a built binary (andon-mcp must sit beside it):
ANDON_BIN=target/distrib/andon-cli-x86_64-pc-windows-msvc/andon.exe bash scripts/stranger-path.sh

# Keep the temporary repository for inspection:
STRANGER_KEEP=1 bash scripts/stranger-path.sh
```

In `ANDON_BIN` mode the real block 1 is still printed, marked as not executed, and the
script asserts that the `andon` it runs resolves inside that binary's directory — a
stale `andon` earlier on PATH cannot pass in its place.

`packaging/stranger-path-transcript.txt` is the run recorded on 2026-08-27: local
validation on Windows (Git Bash) against the binaries extracted from the `dist build`
archives above, in a fresh temporary directory; every assertion held in 4 seconds. It
embeds that machine's temporary paths on purpose — it is evidence of a run, not a
document. **The clean-container run is deferred**: Docker's daemon was down on the
validating machine, and download mode cannot run before a release exists. At the flip,
regenerate it in a container that has never seen this repository:

```sh
docker run --rm -v "$PWD/scripts/stranger-path.sh:/stranger-path.sh:ro" ubuntu:24.04 \
  bash -c 'apt-get update -qq && apt-get install -y -qq curl git ca-certificates >/dev/null && bash /stranger-path.sh'
```
