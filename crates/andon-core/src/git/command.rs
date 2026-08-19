//! The one place a git subprocess is created.
//!
//! Every `git` invocation in the workspace goes through [`Git`], because the
//! hygiene below only counts if it is unskippable. A single unpinned spawn is
//! enough to reintroduce PREMORTEM Story 1: the user's `core.autocrlf=true`
//! reaches one code path, that path's bytes differ from CI's, and a per-result
//! digest mismatch is reported as `divergent` on an honest change.
//!
//! `crates/andon-core/tests/git_spawn_guard.rs` fails the build if
//! `Command::new` appears anywhere under `src/git/` except this file.
//!
//! # What hygiene means here
//!
//! **Environment.** Every `GIT_*` variable inherited from the caller is removed
//! and only a fixed set is put back ([`Git::sanitize_env`]). A sweep rather than
//! a denylist, because the denylist is the thing that goes stale: `GIT_CONFIG_COUNT`
//! injects arbitrary config, `GIT_EXTERNAL_DIFF` runs a program of the caller's
//! choosing, `GIT_ALTERNATE_OBJECT_DIRECTORIES` changes what an OID resolves to,
//! and the next release will add another. `GIT_EXEC_PATH` is the one preserved
//! exception — it locates git's own helper programs, and dropping it breaks git
//! on MSYS installs that rely on it.
//!
//! **Config.** [`PINNED_CONFIG`] is applied as `-c key=value` on every
//! invocation. Command-line `-c` outranks repository, global, and system config,
//! so a hostile `.git/config` loses to it as surely as a hostile `~/.gitconfig`
//! does — which is why the hygiene test plants both.
//!
//! **What is deliberately not pinned:**
//!
//! - `core.fsmonitor`. It changes how fast `git status` answers, never what it
//!   answers, and PLAN P1 asks for fsmonitor where available. A hostile
//!   fsmonitor could under-report dirty files, which is a reason to keep dirty
//!   state in the advisory lane — not a reason to give up the speed that keeps
//!   PREMORTEM T6 off the table.
//! - `core.fileMode`. It affects whether a mode-only change is reported, and
//!   only ever feeds the cache key, which never leaves the machine that built
//!   it. Pinning it would make Linux ignore a real exec-bit change to buy
//!   agreement with a Windows checkout that cannot represent one.
//! - `diff.orderFile`. Git rejects an empty value outright (`failed to read
//!   orderfile ''`), so it cannot be neutralized by pinning. Every enumeration
//!   in this module sorts its own output instead, which is the stronger fix:
//!   the order no longer depends on git's at all.
//! - `GIT_OPTIONAL_LOCKS=0`. The obvious hygiene for a read-only tool, and
//!   measured to cost a third of the dirty-tree path: it stops git writing the
//!   refreshed index, so the stat cache and the untracked cache are never
//!   persisted and every `status` re-walks the whole repository. On the
//!   100k-file perf fixture that is 1629 ms against 1089 ms — the difference
//!   between missing the warm budget badly and missing it narrowly, on exactly
//!   the path PREMORTEM T6 is about. What the lock guards is git's own cache,
//!   not repository content: a refresh updates stat data for entries whose
//!   content already matches, stages nothing, and changes no output. Git also
//!   degrades gracefully when the lock is held, skipping the update rather than
//!   failing. Politeness that costs the tool its headline property is not
//!   politeness worth having.
//! - `core.excludesFile`. It hides untracked files from `status`, and only
//!   untracked files — which are in no commit, so they reach the advisory lane
//!   and never the compared one. Neutralizing it would mean a developer's global
//!   ignore stopped applying and their editor's scratch files started churning
//!   the cache key on every measurement. The determinism it could buy is
//!   determinism nothing needs.
//!
//! # Where the pins are belt and where they are braces
//!
//! Several of these keys cannot actually reach us, because the commands that
//! would read them are already invoked with an overriding flag: `-z` makes
//! `core.quotepath` inert, `--no-ext-diff` outranks `diff.external`,
//! `--find-renames` outranks `diff.renames`. They stay pinned anyway — a future
//! call site that forgets a flag should fail safe — but the flags are the load
//! bearing half, and `crates/andon-core/tests/git_hygiene.rs` proves which by
//! showing each planted setting changing the output of an *unpinned* git first.
//!
//! # The one place the conversion pins must not reach
//!
//! Pinning `core.autocrlf=false` fixes the bytes we hash, which is the whole
//! point — *when the question is what the bytes are*. It is the wrong answer to
//! a different question: **has this file been edited?**
//!
//! A clone made with `core.autocrlf=true`, the Git-for-Windows default, has CRLF
//! on disk for every text file, put there by that conversion and matching the
//! index exactly as far as that conversion is concerned. Its own `git status` is
//! clean. Ours, asking with the conversion pinned off, called all 200 files of a
//! probe repository modified — and then, having refreshed the index stat cache,
//! called them clean on the next run. Two digests for one untouched tree.
//!
//! So [`Git::cmd_in_checkout_conversion`] exists, and exactly one caller uses it:
//! the suspect re-check in [`super::status`]. The symmetry is the one already
//! argued for `core.excludesFile` above — a setting that produced the bytes on
//! disk is not a setting to neutralize when the question is about those bytes'
//! provenance. What it may decide is **membership** of the dirty set. Every OID
//! recorded in a snapshot is still hashed under the full pins.
//!
//! That relaxation has to reach **every scope**, which the first attempt did not.
//! It unpinned the three conversion keys and went on suppressing the system
//! config — and Git for Windows writes `core.autocrlf=true` into
//! `etc/gitconfig`, so on a fresh install that is the only place the setting
//! lives. All 200 files came back dirty again, one scope over from where the
//! fix was looking. The rule is now scope-blind: everything defining this
//! checkout's conversion speaks, wherever it lives.
//!
//! # Filters are repository-defined programs, and this lane does not run them
//!
//! `.gitattributes` may say `*.ts filter=x`, and a `filter.x.clean` command in
//! any config file is then **executed by git** whenever it reads that file's
//! working-tree content. `git status` does it — for any tracked file whose stat
//! data moved but whose size did not, which is what an in-place edit looks like
//! — and `git hash-object -w` does it unconditionally. Both are on the path of
//! an ordinary `andon measure`.
//!
//! That is arbitrary repository code executing inside the lane PRE-DECISIONS
//! separates *from* the code-executing checks, and it was executing: a planted
//! `filter.evil.clean` created a working-tree file, updated a ref, and staged
//! its own side effect while `andon measure` exited 0 and printed `pass`. The
//! hooks pin above closes one mechanism; filters are a second one, and it was
//! open.
//!
//! Neutralized rather than detected, because detection would have to run
//! *after* the enumeration that already ran the program. A filter can only
//! execute if some config file gives its driver a command, and `-c` outranks
//! every config file — so [`Git::open`] reads the driver names once (a `git
//! config` read executes nothing) and every spawn afterwards carries
//! [`FILTER_NEUTRALIZATION`] for each of them: the three commands emptied and
//! `required` pinned false. An emptied command makes git treat the driver as
//! absent and pass the bytes through; `required=true` left alone would instead
//! make it a hard failure, which is how git-lfs — configured globally on most
//! developer machines — would otherwise break every measurement.
//!
//! The enumeration is read through [`Git::cmd_in_checkout_conversion`]'s
//! environment on purpose: that spawn is the one that lets the *system* config
//! speak, so reading driver names under it yields the union of what any spawn
//! in this module could load. A name that cannot be expressed as a `-c` key —
//! one containing `=` or a newline — cannot be neutralized, and that is a
//! typed refusal ([`GitError::UnneutralizableFilter`]) rather than a spawn that
//! proceeds hoping the attribute never matches.
//!
//! What this costs on an honest repository is that content a clean filter would
//! have rewritten is read as the raw working-tree bytes instead. That is the
//! more truthful reading for this tool — the bytes an agent wrote are the bytes
//! it wrote — and it is disclosed rather than assumed: [`Git::filtered_paths`]
//! names the changed paths whose declared filter did not run, and the caller
//! puts them in the report.
//!
//! **System files.** `GIT_CONFIG_NOSYSTEM=1` drops `/etc/gitconfig` and
//! `GIT_ATTR_NOSYSTEM=1` drops the system attributes file. The *global*
//! gitconfig is deliberately left loadable: `actions/checkout` writes
//! `safe.directory` there, and a git that refuses to open the repository is a
//! worse failure than a config key we already outrank with `-c`.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Config pinned with `-c` on every git invocation.
///
/// Ordered by the surface each key affects, and every entry is here because it
/// can change bytes we hash, paths we enumerate, or a program we would end up
/// executing. `git -c` beats every config file, so this list is the effective
/// configuration regardless of what the machine is carrying.
pub const PINNED_CONFIG: &[(&str, &str)] = &[
    // Paths. `quotepath=true` octal-escapes anything non-ASCII, which silently
    // changes the path strings that reach `ResultScope::path` and therefore
    // every digest covering a non-ASCII file.
    ("core.quotepath", "false"),
    // Line endings. The headline mechanism of PREMORTEM Story 1: a CRLF
    // worktree read against an LF CI checkout. Blob reads are immune by
    // construction, but `hash-object` and `status` are not.
    ("core.autocrlf", "false"),
    ("core.eol", "lf"),
    ("core.safecrlf", "false"),
    // A *global* attributes file changes what `hash-object` returns for
    // identical bytes — `*.ts text eol=crlf` in one developer's `~/.gitattributes`
    // is enough — so it is neutralized. Measured, not assumed: with it set, a
    // CRLF file hashes to `85c3040…`; without, `b4ec4d1…`.
    //
    // The repository's own `.gitattributes` still applies, and should: it is
    // committed content that every checkout shares, which is the opposite of a
    // machine-local preference.
    ("core.attributesFile", ""),
    // Never run repository hooks from a measurement. A `reference-transaction`
    // or `post-index-change` hook firing inside `andon measure` is arbitrary
    // repository code executing in the static-safe lane, and nondeterministic
    // besides. The path is one git will not find.
    ("core.hooksPath", "andon-hooks-disabled-by-design"),
    ("core.pager", "cat"),
    ("advice.detachedHead", "false"),
    // Diff shape. `diff.external` and textconv both replace git's diff with a
    // program of the config's choosing; the algorithm and rename settings are
    // the ones whose *defaults* have moved across git releases, which is the
    // drift PREMORTEM Story 1 names alongside CRLF.
    ("diff.external", ""),
    ("diff.algorithm", "histogram"),
    ("diff.renames", "true"),
    ("diff.renameLimit", "4096"),
    ("diff.indentHeuristic", "true"),
    ("diff.noprefix", "false"),
    ("diff.mnemonicPrefix", "false"),
    ("diff.wsErrorHighlight", "none"),
    // Status shape. Renames are resolved from the raw diff instead, so status
    // never has to be asked a question whose answer depends on a score.
    ("status.renames", "false"),
    ("status.showUntrackedFiles", "all"),
    // Text encoding of anything git echoes back.
    ("log.showSignature", "false"),
    ("i18n.logOutputEncoding", "UTF-8"),
    ("i18n.commitEncoding", "UTF-8"),
    // No background repacking mid-measurement. Auto-gc would add seconds to a
    // random run of the perf gate and write to a repository we are only reading.
    ("gc.auto", "0"),
    ("gc.autoDetach", "false"),
    ("maintenance.auto", "false"),
];

/// What every configured filter driver is pinned to, on every invocation.
///
/// One entry per key git consults before deciding to start a program. The three
/// commands are emptied, which is how a driver is spelled "absent"; `required`
/// is pinned false because an emptied command under `required=true` is a fatal
/// error rather than a pass-through, and git-lfs ships `required=true` in the
/// global config of every machine that has run `git lfs install`.
pub const FILTER_NEUTRALIZATION: &[(&str, &str)] = &[
    ("clean", ""),
    ("smudge", ""),
    ("process", ""),
    ("required", "false"),
];

/// The pinned keys that decide check-in conversion.
///
/// A named group because one code path has to *not* apply them — see
/// [`Git::cmd_in_checkout_conversion`] and the module docs. `core.safecrlf` is
/// deliberately absent: it only ever turns a conversion into a warning or an
/// error, never into different bytes, so leaving it pinned off costs nothing and
/// keeps a hostile config from failing the re-check outright.
pub const CONVERSION_CONFIG: &[&str] = &["core.autocrlf", "core.eol", "core.attributesFile"];

/// Environment variables that tell git **where** its config lives, as opposed to
/// what it says.
///
/// The distinction is the whole of the exception in
/// [`Git::cmd_in_checkout_conversion`]: a variable that *locates* a file is part
/// of how this machine's git resolved the conversion that produced the checkout,
/// so honouring it on that one spawn is checkout-consistency. A variable that
/// *injects* config — `GIT_CONFIG_COUNT` and its `KEY_n`/`VALUE_n` — invents
/// settings no file holds, and stays swept everywhere.
const CONFIG_LOCATION_ENV: &[&str] = &["GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL"];

/// Forced variables that suppress machine-wide inputs to conversion.
///
/// Set on every invocation except the checkout-conversion one, where suppressing
/// them is the bug: a system `core.autocrlf=true` is what Git for Windows
/// installs by default, and a checkout produced under it is not dirty for having
/// been.
const SYSTEM_SUPPRESSION_ENV: &[&str] = &["GIT_CONFIG_NOSYSTEM", "GIT_ATTR_NOSYSTEM"];

/// Environment variables set on every git invocation.
const FORCED_ENV: &[(&str, &str)] = &[
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_ATTR_NOSYSTEM", "1"),
    // `git replace` rewrites what an OID resolves to. A repository carrying a
    // replace ref can make `cat-file` return bytes that are not the object's,
    // which would let a blob digest describe content nobody committed.
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    // Never block on a credential or passphrase prompt. A measurement that
    // pauses waiting for input nobody is there to give is a hung agent, and the
    // honest failure is the immediate one.
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_PAGER", "cat"),
    ("PAGER", "cat"),
    // Byte-stable collation and message text.
    ("LC_ALL", "C"),
    ("LANG", "C"),
];

/// A git invocation failed, or its output could not be understood.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    /// The `git` binary could not be started at all.
    #[error("could not run `git {argv}`: {source}")]
    Spawn {
        /// The arguments that were attempted, for the message.
        argv: String,
        /// The underlying OS error.
        source: std::io::Error,
    },
    /// git ran and exited non-zero.
    #[error("`git {argv}` failed with {status}: {stderr}")]
    Failed {
        /// The arguments that were run.
        argv: String,
        /// Exit status, rendered.
        status: String,
        /// Trimmed stderr, which is where git says what went wrong.
        stderr: String,
    },
    /// git produced bytes that are not valid UTF-8 where text was required.
    #[error("`git {argv}` produced output that is not valid UTF-8")]
    NotUtf8 {
        /// The arguments that were run.
        argv: String,
    },
    /// git's output did not match the documented format for the command.
    #[error("could not parse `git {argv}` output: {detail}")]
    Protocol {
        /// The arguments that were run.
        argv: String,
        /// What was expected and what arrived.
        detail: String,
    },
    /// A configured filter driver cannot be neutralized, so it cannot be
    /// guaranteed not to run.
    ///
    /// Filters are repository-defined programs (see the module docs), and this
    /// module keeps them from executing by pinning every configured driver's
    /// commands empty with `-c`. A driver whose *name* contains `=` or a
    /// newline cannot be written as a `-c` key at all — git would parse the
    /// key at the first `=` and set something else — so the pin would silently
    /// miss and the program would run on the next `status`.
    ///
    /// A refusal rather than a warning, because the alternative is measuring a
    /// repository while executing its code and reporting the result as static
    /// analysis.
    #[error(
        "the filter driver `{driver}` is configured with a name this tool cannot neutralize, \
         and a filter is a program this repository defines. Rename it, or unset \
         `filter.{driver}.clean`, `.smudge` and `.process`, and re-run"
    )]
    UnneutralizableFilter {
        /// The driver name, as `git config` reported it.
        driver: String,
    },
    /// The path given is not inside a git repository.
    #[error("{path} is not inside a git repository")]
    NotARepository {
        /// The path that was probed.
        path: String,
    },
    /// The working tree holds an unmerged path: a merge, rebase, or cherry-pick
    /// left conflict markers and more than one stage of the same file in the
    /// index.
    ///
    /// A refusal rather than a skip. A conflicted path has two or three
    /// competing contents and no single one that is "what the tree holds", so
    /// any snapshot that covers it is a snapshot of a state that does not exist.
    /// Dropping the record silently would key the *rest* of the tree under a
    /// digest that claims to describe the whole of it —
    /// [`super::resolve::ResolvedRange::resolve`] refuses in-progress operations
    /// first, but that check reads git's marker files and a conflict can outlive
    /// them (`git merge --no-commit` that conflicts, an aborted operation whose
    /// markers were cleaned while the index was not).
    #[error(
        "{path} is unmerged; a conflicted tree has no single content to key on \
         (resolve the conflict, or abort the operation that created it)"
    )]
    ConflictedTree {
        /// The unmerged path, as git reported it.
        path: String,
    },
    /// git named a path this tool cannot carry without changing it.
    ///
    /// Paths become map keys, digest inputs, and `ResultScope::path` on the
    /// wire, so a path that survives only approximately is a path that has lost
    /// its identity. Two shapes reach here:
    ///
    /// - **Not valid UTF-8.** Git tracks paths as bytes; a filesystem can hand
    ///   back a name no encoding claims. Rendering it lossily replaces every bad
    ///   byte with `U+FFFD`, which makes `src/\xff.ts` and `src/\xfe.ts` the
    ///   same string — one entry overwriting the other in a `BTreeMap`, and one
    ///   digest describing two files.
    /// - **Unusable in a protocol we speak.** `hash-object --stdin-paths` reads
    ///   one path per line, so a path containing a newline is two paths to git
    ///   and one to us, and every OID after it belongs to the wrong file.
    ///
    /// A typed refusal in both cases. The alternative is not "handles more
    /// repositories" but "is quietly wrong on the ones it claims to handle".
    #[error("`git {argv}` named a path that cannot be carried: {detail} (approximately: {lossy})")]
    UnrepresentablePath {
        /// The arguments that were run.
        argv: String,
        /// Which property the path fails.
        detail: String,
        /// The offending git output rendered lossily — wrong by construction,
        /// and the only way to point an operator at the file.
        ///
        /// Not always the path alone. Where the parser had the path in isolation
        /// this is the path; where it had a whole record — porcelain v2 hands
        /// over status letters, modes, and both blob OIDs in the same field as
        /// the path — this is that record. Deliberately, and not just because
        /// slicing invalid UTF-8 back to one field is fiddly: the record is
        /// *more* use to whoever has to find the file than the mangled name is
        /// on its own. The doc said "the path" and the code always said this;
        /// the doc was the wrong half.
        lossy: String,
    },
}

/// Decode a byte record git produced into text, refusing what would only
/// survive approximately.
///
/// Every caller is parsing output whose path field becomes an identity. See
/// [`GitError::UnrepresentablePath`] for why lossy decoding is not an option
/// there.
pub(crate) fn decode_record<'a>(bytes: &'a [u8], argv: &str) -> Result<&'a str, GitError> {
    std::str::from_utf8(bytes).map_err(|err| GitError::UnrepresentablePath {
        argv: argv.to_string(),
        detail: format!("not valid UTF-8 at byte {}", err.valid_up_to()),
        lossy: String::from_utf8_lossy(bytes).into_owned(),
    })
}

/// A repository, and the only handle that can spawn git against it.
///
/// Cloning is cheap and shares the spawn counter, so a measurement that hands
/// clones to several engines still counts every spawn once.
#[derive(Debug, Clone)]
pub struct Git {
    workdir: PathBuf,
    facts: RepoFacts,
    spawns: Arc<AtomicU64>,
    /// `-c` arguments that pin every configured filter driver to inert, built
    /// once at [`Git::open`]. Empty on the overwhelming majority of
    /// repositories, which configure no filter at all.
    filter_pins: Arc<Vec<String>>,
    /// The driver names behind [`Self::filter_pins`], for the disclosure.
    filter_drivers: Arc<Vec<String>>,
}

/// What the repository is, established once when it is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoFacts {
    /// `git --version`, trimmed. Stamped into
    /// [`crate::schema::payload::CompareContext::git_version`] and into the
    /// process [`crate::schema::regime::MeasurementRegime`], because git's
    /// rename-detection defaults move across releases.
    pub version: String,
    /// Absolute path to the working tree root.
    pub toplevel: PathBuf,
    /// Absolute path to the git directory.
    pub git_dir: PathBuf,
    /// True when history is truncated. Merge-base resolution can fail here, and
    /// the honest answer is a typed error rather than a nearer commit
    /// (PLAN P1; P4 turns this into `completeness: unwitnessed`).
    pub shallow: bool,
    /// True when there is no working tree to read advisory bytes from.
    pub bare: bool,
}

impl Git {
    /// Open the repository containing `path`.
    ///
    /// Costs three spawns: one `git --version`, one batched `rev-parse` that
    /// answers every remaining question at once, and one `git config` that
    /// reads the filter drivers this repository's config defines. All are
    /// counted, because a caller's spawn budget has to cover what opening the
    /// repository costs.
    ///
    /// The first two run without the filter pins, which is safe rather than
    /// lucky: neither `--version` nor `rev-parse` reads working-tree content,
    /// so neither can reach a filter. The `config` read cannot either — and it
    /// is what makes the pins available to everything that can.
    pub fn open(path: &Path) -> Result<Self, GitError> {
        let git = Git {
            workdir: path.to_path_buf(),
            facts: RepoFacts {
                version: String::new(),
                toplevel: path.to_path_buf(),
                git_dir: path.to_path_buf(),
                shallow: false,
                bare: false,
            },
            spawns: Arc::new(AtomicU64::new(0)),
            filter_pins: Arc::new(Vec::new()),
            filter_drivers: Arc::new(Vec::new()),
        };

        let version = git.cmd(["--version"]).text()?.trim().to_string();

        // One spawn for four questions. `rev-parse` prints the answers in the
        // order the flags appear, one per line.
        let probe = git
            .cmd([
                "rev-parse",
                // `--absolute-git-dir`, never `--git-dir`: the latter answers
                // `.git` when run from the repository root, and a relative path
                // stored on a long-lived handle resolves against whatever the
                // process's working directory happens to be later. The
                // in-progress-operation markers are found by joining onto this,
                // so a relative answer means a rebase mid-conflict is reported
                // as a clean tree.
                "--absolute-git-dir",
                "--show-toplevel",
                "--is-shallow-repository",
                "--is-bare-repository",
            ])
            .text()
            .map_err(|err| match err {
                GitError::Failed { .. } => GitError::NotARepository {
                    path: path.display().to_string(),
                },
                other => other,
            })?;
        let lines: Vec<&str> = probe.lines().map(str::trim).collect();
        let [git_dir, toplevel, shallow, bare] = lines.as_slice() else {
            return Err(GitError::Protocol {
                argv: "rev-parse".to_string(),
                detail: format!("expected 4 lines, got {}", lines.len()),
            });
        };

        let drivers = git.configured_filter_drivers()?;
        let pins = drivers
            .iter()
            .flat_map(|driver| {
                FILTER_NEUTRALIZATION
                    .iter()
                    .map(move |(key, value)| format!("filter.{driver}.{key}={value}"))
            })
            .collect();

        Ok(Git {
            workdir: PathBuf::from(toplevel),
            facts: RepoFacts {
                version,
                toplevel: PathBuf::from(toplevel),
                git_dir: PathBuf::from(git_dir),
                shallow: *shallow == "true",
                bare: *bare == "true",
            },
            spawns: git.spawns,
            filter_pins: Arc::new(pins),
            filter_drivers: Arc::new(drivers),
        })
    }

    /// Every filter driver any config file gives a command or a `required` flag.
    ///
    /// Read through the checkout-conversion environment, which is the widest
    /// scope any spawn in this module loads: it is the only one that lets the
    /// system config speak, so the names found here cover the pinned spawns too.
    /// Neutralizing a driver the pinned spawns would never have loaded costs a
    /// `-c` argument and nothing else; missing one costs the guarantee.
    ///
    /// `-z` because a driver's command is arbitrary text — `git-lfs clean -- %f`
    /// today, something with a newline in it tomorrow — and the newline-
    /// separated form would then be parsed as another key.
    fn configured_filter_drivers(&self) -> Result<Vec<String>, GitError> {
        // Exit 1 with no output is `--get-regexp`'s "nothing matched", which is
        // the ordinary answer and not a failure.
        let Some(text) = self
            .cmd_in_checkout_conversion(["config", "-z", "--get-regexp", r"^filter\."])
            .succeeds_with_output()?
        else {
            return Ok(Vec::new());
        };

        let mut drivers: Vec<String> = Vec::new();
        for record in text.split('\0').filter(|r| !r.is_empty()) {
            // `key\nvalue`, and a value may itself contain newlines.
            let key = record.split('\n').next().unwrap_or_default();
            // `filter.<name>.<setting>`, where `<name>` may contain dots: git
            // takes the subsection as everything between the first and last one.
            let Some(rest) = key.strip_prefix("filter.") else {
                continue;
            };
            let Some((driver, _setting)) = rest.rsplit_once('.') else {
                continue;
            };
            if driver.is_empty() || drivers.iter().any(|known| known == driver) {
                continue;
            }
            if driver.contains('=') || driver.contains('\n') || driver.contains('\r') {
                return Err(GitError::UnneutralizableFilter {
                    driver: driver.to_string(),
                });
            }
            drivers.push(driver.to_string());
        }
        // Sorted for the same reason every other enumeration here is: the
        // argument list a spawn carries should not depend on config file order.
        drivers.sort();
        Ok(drivers)
    }

    /// The filter drivers this repository's config defines, all of them pinned
    /// inert on every spawn. Empty on a repository that configures none.
    pub fn filter_drivers(&self) -> &[String] {
        &self.filter_drivers
    }

    /// Which of `paths` `.gitattributes` assigns to a driver that is actually
    /// configured — the paths whose declared filter did not run.
    ///
    /// The disclosure half of the neutralization. An attribute naming a driver
    /// nothing configures is not reported, because git would not have run
    /// anything for it either: the content is unaffected and saying otherwise
    /// would be a warning about nothing.
    ///
    /// `check-attr` reads attribute files and starts no program, so this is
    /// safe to ask after the fact — which is the whole reason the neutralization
    /// cannot be replaced by a check.
    pub fn filtered_paths(&self, paths: &[String]) -> Result<Vec<(String, String)>, GitError> {
        if self.filter_drivers.is_empty() || paths.is_empty() {
            return Ok(Vec::new());
        }
        let text = self
            .cmd(["check-attr", "-z", "filter", "--"])
            .args(paths)
            .text()?;

        // `path\0filter\0value\0`, one triple per path.
        let fields: Vec<&str> = text.split('\0').collect();
        let mut filtered: Vec<(String, String)> = fields
            .chunks_exact(3)
            .filter(|triple| self.filter_drivers.iter().any(|d| d == triple[2]))
            .map(|triple| (triple[0].to_string(), triple[2].to_string()))
            .collect();
        filtered.sort();
        Ok(filtered)
    }

    /// What was established when the repository was opened.
    pub fn facts(&self) -> &RepoFacts {
        &self.facts
    }

    /// `git --version`, trimmed.
    pub fn version(&self) -> &str {
        &self.facts.version
    }

    /// The working tree root.
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// How many git processes this handle has started.
    ///
    /// Asserted rather than merely observed by the perf gate: a refactor that
    /// turns one batched `cat-file` into one spawn per file reads as a modest
    /// slowdown on a laptop and as a timeout on a 100k-file repository
    /// (PREMORTEM T6). The count is the early warning; the clock is the late one.
    pub fn spawn_count(&self) -> u64 {
        self.spawns.load(Ordering::Relaxed)
    }

    /// Reset the spawn counter. For harnesses that measure a sub-range.
    pub fn reset_spawn_count(&self) {
        self.spawns.store(0, Ordering::Relaxed);
    }

    /// Build a hygienic git invocation.
    ///
    /// Public because tests and the perf-fixture generator need to run git too,
    /// and the invariant worth protecting is not "few callers" but "one
    /// construction site". Everything that goes out through here carries
    /// [`PINNED_CONFIG`], a swept environment, and a counted spawn — which is
    /// more than a hand-rolled `Command` in a test file would.
    pub fn cmd<I, S>(&self, args: I) -> GitCommand
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.build(args, true)
    }

    /// Build an invocation that lets the checkout's own check-in conversion
    /// speak.
    ///
    /// The deliberate hole, and the second one in this module — see
    /// [`GitCommand::env`] for the first.
    ///
    /// It answers one question, in one caller: *was this file edited, or does it
    /// merely look edited because the checkout that produced it disagrees with
    /// our pins about line endings?* An answer to that has to be given in the
    /// checkout's own terms, because the checkout is what wrote the bytes. No
    /// OID this produces is ever recorded — it decides membership of the dirty
    /// set, and the members are then hashed under the full pins.
    ///
    /// # Exactly what is relaxed
    ///
    /// One rule covers all of it: **everything that defines this checkout's
    /// conversion speaks; everything else is pinned or swept.**
    ///
    /// - [`CONVERSION_CONFIG`] is not pinned, so the three keys resolve from
    ///   config files as git normally resolves them.
    /// - [`SYSTEM_SUPPRESSION_ENV`] is not set, so the *system* config and
    ///   attributes files are read. This is not a corner: Git for Windows ships
    ///   `core.autocrlf=true` in `etc/gitconfig`, so on a fresh install the
    ///   setting that produced the CRLF on disk exists **only** at system scope.
    ///   Suppressing it left exactly the failure this method was added to fix,
    ///   one scope over.
    /// - [`CONFIG_LOCATION_ENV`] survives the sweep, because where a machine
    ///   keeps its config is part of how it resolved that config. Injection
    ///   variables — `GIT_CONFIG_COUNT` and its keys and values — do not: they
    ///   invent settings no file holds. An ambient `GIT_CONFIG_NOSYSTEM` is
    ///   swept too; it suppresses rather than locates.
    ///
    /// Everything else is untouched: the rest of the environment sweep, and
    /// every other pin. `-c` outranks every config file, so what the relaxation
    /// above can actually change is line-ending translation.
    ///
    /// # What it costs
    ///
    /// Line-ending translation, and nothing else. An earlier version of this
    /// paragraph also conceded a filter surface here — a system or global
    /// attributes file naming a `filter` putting a program in this spawn's path
    /// — and argued it was acceptable because the pinned spawn ran the
    /// repository's filters anyway. Both halves were wrong: running a program
    /// the repository defines is not something a static-analysis lane may do at
    /// any scope, and the pinned spawn no longer does it either. The filter pins
    /// are applied here as well, so what this spawn relaxes is the conversion
    /// keys and the config scopes they resolve from, which is the whole of the
    /// residual.
    pub(crate) fn cmd_in_checkout_conversion<I, S>(&self, args: I) -> GitCommand
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.build(args, false)
    }

    fn build<I, S>(&self, args: I, pin_conversion: bool) -> GitCommand
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new("git");
        command.current_dir(&self.workdir);
        Self::sanitize_env(&mut command, pin_conversion);
        for (key, value) in PINNED_CONFIG {
            if !pin_conversion && CONVERSION_CONFIG.contains(key) {
                continue;
            }
            command.arg("-c").arg(format!("{key}={value}"));
        }
        // Applied on the checkout-conversion spawn too. Conversion is what that
        // spawn relaxes; running the repository's programs is not, and a clean
        // filter reached through a system attributes file would be exactly that.
        for pin in self.filter_pins.iter() {
            command.arg("-c").arg(pin);
        }
        // Belt to the `GIT_NO_REPLACE_OBJECTS` brace: the flag works on git
        // builds that predate honouring the variable everywhere.
        command.arg("--no-replace-objects");
        let mut argv: Vec<OsString> = Vec::new();
        for arg in args {
            let arg = arg.as_ref().to_os_string();
            command.arg(&arg);
            argv.push(arg);
        }
        GitCommand {
            command,
            argv,
            spawns: Arc::clone(&self.spawns),
        }
    }

    /// Remove every inherited `GIT_*` variable, then set the fixed ones.
    ///
    /// Sweeping is the point. Enumerating the dangerous variables means the list
    /// is correct until git adds one, and the failure mode of being wrong is
    /// silent: the measurement still succeeds, it just measured something else.
    fn sanitize_env(command: &mut Command, pin_conversion: bool) {
        for (key, _) in std::env::vars_os() {
            let Some(key) = key.to_str() else { continue };
            // `GIT_EXEC_PATH` locates git's own subcommands. Some MSYS and
            // container installs set it and break without it.
            if key == "GIT_EXEC_PATH" || !key.starts_with("GIT_") {
                continue;
            }
            // On the checkout-conversion spawn, the variables that *locate* a
            // config file survive: where this machine keeps its config is part
            // of how it decided what to write to disk. `GIT_CONFIG_NOSYSTEM` is
            // not one of them — it suppresses rather than locates, and an
            // ambient one would silently reintroduce the blindness this spawn
            // exists to remove.
            if !pin_conversion && CONFIG_LOCATION_ENV.contains(&key) {
                continue;
            }
            command.env_remove(key);
        }
        for (key, value) in FORCED_ENV {
            if !pin_conversion && SYSTEM_SUPPRESSION_ENV.contains(key) {
                continue;
            }
            command.env(key, value);
        }
    }
}

/// A prepared git invocation. Spawning it is what increments the counter.
#[derive(Debug)]
pub struct GitCommand {
    command: Command,
    argv: Vec<OsString>,
    spawns: Arc<AtomicU64>,
}

impl GitCommand {
    /// Append an argument.
    pub fn arg<S: AsRef<OsStr>>(mut self, arg: S) -> Self {
        let arg = arg.as_ref().to_os_string();
        self.command.arg(&arg);
        self.argv.push(arg);
        self
    }

    /// Append several arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self = self.arg(arg);
        }
        self
    }

    /// Set an environment variable *after* sanitization.
    ///
    /// The deliberate hole, and a narrow one: building a fixture repository
    /// needs `GIT_AUTHOR_DATE` and friends to make commit OIDs reproducible, and
    /// those are exactly the variables production code must never inherit.
    /// Putting the override at the call site keeps it visible in review;
    /// nothing in the measurement path uses it.
    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(mut self, key: K, value: V) -> Self {
        self.command.env(key, value);
        self
    }

    /// Run, and return raw stdout. Fails on a non-zero exit.
    pub fn output(mut self) -> Result<Vec<u8>, GitError> {
        self.spawns.fetch_add(1, Ordering::Relaxed);
        let output = self.command.output().map_err(|source| GitError::Spawn {
            argv: self.rendered_argv(),
            source,
        })?;
        if !output.status.success() {
            return Err(GitError::Failed {
                argv: self.rendered_argv(),
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        Ok(output.stdout)
    }

    /// Run, and return stdout as UTF-8.
    pub fn text(self) -> Result<String, GitError> {
        let argv = self.rendered_argv();
        let bytes = self.output()?;
        String::from_utf8(bytes).map_err(|_| GitError::NotUtf8 { argv })
    }

    /// Run, and report only whether it exited zero.
    ///
    /// For the questions git answers by exit code — does this object exist, is
    /// this commit an ancestor of that one — where a non-zero exit is an answer
    /// rather than a failure.
    pub fn succeeds(mut self) -> Result<bool, GitError> {
        self.spawns.fetch_add(1, Ordering::Relaxed);
        let output = self.command.output().map_err(|source| GitError::Spawn {
            argv: self.rendered_argv(),
            source,
        })?;
        Ok(output.status.success())
    }

    /// Run, returning stdout on success and `None` on the documented miss.
    ///
    /// For the plumbing commands that answer "there is no such thing" by
    /// exiting 1 with an empty stdout — `merge-base` with no common ancestor,
    /// `rev-parse --verify --quiet` on an unknown revision. Treating those as
    /// errors would turn a legitimate answer into a failure, and treating them
    /// as empty success would turn it into a fabricated one.
    ///
    /// **Exit 1 only.** Git reserves 128 for what it calls fatal — not a
    /// repository, a malformed revision, a reflog shorter than the entry asked
    /// for — and a process killed by a signal reports no code at all. Folding
    /// those into `None` answers "there is no such thing" to a question git
    /// never got round to considering, and discards the stderr line that says
    /// what actually went wrong. Measured, not assumed: `rev-parse --verify
    /// --quiet` on an unknown ref exits 1, in a directory that is not a
    /// repository it exits 128, and on `@{99}` it exits 128 with a message about
    /// how many reflog entries there are — which is worth more to whoever reads
    /// it than "does not resolve to a commit".
    pub fn succeeds_with_output(mut self) -> Result<Option<String>, GitError> {
        self.spawns.fetch_add(1, Ordering::Relaxed);
        let output = self.command.output().map_err(|source| GitError::Spawn {
            argv: self.rendered_argv(),
            source,
        })?;
        if !output.status.success() {
            return if output.status.code() == Some(1) {
                Ok(None)
            } else {
                Err(GitError::Failed {
                    argv: self.rendered_argv(),
                    status: output.status.to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
                })
            };
        }
        String::from_utf8(output.stdout)
            .map(Some)
            .map_err(|_| GitError::NotUtf8 {
                argv: self.rendered_argv(),
            })
    }

    /// Start the process with stdin and stdout piped, for the batch protocols.
    pub fn spawn_piped(mut self) -> Result<Child, GitError> {
        self.spawns.fetch_add(1, Ordering::Relaxed);
        self.command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| GitError::Spawn {
                argv: self.rendered_argv(),
                source,
            })
    }

    /// The subcommand and its arguments, for error messages. Config pins are
    /// omitted: they are on every invocation and would bury the interesting part.
    pub(crate) fn rendered_argv(&self) -> String {
        self.argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pinned_key_is_unique() {
        let mut keys: Vec<&str> = PINNED_CONFIG.iter().map(|(k, _)| *k).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "a key is pinned twice with two values");
    }

    #[test]
    fn the_pins_that_carry_the_determinism_property_are_present() {
        // Named individually so that deleting one is a test failure with a
        // reason attached, rather than a silently shorter list.
        for key in [
            "core.quotepath",
            "core.autocrlf",
            "core.eol",
            "core.hooksPath",
            "diff.external",
            "diff.algorithm",
            "diff.renames",
            "diff.renameLimit",
        ] {
            assert!(
                PINNED_CONFIG.iter().any(|(k, _)| *k == key),
                "{key} must stay pinned: PREMORTEM T1"
            );
        }
    }

    #[test]
    fn every_conversion_key_is_actually_pinned_in_the_first_place() {
        // `CONVERSION_CONFIG` is subtracted from `PINNED_CONFIG` by name. A
        // typo, or a rename on one side only, would silently subtract nothing —
        // and the suspect re-check would then ask the same pinned question
        // twice and always agree with itself.
        for key in CONVERSION_CONFIG {
            assert!(
                PINNED_CONFIG.iter().any(|(k, _)| k == key),
                "{key} is named as a conversion pin but is not pinned"
            );
        }
        assert!(
            !CONVERSION_CONFIG.contains(&"core.safecrlf"),
            "safecrlf only ever turns a conversion into an error, so unpinning \
             it would let a hostile config fail the re-check rather than answer it"
        );
    }

    #[test]
    fn fsmonitor_is_not_pinned() {
        // Pinning it would cost the incremental dirty-tree path that keeps
        // PREMORTEM T6 off the table. Asserted so the reason survives a sweep
        // that adds "every core.* key" for tidiness.
        assert!(!PINNED_CONFIG.iter().any(|(k, _)| *k == "core.fsmonitor"));
    }
}
