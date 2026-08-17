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

/// The pinned keys that decide check-in conversion.
///
/// A named group because one code path has to *not* apply them — see
/// [`Git::cmd_in_checkout_conversion`] and the module docs. `core.safecrlf` is
/// deliberately absent: it only ever turns a conversion into a warning or an
/// error, never into different bytes, so leaving it pinned off costs nothing and
/// keeps a hostile config from failing the re-check outright.
pub const CONVERSION_CONFIG: &[&str] = &["core.autocrlf", "core.eol", "core.attributesFile"];

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
    /// Costs two spawns: one `git --version`, one batched `rev-parse` that
    /// answers every remaining question at once. Both are counted, because a
    /// caller's spawn budget has to cover what opening the repository costs.
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
        })
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
    /// [`GitCommand::env`] for the first. [`CONVERSION_CONFIG`] is left off; the
    /// environment sweep, the system-file suppression, and every other pin stay
    /// exactly as they are, so what a repository or a `~/.gitconfig` gets to
    /// decide here is line-ending translation and nothing else.
    ///
    /// It answers one question, in one caller: *was this file edited, or does it
    /// merely look edited because the checkout that produced it disagrees with
    /// our pins about line endings?* An answer to that has to be given in the
    /// checkout's own terms, because the checkout is what wrote the bytes. No
    /// OID this produces is ever recorded — it decides membership of the dirty
    /// set, and the members are then hashed under the full pins.
    ///
    /// `GIT_ATTR_NOSYSTEM=1` stays set. A system-wide attributes file could in
    /// principle be part of a checkout's conversion, and unsweeping the
    /// environment to find out would widen this hole from three config keys to
    /// everything git reads from the machine. The residual is a
    /// system-attributes checkout still reporting phantom dirt; the trade is
    /// deliberate.
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
        Self::sanitize_env(&mut command);
        for (key, value) in PINNED_CONFIG {
            if !pin_conversion && CONVERSION_CONFIG.contains(key) {
                continue;
            }
            command.arg("-c").arg(format!("{key}={value}"));
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
    fn sanitize_env(command: &mut Command) {
        for (key, _) in std::env::vars_os() {
            let Some(key) = key.to_str() else { continue };
            // `GIT_EXEC_PATH` locates git's own subcommands. Some MSYS and
            // container installs set it and break without it.
            if key.starts_with("GIT_") && key != "GIT_EXEC_PATH" {
                command.env_remove(key);
            }
        }
        for (key, value) in FORCED_ENV {
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
