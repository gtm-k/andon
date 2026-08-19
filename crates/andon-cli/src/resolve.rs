//! Deciding what to measure, and saying so.
//!
//! # The failure this module exists to prevent
//!
//! PREMORTEM A1, rated fatal: *"the stranger's very first command on a clean
//! checkout returned nothing (base == head → empty diff → empty report)"*. The
//! shape of the mistake is that the first-run path was specified for a
//! repository with work in flight, which is exactly what a person evaluating the
//! tool does not have. They clone something, run one command, and judge the tool
//! on what comes back.
//!
//! So there are two separate defences here and they answer different failures.
//!
//! **The base ladder** answers *"I have no idea what this repository looks
//! like"*. `andon-spike`'s default base is `merge-base:origin/main`, which is
//! correct inside this project and errors outright on a repository whose default
//! branch is `master`, or `trunk`, or which has no remote at all because someone
//! ran `git init` an hour ago. An error is not as bad as an empty report, but it
//! is still a first command that produced no measurement.
//!
//! **The no-diff fallback** answers *"there is nothing in flight"*. When the
//! resolved range turns out to contain no changed files, the measurement moves
//! to the last merged change — `HEAD~1..HEAD` — and **says that it did**. The
//! saying is the load-bearing half: a tool that quietly measures something other
//! than what was asked for has told the reader a falsehood about what the
//! numbers are about. Every renderer shows [`Substitution`], and the record
//! itself carries [`FALLBACK_RESOLUTION`] in
//! [`CompareContext::base_resolution`], so the substitution survives being
//! serialized, emailed, and read by someone who never saw the terminal.
//!
//! # What is deliberately not done
//!
//! Neither defence invents a base. Every candidate is a revision the repository
//! actually resolves, and a repository whose HEAD is a root commit with nothing
//! before it gets a refusal that names the situation ([`ResolveFailure`]) rather
//! than a measurement of nothing against nothing. There is no arrangement in
//! which this module returns a range it cannot justify.

use andon_core::git::{ChangedSet, Git, ResolveError, ResolvedRange, Revision};
use andon_core::schema::payload::{CompareContext, HeadKind};

/// The `base_resolution` written when the no-diff fallback fired.
///
/// `andon_core::git::resolve` produces `head`, `explicit`, and `merge-base`, and
/// none of them describes "the caller asked for the working change, there was
/// not one, and this is the last merged change instead". The field is
/// documented as an open description of how the base was arrived at, it is
/// outside `ResultDigestInput`, and nothing in the workspace branches on its
/// value — so extending the vocabulary here records the substitution as a fact
/// about the record rather than as prose in one renderer.
pub const FALLBACK_RESOLUTION: &str = "no-diff-fallback:last-merged-change";

/// Revision specs tried, in order, when the caller names no base.
///
/// Ordered from most to least likely to be the fork point of work in flight.
/// `@{upstream}` is first because a branch that declares one has answered the
/// question directly; the rest are the conventional names, and every one of them
/// is probed rather than assumed.
const BASE_CANDIDATES: &[&str] = &[
    "@{upstream}",
    "origin/HEAD",
    "origin/main",
    "origin/master",
    "upstream/main",
    "main",
    "master",
];

/// Why no range could be resolved at all.
#[derive(Debug, thiserror::Error)]
pub enum ResolveFailure {
    /// The repository's HEAD has no parent this checkout can see.
    ///
    /// The one honest dead end: there is no earlier state to compare against, so
    /// every alternative would mean measuring something against itself and
    /// reporting the result as a change.
    ///
    /// # Why it asks whether the clone is shallow
    ///
    /// "Commit something" is the remedy for a repository with one commit in it.
    /// It is the wrong remedy, and a false statement, for the far more common
    /// way to reach this: `actions/checkout` with `fetch-depth: 1`, the default
    /// CI checkout, where the earlier state exists and simply was not fetched.
    /// Telling that operator to commit something sends them away from the one
    /// command that fixes it.
    ///
    /// `git.facts().shallow` is the same fact [`ResolveError::NoMergeBase`]
    /// already reads for the same reason; this is that reading applied one
    /// dead end over.
    #[error(
        "{}. {}",
        if *.shallow {
            format!(
                "this is a shallow clone and {head_short} is at the boundary of the history it \
                 was given, so there is no earlier state here to compare it against — the \
                 commits before it exist, they were just not fetched"
            )
        } else {
            format!(
                "this repository has a single commit ({head_short}) and no earlier state to \
                 compare it against, so there is no change to measure"
            )
        },
        if *.shallow {
            "Fetch the rest — `git fetch --unshallow`, or `--deepen <n>` — or name both ends \
             explicitly: `andon measure --base <rev> --head <rev>`"
        } else {
            "Commit something, or name both ends explicitly: \
             `andon measure --base <rev> --head <rev>`"
        }
    )]
    NoParent {
        /// Abbreviated HEAD, so the message names the commit it is about.
        head_short: String,
        /// Whether the history is truncated rather than absent. Decides which
        /// of two remedies is the true one.
        shallow: bool,
    },
    /// Every base candidate resolved, and none of them left anything to measure.
    ///
    /// `--no-fallback` is a request to be refused rather than handed the last
    /// merged change, so this is the refusal it asked for. It is a separate
    /// variant from [`Self::NoParent`] because it is a separate situation and
    /// the two were merged: `--no-fallback` returned "this repository has a
    /// single commit" on a repository with three, having never asked whether
    /// `HEAD~1` existed. A refusal that misdescribes the repository sends the
    /// reader to fix something that is not broken.
    #[error(
        "there is no working change to measure here: HEAD ({head_short}) matches every base \
         this repository offers ({}), and the tree is clean.\n  \
         `--no-fallback` is what refuses rather than measuring the last merged change instead. \
         Drop it to measure that, or name a base: `andon measure --base <rev>`",
        if .tried.is_empty() { "none were found".to_string() } else { .tried.join(", ") }
    )]
    NoWorkingChange {
        /// Abbreviated HEAD.
        head_short: String,
        /// The base candidates that resolved, in the order they were tried.
        tried: Vec<String>,
    },
    /// There is uncommitted work, and this build cannot measure it.
    ///
    /// # Why this is a refusal and not a fallback
    ///
    /// This is the state the product exists for: an agent that has just written
    /// a change and not committed it. Measuring the last merged change instead
    /// and reporting `pass` is the worst available answer — the caller reads a
    /// verdict about bytes that are not the ones they are asking about, and a
    /// hook keyed on the exit code lets the change through.
    ///
    /// The reason it cannot be measured is a contract, not an oversight.
    /// `andon_core::git::resolve` refuses to build a `CompareContext` from a
    /// dirty endpoint, because the working tree has no commit OID and writing
    /// `HEAD`'s in its place produces a record that passes the verifier's
    /// tuple check while describing bytes that were never committed — the
    /// laundering path R2-4 exists to close, and false `divergent` verdicts on
    /// honest work, which is PREMORTEM Story 1. Every result is sealed against
    /// that context, so there is no arrangement of this crate that measures
    /// uncommitted bytes into a record.
    ///
    /// Staging does not help and the message does not suggest it: an index
    /// endpoint is dirty too and errors identically.
    #[error(
        "there is uncommitted work here ({}), and this build measures committed content \
         only.\n  \
         A measurement is sealed against a (base, head) commit pair, and the working tree has \
         no commit OID — writing HEAD's in its place would describe bytes that were never \
         committed, which is the failure the trust model exists to prevent. Staging does not \
         change this.\n  \
         What works now:  commit the change, then re-run `andon measure`.\n  \
         Or, deliberately: `andon measure --last-merged` measures the last merged change \
         instead and says so.",
        summarize(.paths)
    )]
    UncommittedWork {
        /// Every uncommitted path, so the refusal names what it is about.
        paths: Vec<String>,
    },
    /// Git refused.
    #[error(transparent)]
    Git(#[from] ResolveError),
    /// The repository could not be read at all.
    #[error(transparent)]
    Open(#[from] andon_core::git::GitError),
}

/// What was measured in place of what was asked for.
///
/// Absent on every ordinary run. Present exactly when the no-diff fallback
/// fired, and then it must appear in every rendering of the record — the reason
/// it is a value rather than a log line.
///
/// Re-exported from `andon_core` rather than declared here. It used to be a CLI
/// type, which is why it could not be a field on the record and why the
/// sentence above was not true of anything read back from disk: two renderings
/// of one record disagreed about whether it was a substitution at all. A CLI
/// twin of a record's own field is the unconnected-duplicate shape this phase
/// keeps finding.
pub use andon_core::schema::payload::Substitution;

/// A range, the change it covers, and how it was arrived at.
#[derive(Debug)]
pub struct Resolution {
    /// The resolved endpoints.
    pub range: ResolvedRange,
    /// The wire tuple, with [`FALLBACK_RESOLUTION`] substituted when the
    /// fallback fired.
    pub compare_context: CompareContext,
    /// The changed paths.
    pub changed: ChangedSet,
    /// How the base was chosen, in one line, for the terminal header.
    pub how: String,
    /// Present only when something other than the request was measured.
    pub substitution: Option<Substitution>,
    /// Repository-relative paths with uncommitted content at resolution time.
    ///
    /// Carried on **every** path, not just the one that refuses over it. A
    /// branch with commits ahead of its fork point measures those commits, which
    /// is correct — but an agent that has since edited the tree has work this
    /// measurement does not describe, and saying nothing about it leaves the
    /// actor unable to see the one thing that would change how they read the
    /// verdict.
    pub uncommitted: Vec<String>,
}

/// What the caller asked for.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// `--base`: an explicit revision, or `merge-base:<ref>`.
    pub base: Option<String>,
    /// `--head`: defaults to `HEAD`.
    pub head: Option<String>,
    /// `--no-fallback`: refuse rather than measure the last merged change.
    pub no_fallback: bool,
    /// `--last-merged`: measure the last merged change even though there is
    /// uncommitted work, having been told that is what it will do.
    pub last_merged: bool,
}

/// Name the uncommitted paths, and stop before the message becomes a listing.
///
/// Three is enough for a reader to recognise their own change; the count tells
/// them whether the rest is one more file or forty.
fn summarize(paths: &[String]) -> String {
    const SHOWN: usize = 3;
    let head: Vec<&str> = paths.iter().take(SHOWN).map(String::as_str).collect();
    match paths.len().checked_sub(SHOWN) {
        Some(rest) if rest > 0 => format!("{} and {rest} more", head.join(", ")),
        _ => head.join(", "),
    }
}

/// Resolve a range, applying the base ladder and the no-diff fallback.
pub fn resolve(git: &Git, request: &Request) -> Result<Resolution, ResolveFailure> {
    let head_spec = request.head.clone().unwrap_or_else(|| "HEAD".to_string());
    // Read once, before any branch, so every outcome can use it.
    let uncommitted = uncommitted_paths(git)?;

    // THE HEAD IS THE WORKING TREE WHEN THERE IS WORK IN IT.
    //
    // This is the state the product exists for — an agent that has just written
    // a change and not committed it — and it was invisible: the head was always
    // `HEAD`, so `diff-tree base..HEAD` saw committed content only, and a
    // deeply nested function sitting uncommitted read `pass` while the identical
    // bytes committed read `block`.
    //
    // A named `--head` always wins: a caller who pinned both ends asked about
    // two commits, and answering about their working tree instead would be the
    // silent substitution this module exists to prevent. `--last-merged` also
    // opts out, because it is a request for the committed history.
    let head = if uncommitted.is_empty() || request.head.is_some() || request.last_merged {
        Revision::Rev(head_spec.clone())
    } else {
        // Worktree rather than Index: E6's honest union covers staged and
        // unstaged together, and an agent that wrote a file without staging it
        // has still written it. `git add` is not a step this tool should require
        // before it will look.
        Revision::Worktree
    };

    // An explicit base is obeyed exactly, including when it yields an empty
    // change. A caller who named both ends asked a specific question, and
    // answering a different one would be the substitution this module exists to
    // make visible, done silently.
    if let Some(spec) = &request.base {
        let base = parse_base(spec);
        let range = ResolvedRange::resolve(git, &base, &head)?;
        // `wire_context` rather than `compare_context`: the head may be the
        // working tree, and the schema now has a representation for that which
        // does not synthesize a commit OID (P5b mini-G2 ruling).
        let compare_context = range.wire_context()?;
        let changed = ChangedSet::enumerate(git, &range)?;
        let how = describe(&compare_context, &compare_context.base_resolution);
        return Ok(Resolution {
            range,
            compare_context,
            changed,
            how,
            substitution: None,
            uncommitted,
        });
    }

    // No base named. Walk the ladder for a fork point that this repository
    // actually has, and keep the first one that leaves something to measure.
    let mut tried: Vec<&str> = Vec::new();
    for candidate in BASE_CANDIDATES {
        if !rev_exists(git, candidate) {
            continue;
        }
        tried.push(candidate);
        let base = Revision::merge_base(*candidate);
        let range = match ResolvedRange::resolve(git, &base, &head) {
            Ok(range) => range,
            // A candidate that exists but shares no history — an unrelated
            // remote, a grafted branch. Not an error: the next candidate may be
            // the right one, and the failure is reported only if none is.
            Err(ResolveError::NoMergeBase { .. }) => continue,
            // EVERYTHING ELSE IS ABOUT THE REPOSITORY, NOT THE CANDIDATE.
            //
            // This arm used to be a `let ... else { continue }`, and the comment
            // above described what it was meant to catch while the code caught
            // every error there is. `OperationInProgress` is the one that made
            // it visible: mid-merge, mid-rebase, mid-cherry-pick, the detector
            // at the top of `ResolvedRange::resolve` fires correctly, the ladder
            // swallowed it, and every candidate then failed the same way — so
            // the ladder exhausted into a refusal about uncommitted work that
            // suggested `--last-merged`, which the next command refuses with the
            // typed error that was thrown away here. A true statement was
            // discarded and a false one printed in its place.
            //
            // Trying the next candidate cannot help with any of these: they are
            // facts about the repository, and the next candidate is in the same
            // repository.
            Err(other) => return Err(other.into()),
        };
        let compare_context = range.wire_context()?;
        let changed = ChangedSet::enumerate(git, &range)?;
        if !changed.is_empty() {
            let how = describe(&compare_context, &format!("fork point against {candidate}"));
            return Ok(Resolution {
                range,
                compare_context,
                changed,
                how,
                substitution: None,
                uncommitted,
            });
        }
    }

    // Reaching here with a dirty tree means the working-tree head produced no
    // changed set at all — a bare repository with no worktree to resolve, or a
    // snapshot git reported and then could not diff. The representation cannot
    // describe those, so the refusal remains for them, and that is now the only
    // thing it covers: an ordinary dirty tree is measured above.
    if !uncommitted.is_empty() && !request.last_merged {
        return Err(ResolveFailure::UncommittedWork { paths: uncommitted });
    }

    // Genuinely clean. This is the checkout PREMORTEM A1 is about — the stranger
    // who cloned something and ran one command — and the last merged change is a
    // real change with real evidence behind it.
    let asked_for = if tried.is_empty() {
        "the working change (no branch point found)".to_string()
    } else {
        format!("the working change against {}", tried.join(", "))
    };
    if request.no_fallback {
        // Which refusal this is depends on the repository, so it is asked rather
        // than assumed. A root commit really has no earlier state; a repository
        // with history whose HEAD simply matches every candidate has one, and
        // telling its owner to commit something describes a repository they do
        // not have.
        let head_short = short(&rev_parse(git, &head_spec)?);
        if rev_exists(git, &format!("{head_spec}~1")) {
            return Err(ResolveFailure::NoWorkingChange {
                head_short,
                tried: tried.iter().map(|c| c.to_string()).collect(),
            });
        }
        return Err(ResolveFailure::NoParent {
            head_short,
            shallow: git.facts().shallow,
        });
    }
    last_merged_change(git, &head_spec, &asked_for, &uncommitted)
}

/// Repository-relative paths with uncommitted content, staged or not.
///
/// `--porcelain` because the human-readable form is explicitly not a stable
/// interface, and untracked files are included: a new source file nobody has
/// committed is uncommitted work in exactly the sense that matters here.
fn uncommitted_paths(git: &Git) -> Result<Vec<String>, ResolveFailure> {
    let text = git
        .cmd(["status", "--porcelain", "--untracked-files=normal"])
        .text()
        .map_err(|e| ResolveFailure::Git(ResolveError::Git(e)))?;
    Ok(text
        .lines()
        .filter_map(|line| line.get(3..).map(str::trim))
        // A rename is reported as `R  old -> new`, and the path this is about is
        // the destination. Without this the note names `old.ts -> new.ts` as
        // though it were one file — a sentence that does not describe anything
        // in the repository, in a message whose whole job is to name what was
        // not measured.
        //
        // Non-ASCII paths need no handling: `core.quotepath` is pinned off by
        // the hygiene wrapper, so they arrive as themselves rather than
        // octal-escaped.
        .map(|path| path.rsplit(" -> ").next().unwrap_or(path).trim())
        .filter(|path| !path.is_empty())
        .map(|path| path.to_string())
        .collect())
}

/// One line naming the range, with the head's kind said out loud.
///
/// A content hash and a commit OID are both forty-odd hex characters, and a
/// reader glancing at a header has no way to tell them apart. So the header says
/// which it is — an uncommitted head is the single most important fact about
/// what these numbers describe, and it must not be inferable only from the JSON.
fn describe(ctx: &CompareContext, how_base: &str) -> String {
    format!("{} ({how_base})", change_line(ctx))
}

/// The two ends of a measured range, with the head's kind said out loud.
///
/// **Every renderer of a range uses this.** Each one that formatted its own
/// `short(base) → short(head)` printed a dirty head's content hash abbreviated
/// to twelve characters — which is exactly the shape of a commit OID, in a
/// field whose whole job is to say what the numbers are about. `andon report`
/// and `andon wait` did that on a record whose own `head_kind` said
/// `uncommitted-worktree`, so two shipped renderings of one record disagreed.
///
/// The schema's defence for carrying a content hash in `head_oid` is that
/// "nothing downstream will mistake it for one, because this field says not
/// to". That is a claim about readers, and it is only true where a reader reads
/// the field. This is the one place that does it.
pub fn change_line(ctx: &CompareContext) -> String {
    match ctx.head_kind {
        HeadKind::Commit => format!("{} → {}", short(&ctx.base_oid), short(&ctx.head_oid)),
        HeadKind::UncommittedWorktree => {
            format!("{} → your uncommitted working tree", short(&ctx.base_oid))
        }
        HeadKind::UncommittedIndex => format!("{} → your staged changes", short(&ctx.base_oid)),
    }
}

/// `HEAD~1..HEAD`, labelled as the substitution it is.
fn last_merged_change(
    git: &Git,
    head_spec: &str,
    asked_for: &str,
    uncommitted: &[String],
) -> Result<Resolution, ResolveFailure> {
    let head_oid = rev_parse(git, head_spec)?;
    let parent_spec = format!("{head_spec}~1");
    if !rev_exists(git, &parent_spec) {
        return Err(ResolveFailure::NoParent {
            head_short: short(&head_oid),
            // The default path with no flags reaches here, which is what makes
            // the shallow case PREMORTEM A1 rather than a corner: a CI checkout
            // at `fetch-depth: 1` is a stranger's first command.
            shallow: git.facts().shallow,
        });
    }

    let range = ResolvedRange::resolve(
        git,
        &Revision::Rev(parent_spec),
        &Revision::Rev(head_spec.to_string()),
    )?;
    let mut compare_context = range.compare_context()?;
    // The record's own account of how it got here. Overwritten rather than left
    // as `explicit`, because `explicit` would say the caller named this base and
    // the caller did not.
    compare_context.base_resolution = FALLBACK_RESOLUTION.to_string();
    let changed = ChangedSet::enumerate(git, &range)?;

    let how = format!(
        "{} → {} (last merged change)",
        short(&compare_context.base_oid),
        short(&compare_context.head_oid),
    );
    let measured = format!(
        "the last merged change, {}..{}",
        short(&compare_context.base_oid),
        short(&compare_context.head_oid)
    );
    Ok(Resolution {
        range,
        compare_context,
        changed,
        how,
        uncommitted: uncommitted.to_vec(),
        substitution: Some(Substitution {
            asked_for: asked_for.to_string(),
            measured,
            // Two different situations reach this line and they need two
            // different sentences. Saying "nothing is in flight" over a dirty
            // tree is false about the one thing the reader can check in a
            // single command, and it is the defect class this phase inherited
            // three instances of: a statement that contradicts the state it
            // describes. So the sentence reads the state.
            because: if uncommitted.is_empty() {
                "nothing is in flight in this checkout, so there was no working change to \
                 measure. These numbers describe the most recent commit, not uncommitted work."
                    .to_string()
            } else {
                format!(
                    "there IS uncommitted work here ({}), and these numbers are not about \
                     it. You asked for the last merged change; this build cannot measure \
                     uncommitted bytes into a record, because a measurement is sealed \
                     against a (base, head) commit pair and the working tree has no commit \
                     OID.",
                    summarize(uncommitted)
                )
            },
        }),
    })
}

/// `merge-base:<ref>` or a plain revision, matching `andon-spike`'s spelling.
fn parse_base(spec: &str) -> Revision {
    match spec.strip_prefix("merge-base:") {
        Some(reference) => Revision::merge_base(reference),
        None => Revision::Rev(spec.to_string()),
    }
}

/// Whether a revision resolves to a commit in this repository.
///
/// Both of git's refusal shapes are treated as "no": exit 1 becomes `Ok(None)`
/// inside the wrapper, and exit 128 — which is what `HEAD~1` produces on a root
/// commit — arrives as an error. Distinguishing them here would make the
/// behaviour depend on which of two spellings a given git version chose for the
/// same fact.
fn rev_exists(git: &Git, spec: &str) -> bool {
    matches!(
        git.cmd([
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &format!("{spec}^{{commit}}"),
        ])
        .succeeds_with_output(),
        Ok(Some(_))
    )
}

/// Resolve a revision to a full OID, or say git refused.
fn rev_parse(git: &Git, spec: &str) -> Result<String, ResolveFailure> {
    let output = git
        .cmd([
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &format!("{spec}^{{commit}}"),
        ])
        .succeeds_with_output()
        .map_err(|e| ResolveFailure::Git(ResolveError::Git(e)))?;
    output.map(|text| text.trim().to_string()).ok_or_else(|| {
        ResolveFailure::Git(ResolveError::UnknownRevision {
            rev: spec.to_string(),
        })
    })
}

/// Twelve characters, the length git itself prints in most contexts.
pub fn short(oid: &str) -> String {
    oid.chars().take(12).collect()
}
