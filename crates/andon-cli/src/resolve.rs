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
use andon_core::schema::payload::CompareContext;

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
    /// The repository's HEAD has no parent and the caller named no base.
    ///
    /// The one honest dead end. There is no earlier state to compare against,
    /// so every alternative would mean measuring something against itself and
    /// reporting the result as a change.
    #[error(
        "this repository has a single commit ({head_short}) and no earlier state to compare it \
         against, so there is no change to measure. Commit something, or name both ends \
         explicitly: `andon measure --base <rev> --head <rev>`"
    )]
    NoParent {
        /// Abbreviated HEAD, so the message names the commit it is about.
        head_short: String,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substitution {
    /// What the caller's arguments resolved to, in the caller's own terms.
    pub asked_for: String,
    /// What was measured instead.
    pub measured: String,
    /// Why, in one sentence, for a reader who has only the report.
    pub because: String,
}

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
    let head = Revision::Rev(head_spec.clone());
    // Read once, before any branch, so every outcome can disclose it.
    let uncommitted = uncommitted_paths(git)?;

    // An explicit base is obeyed exactly, including when it yields an empty
    // change. A caller who named both ends asked a specific question, and
    // answering a different one would be the substitution this module exists to
    // make visible, done silently.
    if let Some(spec) = &request.base {
        let base = parse_base(spec);
        let range = ResolvedRange::resolve(git, &base, &head)?;
        let compare_context = range.compare_context()?;
        let changed = ChangedSet::enumerate(git, &range)?;
        let how = format!(
            "{} → {} ({})",
            short(&compare_context.base_oid),
            short(&compare_context.head_oid),
            compare_context.base_resolution
        );
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
        let Ok(range) = ResolvedRange::resolve(git, &base, &head) else {
            // A candidate that exists but shares no history — an unrelated
            // remote, a grafted branch. Not an error: the next candidate may be
            // the right one, and the failure is reported only if none is.
            continue;
        };
        let compare_context = range.compare_context()?;
        let changed = ChangedSet::enumerate(git, &range)?;
        if !changed.is_empty() {
            let how = format!(
                "{} → {} (fork point against {candidate})",
                short(&compare_context.base_oid),
                short(&compare_context.head_oid),
            );
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

    // Nothing has been *committed* ahead of the fork point. Two very different
    // situations reach this line, and telling them apart is the whole of the
    // decision below.
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
        return Err(ResolveFailure::NoParent {
            head_short: short(&rev_parse(git, &head_spec)?),
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
        .filter(|path| !path.is_empty())
        .map(|path| path.to_string())
        .collect())
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
