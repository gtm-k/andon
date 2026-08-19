//! Finding the clones: seeds from equal window hashes, extension, exact
//! confirmation, and the numbers that come out.
//!
//! # The file set is an input, never a side effect of the index
//!
//! Detection runs over the paths handed to [`detect`], not over everything the
//! index happens to hold. That is the difference between a number the verifier
//! can reproduce and one that depends on which files this machine measured last
//! week: the index is a cache of per-file fingerprints and contributes no
//! members of its own. PLAN P3 requires that only cold-reproducible values enter
//! the compare set, and this is where that is decided.
//!
//! The consequence is honest and worth stating: v1 finds duplication *within
//! the measured set*. Passing a wider set — the whole repository — is the
//! caller's choice and changes the numbers, which is why the set size is
//! reported alongside them.
//!
//! # A hash match is a candidate, never a finding
//!
//! Every extended match is confirmed by comparing the symbol slices themselves.
//! A Rabin-Karp collision therefore costs a comparison and cannot produce a
//! clone that is not one. In a compare-set value, "almost certainly right" is
//! not a property worth having.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use crate::fingerprint::{
    self, MIN_CLONE_TOKENS, REGION_PAIR_BUDGET, SATURATED_OCCURRENCES, WINDOW_TOKENS,
};
use crate::index::Index;

/// One side of a clone.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fragment {
    /// Repository-relative path.
    pub path: String,
    /// Index of the first token in the fragment.
    pub token_start: u32,
    /// Number of tokens.
    pub token_len: u32,
    /// First line of the fragment, 1-based.
    pub line_start: u32,
    /// Last line of the fragment, 1-based.
    pub line_end: u32,
}

/// A set of fragments with identical normalized token sequences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneGroup {
    /// Length of the shared sequence, in tokens.
    pub token_len: u32,
    /// Every place it appears, sorted.
    pub fragments: Vec<Fragment>,
}

/// What detection found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CloneReport {
    /// Distinct duplicated sequences worth reporting, longest first.
    ///
    /// A *deduplicated* view: overlapping groups are collapsed so one
    /// duplicated region is described once. It is therefore not a partition of
    /// [`CloneReport::duplicated_tokens_by_path`] and the two can legitimately
    /// disagree — five files can hold a copy while the group list names two of
    /// them, because a longer clone between that pair won the region. The
    /// counts are the coverage; this is the description.
    pub groups: Vec<CloneGroup>,
    /// Tokens covered by at least one confirmed clone fragment, per path.
    ///
    /// A union over every confirmed match, taken before group selection — see
    /// the note in [`detect`] on why the two answers come from different sets.
    pub duplicated_tokens_by_path: BTreeMap<String, u32>,
    /// The longest unbroken duplicated stretch in each file, as lines.
    ///
    /// # Why the longest run and not the whole covered envelope
    ///
    /// Coverage is a set of token positions and can be full of holes: a file
    /// with a copied helper at the top and another at the bottom is duplicated
    /// in two places and ordinary in between. A span from the first covered
    /// token to the last would say the whole file is a copy, which is a
    /// different and false claim. The longest contiguous run is the one place a
    /// reader should open first, and it is a statement the coverage set
    /// actually supports.
    ///
    /// Present for exactly the paths in [`CloneReport::duplicated_tokens_by_path`]
    /// with a non-zero count — including the files that hold a copy but appear
    /// in no reported group, which is the case `groups` alone cannot answer.
    pub duplicated_span_by_path: BTreeMap<String, LineRange>,
    /// Tokens in the measured set, per path.
    pub tokens_by_path: BTreeMap<String, u32>,
    /// Paths whose duplication was searched with part of the candidate set
    /// never enumerated.
    ///
    /// The saturation cap pairs an occurrence with a bounded set of partners
    /// rather than with all of them, and [`bounded_partners`] derives that set
    /// from the *regions* the repetition falls into — which costs occurrences
    /// times regions. Above `REGION_PAIR_BUDGET` the region list is sampled
    /// instead of walked, and a sampled search is one that did not look
    /// everywhere. Every result over a path in this set is reported `partial`
    /// rather than `complete`: the number is still the union of what was
    /// confirmed, and what stops is the claim that it is the whole answer.
    ///
    /// Empty on ordinary content, and on repetitive content whose regions the
    /// budget covers — which is the point. A caveat that arrived on every
    /// generated file would say nothing about the one where the search really
    /// was cut short.
    ///
    /// The budget is spent per file and this holds the files that reached their
    /// own. It used to hold every file that merely shared a hash bucket with
    /// one that did, so a one-region file whose walk cost nothing was told its
    /// regions had been sampled. See [`Runs::work_by_file`].
    pub truncated_paths: BTreeSet<String>,
}

/// A 1-based inclusive range of lines.
///
/// Deliberately this crate's own type rather than P0's `LineSpan`: `detect` is
/// the pure detection layer and has no schema dependency, and the engine
/// converts on the way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LineRange {
    /// First line, 1-based and inclusive.
    pub start: u32,
    /// Last line, 1-based and inclusive.
    pub end: u32,
}

impl CloneReport {
    /// Tokens covered by at least one clone fragment, across the set.
    pub fn duplicated_tokens(&self) -> u64 {
        self.duplicated_tokens_by_path
            .values()
            .map(|v| *v as u64)
            .sum()
    }

    /// Tokens in the measured set.
    pub fn total_tokens(&self) -> u64 {
        self.tokens_by_path.values().map(|v| *v as u64).sum()
    }

    /// Duplicated tokens as a proportion of the set. Zero on an empty set —
    /// there is no duplication in nothing, and a NaN cannot ride the wire.
    pub fn duplicated_ratio(&self) -> f64 {
        let total = self.total_tokens();
        if total == 0 {
            return 0.0;
        }
        self.duplicated_tokens() as f64 / total as f64
    }

    /// Longest clone found, in tokens.
    pub fn largest_clone_tokens(&self) -> u64 {
        self.groups
            .iter()
            .map(|g| g.token_len as u64)
            .max()
            .unwrap_or(0)
    }
}

/// A clone group's identity: length, a hash of the shared normalized sequence,
/// and its first and last symbols. Two fragments belong together when all four
/// agree.
///
/// # Why the endpoints are in the key
///
/// Every *pair* in a group was confirmed symbol by symbol, so no member is in it
/// by accident. What the hash alone left open was two independently-correct
/// groups of the same length colliding into one — reporting "these six places
/// are the same code" when they are two sets of three. The endpoints cost two
/// `u64` comparisons and remove the cheapest way for that to happen. It remains
/// possible in principle; [`sequence_hash`] says so rather than claiming the
/// hash is a proof.
type GroupKey = (u32, u64, u64, u64);

/// Where a fragment starts: index into the measured file list, then token
/// offset within that file.
type Placement = (u32, u32);

/// Where one window sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Occurrence {
    file: u32,
    window: u32,
}

/// Detect clones among `paths`, using the fingerprints in `index`.
///
/// Paths absent from the index — a language with no grammar here, or a file
/// shorter than one window — contribute nothing and are simply not represented.
pub fn detect(index: &Index, paths: &[String]) -> CloneReport {
    detect_with_cap(index, paths, SATURATED_OCCURRENCES)
}

/// [`detect`], with the saturation cap supplied rather than taken from
/// [`SATURATED_OCCURRENCES`].
///
/// Exists so the oracle is runnable rather than remembered. Every exact value in
/// `tests/periodic_saturation.rs` used to be a number somebody measured once
/// against a locally-edited constant and pasted into an assertion, which is a
/// disclosure that decays silently: the residual the registry publishes is a
/// ratio between the capped answer and the uncapped one, and nothing recomputed
/// it. Passing `usize::MAX` here runs the pairwise expansion the cap replaces,
/// so a test can assert the two answers against each other on any shape.
pub fn detect_with_cap(index: &Index, paths: &[String], saturation_cap: usize) -> CloneReport {
    // Sorted, deduplicated, and restricted to what the index actually holds:
    // the traversal order below is the report order, so it has to be ours
    // rather than the caller's.
    let files: Vec<&String> = paths
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|path| index.files.contains_key(*path))
        .collect();

    let mut report = CloneReport::default();
    for path in &files {
        let entry = &index.files[*path];
        report
            .tokens_by_path
            .insert((*path).clone(), entry.token_count() as u32);
    }

    let mut postings: BTreeMap<u64, Vec<Occurrence>> = BTreeMap::new();
    for (file, path) in files.iter().enumerate() {
        for (window, hash) in index.files[*path].windows.iter().enumerate() {
            postings.entry(*hash).or_default().push(Occurrence {
                file: file as u32,
                window: window as u32,
            });
        }
    }

    let symbols: Vec<&[u64]> = files
        .iter()
        .map(|path| index.files[*path].symbols.as_slice())
        .collect();

    // Keyed by the shared sequence, so two fragments land in one group exactly
    // when they are the same code.
    let mut groups: BTreeMap<GroupKey, BTreeSet<Placement>> = BTreeMap::new();
    // Files that took part in a bucket whose region enumeration was sampled.
    let mut truncated_files: BTreeSet<u32> = BTreeSet::new();

    for occurrences in postings.values() {
        if occurrences.len() < 2 {
            continue;
        }
        // A saturated bucket pairs each occurrence with a **bounded set** of
        // partners instead of with all of them. See `bounded_partners` for
        // which ones and why, and `fingerprint::SATURATED_OCCURRENCES` for the
        // cost this is buying and the wrong number the previous rule produced.
        let saturated = occurrences.len() > saturation_cap;
        let runs = if saturated {
            Runs::of(occurrences)
        } else {
            Runs::default()
        };
        // Laying every region against every occurrence is what makes the
        // answer over interrupted repetition right, and it costs occurrences
        // times regions. Above the budget the region list is sampled instead —
        // the one place this pass knows it did not look everywhere — so the
        // files it touched are recorded and reported `partial`, rather than a
        // sampled search being handed on as a finished one.
        //
        // Per file, because the walk breaks at the first foreign region and no
        // file's cost has ever depended on another's. See `Runs::work_by_file`
        // for the file this used to demote for its neighbour's repetition.
        let over_budget: BTreeSet<u32> = if saturated {
            runs.work_by_file(occurrences)
                .into_iter()
                .filter(|(_, work)| *work > REGION_PAIR_BUDGET)
                .map(|(file, _)| file)
                .collect()
        } else {
            BTreeSet::new()
        };
        truncated_files.extend(&over_budget);
        for (i, a) in occurrences.iter().enumerate() {
            let truncated = over_budget.contains(&a.file);
            let rest = &occurrences[i + 1..];
            let partners: Cow<'_, [Occurrence]> = if saturated {
                Cow::Owned(bounded_partners(
                    occurrences,
                    i,
                    symbols[a.file as usize].len() as u32,
                    &runs,
                    truncated,
                ))
            } else {
                Cow::Borrowed(rest)
            };
            for b in partners.iter() {
                // Seeds only. If the preceding window pair also matches, this
                // pair is the interior of a match already being extended from
                // its own start, and extending it again would report the same
                // clone once per token.
                if preceded_by_a_match(&symbols, a, b) {
                    continue;
                }
                // Two windows of one file must not overlap, or every run of
                // repeated syntax reports as a clone of itself.
                if a.file == b.file && b.window < a.window + WINDOW_TOKENS {
                    continue;
                }
                let len = extend(&symbols, a, b);
                if len < MIN_CLONE_TOKENS {
                    continue;
                }
                // Overlapping self-clones are reported at the length that keeps
                // them disjoint; beyond that the two halves share tokens and the
                // "duplicate" is one run of repetition counted twice.
                let len = if a.file == b.file {
                    len.min(b.window - a.window)
                } else {
                    len
                };
                if len < MIN_CLONE_TOKENS {
                    continue;
                }
                let sequence = &symbols[a.file as usize][a.window as usize..][..len as usize];
                let key = (
                    len,
                    sequence_hash(sequence),
                    sequence[0],
                    sequence[sequence.len() - 1],
                );
                let members = groups.entry(key).or_default();
                members.insert((a.file, a.window));
                members.insert((b.file, b.window));
            }
        }
    }

    // Coverage first, over **every** confirmed match, before any selection.
    //
    // # Why the two answers are computed from different sets
    //
    // "Which regions are duplicated" and "which groups are worth reporting" are
    // different questions, and answering both from the selected groups gets the
    // first one wrong. The greedy pass below drops a whole group when any one of
    // its members overlaps something already kept — and a group's members are
    // spread across files. Probed: five modules sharing a 56-token helper, two
    // of which also share a 19-token suffix. The longer two-member group wins
    // the region, the five-member group is dropped entire, and the three modules
    // whose only content is the duplicated helper are reported as containing no
    // duplication at all.
    //
    // A coverage set cannot double-count — a token is in it or is not — so it
    // takes the union over every confirmed maximal match and needs no selection
    // at all. Group *reporting* still does, for the reason below.
    let mut covered: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for ((len, ..), members) in &groups {
        for (file, window) in members {
            let tokens = symbols[*file as usize].len() as u32;
            covered
                .entry(*file)
                .or_default()
                .extend(*window..(*window + *len).min(tokens));
        }
    }

    // Longest first, and nothing overlapping anything already kept.
    //
    // # Why overlap has to be excluded rather than merely deduplicated
    //
    // Periodic content — a table of `[n, m]` rows, a long `switch`, a list of
    // similar guard clauses — normalizes to one repeating token pattern. Every
    // *lag* through it produces a genuinely distinct maximal match: rows one
    // apart, two apart, three apart. Each is a real repetition, and reporting
    // all of them turned a thirty-row table into eight clone groups on the
    // matrix specimen, which is a true answer to a question nobody asked. A
    // reader wants to know that a region is duplicated, once.
    //
    // So the selection is greedy over disjoint regions: take the longest group,
    // mark its tokens covered, and skip any later group that would report a
    // token twice. The order is fully determined by `(length, sequence hash,
    // placements)`, all of which come out of `BTreeMap`s, so two machines make
    // the same choices — which matters more here than usual, because these
    // groups are what the cross-OS digests are taken over.
    let mut ordered: Vec<(GroupKey, BTreeSet<Placement>)> = groups.into_iter().collect();
    ordered.sort_by(|(a_key, a_members), (b_key, b_members)| {
        b_key
            .0
            .cmp(&a_key.0)
            .then_with(|| a_members.cmp(b_members))
            .then_with(|| a_key.cmp(b_key))
    });

    let mut claimed: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    let mut kept: Vec<(GroupKey, BTreeSet<Placement>)> = Vec::new();
    for (key, members) in ordered {
        let overlaps = members.iter().any(|(file, window)| {
            claimed.get(file).is_some_and(|tokens| {
                (*window..window + key.0).any(|token| tokens.contains(&token))
            })
        });
        if overlaps {
            continue;
        }
        for (file, window) in &members {
            let tokens = claimed.entry(*file).or_default();
            tokens.extend(*window..window + key.0);
        }
        kept.push((key, members));
    }

    let mut out_groups = Vec::new();
    for ((len, ..), members) in kept {
        let mut fragments = Vec::new();
        for (file, window) in &members {
            let path = files[*file as usize];
            let entry = &index.files[path];
            let start = *window as usize;
            let end = (start + len as usize).min(entry.rows.len());
            fragments.push(Fragment {
                path: path.clone(),
                token_start: *window,
                token_len: len,
                line_start: entry.rows.get(start).copied().unwrap_or(0) + 1,
                line_end: entry.rows.get(end.saturating_sub(1)).copied().unwrap_or(0) + 1,
            });
        }
        fragments.sort();
        out_groups.push(CloneGroup {
            token_len: len,
            fragments,
        });
    }
    out_groups.sort_by(|a, b| {
        b.token_len
            .cmp(&a.token_len)
            .then_with(|| a.fragments.cmp(&b.fragments))
    });
    report.groups = out_groups;

    for (file, tokens) in covered {
        let path = files[file as usize];
        report
            .duplicated_tokens_by_path
            .insert(path.clone(), tokens.len() as u32);
        // Where to open the file. Derived from the coverage set rather than
        // from `groups`, because a file can hold a copy and appear in no
        // reported group — the greedy selection drops a whole group when one
        // member overlaps something already kept, and the other members are
        // still duplicated code somebody has to find.
        if let Some((first, last)) = longest_run(&tokens) {
            let rows = &index.files[path].rows;
            report.duplicated_span_by_path.insert(
                path.clone(),
                LineRange {
                    start: rows.get(first as usize).copied().unwrap_or(0) + 1,
                    end: rows.get(last as usize).copied().unwrap_or(0) + 1,
                },
            );
        }
    }
    for file in truncated_files {
        report.truncated_paths.insert(files[file as usize].clone());
    }
    report
}

/// The longest run of consecutive values in a sorted set, as an inclusive pair.
fn longest_run(values: &BTreeSet<u32>) -> Option<(u32, u32)> {
    let mut best: Option<(u32, u32)> = None;
    let mut run: Option<(u32, u32)> = None;
    for value in values {
        run = match run {
            Some((start, end)) if *value == end + 1 => Some((start, *value)),
            Some((start, end)) => {
                if best.is_none_or(|(b0, b1)| b1 - b0 < end - start) {
                    best = Some((start, end));
                }
                Some((*value, *value))
            }
            None => Some((*value, *value)),
        };
    }
    match (best, run) {
        (Some((b0, b1)), Some((r0, r1))) if r1 - r0 > b1 - b0 => Some((r0, r1)),
        (Some(b), _) => Some(b),
        (None, run) => run,
    }
}

/// The partners one occurrence of a saturated hash is paired with.
///
/// `rest` is the occurrences after `a`, in `(file, window)` order, so the ones
/// sharing `a`'s file are a prefix of it. `tokens_in_file` is the length of
/// `a`'s token stream.
///
/// # Two extremes, because the two answers this engine reports live at
/// different ones
///
/// A same-file pair is reported at `min(extend, lag)` — the overlap rule a few
/// lines above caps a self-clone at its own lag, or the two halves share tokens
/// and one run of repetition is counted twice. `extend` cannot run past the end
/// of the later copy, so that length is bounded by
/// `min(b.window - a.window, tokens_in_file - b.window)`: it *rises* with the
/// lag while the first term binds and *falls* with it once the second does. The
/// two terms cross at `a.window + (tokens_in_file - a.window) / 2`, and no
/// partner anywhere in the bucket can yield a longer reportable clone than one
/// at that crossing.
///
/// So the two extremes are:
///
/// - the **nearest usable** partner, which is the shortest reportable lag. It
///   is what finds a helper copied into a hundred files, because a partner in
///   another file stops the scan immediately; and in one file it is the
///   tightest repetition the floor admits.
/// - the two same-file occurrences **bracketing the crossing**, which is where
///   the longest reportable clone can be. Two, not one, because the occurrence
///   list is discrete and the crossing generally falls between two of them —
///   with only the lower of the pair, 37 identical lines report 216 of 222
///   tokens instead of 222.
///
/// Both are needed and neither substitutes for the other: `largest-clone-tokens`
/// and the greedy group selection read the longest match, while the coverage
/// union reads every confirmed one. Generating only the nearest is what froze
/// the duplicated-token count at 108 for every file above the cap.
///
/// Bounded work, which is the whole point of the cap: one forward scan for the
/// nearest — at most `MIN_CLONE_TOKENS` occurrences of one hash fit inside that
/// distance in one file, and another file ends it — plus two binary searches,
/// and at most three extensions where an uncapped bucket would do one per
/// remaining occurrence.
/// One repeated window hash, split into the stretches of the file it repeats in.
///
/// # Why regions, and not one periodic block
///
/// A saturated bucket is a window that occurs everywhere, and "everywhere" is
/// rarely one place. `export const a = [600 rows]`, a helper, `const b = [300
/// rows]`, the same helper, `const c = [300 rows]` is three stretches of one
/// repetition with two identical interruptions — and the previous rule, nearest
/// usable partner plus the two occurrences bracketing the half-file crossing,
/// was derived for a file where the repetition is contiguous. On that file it
/// lost the middle: 5499 of 7333 tokens reported, a quarter of the file missed
/// and stamped `complete`, and a longest clone of 1805 where the answer is
/// 1863. Splitting the bucket at its own gaps is what makes those boundaries
/// visible to the pairing at all.
#[derive(Debug, Default)]
struct Runs {
    /// `(first index, last index)` into the bucket, one per region, in order.
    spans: Vec<(usize, usize)>,
    /// The region each occurrence belongs to.
    region_of: Vec<usize>,
    /// The tightest spacing anywhere in the bucket — the repetition's own
    /// period, and therefore the widest gap a region may have inside it.
    stride: u32,
}

impl Runs {
    fn of(occurrences: &[Occurrence]) -> Runs {
        let stride = occurrences
            .windows(2)
            .filter(|w| w[0].file == w[1].file)
            .map(|w| w[1].window - w[0].window)
            .min()
            .unwrap_or(0);
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let mut region_of = Vec::with_capacity(occurrences.len());
        for (i, o) in occurrences.iter().enumerate() {
            let continues = i > 0
                && occurrences[i - 1].file == o.file
                && o.window - occurrences[i - 1].window <= stride;
            if continues {
                spans
                    .last_mut()
                    .expect("the first occurrence opens a region")
                    .1 = i;
            } else {
                spans.push((i, i));
            }
            region_of.push(spans.len() - 1);
        }
        Runs {
            spans,
            region_of,
            stride,
        }
    }

    /// What laying every region against every occurrence would cost, per file.
    ///
    /// Over the regions *after* each occurrence rather than all of them, and
    /// never across a file boundary. Both narrowings are the difference between
    /// costing what the walk does and costing something it does not:
    ///
    /// - the alignment is a token offset and means nothing across a file
    ///   boundary, so the walk never leaves `a`'s own file. Counting the whole
    ///   bucket would have called a helper copied into five hundred files too
    ///   expensive to search.
    /// - a file whose repetition is one unbroken region has no later region to
    ///   be laid against and costs nothing at all here. Counting it as
    ///   `occurrences x 1` reported 200,000 identical lines `partial` — the
    ///   plainest generated file there is, answered exactly, carrying a caveat
    ///   about a search that never happened.
    ///
    /// # Kept apart per file, because that is where it is spent
    ///
    /// These per-file costs used to be summed and compared to the budget once,
    /// and every file in the bucket then joined
    /// [`CloneReport::truncated_paths`] together. The sum is not what any one
    /// file's walk costs: a file whose repetition is one unbroken region does
    /// no region work at all, and it was still told its regions had been
    /// sampled because something else in the same bucket was expensive. That is
    /// a caveat about a search that never happened to it, in a report whose
    /// whole claim is that a caveat names the file that earned it.
    ///
    /// Applying the budget per file is exact rather than merely kinder: the
    /// walk it bounds stops at the first foreign region, so no file's cost has
    /// ever depended on another's. What changes is the ceiling on one bucket —
    /// the sum of what each file spends under its own budget, rather than one
    /// gate over all of them. Every file is still bounded, and every file that
    /// reaches its bound is still named.
    fn work_by_file(&self, occurrences: &[Occurrence]) -> BTreeMap<u32, usize> {
        let mut out: BTreeMap<u32, usize> = BTreeMap::new();
        let mut file: Option<u32> = None;
        let mut regions = 0usize;
        let mut members = 0usize;
        let mut close = |file: Option<u32>, regions: usize, members: usize| {
            if let Some(file) = file {
                out.insert(file, members.saturating_mul(regions.saturating_sub(1)));
            }
        };
        for &(first, last) in &self.spans {
            if Some(occurrences[first].file) != file {
                close(file, regions, members);
                file = Some(occurrences[first].file);
                regions = 0;
                members = 0;
            }
            regions += 1;
            members += last - first + 1;
        }
        close(file, regions, members);
        out
    }

    fn members<'a>(&self, occurrences: &'a [Occurrence], region: usize) -> &'a [Occurrence] {
        let (first, last) = self.spans[region];
        &occurrences[first..=last]
    }

    /// The token just past a region.
    ///
    /// Derived rather than known: the last occurrence *inside* a region is one
    /// whose whole window fits inside it, so the region runs on for a window
    /// past that, and for up to one period more before the next occurrence
    /// would have started. Both terms are load-bearing — without them the
    /// crossing landed 12 tokens short on 300 rows followed by a helper, and
    /// the longest clone came back 888 where the answer is 900. The estimate
    /// only aims [`bracket`], which takes the occurrences on both sides of
    /// where it aims, so an error under one period costs nothing.
    fn end_of(&self, occurrences: &[Occurrence], region: usize) -> u32 {
        let (_, last) = self.spans[region];
        occurrences[last].window + WINDOW_TOKENS + self.stride.saturating_sub(1)
    }
}

/// The partners one occurrence of a saturated hash is paired with.
///
/// # Three rules, because a reportable match is maximized in three places
///
/// A same-file pair is reported at `min(extend, lag)` — the overlap rule in
/// [`detect`] caps a self-clone at its own lag, or the two halves share tokens
/// and one run of repetition is counted twice. The length therefore rises with
/// the lag while the lag binds and falls once the content does, and each rule
/// below is a place that trade-off turns over:
///
/// - the **nearest usable** partner, the shortest reportable lag. It is what
///   finds a helper copied into a hundred files, because a partner in another
///   file stops the scan immediately; and inside one file it is the tightest
///   repetition the floor admits.
/// - the occurrences **bracketing a crossing**, for a match that stays inside
///   one region. `extend` cannot run past the end of the later copy, so the two
///   terms cross halfway between `a` and that end. Taken against the end of
///   `a`'s own region *and* against the end of the file, because a match that
///   stops at the region boundary is bounded by the first and one that runs on
///   past it by the second.
/// - the occurrences **aligning `a` with each later region**, for a match that
///   crosses a boundary. Two stretches of the same repetition lie against each
///   other in two ways — heads together and tails together — and which one
///   produces the longer match depends on which stretch is shorter. Both are
///   generated: 40 rows, a helper, then 100 rows has its longest clone at the
///   tail alignment, 543 tokens beginning 60 rows into the second table, while
///   600/300/300 has its 1863-token clone at the head alignment.
///
/// The rule this replaces had the first two and not the third, and the third is
/// the whole of the repair. Without it nothing is ever laid across an
/// interruption: the coverage union lost a quarter of a three-table file, and
/// `largest-clone-tokens` froze at 1794 on a file whose longest clone grows
/// without bound — the original defect's own signature on a new shape.
///
/// # What it costs, and what happens when that is too much
///
/// One forward scan for the nearest, two binary searches per crossing, and four
/// per later region. The region term is `occurrences x regions` over the
/// bucket, which content bounds and construction does not — so `truncated` says
/// the budget was reached and only the next region is laid against `a`. That is
/// the answer this engine reports as `partial`; see
/// [`CloneReport::truncated_paths`].
fn bounded_partners(
    occurrences: &[Occurrence],
    index: usize,
    tokens_in_file: u32,
    runs: &Runs,
    truncated: bool,
) -> Vec<Occurrence> {
    let a = &occurrences[index];
    let rest = &occurrences[index + 1..];
    let mut chosen: Vec<Occurrence> = Vec::new();

    // Nearest *usable*, not nearest, and the distinction was worth two wrong
    // attempts. In a periodic region the following occurrences are one period
    // apart, and a partner closer than `MIN_CLONE_TOKENS` can never produce a
    // clone that clears the floor. Stopping at the first non-overlapping
    // partner found nothing at all on a three-thousand-row table: zero groups
    // where the answer is one.
    if let Some(first) = rest
        .iter()
        .position(|b| a.file != b.file || b.window >= a.window + MIN_CLONE_TOKENS)
    {
        chosen.push(rest[first]);
    }

    let mine = runs.region_of[index];
    let head_of_mine = runs.members(occurrences, mine)[0].window;
    let end_of_mine = runs.end_of(occurrences, mine);
    let regions = mine + 1..runs.spans.len();
    for region in regions.take(if truncated { 1 } else { usize::MAX }) {
        let members = runs.members(occurrences, region);
        if members[0].file != a.file {
            // A crossing and an alignment are both token offsets in `a`'s file
            // and say nothing about another one. Regions are in `(file,
            // window)` order, so the first foreign one ends the walk — and
            // ending it is what keeps this bounded: pairing every occurrence
            // with the head of the next file's region turned two copies of a
            // 5000-deep nested literal from 173 ms into 16 s, because that
            // pair is a seed by construction and extends the length of the
            // file every time. What crosses files here is the nearest usable
            // partner above, as it was before regions existed.
            break;
        }
        let head = members[0].window + (a.window - head_of_mine);
        let tail = runs
            .end_of(occurrences, region)
            .saturating_sub(end_of_mine.saturating_sub(a.window));
        bracket(members, head, &mut chosen);
        bracket(members, tail, &mut chosen);
    }

    let same_file = &rest[..rest.partition_point(|b| b.file == a.file)];
    for limit in [tokens_in_file, end_of_mine] {
        let crossing = a.window + limit.saturating_sub(a.window) / 2;
        bracket(same_file, crossing, &mut chosen);
    }

    // Forward-only, sorted and deduplicated, so the partner set — and therefore
    // the group order, and therefore the digests taken over it — does not
    // depend on which rule proposed a placement first. The forward filter is
    // what keeps an alignment landing behind `a` from turning the pair round
    // and reporting one clone from both of its ends.
    chosen.retain(|b| b > a);
    chosen.sort_unstable();
    chosen.dedup();
    chosen
}

/// The occurrences on either side of `at`, appended to `chosen`.
///
/// Both, because the occurrence list is discrete and an aim generally falls
/// between two of them — with only the lower of the pair, 37 identical lines
/// report 216 of 222 tokens instead of 222.
fn bracket(sorted: &[Occurrence], at: u32, chosen: &mut Vec<Occurrence>) {
    let index = sorted.partition_point(|b| b.window < at);
    if index > 0 {
        chosen.push(sorted[index - 1]);
    }
    if index < sorted.len() {
        chosen.push(sorted[index]);
    }
}

/// Whether the window pair one position earlier also matches — the test that
/// makes a seed a seed.
fn preceded_by_a_match(symbols: &[&[u64]], a: &Occurrence, b: &Occurrence) -> bool {
    if a.window == 0 || b.window == 0 {
        return false;
    }
    let width = WINDOW_TOKENS as usize;
    let ap = a.window as usize - 1;
    let bp = b.window as usize - 1;
    symbols[a.file as usize][ap..ap + width] == symbols[b.file as usize][bp..bp + width]
}

/// How far two matching windows agree, in tokens. Confirms the seed itself, so
/// a collision returns 0 rather than a clone.
fn extend(symbols: &[&[u64]], a: &Occurrence, b: &Occurrence) -> u32 {
    let width = WINDOW_TOKENS as usize;
    let sa = symbols[a.file as usize];
    let sb = symbols[b.file as usize];
    let (ai, bi) = (a.window as usize, b.window as usize);
    if sa[ai..ai + width] != sb[bi..bi + width] {
        return 0; // a hash collision, not a clone
    }
    let mut len = width;
    while ai + len < sa.len() && bi + len < sb.len() && sa[ai + len] == sb[bi + len] {
        len += 1;
    }
    len as u32
}

/// A 64-bit identity for a token sequence, used only to group fragments that
/// [`extend`] already confirmed pairwise.
///
/// Not a proof of equality, and nothing here treats it as one. A collision
/// between two equal-length sequences would merge two groups that are each
/// internally correct — the lengths and counts stay right, the "these places are
/// the same code" claim becomes wrong across the merged halves. [`GroupKey`]
/// carries the first and last symbols alongside it for that reason. The
/// exactness claim in this module's header is about [`extend`], which compares
/// symbols directly; it is not a claim about this function.
fn sequence_hash(symbols: &[u64]) -> u64 {
    let mut bytes = Vec::with_capacity(symbols.len() * 8);
    for symbol in symbols {
        bytes.extend_from_slice(&symbol.to_be_bytes());
    }
    crate::syntax::fnv1a(&bytes)
}

/// Window and clone-length parameters, for the regime stamp.
pub fn parameters() -> (u32, u32) {
    (fingerprint::WINDOW_TOKENS, fingerprint::MIN_CLONE_TOKENS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::FileInput;

    fn input(path: &str, source: &str) -> FileInput {
        FileInput {
            path: path.to_string(),
            // The OID only has to be a content identity for these tests; the
            // engine supplies git's.
            blob_oid: format!("{:016x}", crate::syntax::fnv1a(source.as_bytes())),
            source: source.as_bytes().to_vec(),
        }
    }

    /// A block comfortably over the 50-token floor.
    fn block(name: &str) -> String {
        format!(
            "export function {name}(items: number[], factor: number): number {{\n\
             \x20 let total = 0;\n\
             \x20 for (const item of items) {{\n\
             \x20   if (item > factor) {{ total += item * factor; }}\n\
             \x20   else {{ total -= item; }}\n\
             \x20 }}\n\
             \x20 return total;\n\
             }}\n"
        )
    }

    fn run(inputs: &[FileInput]) -> CloneReport {
        let (index, _) = Index::empty().update(inputs);
        let paths: Vec<String> = inputs.iter().map(|i| i.path.clone()).collect();
        detect(&index, &paths)
    }

    #[test]
    fn a_copy_with_renamed_identifiers_is_found() {
        let report = run(&[
            input("a.ts", &block("alpha")),
            input("b.ts", &block("somethingEntirelyDifferent")),
        ]);
        assert_eq!(report.groups.len(), 1, "{:#?}", report.groups);
        assert_eq!(report.groups[0].fragments.len(), 2);
        assert!(report.duplicated_tokens() > 0);
        assert!(report.duplicated_ratio() > 0.5);
    }

    #[test]
    fn unrelated_code_produces_nothing() {
        let a = "export const config = { retries: 3, timeout: 1000, verbose: false };\n";
        let b = "class Widget { constructor(private id: string) {} render(): string { return this.id; } }\n";
        let report = run(&[input("a.ts", a), input("b.ts", b)]);
        assert!(report.groups.is_empty(), "{:#?}", report.groups);
        assert_eq!(report.duplicated_tokens(), 0);
        assert_eq!(report.duplicated_ratio(), 0.0);
    }

    #[test]
    fn a_copy_below_the_floor_is_not_a_clone() {
        let short = "function f(a) { return a + 1; }\n";
        let report = run(&[input("a.js", short), input("b.js", short)]);
        assert!(report.groups.is_empty());
    }

    #[test]
    fn duplication_inside_one_file_counts() {
        let source = format!("{}{}", block("first"), block("second"));
        let report = run(&[input("a.ts", &source)]);
        assert_eq!(report.groups.len(), 1, "{:#?}", report.groups);
        assert_eq!(report.groups[0].fragments.len(), 2);
    }

    #[test]
    fn three_copies_are_one_group_of_three() {
        let report = run(&[
            input("a.ts", &block("one")),
            input("b.ts", &block("two")),
            input("c.ts", &block("three")),
        ]);
        assert_eq!(report.groups.len(), 1, "{:#?}", report.groups);
        assert_eq!(report.groups[0].fragments.len(), 3);
    }

    #[test]
    fn the_answer_does_not_depend_on_the_order_paths_arrive_in() {
        let inputs = vec![
            input("z.ts", &block("one")),
            input("a.ts", &block("two")),
            input("m.ts", &block("three")),
        ];
        let (index, _) = Index::empty().update(&inputs);
        let forward: Vec<String> = inputs.iter().map(|i| i.path.clone()).collect();
        let mut backward = forward.clone();
        backward.reverse();
        assert_eq!(detect(&index, &forward), detect(&index, &backward));
    }

    #[test]
    fn periodic_content_is_one_group_and_not_one_per_lag() {
        // A table of `[n, m]` rows normalizes to one repeating pattern, and
        // every lag through it is a genuinely distinct maximal match. Reporting
        // all of them turned a thirty-row table into eight groups on the matrix
        // specimen: a set of true statements adding up to a useless report.
        let rows: Vec<String> = (0..30).map(|i| format!("  [{i}, {}]", i * i)).collect();
        let source = format!(
            "export function rate(x: number): number {{\n  const t = [\n{}\n  ];\n  return t[x][1];\n}}\n",
            rows.join(",\n")
        );
        let report = run(&[input("a.ts", &source)]);
        assert_eq!(report.groups.len(), 1, "{:#?}", report.groups);
    }

    #[test]
    fn every_file_holding_a_copy_is_credited_with_it() {
        // Five modules share a helper; two of them also share a suffix, which
        // makes a longer clone between that pair. The longer group wins the
        // greedy selection and the five-member group is dropped from the
        // *report* — but the three modules whose only content is the shared
        // helper still contain it, and were being credited with zero
        // duplicated tokens. Coverage is a union over every confirmed match,
        // taken before any selection happens.
        let helper = block("shared");
        let suffix = "\nexport function extra(x: number): number {\n  const y = x * 2;\n  const z = y + 3;\n  return z - 1;\n}\n";
        let inputs: Vec<_> = (0..5)
            .map(|n| {
                let source = if n < 2 {
                    format!("{helper}{suffix}")
                } else {
                    helper.clone()
                };
                input(&format!("m{n}.ts"), &source)
            })
            .collect();
        let report = run(&inputs);
        for n in 0..5 {
            let path = format!("m{n}.ts");
            let duplicated = report
                .duplicated_tokens_by_path
                .get(&path)
                .copied()
                .unwrap_or(0);
            assert!(
                duplicated > 0,
                "{path} holds a copy of the shared helper and was credited with none: {:?}",
                report.duplicated_tokens_by_path
            );
        }
        // And the pair that shares more is credited with more.
        assert!(
            report.duplicated_tokens_by_path["m0.ts"] > report.duplicated_tokens_by_path["m2.ts"]
        );
    }

    #[test]
    fn a_saturated_bucket_does_not_cost_quadratic_time() {
        // Pairwise expansion over a repeating table was measured at 2.8 ms for
        // 200 rows, 27 ms for 800, and 178 ms for 2000 — a shape that puts a
        // large generated file past the fast lane's whole warm budget on its
        // own. The bound is asserted rather than described, because a
        // performance property nobody measures is a performance property that
        // regresses.
        let rows: Vec<String> = (0..3000).map(|i| format!("  [{i}, {}],", i * i)).collect();
        let source = format!(
            "export function f(x: number) {{
  const t = [
{}
  ];
  return t[x];
}}
",
            rows.join(
                "
"
            )
        );
        let started = std::time::Instant::now();
        let report = run(&[input("a.ts", &source)]);
        let elapsed = started.elapsed();
        assert_eq!(report.groups.len(), 1, "{:#?}", report.groups);
        // The group count alone is not enough, and asserting only it is how
        // this test stayed green through the freeze: one group is exactly what
        // the broken saturated path produced too, at 108 duplicated tokens of
        // 18022. The number is the thing the cap was accused of preserving.
        assert!(
            report.duplicated_ratio() > 0.99,
            "3000 rows of literal table are duplicated nearly end to end; \
             {} of {} tokens is the frozen answer returning",
            report.duplicated_tokens(),
            report.total_tokens()
        );
        // Generous by an order of magnitude against the measured cost, because
        // this runs on shared CI hardware in a debug build; it is a guard
        // against the quadratic shape returning, not a benchmark.
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "detection over 3000 repeating rows took {elapsed:?}; the saturation guard is not working"
        );
    }

    #[test]
    fn a_real_clone_survives_beside_periodic_content() {
        let rows: Vec<String> = (0..30).map(|i| format!("  [{i}, {}]", i * i)).collect();
        let table = format!(
            "export function rate(x: number): number {{\n  const t = [\n{}\n  ];\n  return t[x][1];\n}}\n",
            rows.join(",\n")
        );
        let report = run(&[
            input("table.ts", &table),
            input("a.ts", &block("one")),
            input("b.ts", &block("two")),
        ]);
        assert_eq!(report.groups.len(), 2, "{:#?}", report.groups);
        assert!(
            report
                .groups
                .iter()
                .any(|g| g.fragments.len() == 2 && g.fragments[0].path != g.fragments[1].path),
            "the cross-file clone must not be crowded out by the table"
        );
    }

    #[test]
    fn fragments_carry_line_numbers_a_human_can_open() {
        let source = format!("// header\n{}\n// gap\n{}", block("first"), block("second"));
        let report = run(&[input("a.ts", &source)]);
        let fragment = &report.groups[0].fragments[0];
        assert!(fragment.line_start >= 2, "{fragment:?}");
        assert!(fragment.line_end >= fragment.line_start);
    }
}
