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

use std::collections::{BTreeMap, BTreeSet};

use crate::fingerprint::{self, MIN_CLONE_TOKENS, SATURATED_OCCURRENCES, WINDOW_TOKENS};
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
    /// Groups with two or more members, sorted by length then position.
    pub groups: Vec<CloneGroup>,
    /// Tokens covered by at least one fragment, per path.
    pub duplicated_tokens_by_path: BTreeMap<String, u32>,
    /// Tokens in the measured set, per path.
    pub tokens_by_path: BTreeMap<String, u32>,
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

/// A clone group's identity: its length in tokens and a hash of the shared
/// normalized sequence. Two fragments belong together exactly when both agree.
type GroupKey = (u32, u64);

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

    for occurrences in postings.values() {
        if occurrences.len() < 2 {
            continue;
        }
        // A saturated bucket pairs each occurrence with its **nearest usable**
        // partner instead of with all of them. See
        // `fingerprint::SATURATED_OCCURRENCES` for why that bounds the cost.
        //
        // Nearest *usable*, not nearest, and the distinction was worth two
        // wrong attempts. In a periodic region the following occurrences are one
        // period apart, and a same-file pair is reported at no more than its lag
        // — so a partner closer than `MIN_CLONE_TOKENS` can never produce a
        // clone that clears the floor. Stopping at the first non-overlapping
        // partner found nothing at all on a three-thousand-row table: zero
        // groups where the answer is one.
        //
        // So the scan walks to the first partner that could yield a reportable
        // clone. It is bounded: at most `MIN_CLONE_TOKENS` occurrences of one
        // hash fit within that distance in one file, and a partner in another
        // file stops it immediately.
        let saturated = occurrences.len() > SATURATED_OCCURRENCES;
        for (i, a) in occurrences.iter().enumerate() {
            let rest = &occurrences[i + 1..];
            let partners: &[Occurrence] = if saturated {
                match rest
                    .iter()
                    .position(|b| a.file != b.file || b.window >= a.window + MIN_CLONE_TOKENS)
                {
                    Some(first) => &rest[first..first + 1],
                    None => &[],
                }
            } else {
                rest
            };
            for b in partners {
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
                let key = (
                    len,
                    sequence_hash(&symbols[a.file as usize][a.window as usize..][..len as usize]),
                );
                let members = groups.entry(key).or_default();
                members.insert((a.file, a.window));
                members.insert((b.file, b.window));
            }
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
            .then_with(|| a_key.1.cmp(&b_key.1))
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

    let mut covered: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    let mut out_groups = Vec::new();
    for ((len, _), members) in kept {
        let mut fragments = Vec::new();
        for (file, window) in &members {
            let path = files[*file as usize];
            let entry = &index.files[path];
            let start = *window as usize;
            let end = (start + len as usize).min(entry.rows.len());
            for token in start..end {
                covered.entry(*file).or_default().insert(token as u32);
            }
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
        report
            .duplicated_tokens_by_path
            .insert(files[file as usize].clone(), tokens.len() as u32);
    }
    report
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
