//! The duplication count over repetitive content, pinned so it cannot re-freeze.
//!
//! # It froze twice, in two shapes of the same defect
//!
//! The first freeze was over *contiguous* repetition and is described below.
//! The second was over repetition an identical block interrupts, and it came
//! from the rule that fixed the first: pairing an occurrence with the nearest
//! usable partner and with the occurrences bracketing the half-file crossing is
//! derived for a file whose repetition is one stretch, and it never lays
//! anything across an interruption. Measured, on
//! `600 rows / helper / 300 rows / helper / 300 rows`: 5499 of 7333 tokens and
//! a ratio of 0.749898 where the answer is 7333 and 1.0, a longest clone of
//! 1805 where the answer is 1863 — a quarter of the file missed, and every one
//! of those numbers stamped `completeness: complete`. On the same content with
//! `k` interruptions, `largest-clone-tokens` sat at 1794 for k = 3, 5, 7 and 9
//! while the true longest clone grew 1856 -> 3712 -> 5568 -> 7424. That is the
//! first defect's own signature on a second shape.
//!
//! The repair splits a saturated bucket into the regions it repeats in and lays
//! `a` against each of them head to head and tail to tail; `detect::bounded_partners`
//! derives it.
//!
//! # The oracle is run here rather than remembered
//!
//! Every exact value below used to be a number somebody measured once against a
//! locally-edited constant and pasted into an assertion — including the
//! residual `registry/clones.toml` publishes, which said 98% of the uncapped
//! count and was 75% of it on shapes nothing in this file tried.
//! `detect::detect_with_cap` takes the cap as an argument, so the uncapped
//! answer is computed beside the capped one on every shape in
//! [`battery`], and the disclosure is a measurement that reruns rather than a
//! sentence that decays.
//!
//! # What went wrong the first time, in one sentence
//!
//! The saturation cap paired each occurrence of a repeated window hash with its
//! *nearest usable* partner, on the documented ground that the greedy disjoint
//! selection in `detect` "keeps exactly that one — the longer-lag matches are
//! the ones it discards anyway". The selection sorts by length **descending**:
//! it keeps the longest match. The saturated path generated only the candidate
//! the selection discards and never the one it keeps, so every file above the
//! cap reported one group at one short lag however long the file was.
//!
//! # The numbers it produced, measured before the fix
//!
//! `N` identical `export const vN = N;` lines, six tokens each:
//!
//! | N | duplicated tokens | ratio |
//! |---|---|---|
//! | 36 | 216 | 1.0 |
//! | 37 | 108 | 0.4865 |
//! | 200 | 108 | 0.09 |
//! | 200,000 | 108 | 0.00009 |
//!
//! Frozen at 108 duplicated tokens and a largest clone of 54, forever — and the
//! reported ratio *fell as the real duplication rose*, every one of them stamped
//! `completeness: complete`. That is a confident wrong number in the metric the
//! VISION leads with, on the content it is most likely to meet: generated code,
//! lookup tables, i18n maps, minified bundles.
//!
//! # What this file pins, and why each pin is here
//!
//! 1. **The boundary**, at the transition point rather than near it. The cap
//!    engages *above* 32 occurrences of one hash and the fixture's arithmetic is
//!    checked here rather than assumed, so a future change to `WINDOW_TOKENS` or
//!    to the fixture cannot leave a test that passes without straddling
//!    anything.
//! 2. **The arithmetic**, as exact equalities. A monotonicity assertion alone
//!    would pass on a count that grew by one token per line, and the answer that
//!    matters is that the whole of a wholly-duplicated file is reported.
//! 3. **Growth**, so a count that stops growing fails even if some future shape
//!    makes the exact values move.
//! 4. **The residual**, which is a real remaining loss and is asserted as a
//!    *bound* rather than described in a comment.
//! 5. **The interrupted shapes**, at the arithmetic the reviewers measured,
//!    with the wrong number each one used to produce written beside it.
//! 6. **Every size against the oracle**, over a battery of 47 shapes, because
//!    the pins above are the shapes somebody thought of.
//! 7. **The one answer a bounded pairing cannot certify**, which is the group
//!    *count* — asserted as a measured bound and disclosed, rather than left to
//!    be discovered.
//! 8. **The sampled bucket**, which is the one shortfall the engine can see
//!    while it happens and therefore reports rather than discloses.

use andon_engine_clones::detect::{detect, detect_with_cap, CloneReport};
use andon_engine_clones::fingerprint::{SATURATED_OCCURRENCES, WINDOW_TOKENS};
use andon_engine_clones::index::{FileInput, Index};
use andon_engine_clones::syntax;

/// Tokens one `export const vN = N;` line normalizes to: `export`, `const`, the
/// identifier, `=`, the literal, `;`.
const TOKENS_PER_LINE: u32 = 6;

fn input(path: &str, source: &str) -> FileInput {
    FileInput {
        path: path.to_string(),
        blob_oid: format!("{:040x}", syntax::fnv1a(source.as_bytes())),
        source: source.as_bytes().to_vec(),
    }
}

/// `n` identical statements, differing only in the identifier and the literal —
/// both of which the normalization collapses, so the token stream is exactly
/// periodic with a period of [`TOKENS_PER_LINE`].
fn identical_lines(n: usize) -> String {
    (0..n)
        .map(|i| format!("export const v{i} = {i};\n"))
        .collect()
}

fn measure(source: &str) -> (u64, u64, f64, u64, usize) {
    let inputs = vec![input("a.ts", source)];
    let (index, _) = Index::empty().update(&inputs);
    let paths: Vec<String> = inputs.iter().map(|i| i.path.clone()).collect();
    let report = detect(&index, &paths);
    (
        report.total_tokens(),
        report.duplicated_tokens(),
        report.duplicated_ratio(),
        report.largest_clone_tokens(),
        report.groups.len(),
    )
}

/// Occurrences of one window hash in a purely periodic file of `lines` lines.
///
/// Every window position holds one of `TOKENS_PER_LINE` distinct hashes, evenly
/// spread, so the count per hash is the window count divided by the period.
fn occurrences_per_hash(lines: u32) -> u32 {
    let tokens = lines * TOKENS_PER_LINE;
    let windows = tokens - WINDOW_TOKENS + 1;
    windows / TOKENS_PER_LINE
}

#[test]
fn the_fixture_really_does_straddle_the_cap() {
    // Asserted rather than assumed. If a future `WINDOW_TOKENS` moved the
    // boundary off 36/37, the two tests below would still pass while testing
    // the same side of it twice — which is how a boundary test stops being one.
    assert_eq!(
        occurrences_per_hash(36),
        SATURATED_OCCURRENCES as u32,
        "36 identical lines is the largest fixture the cap does NOT engage on: \
         216 tokens, {} windows, {} per hash",
        216 - WINDOW_TOKENS + 1,
        occurrences_per_hash(36)
    );
    assert!(
        occurrences_per_hash(37) > SATURATED_OCCURRENCES as u32,
        "37 identical lines must be the first fixture the cap DOES engage on"
    );
}

#[test]
fn the_count_does_not_freeze_at_the_saturation_boundary() {
    // The defect in its smallest form: one line more, and the reported
    // duplication fell from 216 tokens to 108 and the ratio from 1.00 to 0.49.
    let (total_36, dup_36, ratio_36, largest_36, _) = measure(&identical_lines(36));
    let (total_37, dup_37, ratio_37, largest_37, _) = measure(&identical_lines(37));

    assert_eq!((total_36, dup_36), (216, 216));
    assert_eq!((total_37, dup_37), (222, 222));
    assert_eq!(ratio_36, 1.0);
    assert_eq!(
        ratio_37, 1.0,
        "a file whose every line is a copy of every other line is wholly \
         duplicated on both sides of the cap; before the fix this was 0.4865"
    );
    assert!(
        dup_37 > dup_36,
        "crossing the cap must not lower the reported duplication: 36 lines \
         reported {dup_36} tokens and 37 lines reported {dup_37}"
    );
    // The longest clone is the half-file lag, on both sides of the boundary.
    assert_eq!(largest_36, 108);
    assert_eq!(
        largest_37, 108,
        "before the fix the longest clone froze at 54 tokens — one lag — for \
         every file above the cap"
    );
}

#[test]
fn a_wholly_duplicated_file_is_wholly_reported_however_long_it_is() {
    // The arithmetic, as equalities. Every value here was confirmed against an
    // uncapped run: `duplicated == total` because every token of a file of
    // identical lines is inside some confirmed clone, and the longest clone is
    // the half-file lag, which is the longest reportable one — a self-clone is
    // capped at its own lag, and beyond half the file the second copy runs out.
    for lines in [37u32, 38, 50, 200, 500, 1000] {
        let (total, duplicated, ratio, largest, groups) = measure(&identical_lines(lines as usize));
        let expected_total = u64::from(lines * TOKENS_PER_LINE);
        assert_eq!(total, expected_total, "{lines} lines");
        assert_eq!(
            duplicated, expected_total,
            "{lines} identical lines: every token is a copy, so every token is \
             covered. Before the fix this was 108 for every one of these."
        );
        assert_eq!(ratio, 1.0, "{lines} lines");
        // The half-file lag, rounded down to a whole period: a clone boundary
        // can only fall where the repeating unit does, so an odd line count
        // reports the largest whole-line lag under half the file (37 lines →
        // 108 tokens, not 111).
        let half_file_lag =
            expected_total / 2 / u64::from(TOKENS_PER_LINE) * u64::from(TOKENS_PER_LINE);
        assert_eq!(
            largest, half_file_lag,
            "{lines} lines: the longest reportable clone is the half-file lag"
        );
        assert_eq!(
            groups, 1,
            "{lines} lines: one duplicated region, described once — reporting \
             every lag through it would be a set of true statements adding up \
             to a useless report"
        );
    }
}

#[test]
fn the_count_grows_with_the_content_rather_than_standing_still() {
    // The property the exact values above are a special case of, asserted
    // separately so a future change that moves the numbers still has to keep
    // them moving in the right direction. A count that stopped growing is the
    // whole defect, whatever value it stopped at.
    let mut previous = 0u64;
    let mut previous_largest = 0u64;
    for lines in [37usize, 40, 60, 120, 400, 900] {
        let (_, duplicated, ratio, largest, _) = measure(&identical_lines(lines));
        assert!(
            duplicated > previous,
            "{lines} lines reported {duplicated} duplicated tokens, no more than \
             the {previous} reported by the shorter file before it"
        );
        assert!(
            largest > previous_largest,
            "{lines} lines reported a largest clone of {largest}, no longer than \
             the {previous_largest} of the shorter file before it"
        );
        assert_eq!(
            ratio, 1.0,
            "{lines} lines: the ratio must not fall as the duplication rises — \
             it fell to 0.00009 at 200,000 lines before the fix"
        );
        previous = duplicated;
        previous_largest = largest;
    }
}

#[test]
fn a_generated_table_reports_the_whole_table() {
    // The shape the cap was written for, and the one it was reporting at 0.6%.
    // The prologue and the closing lines are the 22 tokens that are not part of
    // the repeating region and are correctly not counted as duplicated.
    let rows: Vec<String> = (0..3000).map(|i| format!("  [{i}, {}],", i * i)).collect();
    let source = format!(
        "export function f(x: number) {{\n  const t = [\n{}\n  ];\n  return t[x];\n}}\n",
        rows.join("\n")
    );
    let (total, duplicated, ratio, largest, groups) = measure(&source);
    assert_eq!((total, duplicated), (18022, 18000));
    assert!(
        ratio > 0.99,
        "a file that is 3000 rows of literal table is duplicated nearly \
         end to end; the reported ratio was 0.0060 before the fix ({ratio})"
    );
    assert_eq!(largest, 9000, "the half-region lag");
    assert_eq!(groups, 1);
}

#[test]
fn the_answer_is_the_same_whichever_end_of_the_file_it_is_read_from() {
    // The partner set is sorted and deduplicated before it is used, because the
    // group order is what the cross-OS digests are taken over. Two files with
    // the same periodic content at different offsets must agree.
    let padded = format!("// a comment\n// another\n{}", identical_lines(300));
    let (_, duplicated, ratio, _, _) = measure(&padded);
    let (_, bare_duplicated, bare_ratio, _, _) = measure(&identical_lines(300));
    assert_eq!(duplicated, bare_duplicated, "comments are not tokens");
    assert_eq!(ratio, bare_ratio);
}

#[test]
fn what_the_cap_still_gives_up_is_a_bound_and_not_a_comment() {
    // The residual the cap's own documentation admits: inside a saturated
    // bucket, a longer match between two occurrences at neither extreme of the
    // partner set can still be missed. Two copies of a distinct block at
    // opposite ends of a file full of repeated syntax are the shape, and it is
    // the ONLY shape in the fixture battery where the capped answer and an
    // uncapped one differ at all.
    //
    // Asserted as a bound rather than as an equality: the point is that the
    // loss is small and one-directional — the reported number is a lower bound
    // on the uncapped one and never an overstatement, because coverage is a
    // union over confirmed matches and a token is in it or is not.
    let block = "export function distinctHelper(items: number[], factor: number): number {\n\
                 \x20 let total = 0;\n\
                 \x20 for (const item of items) {\n\
                 \x20   if (item > factor) { total += item * factor; }\n\
                 \x20   else { total -= item; }\n\
                 \x20 }\n\
                 \x20 return total;\n\
                 }\n";
    let rows: Vec<String> = (0..500).map(|i| format!("  [{i}, {}],", i * i)).collect();
    let filler = format!(
        "export function f(x: number) {{\n  const t = [\n{}\n  ];\n  return t[x];\n}}\n",
        rows.join("\n")
    );
    let source = format!("{block}{filler}{block}");
    let (capped, uncapped) = both(&[("a.ts", &source)]);
    let duplicated = capped.duplicated_tokens();

    // The uncapped count is computed here rather than remembered: it was 3112
    // of 3134 when this test was written, and the capped run answered 3052 —
    // the one shape in the battery where the two differed at all. Region
    // alignment closed it, so the bound below is now met with nothing to spare,
    // which is the point.
    assert!(
        duplicated <= uncapped.duplicated_tokens(),
        "the capped answer must never exceed the uncapped one: coverage is a \
         union over confirmed matches, so it can under-report and cannot \
         over-report ({duplicated} > {})",
        uncapped.duplicated_tokens()
    );
    assert_eq!(
        duplicated,
        uncapped.duplicated_tokens(),
        "two copies of a distinct block at opposite ends of repetitive filler \
         is the shape the cap was last measured to cost 60 tokens on, and it \
         costs none; a gap reappearing here is the freeze returning in a \
         different disguise"
    );
    assert_eq!(capped.total_tokens(), 3134);
}

/// One file set, measured with the cap and without it.
fn both(files: &[(&str, &str)]) -> (CloneReport, CloneReport) {
    let inputs: Vec<FileInput> = files.iter().map(|(p, s)| input(p, s)).collect();
    let (index, _) = Index::empty().update(&inputs);
    let paths: Vec<String> = inputs.iter().map(|i| i.path.clone()).collect();
    (
        detect(&index, &paths),
        detect_with_cap(&index, &paths, usize::MAX),
    )
}

/// A 56-token helper, used as the interruption that splits a repetition.
const HELPER: &str = "export function helper(items: number[], factor: number): number {\n  let total = 0;\n  for (const item of items) {\n    if (item > factor) { total += item * factor; }\n    else { total -= item; }\n  }\n  return total;\n}\n";

/// `rows` rows of `  [i, 3i],` inside a named array — six tokens a row, so the
/// stream is exactly periodic between the prologue and the closing bracket.
fn table(name: &str, rows: usize) -> String {
    let body: Vec<String> = (0..rows).map(|i| format!("  [{i}, {}],", i * 3)).collect();
    format!("export const {name} = [\n{}\n];\n", body.join("\n"))
}

#[test]
fn an_interruption_does_not_lose_the_middle_of_a_repetition() {
    // The reviewers' fixture, at their arithmetic. Three tables of one
    // repeating row, split by two copies of one helper: valid TypeScript, and
    // the plainest shape of generated code there is.
    let source = format!(
        "{}{HELPER}{}{HELPER}{}",
        table("table0", 600),
        table("table1", 300),
        table("table2", 300)
    );
    let (capped, uncapped) = both(&[("a.ts", &source)]);

    // Exact, because a monotonicity assertion is what let the first freeze
    // through: every one of these was wrong by a quarter of the file and none
    // of them was falling.
    assert_eq!(capped.total_tokens(), 7333);
    assert_eq!(
        capped.duplicated_tokens(),
        7333,
        "every token of this file is inside some confirmed clone; the rule this \
         replaced reported 5499 and called it complete"
    );
    assert_eq!(capped.duplicated_ratio(), 1.0, "was 0.749898");
    assert_eq!(
        capped.largest_clone_tokens(),
        1863,
        "the helper, the second table's prologue, its 300 rows and its closing \
         bracket, against the same run over the third table; was 1805"
    );

    // And the same numbers as a run that pairs everything, which is the claim
    // the registry makes and the reason the oracle is computed rather than
    // quoted.
    assert_eq!(capped.duplicated_tokens(), uncapped.duplicated_tokens());
    assert_eq!(
        capped.largest_clone_tokens(),
        uncapped.largest_clone_tokens()
    );
    assert_eq!(
        capped.duplicated_tokens_by_path,
        uncapped.duplicated_tokens_by_path
    );
    assert_eq!(
        capped.duplicated_span_by_path, uncapped.duplicated_span_by_path,
        "the location has to survive the repair as well as the count"
    );
}

#[test]
fn the_longest_clone_grows_with_the_number_of_interruptions() {
    // `k` runs of 300 rows, separated by `k - 1` copies of one helper. The
    // longest reportable clone is the largest whole number of `row-run +
    // helper` units that fits in half the file, so it steps up every second
    // `k` — and the rule this replaces sat at 1794 for every odd `k` above one,
    // which is a count that stopped growing however much content arrived.
    const LARGEST: [u64; 9] = [900, 1856, 1856, 3712, 3712, 5568, 5568, 7424, 7424];
    const DUPLICATED: [u64; 9] = [1800, 3712, 5568, 7424, 9280, 11136, 12992, 14848, 16704];
    let rows: Vec<String> = (0..300).map(|i| format!("  [{i}, {}],", i * 3)).collect();
    let unit = format!("{}\n{HELPER}", rows.join("\n"));
    for k in 1..=9usize {
        let mut source = String::from("export const t = [\n");
        for _ in 0..k {
            source.push_str(&unit);
        }
        source.push_str("];\n");
        let (capped, uncapped) = both(&[("a.ts", &source)]);
        assert_eq!(
            capped.largest_clone_tokens(),
            LARGEST[k - 1],
            "{k} interrupted runs: the longest clone froze at 1794 for k = 3, \
             5, 7 and 9 before the repair"
        );
        assert_eq!(capped.duplicated_tokens(), DUPLICATED[k - 1], "{k} runs");
        assert_eq!(
            capped.largest_clone_tokens(),
            uncapped.largest_clone_tokens(),
            "{k} runs"
        );
        assert_eq!(
            capped.duplicated_tokens(),
            uncapped.duplicated_tokens(),
            "{k} runs"
        );
    }
}

/// Every shape the capped answer is measured against an uncapped one on.
///
/// Wider than the pins above on purpose: those are the shapes somebody thought
/// of, and the disclosure in `registry/clones.toml` is a claim about all of
/// them. Sizes vary either side of the cap, interruptions vary in number and in
/// where they fall, and the tables either side of one vary in length — because
/// two regions of *unequal* length align at their tails and not their heads,
/// and a battery of equal ones would never notice.
fn battery() -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    let mut one = |label: String, source: String| {
        out.push((label, vec![("a.ts".to_string(), source)]));
    };
    for n in [37usize, 60, 200, 500] {
        one(format!("identical {n}"), identical_lines(n));
    }
    for rows in [40usize, 300] {
        one(format!("table {rows}"), table("t", rows));
    }
    for a in [40usize, 300, 600] {
        for b in [40usize, 100, 300] {
            for c in [0usize, 100, 300] {
                let mut source = table("t0", a);
                source.push_str(HELPER);
                source.push_str(&table("t1", b));
                if c > 0 {
                    source.push_str(HELPER);
                    source.push_str(&table("t2", c));
                }
                one(format!("tables {a}/{b}/{c}"), source);
            }
        }
    }
    let block = "export function distinctHelper(items: number[], factor: number): number {\n  let total = 0;\n  for (const item of items) {\n    if (item > factor) { total += item * factor; }\n    else { total -= item; }\n  }\n  return total;\n}\n";
    for rows in [50usize, 200, 500] {
        let filler = table("f", rows);
        one(
            format!("block/filler {rows}/block"),
            format!("{block}{filler}{block}"),
        );
        one(
            format!("filler {rows}/block/filler"),
            format!("{filler}{block}{filler}"),
        );
    }
    for n in [60usize, 200] {
        for cuts in [1usize, 2, 3] {
            let mut source = String::new();
            for cut in 0..=cuts {
                source.push_str(&identical_lines(n));
                if cut < cuts {
                    source.push_str(HELPER);
                }
            }
            one(format!("identical {n} x{cuts}"), source);
        }
    }
    for rows in [100usize, 400] {
        out.push((
            format!("two files of {rows}"),
            vec![
                ("a.ts".to_string(), table("t", rows)),
                ("b.ts".to_string(), format!("{HELPER}{}", table("t", rows))),
            ],
        ));
    }
    out
}

fn measure_both(files: &[(String, String)]) -> (CloneReport, CloneReport) {
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, s)| (p.as_str(), s.as_str()))
        .collect();
    both(&borrowed)
}

#[test]
fn every_size_this_engine_reports_equals_an_uncapped_run() {
    // The disclosure, as a measurement. Four change-scoped numbers, the
    // per-file counts and the per-file spans, against a run that pairs every
    // occurrence with every other one, on every shape in the battery.
    let shapes = battery();
    assert!(shapes.len() >= 40, "the battery is the claim's evidence");
    for (label, files) in &shapes {
        let (capped, uncapped) = measure_both(files);
        assert_eq!(capped.total_tokens(), uncapped.total_tokens(), "{label}");
        assert_eq!(
            capped.duplicated_tokens(),
            uncapped.duplicated_tokens(),
            "{label}"
        );
        assert_eq!(
            capped.duplicated_ratio(),
            uncapped.duplicated_ratio(),
            "{label}"
        );
        assert_eq!(
            capped.largest_clone_tokens(),
            uncapped.largest_clone_tokens(),
            "{label}"
        );
        assert_eq!(
            capped.duplicated_tokens_by_path, uncapped.duplicated_tokens_by_path,
            "{label}"
        );
        assert_eq!(
            capped.duplicated_span_by_path, uncapped.duplicated_span_by_path,
            "{label}: a count with the wrong location is a count nobody can act on"
        );
    }
}

#[test]
fn the_group_count_is_the_one_answer_a_bounded_pairing_cannot_certify() {
    // A group's *members* are the placements some confirmed pair put there, and
    // a bounded pairing finds fewer of them. That changes no size — coverage is
    // a union and a token is in it or is not — and it does change the greedy
    // selection, which drops a whole group when any one member overlaps a
    // region already kept. A group with fewer members can therefore survive a
    // selection its full self would not have.
    //
    // This is the residual, and it is asserted as a measured bound rather than
    // described in a comment, because a comment cannot fail. Both halves
    // matter: how far apart the two counts get, and which way.
    let mut differing = 0usize;
    let mut worst = 0i64;
    for (label, files) in &battery() {
        let (capped, uncapped) = measure_both(files);
        let delta = capped.groups.len() as i64 - uncapped.groups.len() as i64;
        if delta != 0 {
            differing += 1;
            worst = worst.max(delta.abs());
        }
        assert!(
            delta >= 0,
            "{label}: capped {} groups, uncapped {}. Measured, the bounded \
             pairing has only ever described one duplicated region in more \
             pieces than an exhaustive one, never in fewer — so the error \
             cannot buy a pass. A negative delta is a different residual than \
             the one the registry discloses",
            capped.groups.len(),
            uncapped.groups.len()
        );
        assert!(
            delta <= 2,
            "{label}: capped {} groups, uncapped {}",
            capped.groups.len(),
            uncapped.groups.len()
        );
    }
    assert_eq!(
        (differing, worst),
        (15, 2),
        "15 of the battery's shapes report a different group count and the \
         worst is two groups where an uncapped run reports one. The exact \
         figures are here because `registry/clones.toml` publishes them, and a \
         disclosure nothing recomputes is the one that was wrong by an order \
         of magnitude last time"
    );
}

#[test]
fn a_smallest_interrupted_case_says_what_the_group_difference_is() {
    // The residual above in its smallest form, so the mechanism is pinned and
    // not merely counted. 40 rows, a helper, 100 rows: both runs find the
    // 300-token clone inside the second table and cover the same 854 tokens.
    // The uncapped run also finds the 120-token row sequence in *both* tables,
    // which puts a member of that group inside the region already claimed and
    // drops the whole group; the capped run finds it only in the first table,
    // where nothing has been claimed, and keeps it.
    let source = format!("{}{HELPER}{}", table("t0", 40), table("t1", 100));
    let (capped, uncapped) = both(&[("a.ts", &source)]);
    assert_eq!(capped.duplicated_tokens(), 854);
    assert_eq!(uncapped.duplicated_tokens(), 854);
    assert_eq!(capped.largest_clone_tokens(), 300);
    assert_eq!(uncapped.largest_clone_tokens(), 300);
    assert_eq!(capped.groups.len(), 2);
    assert_eq!(uncapped.groups.len(), 1);
}

#[test]
fn a_bucket_too_richly_interrupted_to_walk_says_so() {
    // Laying every region against every occurrence costs occurrences times
    // regions, which content bounds and construction does not. Above the budget
    // the region list is sampled, and that is the one shortfall this engine can
    // see while it happens — so it names the files rather than leaving them to
    // a disclosure. `crates/engines/clones/src/engine.rs` turns the set into
    // `completeness: partial`.
    let mut source = String::from("export const t = [\n");
    for _ in 0..100 {
        let rows: Vec<String> = (0..20).map(|i| format!("  [{i}, {}],", i * 3)).collect();
        source.push_str(&rows.join("\n"));
        source.push('\n');
        source.push_str(HELPER);
    }
    source.push_str("];\n");
    let inputs = vec![input("a.ts", &source)];
    let (index, _) = Index::empty().update(&inputs);
    let paths: Vec<String> = inputs.iter().map(|i| i.path.clone()).collect();
    let report = detect(&index, &paths);
    assert_eq!(
        report.truncated_paths.iter().collect::<Vec<_>>(),
        vec!["a.ts"],
        "a hundred twenty-row runs is four thousand occurrences against a \
         hundred regions, which is four times the budget"
    );

    // And the answer is still a good one: what stops is the claim that it is
    // the whole one.
    assert_eq!(report.duplicated_tokens(), 17600);

    // The shapes the budget covers must not carry the caveat, or it says
    // nothing about the file that earned it. A 3000-row generated table is one
    // region however long it is.
    let rows: Vec<String> = (0..3000).map(|i| format!("  [{i}, {}],", i * i)).collect();
    let table = format!(
        "export function f(x: number) {{\n  const t = [\n{}\n  ];\n  return t[x];\n}}\n",
        rows.join("\n")
    );
    let inputs = vec![input("a.ts", &table)];
    let (index, _) = Index::empty().update(&inputs);
    let paths: Vec<String> = inputs.iter().map(|i| i.path.clone()).collect();
    assert!(detect(&index, &paths).truncated_paths.is_empty());

    // Nor does length alone reach it. Repetition in one unbroken region has no
    // later region to be laid against and costs nothing in the budget however
    // far it runs — 20,000 identical lines are answered exactly, and a caveat
    // there would be about a search that never happened.
    let long = identical_lines(20_000);
    let inputs = vec![input("a.ts", &long)];
    let (index, _) = Index::empty().update(&inputs);
    let paths: Vec<String> = inputs.iter().map(|i| i.path.clone()).collect();
    let report = detect(&index, &paths);
    assert!(report.truncated_paths.is_empty());
    assert_eq!(report.duplicated_tokens(), report.total_tokens());
    assert_eq!(report.duplicated_ratio(), 1.0);
}
