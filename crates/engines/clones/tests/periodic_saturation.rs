//! The duplication count over periodic content, pinned so it cannot re-freeze.
//!
//! # What went wrong, in one sentence
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
//!
//! The values below were confirmed against a run with the cap disabled
//! (`SATURATED_OCCURRENCES = usize::MAX`): every shape here answers identically
//! capped and uncapped, at 1/70th of the cost on the largest of them.

use andon_engine_clones::detect::detect;
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
    let (total, duplicated, _, _, _) = measure(&format!("{block}{filler}{block}"));

    // Measured uncapped: 3112 of 3134. Capped: 3052.
    const UNCAPPED: u64 = 3112;
    assert!(
        duplicated <= UNCAPPED,
        "the capped answer must never exceed the uncapped one: coverage is a \
         union over confirmed matches, so it can under-report and cannot \
         over-report ({duplicated} > {UNCAPPED})"
    );
    assert!(
        duplicated * 100 >= UNCAPPED * 95,
        "the residual loss on the worst shape in the battery was 60 tokens of \
         {UNCAPPED}; {duplicated} of {total} is a bigger gap than this cap has \
         ever been measured to cost, and a growing one is the freeze returning \
         in a different disguise"
    );
}
