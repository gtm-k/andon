//! Rabin-Karp fingerprints over a token window.
//!
//! One rolling hash per position, each covering [`WINDOW_TOKENS`] normalized
//! symbols. Two windows with equal hashes are *candidate* copies; the candidate
//! is confirmed by comparing the symbol slices themselves ([`super::detect`]),
//! so a hash collision produces a slower run and never a wrong answer. That
//! matters more here than in a search index: a false clone report is a number an
//! agent is asked to act on, and — through the digest compare — a number the
//! verifier must reproduce exactly.
//!
//! All arithmetic is `wrapping_*` on `u64`, which is defined identically on
//! every target. Nothing here depends on pointer width, float behaviour, or a
//! process seed.

/// Symbols covered by one rolling window.
///
/// The granularity at which a copy is *noticed*. Small enough that a copied
/// helper is seen, large enough that ordinary syntax (`} else {`, `return x;`)
/// does not collide with itself across a codebase.
pub const WINDOW_TOKENS: u32 = 25;

/// Shortest run of tokens reported as a clone.
///
/// A window match alone is not a finding: [`WINDOW_TOKENS`] of shared syntax is
/// common in honest code. A clone is reported once matching windows extend to
/// this many tokens, i.e. `MIN_CLONE_TOKENS - WINDOW_TOKENS + 1` consecutive
/// window matches.
pub const MIN_CLONE_TOKENS: u32 = 50;

/// Occurrences of one window hash beyond which a bucket is treated as
/// saturated repetition.
///
/// # Why a cap exists at all
///
/// Expansion is pairwise within a bucket, so a file whose tokens repeat — a
/// long literal table, a minified bundle, a hundred near-identical guard
/// clauses — costs O(n^2) in the number of occurrences. Measured on a literal
/// table: 200 rows in 2.8 ms, 800 in 27 ms, 2000 in 178 ms. Extrapolated, a
/// large generated file would blow the fast lane's 1000 ms warm budget on its
/// own, which is PREMORTEM T6 arriving through an engine instead of through git.
///
/// # The paragraph that used to be here was false, and it froze a number
///
/// It said that pairing each occurrence with its *nearest usable* partner
/// preserved the answer for periodic content, "because the greedy disjoint
/// selection in [`crate::detect`] keeps exactly that one — the longer-lag
/// matches are the ones it discards anyway".
///
/// The greedy selection sorts by length **descending**. It keeps the longest
/// match and discards the shorter ones, which is the opposite of what that
/// sentence claimed — so the saturated path generated only the candidate the
/// selection throws away and never the candidate it keeps. On content periodic
/// enough to saturate a bucket, every occurrence's nearest usable partner sits
/// at the same short lag and every seed but the first is rejected as the
/// interior of a match already being extended, leaving exactly one group of
/// exactly one lag no matter how long the file is. Measured, on N identical
/// `export const vN = N;` lines: 36 lines reported 216 duplicated tokens and a
/// ratio of 1.0, and 37 lines through 200,000 lines all reported 108 tokens —
/// so the reported *ratio fell as the real duplication rose*, to 0.00009.
///
/// # The rule that replaced it was derived for one periodic block
///
/// It paired an occurrence with the nearest usable partner and with the two
/// same-file occurrences bracketing the position that maximizes the reportable
/// length — which is exactly right while the repetition is contiguous, and
/// loses the middle as soon as identical interruptions split it into three
/// stretches or more. A file of `600 rows / helper / 300 rows / helper / 300
/// rows` reported 5499 of 7333 tokens, a quarter of itself missed and stamped
/// `complete`, and the same interruption froze `largest-clone-tokens` at 1794
/// however far the true longest clone grew. The freeze above was the
/// contiguous form of one defect; that was the interrupted form of it.
///
/// # What the cap does now
///
/// Above the cap, an occurrence is paired with a bounded set of partners
/// instead of with all of them. The bucket is first split into the *regions*
/// its occurrences fall into, and `bounded_partners` in [`crate::detect`] lays
/// `a` against each of them head to head and tail to tail, alongside the two
/// crossings and the nearest usable partner. The three rules and their
/// derivations are there rather than here.
///
/// Measured rather than asserted, and the oracle is runnable rather than
/// remembered: `detect::detect_with_cap` takes the cap as an argument, so
/// `tests/periodic_saturation.rs` computes the uncapped answer on every shape
/// in its battery and compares. Every size the engine reports — duplicated
/// tokens, the ratio, the per-file count and the longest clone — is equal to
/// the uncapped answer on all of them.
///
/// Given up, and it is `clones.clone-groups` alone that gives it up: the
/// *members* of a group are the placements some confirmed pair put there, and a
/// bounded pairing finds fewer of them. That changes nothing about the sizes,
/// which are a union, and it does change the greedy selection in
/// [`crate::detect`], which drops a whole group when any one member overlaps a
/// region already kept — so a group with fewer members can survive a selection
/// its full self would not have, or fail to block one. The measured effect is
/// small and runs in both directions; it is bounded in the battery and
/// disclosed in `registry/clones.toml`, because the reader who needs it is
/// reading a number and not this file.
///
/// The cap only engages above 32 occurrences of one window hash, which takes
/// genuinely repetitive content to reach, and the alternative is quadratic — an
/// uncapped run over a 3000-row literal table took 6.6 s against a 1000 ms
/// fast-lane budget.
///
/// The cap changes numbers, so it is part of the regime: see [`ALGORITHM`].
pub const SATURATED_OCCURRENCES: usize = 32;

/// Occurrence-region pairs a saturated bucket may lay out before the region
/// list is sampled instead of walked.
///
/// Laying every region against every occurrence is what makes the answer over
/// interrupted repetition right, and its cost is `occurrences x regions` —
/// bounded by the content and not by the algorithm. A file alternating six rows
/// with a helper a thousand times reaches 6,000,000 and took 19.7 s in a debug
/// build; the same file under this budget takes 0.8 s.
///
/// Above it, only the next region is laid against each occurrence and the
/// search is no longer a search of everywhere. Unlike every other shortfall the
/// cap has, this one is *detectable while it happens*, so it is not left to a
/// disclosure: `detect` records the files of every bucket it sampled and the
/// engine reports their results `partial` rather than `complete`. See
/// [`crate::detect::CloneReport::truncated_paths`].
///
/// Changes numbers when it engages, so it is named in [`ALGORITHM`] beside the
/// occurrence cap.
pub const REGION_PAIR_BUDGET: usize = 100_000;

/// The algorithm name stamped into the `measurement_regime`.
///
/// Carries [`SATURATED_OCCURRENCES`] because that constant can change a
/// reported value, and a parameter that changes results and is not in the regime
/// is a digest disagreement the verifier would read as tampering rather than as
/// skew (PREMORTEM S4).
///
/// The suffix is the same rule applied to the *strategy* rather than the
/// constant. The cap is still 32; what changed is which partners a saturated
/// bucket pairs — and that moves every reported number on periodic content, so
/// a run before this change and a run after it are not comparable measurements
/// and must not meet at an equal regime. It has now moved twice: `sat32-mid`
/// was the crossing rule that unfroze contiguous repetition, and
/// `sat32-region100k` is the region alignment that unfroze interrupted
/// repetition, carrying [`REGION_PAIR_BUDGET`] because that constant decides
/// where the region walk stops and therefore what the numbers are.
///
/// It carries the location change too, which arrived in the same revision:
/// `ResultScope` is inside `ResultDigestInput`, so filling in a path and a line
/// span moves every per-result digest this engine produces even where the number
/// is unchanged. One regime move for both, because they ship together and no
/// build exists with one and not the other.
pub const ALGORITHM: &str = "rabin-karp+sat32-region100k";

/// Rolling-hash base. An odd constant, so multiplication is invertible modulo
/// 2^64 and the low bits are not thrown away.
const BASE: u64 = 0x0000_0100_0000_01b3;

/// The number of consecutive window matches a clone of `tokens` length spans.
pub fn windows_for(tokens: u32) -> u32 {
    tokens.saturating_sub(WINDOW_TOKENS).saturating_add(1)
}

/// Rolling hashes for every window position in `symbols`.
///
/// Returns an empty vector when the stream is shorter than one window: a file
/// with fewer than [`WINDOW_TOKENS`] tokens cannot contain a clone of
/// [`MIN_CLONE_TOKENS`], so it contributes nothing rather than contributing a
/// short window that would match every other short file.
pub fn windows(symbols: &[u64]) -> Vec<u64> {
    let width = WINDOW_TOKENS as usize;
    if symbols.len() < width {
        return Vec::new();
    }

    // BASE^(width-1), for removing the symbol leaving the window.
    let mut high = 1u64;
    for _ in 0..width - 1 {
        high = high.wrapping_mul(BASE);
    }

    let mut hashes = Vec::with_capacity(symbols.len() - width + 1);
    let mut hash = 0u64;
    for symbol in &symbols[..width] {
        hash = hash.wrapping_mul(BASE).wrapping_add(*symbol);
    }
    hashes.push(hash);

    for start in 1..=symbols.len() - width {
        let leaving = symbols[start - 1].wrapping_mul(high);
        hash = hash
            .wrapping_sub(leaving)
            .wrapping_mul(BASE)
            .wrapping_add(symbols[start + width - 1]);
        hashes.push(hash);
    }
    hashes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(symbols: &[u64]) -> Vec<u64> {
        let width = WINDOW_TOKENS as usize;
        if symbols.len() < width {
            return Vec::new();
        }
        (0..=symbols.len() - width)
            .map(|start| {
                symbols[start..start + width]
                    .iter()
                    .fold(0u64, |acc, s| acc.wrapping_mul(BASE).wrapping_add(*s))
            })
            .collect()
    }

    fn stream(len: usize) -> Vec<u64> {
        (0..len as u64)
            .map(|i| i.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x5bf0_3635)
            .collect()
    }

    #[test]
    fn the_roll_agrees_with_recomputing_each_window() {
        for len in [25usize, 26, 40, 200] {
            let symbols = stream(len);
            assert_eq!(windows(&symbols), naive(&symbols), "length {len}");
        }
    }

    #[test]
    fn short_streams_contribute_nothing() {
        assert!(windows(&stream(0)).is_empty());
        assert!(windows(&stream(WINDOW_TOKENS as usize - 1)).is_empty());
        assert_eq!(windows(&stream(WINDOW_TOKENS as usize)).len(), 1);
    }

    #[test]
    fn equal_content_at_different_offsets_hashes_equal() {
        let body = stream(60);
        let mut a = stream(7);
        a.extend_from_slice(&body);
        let mut b = stream(31);
        b.extend_from_slice(&body);
        let wa = windows(&a);
        let wb = windows(&b);
        assert_eq!(wa[7], wb[31]);
    }

    #[test]
    fn a_clone_at_the_floor_spans_the_expected_window_count() {
        assert_eq!(windows_for(MIN_CLONE_TOKENS), 26);
        assert_eq!(windows_for(WINDOW_TOKENS), 1);
        assert_eq!(windows_for(0), 1);
    }
}
