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

/// The algorithm name stamped into the `measurement_regime`.
pub const ALGORITHM: &str = "rabin-karp";

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
