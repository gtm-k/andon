//! Shannon entropy, computed without a floating-point library.
//!
//! # Why not `f64::log2`
//!
//! Ownership entropy is the one number in this engine that wants a logarithm,
//! and a logarithm is exactly the operation IEEE 754 does **not** require to be
//! correctly rounded. `f64::log2` calls the platform's libm — glibc, Apple's,
//! and the MSVC runtime are three different implementations — and they are
//! permitted to disagree in the last place. A one-ULP disagreement between a
//! Windows agent and a Linux verifier is a different `value` in
//! `ResultDigestInput`, a different per-result digest, and `divergent` on an
//! honest change. That is PREMORTEM Story 1 with the CRLF swapped for a
//! transcendental function, and no amount of blob-only reading prevents it.
//!
//! Quantizing to six decimal places (`RATIO_DECIMAL_PLACES`) shrinks the
//! exposure without removing it: two values a ULP apart still round to different
//! sixth decimals when they straddle a rounding boundary. Rare is how the false
//! divergence epidemic starts, not a reason it will not.
//!
//! So the entropy is computed in **integer arithmetic only** and reported in
//! micro-bits, which the caller divides by 1e6. Every step below is exact and
//! platform-independent: fixed-point squaring, comparison, shifting, and integer
//! division. The one floating-point operation left is that final division, and
//! division *is* correctly rounded by IEEE 754 — the same bits everywhere.
//!
//! # The formula
//!
//! ```text
//! H = -Σ (cᵢ/N)·log2(cᵢ/N) = log2(N) - (Σ cᵢ·log2(cᵢ)) / N
//! ```
//!
//! The right-hand form is used because it needs logarithms of *integers* only,
//! which is what `log2_q32` can compute exactly enough. Zero for a single
//! author, `log2(k)` for k authors with equal shares.

/// Fractional bits in the fixed-point representation. 2⁻³² ≈ 2.3e-10 bits,
/// four orders of magnitude finer than the micro-bit the result is reported in.
const FRACTIONAL_BITS: u32 = 32;

/// One, in Q32.
const ONE: u128 = 1 << FRACTIONAL_BITS;

/// Micro-bits per bit. The reporting unit, chosen to match
/// `RATIO_DECIMAL_PLACES = 6`: a value expressed in whole micro-bits survives
/// the payload's quantization exactly, so nothing is lost twice.
pub const MICROBITS_PER_BIT: u64 = 1_000_000;

/// Shannon entropy of a count distribution, in micro-bits.
///
/// `counts` are commit counts per author. Zeros are ignored — an author with no
/// commits contributes nothing to the distribution and `0·log2(0)` is defined as
/// zero in this limit — and an empty or single-valued distribution is zero,
/// which is the honest reading: one author means no diffusion.
pub fn entropy_microbits(counts: &[u64]) -> u64 {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0;
    }
    let mut weighted: u128 = 0;
    for count in counts.iter().copied().filter(|c| *c > 0) {
        weighted += u128::from(count) * log2_q32(count);
    }
    // Integer division truncates, which biases the subtrahend down by at most
    // 2⁻³² bits and therefore the entropy up by the same. Deterministic, and
    // four orders of magnitude below the reported unit.
    let h_q32 = log2_q32(total).saturating_sub(weighted / u128::from(total));
    // Round to nearest micro-bit rather than truncating, so that a distribution
    // whose entropy is exactly k micro-bits reports k and not k-1.
    let scaled = h_q32 * u128::from(MICROBITS_PER_BIT) + (ONE >> 1);
    (scaled >> FRACTIONAL_BITS) as u64
}

/// `log2(n) × 2³²`, for `n ≥ 1`, by binary digit extraction.
///
/// The integer part comes from the position of the top bit. The fraction is
/// found one bit at a time: square the mantissa, and if it crossed two, emit a
/// one and halve it. Thirty-two iterations give thirty-two fractional bits.
///
/// `n` is a commit count, so the `n < 2³³` bound the mantissa shift needs is not
/// a constraint anyone can reach — a single file would have to be touched by
/// eight billion commits inside the window. It is checked rather than assumed,
/// and the fallback is a saturating shift that loses precision rather than
/// panicking, because a measurement engine has no business aborting a
/// measurement over an implausible number.
fn log2_q32(n: u64) -> u128 {
    if n <= 1 {
        return 0;
    }
    let integer_part = 63 - n.leading_zeros();
    let mut result = u128::from(integer_part) << FRACTIONAL_BITS;

    // The mantissa, in Q32 and in [1, 2).
    let mut mantissa = if integer_part <= FRACTIONAL_BITS {
        u128::from(n) << (FRACTIONAL_BITS - integer_part)
    } else {
        u128::from(n) >> (integer_part - FRACTIONAL_BITS)
    };

    let mut bit = ONE >> 1;
    while bit > 0 {
        mantissa = (mantissa * mantissa) >> FRACTIONAL_BITS;
        if mantissa >= ONE << 1 {
            mantissa >>= 1;
            result += bit;
        }
        bit >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entropy in bits, for readable assertions.
    fn bits(counts: &[u64]) -> f64 {
        entropy_microbits(counts) as f64 / MICROBITS_PER_BIT as f64
    }

    #[test]
    fn one_author_is_zero_entropy() {
        assert_eq!(entropy_microbits(&[7]), 0);
        assert_eq!(entropy_microbits(&[]), 0);
        assert_eq!(entropy_microbits(&[0, 0]), 0);
    }

    #[test]
    fn equal_shares_give_log2_of_the_author_count() {
        // The textbook values, to the micro-bit.
        assert!((bits(&[1, 1]) - 1.0).abs() < 1e-6);
        assert!((bits(&[3, 3, 3, 3]) - 2.0).abs() < 1e-6);
        assert!((bits(&[1, 1, 1, 1, 1, 1, 1, 1]) - 3.0).abs() < 1e-6);
    }

    #[test]
    fn a_lopsided_distribution_sits_below_the_even_one() {
        // 99:1 is nearly single-owner; 50:50 is maximally diffused for two.
        assert!(bits(&[99, 1]) < bits(&[50, 50]));
        assert!(bits(&[99, 1]) > 0.0);
    }

    #[test]
    fn the_three_author_case_matches_the_closed_form() {
        // H(1/2, 1/4, 1/4) = 1.5 bits exactly.
        assert_eq!(entropy_microbits(&[2, 1, 1]), 1_500_000);
    }

    #[test]
    fn log2_is_exact_on_the_powers_of_two() {
        for exponent in 0..40u32 {
            assert_eq!(
                log2_q32(1u64 << exponent),
                u128::from(exponent) << FRACTIONAL_BITS,
                "log2(2^{exponent}) must be exactly {exponent}"
            );
        }
    }

    #[test]
    fn log2_agrees_with_the_platform_to_well_under_a_microbit() {
        // The platform's libm is the *reference* here and never the
        // implementation: this test is what says the integer version is right,
        // and the integer version is what ships, so a libm that disagrees in the
        // last place cannot reach a digest.
        for n in [2u64, 3, 5, 7, 10, 100, 1_000, 65_537, 1_000_000] {
            let ours = log2_q32(n) as f64 / (ONE as f64);
            assert!(
                (ours - (n as f64).log2()).abs() < 1e-9,
                "log2({n}): integer {ours} vs libm {}",
                (n as f64).log2()
            );
        }
    }

    #[test]
    fn the_result_survives_the_payloads_quantization_unchanged() {
        // Micro-bits were chosen to match RATIO_DECIMAL_PLACES. If that ever
        // stops holding, entropy starts losing its last digit on the wire.
        for counts in [&[2u64, 1, 1][..], &[99, 1][..], &[5, 3, 2, 1][..]] {
            let micro = entropy_microbits(counts);
            let as_ratio = micro as f64 / MICROBITS_PER_BIT as f64;
            let quantized = andon_core::schema::payload::quantize_ratio(as_ratio)
                .expect("entropy is finite and small");
            assert_eq!(
                (quantized * MICROBITS_PER_BIT as f64).round() as u64,
                micro,
                "quantization changed the entropy of {counts:?}"
            );
        }
    }
}
