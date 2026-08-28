//! Canonical JSON serialization and per-result digests.
//!
//! Every digest that Andon compares agent-side against CI-side is taken over the
//! output of [`to_canonical_string`]. Byte-nondeterminism here is the mechanism
//! behind PREMORTEM T1 — the false-divergence epidemic — so the rules are fixed,
//! documented, and property-tested rather than inherited from a serializer's
//! defaults.
//!
//! # Rules
//!
//! 1. **Object keys are sorted by UTF-16 code unit**, as RFC 8785 (JCS) requires.
//!    `serde_json` runs with `preserve_order`, so nothing else in the workspace
//!    sorts keys implicitly: this function is the only sort.
//! 2. **No insignificant whitespace.** No spaces after `:` or `,`, no newlines.
//! 3. **Strings** use minimal JSON escaping: `"`, `\`, and control characters
//!    below `0x20` (with the short forms `\b \f \n \r \t` where they exist,
//!    `\u00xx` otherwise). Non-ASCII is emitted as UTF-8, never escaped.
//! 4. **Integers** that fit `i64`/`u64` are emitted as exact decimal digits.
//! 5. **Floats** are emitted with ECMAScript `Number::toString` formatting: the
//!    shortest decimal string that round-trips, positioned per ES6's exponent
//!    rules. `-0.0` normalizes to `0`. Non-finite floats are rejected.
//!
//! # Where rule 5 is actually enforced
//!
//! Not here, and the distinction matters. This module reaches its own float path
//! through `serde_json::to_value`, and `serde_json::Number` cannot hold a
//! non-finite value at all: `to_value` maps NaN and the infinities to `null`
//! instead of failing. A `Serialize` type that hands out a NaN therefore arrives
//! at `write_value` as a `null` that hashes perfectly well, producing a valid
//! digest over a hole where a measurement should be. [`format_es6_double`] does
//! reject non-finite input, but nothing routed through `to_value` can reach it
//! with one.
//!
//! The enforcing boundary is the schema's serializer instead:
//! [`crate::schema::payload::MetricValue::Ratio`] is the only float payload v1
//! declares, and it rejects non-finite and non-quantizable values at
//! serialization time, so `seal()` fails rather than sealing corruption. **Any
//! new float field must do the same** — an `f64` serialized with serde's default
//! impl is silently `null`-able, and a test asserting that the committed schemas
//! declare exactly one float carrier guards the assumption.
//!
//! # Deliberate deviation from RFC 8785
//!
//! JCS routes *every* number through the ES6 double path, which silently loses
//! precision above 2^53. Andon emits `i64`/`u64` exactly instead, because counts
//! are a compared quantity and PLAN.md requires them exact. The output is
//! therefore *JCS-style*, not JCS-conformant. Both sides of every digest compare
//! run the same binary, so self-consistency is what carries the trust property;
//! wire-compatibility with third-party JCS implementations is not claimed.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Something went wrong turning a value into canonical bytes.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    /// A float was NaN or an infinity. JSON cannot represent either, and a
    /// measurement that produced one is a bug in the engine, not a value to
    /// round-trip.
    #[error("non-finite float ({0}) cannot be canonically serialized")]
    NonFiniteFloat(f64),
    /// The value could not be converted into `serde_json::Value` at all.
    #[error("value is not serializable as JSON: {0}")]
    NotSerializable(#[from] serde_json::Error),
}

/// Serialize any `Serialize` value to its canonical JSON string.
pub fn to_canonical_string<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let json = serde_json::to_value(value)?;
    let mut out = String::new();
    write_value(&json, &mut out)?;
    Ok(out)
}

/// Canonical JSON bytes. The digest input is always this, never a `Display` form.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    to_canonical_string(value).map(String::into_bytes)
}

/// Lowercase hex SHA-256 over the canonical bytes of `value`.
///
/// This is the one digest function in the workspace. Per-result digests, the
/// policy hash, and the registry fingerprint all route through it so that "the
/// digest" is never ambiguous about what was hashed or how it was encoded.
pub fn digest<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let bytes = to_canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn write_value(value: &serde_json::Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(true) => out.push_str("true"),
        serde_json::Value::Bool(false) => out.push_str("false"),
        serde_json::Value::Number(n) => write_number(n, out)?,
        serde_json::Value::String(s) => write_string(s, out),
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            // Sort by UTF-16 code unit (JCS §3.2.3). For ASCII keys this matches
            // byte order; it diverges only above the BMP, where UTF-16 surrogate
            // pairs order differently than UTF-8 bytes.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[key.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), CanonicalError> {
    if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
        return Ok(());
    }
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
        return Ok(());
    }
    let f = n.as_f64().ok_or(CanonicalError::NonFiniteFloat(f64::NAN))?;
    out.push_str(&format_es6_double(f)?);
    Ok(())
}

/// Format a double the way ECMAScript's `Number::toString` (radix 10) does.
///
/// ES6 defines the output in terms of integers `s`, `k`, `n` where `s` has `k`
/// decimal digits, `10^(k-1) <= s < 10^k`, `s * 10^(n-k) == x`, and `k` is as
/// small as possible. We recover `s` and `n` by asking Rust's formatter for
/// increasing significant-digit counts and taking the first that round-trips —
/// `core::fmt`'s fixed-precision float formatting is exact and pure Rust, so the
/// search is deterministic on every platform.
pub fn format_es6_double(x: f64) -> Result<String, CanonicalError> {
    if !x.is_finite() {
        return Err(CanonicalError::NonFiniteFloat(x));
    }
    // ES6 renders both zeroes as "0"; JCS §3.2.2.3 likewise normalizes -0.
    if x == 0.0 {
        return Ok("0".to_string());
    }
    let negative = x < 0.0;
    let abs = x.abs();

    let (digits, n) = shortest_digits(abs);
    let k = digits.len() as i32;

    let mut body = String::new();
    if k <= n && n <= 21 {
        // Integer with (n - k) trailing zeros.
        body.push_str(&digits);
        for _ in 0..(n - k) {
            body.push('0');
        }
    } else if 0 < n && n <= 21 {
        // Decimal point falls inside the digit string.
        body.push_str(&digits[..n as usize]);
        body.push('.');
        body.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        // Leading "0." then (-n) zeros.
        body.push_str("0.");
        for _ in 0..(-n) {
            body.push('0');
        }
        body.push_str(&digits);
    } else {
        // Exponential form; exponent is n-1 and always carries an explicit sign.
        let exp = n - 1;
        if k == 1 {
            body.push_str(&digits);
        } else {
            body.push_str(&digits[..1]);
            body.push('.');
            body.push_str(&digits[1..]);
        }
        body.push('e');
        if exp >= 0 {
            body.push('+');
        } else {
            body.push('-');
        }
        body.push_str(&exp.abs().to_string());
    }

    Ok(if negative { format!("-{body}") } else { body })
}

/// Returns the shortest round-tripping decimal digit string for a positive
/// finite double, plus the ES6 exponent `n` (value == 0.digits * 10^n).
fn shortest_digits(abs: f64) -> (String, i32) {
    debug_assert!(abs > 0.0 && abs.is_finite());
    for precision in 0..=17usize {
        let formatted = format!("{abs:.precision$e}");
        // Rust renders scientific notation as `d.ddd e ±?exp`, e.g. "1.25e2",
        // "1e-7". The exponent has no explicit `+`.
        let (mantissa, exp) = formatted
            .split_once('e')
            .expect("Rust LowerExp always emits an exponent");
        if formatted.parse::<f64>() != Ok(abs) {
            continue;
        }
        let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
        // The minimal-precision search cannot leave a trailing zero: if the
        // p-digit rounding ended in one, the (p-1)-digit rounding names the same
        // value and would have round-tripped first. Trim defensively anyway so a
        // formatter change can never leak a non-canonical digit string.
        let digits = digits.trim_end_matches('0');
        let digits = if digits.is_empty() { "0" } else { digits };
        let exp: i32 = exp.parse().expect("Rust emits a decimal exponent");
        // Rust's mantissa is `d.ddd` (one digit before the point), so the value
        // is digits * 10^(exp - (k-1)). ES6 wants s * 10^(n-k), giving n = exp+1.
        return (digits.to_string(), exp + 1);
    }
    unreachable!("17 significant digits always round-trip an f64");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn es6_number_formatting_matches_the_spec_examples() {
        // Hand-checked against ECMAScript Number::toString.
        let cases: &[(f64, &str)] = &[
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (-1.0, "-1"),
            (100.0, "100"),
            (0.1, "0.1"),
            (1.5, "1.5"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1.25e-7, "1.25e-7"),
            (f64::MAX, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                &format_es6_double(*input).unwrap(),
                expected,
                "formatting {input}"
            );
        }
    }

    #[test]
    fn non_finite_floats_are_rejected() {
        assert!(format_es6_double(f64::NAN).is_err());
        assert!(format_es6_double(f64::INFINITY).is_err());
        assert!(format_es6_double(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn keys_are_sorted_and_whitespace_is_stripped() {
        let value = json!({ "b": 1, "a": 2, "C": 3 });
        // Uppercase sorts before lowercase in UTF-16 code unit order.
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            r#"{"C":3,"a":2,"b":1}"#
        );
    }

    #[test]
    fn large_integers_keep_full_precision() {
        // The JCS deviation, pinned: u64::MAX survives, where the ES6 double path
        // would round it to 18446744073709552000.
        let value = json!({ "count": u64::MAX });
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            r#"{"count":18446744073709551615}"#
        );
    }

    #[test]
    fn strings_use_minimal_escaping_and_raw_utf8() {
        let value = json!({ "k": "a\"b\\c\nd\u{1}e — ü" });
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            "{\"k\":\"a\\\"b\\\\c\\nd\\u0001e — ü\"}"
        );
    }

    #[test]
    fn digest_is_stable_and_hex() {
        let d = digest(&json!({ "a": 1 })).unwrap();
        assert_eq!(d.len(), 64);
        assert!(d
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        assert_eq!(d, digest(&json!({ "a": 1 })).unwrap());
    }
}
