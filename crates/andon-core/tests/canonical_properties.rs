//! Property tests for canonical serialization.
//!
//! PLAN.md P0 requires these to be properties rather than snapshots, and the
//! reason is in PREMORTEM Story 1: a snapshot pins the cases someone thought of,
//! while the failure mode was three independent sources of byte-nondeterminism
//! nobody thought of. A property that holds over generated input is the only
//! kind of evidence that speaks to the cases not enumerated.

use andon_core::canonical::{digest, format_es6_double, to_canonical_string};
use andon_core::schema::payload::{quantize_ratio, MetricValue};
use andon_core::testing::{sample_compare_context, sample_result};
use proptest::prelude::*;
use serde_json::{Map, Number, Value};

/// A ratio that cannot be carried never reaches a digest.
///
/// The path under test is the real one — `MeasurementResult::seal` — and not
/// `format_es6_double`, because the canonicalizer never sees these values as
/// numbers. `serde_json::to_value` maps NaN and the infinities to `null`, so
/// without a rejecting serializer on the schema's only float carrier a corrupted
/// measurement seals into a perfectly valid digest taken over a hole. `1e308` is
/// the case that looks safe: finite on the way in, infinite once scaled for
/// six-decimal rounding.
#[test]
fn a_ratio_that_cannot_be_carried_never_reaches_a_digest() {
    let ctx = sample_compare_context();
    for bad in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        1e308,
        -1e308,
        f64::MAX,
    ] {
        let mut result = sample_result();
        result.value = MetricValue::Ratio(bad);
        result.digest = String::new();

        assert!(
            to_canonical_string(&MetricValue::Ratio(bad)).is_err(),
            "canonical serialization accepted {bad}"
        );
        assert!(
            digest(&result.digest_input(&ctx)).is_err(),
            "the digest input accepted {bad}"
        );
        assert!(result.seal(&ctx).is_err(), "seal accepted {bad}");
        assert!(
            result.digest.is_empty(),
            "a failed seal on {bad} must leave no digest behind"
        );
    }
}

/// A failed re-seal leaves no digest, rather than the previous one.
///
/// PROBE14. The test above starts from an unsealed result, so it never covered
/// the case where a *valid* digest is already in place: seal, mutate the value
/// to something unserializable, re-seal. The error was returned correctly, but
/// the old digest survived — a record that still looked sealed while its digest
/// described a value it no longer held. An absent digest is a visible problem; a
/// stale one is indistinguishable from a good seal.
#[test]
fn a_failed_reseal_leaves_no_stale_digest() {
    let ctx = sample_compare_context();
    let mut result = sample_result();
    let original = result.digest.clone();
    assert!(!original.is_empty(), "the fixture arrives sealed");

    result.value = MetricValue::Ratio(f64::NAN);
    assert!(result.seal(&ctx).is_err(), "NaN must not seal");
    assert!(
        result.digest.is_empty(),
        "a failed re-seal left the previous digest in place: {}",
        result.digest
    );
    assert_ne!(result.digest, original);
}

/// The rejection holds on the way in as well.
///
/// NaN cannot be spelled in JSON, but `1e308` can, so a stored or hostile record
/// could otherwise import a value that overflows the moment it is re-quantized.
#[test]
fn an_unquantizable_ratio_is_refused_when_read_back() {
    assert!(
        serde_json::from_str::<MetricValue>(r#"{"kind":"ratio","value":1e308}"#).is_err(),
        "a ratio that cannot be quantized must not deserialize"
    );
    assert!(
        serde_json::from_str::<MetricValue>(r#"{"kind":"ratio","value":0.5}"#).is_ok(),
        "an ordinary ratio still reads back"
    );
}

/// Guards the key-order property below.
///
/// The whole point of that test is that the canonicalizer does the sorting. If
/// `serde_json` were built without `preserve_order` its `Map` would be a
/// `BTreeMap`, insertion order would be lost before the canonicalizer ever ran,
/// and the test would pass while proving nothing. This asserts the premise.
#[test]
fn serde_json_preserves_insertion_order_so_the_key_order_property_is_not_vacuous() {
    let mut map = Map::new();
    map.insert("z".to_string(), Value::from(1));
    map.insert("a".to_string(), Value::from(2));
    let keys: Vec<&String> = map.keys().collect();
    assert_eq!(
        keys,
        vec!["z", "a"],
        "serde_json must be built with `preserve_order`, or the key-order \
         property test is testing nothing"
    );
}

/// `serde_json`'s float parser is not correctly rounded for every input.
///
/// Pinned here because the discovery shaped the schema. `format_es6_double`
/// emits the shortest text that Rust's own (correctly rounded) parser maps back
/// to the identical bits; `serde_json` reads that same text one ULP low. So a
/// raw `f64` written by the agent and re-read by a consumer is not guaranteed to
/// be the number that was measured — and a digest taken over the re-read value
/// would differ, reporting `divergent` on an honest change (PREMORTEM T1).
///
/// The schema's answer is [`andon_core::schema::payload::MetricValue::Ratio`],
/// which quantizes to six decimal places and so never reaches the imprecise
/// path. This test fails if `serde_json` is ever fixed, which is the moment to
/// revisit that decision — a failure here is good news, not a regression.
#[test]
fn serde_json_float_parsing_is_not_ulp_exact() {
    let value = 1.2689392828653361e-47f64;
    let text = format_es6_double(value).unwrap();

    let by_rust: f64 = text.parse().unwrap();
    assert_eq!(
        by_rust.to_bits(),
        value.to_bits(),
        "the canonical writer must round-trip through a correctly rounded parser"
    );

    let by_serde: f64 = serde_json::from_str(&text).unwrap();
    assert_ne!(
        by_serde.to_bits(),
        value.to_bits(),
        "serde_json now parses this exactly; re-examine whether MetricValue::Ratio \
         still needs quantizing"
    );
}

/// Generate arbitrary JSON, with finite floats only — a non-finite float cannot
/// be represented in JSON and the canonicalizer rejects it by design.
///
/// Floats are quantized the way `MetricValue::Ratio` quantizes them. That is not
/// a convenience: the round-trip properties below assert what the *schema*
/// guarantees, and the schema guarantees stability for the values it actually
/// carries. `format_es6_double` is separately exercised over the full range of
/// finite doubles by the properties that do not involve a JSON parser.
fn arbitrary_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        (-1e9f64..1e9f64)
            .prop_map(|f| quantize_ratio(f).expect("this range is always quantizable"))
            .prop_map(|f| Value::Number(Number::from_f64(f).expect("finite"))),
        ".*".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            // Keys are drawn from a small alphabet so collisions and orderings
            // actually occur rather than being astronomically unlikely.
            prop::collection::vec(("[a-zA-Z]{1,3}", inner), 0..6).prop_map(|entries| {
                let mut map = Map::new();
                for (key, value) in entries {
                    map.insert(key, value);
                }
                Value::Object(map)
            }),
        ]
    })
}

proptest! {
    /// Canonical output must not depend on the order keys were inserted in.
    ///
    /// Randomized map iteration order was one of the three independent causes
    /// behind the false-divergence story.
    #[test]
    fn key_insertion_order_does_not_change_canonical_bytes(
        entries in prop::collection::vec(("[a-zA-Z]{1,4}", any::<i64>()), 0..12),
        rotation in 0usize..12,
    ) {
        let mut forward = Map::new();
        for (key, value) in &entries {
            forward.insert(key.clone(), Value::from(*value));
        }

        // Same entries, different insertion order: reversed, then rotated.
        let mut shuffled_entries: Vec<_> = entries.clone();
        shuffled_entries.reverse();
        let len = shuffled_entries.len();
        if len > 0 {
            shuffled_entries.rotate_left(rotation % len);
        }
        let mut shuffled = Map::new();
        for (key, value) in &shuffled_entries {
            shuffled.insert(key.clone(), Value::from(*value));
        }

        // A duplicate key resolves to whichever value was inserted last, so the
        // two maps only have to agree when every key is distinct.
        let mut seen: Vec<&String> = entries.iter().map(|(k, _)| k).collect();
        seen.sort();
        let distinct = seen.windows(2).all(|w| w[0] != w[1]);
        prop_assume!(distinct);

        prop_assert_eq!(
            to_canonical_string(&Value::Object(forward)).unwrap(),
            to_canonical_string(&Value::Object(shuffled)).unwrap()
        );
    }

    /// Every canonically written float parses back to the same double.
    ///
    /// This is the round-trip guarantee the digest compare rests on: if a value
    /// could not be recovered from its canonical text, two runs computing the
    /// identical number could still write different bytes.
    #[test]
    fn floats_round_trip_through_canonical_form(
        value in any::<f64>().prop_filter("finite", |f| f.is_finite())
    ) {
        let text = format_es6_double(value).unwrap();
        let parsed: f64 = text.parse().unwrap();
        // `-0.0 == 0.0` numerically, which is the comparison that matters:
        // ES6 and JCS both normalize negative zero to "0".
        prop_assert_eq!(parsed, value, "{} did not round-trip via {:?}", value, text);
    }

    /// Canonical form never uses exponential notation where a plain decimal is
    /// what ES6 specifies, and never emits the artefacts a naive formatter would.
    #[test]
    fn float_formatting_is_well_formed(
        value in any::<f64>().prop_filter("finite", |f| f.is_finite())
    ) {
        let text = format_es6_double(value).unwrap();
        prop_assert!(!text.contains("NaN") && !text.contains("inf"));
        prop_assert!(!text.ends_with('.'), "trailing point in {text:?}");
        prop_assert!(!text.contains(".e"), "empty fraction in {text:?}");
        // A leading zero may only appear as "0" or "0.xxx".
        let unsigned = text.strip_prefix('-').unwrap_or(&text);
        if unsigned.starts_with('0') {
            prop_assert!(
                unsigned == "0" || unsigned.starts_with("0."),
                "non-canonical leading zero in {text:?}"
            );
        }
        // Exponential form always carries an explicit sign, per ES6.
        if let Some((_, exponent)) = unsigned.split_once('e') {
            prop_assert!(
                exponent.starts_with('+') || exponent.starts_with('-'),
                "unsigned exponent in {text:?}"
            );
        }
    }

    /// Canonicalizing is idempotent: re-parsing canonical text and
    /// canonicalizing it again gives the identical bytes.
    ///
    /// Without this, a record that survived a round trip through storage could
    /// hash differently to the one that was written.
    #[test]
    fn canonical_form_is_stable_across_a_round_trip(value in arbitrary_json()) {
        let once = to_canonical_string(&value).unwrap();
        let reparsed: Value = serde_json::from_str(&once).unwrap();
        let twice = to_canonical_string(&reparsed).unwrap();
        prop_assert_eq!(once, twice);
    }

    /// Canonical text is always valid JSON that parses to an equal value.
    #[test]
    fn canonical_text_parses_back_to_an_equal_value(value in arbitrary_json()) {
        let text = to_canonical_string(&value).unwrap();
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|e| TestCaseError::fail(format!("{e} in {text:?}")))?;
        prop_assert_eq!(parsed, value);
    }

    /// Object keys come out in UTF-16 code unit order, whatever went in.
    #[test]
    fn object_keys_are_emitted_in_sorted_order(value in arbitrary_json()) {
        let text = to_canonical_string(&value).unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_sorted(&parsed);
    }

    /// Quantizing either succeeds and is idempotent — which is what makes
    /// repeated serialization of a ratio stable — or rejects. It never returns a
    /// value JSON cannot carry, which is the property the digest path depends on.
    #[test]
    fn ratio_quantization_is_idempotent_or_rejects(value in any::<f64>()) {
        match quantize_ratio(value) {
            Ok(once) => {
                prop_assert!(once.is_finite(), "a quantized ratio is always finite");
                let twice = quantize_ratio(once).expect("a quantized ratio re-quantizes");
                prop_assert_eq!(twice.to_bits(), once.to_bits());
            }
            Err(_) => prop_assert!(
                !value.is_finite() || value.abs() > 1e300,
                "only non-finite or overflow-scale values may be rejected, not {}",
                value
            ),
        }
    }

    /// The property the schema actually promises: a measured value survives a
    /// JSON round trip with an unchanged digest.
    ///
    /// This is the guarantee that keeps an honest change out of the `divergent`
    /// bucket when a payload is stored, re-read, and re-hashed.
    #[test]
    fn metric_values_keep_their_digest_across_a_json_round_trip(
        value in prop_oneof![
            any::<u64>().prop_map(MetricValue::Count),
            any::<i64>().prop_map(MetricValue::Integer),
            (-1e9f64..1e9f64).prop_map(MetricValue::Ratio),
            any::<u64>().prop_map(|millis| MetricValue::Duration { millis }),
            any::<bool>().prop_map(MetricValue::Flag),
            ".*".prop_map(MetricValue::Text),
        ]
    ) {
        let written = to_canonical_string(&value).unwrap();
        let reparsed: MetricValue = serde_json::from_str(&written).unwrap();
        prop_assert_eq!(&to_canonical_string(&reparsed).unwrap(), &written);
        prop_assert_eq!(digest(&reparsed).unwrap(), digest(&value).unwrap());
    }
}

fn assert_sorted(value: &Value) {
    match value {
        Value::Object(map) => {
            let keys: Vec<&String> = map.keys().collect();
            for pair in keys.windows(2) {
                assert!(
                    pair[0].encode_utf16().lt(pair[1].encode_utf16()),
                    "keys {:?} and {:?} are out of order",
                    pair[0],
                    pair[1]
                );
            }
            for nested in map.values() {
                assert_sorted(nested);
            }
        }
        Value::Array(items) => items.iter().for_each(assert_sorted),
        _ => {}
    }
}
