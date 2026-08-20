//! The trailer digest's committed test vector.
//!
//! The trailer is a wire contract: P9's verifier reproduces the digest from
//! its own recompute, byte for byte, or the compare silently never matches. A
//! round-trip test cannot hold that — both sides of a round trip move together
//! — so this file pins the exact canonical input bytes AND the digest for one
//! fully specified record.
//!
//! **If this test reddens, a wire contract changed.** That is sometimes right
//! (a schema bump is supposed to change it — `schema_version` is inside the
//! input on purpose), but it is never a refactor: whoever updates these
//! constants is declaring that every existing trailer in every commit message
//! out there no longer matches, and the change needs the serialization-shape
//! stop-and-ask, not a fixture touch-up.

use andon_core::testing::{sample_compare_context, sample_record, sample_result};
use andon_ledger::trailer::{digest_input_canonical, trailer_digest, trailer_line};

/// One fully specified record: sample identities, hand-set row digests, so the
/// vector depends on nothing but the fields the trailer actually binds.
fn vector_record() -> andon_core::schema::payload::MeasurementRecord {
    let mut record = sample_record();
    record.compare_context = sample_compare_context();
    let mut first = sample_result();
    first.metric_id = "vector.alpha".to_string();
    first.digest = "a".repeat(64);
    let mut second = sample_result();
    second.metric_id = "vector.beta".to_string();
    second.digest = "b".repeat(64);
    second.deterministic = false;
    // Deliberately pushed out of order: the input sorts rows by
    // (metric_id, scope), and the vector must prove it.
    record.results = vec![second, first];
    record
}

const EXPECTED_INPUT: &str = "{\"base_oid\":\"1111111111111111111111111111111111111111\",\
\"head_kind\":\"commit\",\
\"head_oid\":\"2222222222222222222222222222222222222222\",\
\"rows\":[\
{\"deterministic\":true,\"digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"metric_id\":\"vector.alpha\",\"scope\":\"{\\\"blob_oid\\\":\\\"3333333333333333333333333333333333333333\\\",\\\"kind\\\":\\\"function\\\",\\\"line_span\\\":{\\\"end\\\":48,\\\"start\\\":10},\\\"path\\\":\\\"src/index.ts\\\",\\\"symbol\\\":\\\"handleRequest\\\"}\"},\
{\"deterministic\":false,\"digest\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"metric_id\":\"vector.beta\",\"scope\":\"{\\\"blob_oid\\\":\\\"3333333333333333333333333333333333333333\\\",\\\"kind\\\":\\\"function\\\",\\\"line_span\\\":{\\\"end\\\":48,\\\"start\\\":10},\\\"path\\\":\\\"src/index.ts\\\",\\\"symbol\\\":\\\"handleRequest\\\"}\"}\
],\
\"schema_version\":2}";

const EXPECTED_DIGEST: &str = "5a8b2726f8148df4c1df7c7c4c51a2ed2c91faeb777d3f5ccbfab694afaca834";

#[test]
fn the_canonical_input_bytes_are_pinned() {
    assert_eq!(
        digest_input_canonical(&vector_record()).expect("canonical input"),
        EXPECTED_INPUT,
        "the trailer's digest input changed shape; see the module docs before updating"
    );
}

#[test]
fn the_digest_is_pinned() {
    assert_eq!(
        trailer_digest(&vector_record()).expect("digest"),
        EXPECTED_DIGEST,
        "the trailer digest of the pinned record moved; see the module docs before updating"
    );
    assert_eq!(
        trailer_line(&vector_record()).expect("line"),
        format!("Andon-Measure-Digest: {EXPECTED_DIGEST}")
    );
}
