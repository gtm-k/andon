//! The commit-trailer digest option: a ledger foothold that survives transports
//! git notes do not.
//!
//! # Why a trailer exists at all
//!
//! Notes refs do not travel with a fork PR (PLAN P9, R2 fold): the fork's
//! `refs/notes/andon-measure` never reaches the upstream repository, so the
//! verifier there has nothing to compare against. A commit **message** travels
//! everywhere the commit does. One trailer line — `Andon-Measure-Digest:
//! <sha256>` — is enough for the fork-tier verifier to check that what it
//! recomputed matches what the agent measured, without the record itself ever
//! making the trip.
//!
//! # The wire contract (P9 must reproduce this byte-for-byte)
//!
//! The digest is SHA-256 over the canonical JSON of [`TrailerDigestInput`]:
//! the record's `schema_version`, its `(base_oid, head_oid, head_kind)` tuple,
//! and **every** result row — `(metric_id, canonical scope, per-result digest,
//! deterministic flag)`, sorted by `(metric_id, scope)`. The rows come from
//! [`andon_ledger_min::records::digest_rows`], the same table the cross-OS
//! matrix compares, so "what the trailer binds" and "what the matrix compares"
//! cannot drift apart. `tests/trailer_vector.rs` pins the digest of a fixed
//! record as a committed test vector; if this input ever changes shape, that
//! test reddens and the change is a wire-contract decision, not a refactor.
//!
//! # Binding every row is safe, and the direction of failure is the point
//!
//! The trailer includes rows a verifier might exclude from its own compare set
//! (seeded, timing-dependent). That can only make an honest trailer *fail* to
//! match a recompute — never make a forged one pass — and a failed match at
//! fork tier degrades to `confirmed-static` without compare, which is the
//! labeled lower-trust tier, not an accusation. Over-inclusion under-trusts;
//! under-inclusion would be a hole. The choice is deliberate.

use andon_core::canonical::{self, CanonicalError};
use andon_core::git::{Git, GitError};
use andon_core::schema::payload::{HeadKind, MeasurementRecord};
use andon_ledger_min::records::{digest_rows, RecordError};
use serde::Serialize;

/// The trailer key, as it appears in a commit message.
pub const TRAILER_KEY: &str = "Andon-Measure-Digest";

/// A trailer could not be produced or read.
#[derive(Debug, thiserror::Error)]
pub enum TrailerError {
    /// The record's rows could not be tabulated.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// The digest input could not be canonically serialized.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Git could not produce the commit message.
    #[error(transparent)]
    Git(#[from] GitError),
}

/// Exactly what the trailer digest covers. See the module docs: this is a wire
/// contract, pinned by a committed test vector.
#[derive(Debug, Serialize)]
struct TrailerDigestInput<'a> {
    schema_version: u32,
    base_oid: &'a str,
    head_oid: &'a str,
    head_kind: HeadKind,
    rows: Vec<TrailerRow>,
}

/// One result's identity in the trailer digest. `scope` is the scope's
/// canonical JSON as a string — already the pairing key the matrix uses.
#[derive(Debug, Serialize)]
struct TrailerRow {
    metric_id: String,
    scope: String,
    digest: String,
    deterministic: bool,
}

/// The canonical JSON the trailer digest is computed over.
///
/// Public so the wire contract has a face: P9's verifier must reproduce these
/// bytes exactly to reproduce the digest, and `tests/trailer_vector.rs` pins
/// them verbatim. Debugging a trailer mismatch starts by diffing two of these.
pub fn digest_input_canonical(record: &MeasurementRecord) -> Result<String, TrailerError> {
    Ok(canonical::to_canonical_string(&input_of(record)?)?)
}

fn input_of(record: &MeasurementRecord) -> Result<TrailerDigestInput<'_>, TrailerError> {
    let rows = digest_rows(record)?
        .into_iter()
        .map(|row| TrailerRow {
            metric_id: row.metric_id,
            scope: row.scope,
            digest: row.digest,
            deterministic: row.deterministic,
        })
        .collect();
    Ok(TrailerDigestInput {
        schema_version: record.schema_version,
        base_oid: &record.compare_context.base_oid,
        head_oid: &record.compare_context.head_oid,
        head_kind: record.compare_context.head_kind,
        rows,
    })
}

/// The trailer digest of a record: 64 lowercase hex characters.
pub fn trailer_digest(record: &MeasurementRecord) -> Result<String, TrailerError> {
    Ok(canonical::digest(&input_of(record)?)?)
}

/// The full trailer line, ready to append to a commit message.
pub fn trailer_line(record: &MeasurementRecord) -> Result<String, TrailerError> {
    Ok(format!("{TRAILER_KEY}: {}", trailer_digest(record)?))
}

/// Every trailer digest in `commit`'s message, in order of appearance.
///
/// A `Vec` rather than an `Option` because squash merges concatenate the
/// squashed commits' messages, so one landed commit legitimately carries
/// several trailers — one per measured commit that went into it. The parse
/// accepts the key anywhere in the message, not only in the final trailer
/// block: `git interpret-trailers` would insist on the block, and a squash
/// concatenation puts earlier messages' trailers mid-body, which is exactly
/// the case the trailer exists to survive.
pub fn read_trailer_digests(git: &Git, commit: &str) -> Result<Vec<String>, TrailerError> {
    let message = git
        .cmd(["log", "-1", "--format=%B", "--end-of-options", commit])
        .text()?;
    Ok(digests_in(&message))
}

/// The trailer digests present in a commit message.
pub fn digests_in(message: &str) -> Vec<String> {
    message
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix(TRAILER_KEY)?;
            let value = rest.strip_prefix(':')?.trim();
            (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| value.to_ascii_lowercase())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use andon_core::testing::sample_record;

    #[test]
    fn the_line_round_trips_through_a_commit_message() {
        let record = sample_record();
        let line = trailer_line(&record).expect("a trailer line");
        let message = format!("fix the widget\n\nlonger prose here\n\n{line}\n");
        assert_eq!(
            digests_in(&message),
            vec![trailer_digest(&record).expect("a digest")]
        );
    }

    #[test]
    fn a_squashed_message_yields_every_trailer() {
        let record = sample_record();
        let line = trailer_line(&record).expect("a trailer line");
        // Squash concatenation: two messages, each with its trailer, one of
        // them mid-body rather than in a final trailer block.
        let message = format!("squash: both branches\n\n* one\n\n{line}\n\n* two\n\n{line}\n");
        assert_eq!(digests_in(&message).len(), 2);
    }

    #[test]
    fn near_misses_are_not_trailers() {
        for message in [
            "Andon-Measure-Digest: not-hex-at-all",
            "Andon-Measure-Digest: abc123",                    // too short
            "Andon-Measure-Digest deadbeef",                   // no colon
            "Some-Other-Trailer: 0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(
                digests_in(message).is_empty(),
                "{message:?} should not parse as a trailer"
            );
        }
    }

    #[test]
    fn the_digest_binds_the_tuple() {
        // Two records identical but for the head must not share a trailer:
        // otherwise a digest minted on one commit could vouch for another.
        let record = sample_record();
        let mut moved = sample_record();
        moved.compare_context.head_oid = "9".repeat(40);
        assert_ne!(
            trailer_digest(&record).expect("digest"),
            trailer_digest(&moved).expect("digest")
        );
    }

    #[test]
    fn the_digest_binds_every_row() {
        let record = sample_record();
        let mut fewer = sample_record();
        fewer.results.clear();
        assert_ne!(
            trailer_digest(&record).expect("digest"),
            trailer_digest(&fewer).expect("digest")
        );
    }
}
