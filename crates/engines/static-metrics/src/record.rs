//! The P2 measurement harness: a change in, a `MeasurementRecord` out.
//!
//! # Why this exists and what replaces it
//!
//! P5a assembles payloads and P5b ships the CLI. Neither exists yet, and the
//! cross-OS matrix needs static-metric results in a form it can compare **now**
//! — so this builds the same record the product will, with the parts that are
//! not this phase's left honest rather than invented: the verdict is `pass` with
//! no reasons because the static family has no verdict of its own to give, and
//! the attestation is the default `unwitnessed` every fresh record starts at.
//!
//! `tool.name` is `andon-static`, distinct from `andon` and from the spike's
//! `andon-spike`, for the reason the spike recorded: a ledger that cannot tell a
//! phase harness from the product would let harness numbers be read as release
//! numbers later.
//!
//! The records this writes are compared by `andon-spike compare-records`, which
//! reads a `MeasurementRecord` and cares nothing about which engine produced it.
//! Reusing it rather than writing a second cross-leg comparison keeps the
//! matrix's failure messages coming out of one tested implementation — the one
//! whose absent-leg, tuple-mismatch and result-floor cases are already pinned.
//!
//! # Commit endpoints only
//!
//! Like the spike, this asks for [`ResolvedRange::compare_context`] before doing
//! any work, which is already a typed refusal for a dirty endpoint. A
//! measurement with no commit id cannot be attested, and inventing one is the
//! laundering path R2-4 exists to close. The engine itself is happy to measure
//! uncommitted bytes — see [`crate::engine::measure_blob`] — and P5b is where
//! that lane gets a caller.

use std::path::Path;

use andon_core::canonical::{self, CanonicalError};
use andon_core::engine::{run_engine, EngineError, MeasureContext};
use andon_core::git::{ChangedSet, Git, ResolveError, ResolvedRange, Revision};
use andon_core::policy::{Policy, PolicyError};
use andon_core::schema::enums::{InvocationSource, RecordKind, Verdict};
use andon_core::schema::payload::{
    AttestationBlock, Invocation, IterationState, MeasurementRecord, Reserved, ToolIdentity,
    VerdictSummary, SCHEMA_VERSION,
};

use crate::engine::{StaticError, StaticMetricsEngine};
use crate::health;

/// Tool name on the wire.
pub const TOOL_NAME: &str = "andon-static";

/// Commit this binary was built from, when the build was told.
///
/// `option_env!` rather than a build script, for the reason the spike recorded:
/// a build script that shells out to git turns every cached build into a
/// different one, and `build_oid` is outside the digest input, so an unknown one
/// costs traceability and nothing else. An all-zero OID says "unknown" out loud.
const BUILD_OID: &str = match option_env!("ANDON_STATIC_BUILD_OID") {
    Some(oid) => oid,
    None => "0000000000000000000000000000000000000000",
};

/// A record could not be produced, read, or written.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The range could not be resolved, or an endpoint has no commit id.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// Reading or measuring blobs failed.
    #[error(transparent)]
    Static(#[from] StaticError),
    /// An engine refused or failed.
    #[error(transparent)]
    Engine(#[from] EngineError),
    /// The policy could not be hashed.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// The record could not be canonically serialized.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Filesystem work failed.
    #[error("{detail}: {source}")]
    Io {
        /// What was being attempted.
        detail: String,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

/// Measure `base..head` with the static engine and return a sealed record.
pub fn measure(
    git: &Git,
    base: &Revision,
    head: &Revision,
    engine_version: &str,
) -> Result<MeasurementRecord, RecordError> {
    let range = ResolvedRange::resolve(git, base, head)?;
    // Asked for before any work is done, so an un-attestable range fails fast
    // rather than after reading every blob.
    let compare_context = range.compare_context()?;
    let changed = ChangedSet::enumerate(git, &range)?;
    let engine = StaticMetricsEngine::for_change(git, &changed, engine_version)?;

    let policy = Policy::default();
    let ctx = MeasureContext {
        compare_context: compare_context.clone(),
        policy: policy.clone(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        // Nothing in the static family executes repository code, so no sandbox
        // is offered. `run_engine` refuses a `code-exec` engine here, which is
        // the assertion rather than a comment.
        sandbox_available: false,
    };
    let mut results = run_engine(&engine, &ctx)?;

    let measured_at = now_rfc3339();
    for result in &mut results {
        // Written after sealing, which makes the exclusion visible: a wall clock
        // cannot reach a compared byte because it is stamped after the compared
        // bytes are fixed.
        result.freshness.measured_at = measured_at.clone();
    }

    let completeness = health::weakest(&results);
    Ok(MeasurementRecord {
        schema_version: SCHEMA_VERSION,
        record_kind: RecordKind::SelfReport,
        tool: ToolIdentity {
            name: TOOL_NAME.to_string(),
            version: engine_version.to_string(),
            build_oid: BUILD_OID.to_string(),
            // The bootstrap exception, stated in the record rather than assumed:
            // no attested release of Andon exists yet.
            attested_release: false,
        },
        compare_context,
        invocation: Invocation {
            source: InvocationSource::HumanCli,
            harness: None,
            model: None,
            author: None,
            iteration: 1,
        },
        reserved: Reserved::default(),
        policy_hash: policy.policy_hash()?,
        results,
        completeness,
        verdict: VerdictSummary {
            // The static family produces facts, not findings. P5a assembles a
            // real verdict from them and P9 composes it with the attestation
            // axis; `pass` with no reasons is the honest shape until then.
            verdict: Verdict::Pass,
            reasons: Vec::new(),
            iteration: IterationState {
                count: 1,
                cap: policy.loop_policy.iteration_cap,
                escalated: false,
            },
        },
        // Every record starts unwitnessed. The verifier moves it, and only the
        // verifier.
        attestation: AttestationBlock::default(),
    })
}

/// Write a record as canonical JSON.
///
/// Canonical rather than pretty, so two legs that measured the same thing
/// produce byte-identical files and a plain `diff` is a usable first diagnostic
/// before anyone reaches for the digest table.
pub fn write(path: &Path, record: &MeasurementRecord) -> Result<(), RecordError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| RecordError::Io {
                detail: format!("create {}", parent.display()),
                source,
            })?;
        }
    }
    let mut text = canonical::to_canonical_string(record)?;
    text.push('\n');
    std::fs::write(path, text).map_err(|source| RecordError::Io {
        detail: format!("write {}", path.display()),
        source,
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ` from the system clock.
///
/// Hand-rolled for the reason `andon_core::date` is: a date crate would pull a
/// timezone database into a binary whose trust story is that it is small.
/// Nothing branches on this field and it is outside every digest.
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let date = andon_core::date::Date::from_days_since_epoch(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{date}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_harness_names_itself_and_not_the_product() {
        // A ledger that cannot tell a phase harness from the product would let
        // P2 numbers be read as release numbers later.
        assert_eq!(TOOL_NAME, "andon-static");
        assert_ne!(TOOL_NAME, "andon");
    }

    #[test]
    fn the_build_oid_is_a_full_length_object_id() {
        assert_eq!(BUILD_OID.len(), 40, "{BUILD_OID}");
        assert!(BUILD_OID.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn timestamps_render_as_rfc_3339() {
        let stamp = now_rfc3339();
        assert_eq!(stamp.len(), 20, "{stamp}");
        assert!(stamp.ends_with('Z') && stamp.contains('T'), "{stamp}");
    }
}
