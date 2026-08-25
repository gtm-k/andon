//! Producing a record: resolve a range, read its blobs, seal the results.
//!
//! The same function serves both sides of the trust boundary. The agent calls it
//! and writes the result to [`crate::notes::MEASURE_REF`] as a self-report; the
//! verifier calls it on a clean checkout and compares what comes back. Two
//! implementations of "measure" would be two chances to disagree for reasons
//! that are not tampering, so there is one — the sides differ only in
//! [`andon_core::schema::enums::RecordKind`] and in who resolved the tuple.
//!
//! # Commit endpoints only
//!
//! The spike refuses a working-tree or index endpoint, and does so by simply
//! asking for [`andon_core::git::ResolvedRange::compare_context`], which is
//! already a typed refusal (P1). A dirty measurement has no commit id, so it
//! cannot be attested — and inventing one is the laundering path R2-4 exists to
//! close. P1's union machinery for dirty heads is real and used by `andon
//! measure`; it has no place in the CI recompute path, where there is nothing
//! uncommitted to measure.

use andon_core::engine::{run_engine, EngineError, MeasureContext};
use andon_core::git::{ChangedSet, Git, ResolveError, ResolvedRange, Revision};
use andon_core::policy::{Policy, PolicyError};
use andon_core::schema::enums::{Completeness, InvocationSource, RecordKind, Severity, Verdict};
use andon_core::schema::payload::{
    AttestationBlock, CompareContext, Invocation, IterationState, MeasurementRecord, Reserved,
    ToolIdentity, VerdictSummary, SCHEMA_VERSION,
};

use crate::spike::{SpikeEngine, SpikeError};

/// Tool name on the wire. Distinct from `andon` on purpose: this binary is the
/// P1.5 spike, not the shipped CLI, and a ledger that cannot tell them apart
/// would let spike numbers be read as product numbers later.
pub const TOOL_NAME: &str = "andon-spike";

/// Commit this binary was built from, when the build was told.
///
/// `option_env!` rather than a build script: a build script that shells out to
/// git turns every cached or vendored build into a different one, and the
/// provenance it would recover is not something any digest depends on.
/// `build_oid` is outside [`andon_core::schema::payload::ResultDigestInput`], so
/// an unknown one costs traceability and nothing else — and an all-zero OID says
/// "unknown" out loud rather than guessing.
const BUILD_OID: &str = match option_env!("ANDON_SPIKE_BUILD_OID") {
    Some(oid) => oid,
    None => "0000000000000000000000000000000000000000",
};

/// A measurement could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum MeasureError {
    /// The range could not be resolved, or has an endpoint with no commit id.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// Reading blobs failed.
    #[error(transparent)]
    Spike(#[from] SpikeError),
    /// An engine refused or failed.
    #[error(transparent)]
    Engine(#[from] EngineError),
    /// The policy could not be hashed.
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

/// Measure `base..head` and return a sealed record.
///
/// `policy` participates in nothing this phase compares — it supplies
/// `policy_hash`, which is a record-level field deliberately outside every
/// per-result digest (P0), because the verifier loads policy from the base
/// commit while the agent measured under the head's. Loading it from the base
/// commit is P9's acceptance criterion; the spike passes the conservative
/// defaults so that the field is populated honestly rather than left to look
/// like a decision nobody made.
pub fn measure(
    git: &Git,
    base: &Revision,
    head: &Revision,
    kind: RecordKind,
    source: InvocationSource,
    engine_version: &str,
) -> Result<(MeasurementRecord, ResolvedRange), MeasureError> {
    let range = ResolvedRange::resolve(git, base, head)?;
    // Errors on a dirty endpoint. Asked for before any work is done, so an
    // un-attestable range fails fast rather than after reading every blob.
    let compare_context = range.compare_context()?;
    let changed = ChangedSet::enumerate(git, &range)?;
    let engine = SpikeEngine::for_change(git, &changed, engine_version)?;

    let policy = Policy::default();
    let ctx = MeasureContext {
        compare_context: compare_context.clone(),
        policy: policy.clone(),
        changed_paths: changed.entries.iter().map(|e| e.path.clone()).collect(),
        // Nothing in the spike executes repository code, so no sandbox is
        // offered. `run_engine` refuses a `code-exec` engine here, which is the
        // assertion rather than a comment.
        sandbox: None,
    };
    let mut results = run_engine(&engine, &ctx)?;
    let measured_at = now_rfc3339();
    for result in &mut results {
        // Freshness is written after sealing on purpose: it is excluded from
        // the digest input, and writing it here makes the exclusion visible —
        // a wall clock cannot reach a compared byte because it is stamped after
        // the compared bytes are fixed.
        result.freshness.measured_at = measured_at.clone();
    }

    let record = MeasurementRecord {
        schema_version: SCHEMA_VERSION,
        // Neither applies to a single-engine record built from a commit range:
        // nothing was substituted, and every changed path this engine was given
        // was read or it would not be here.
        substitution: None,
        unreadable_paths: Vec::new(),
        self_measure: None,
        record_kind: kind,
        tool: ToolIdentity {
            name: TOOL_NAME.to_string(),
            version: engine_version.to_string(),
            build_oid: BUILD_OID.to_string(),
            // The bootstrap exception, stated in the record rather than assumed:
            // no attested release of Andon exists yet (decision log 2026-08-16).
            attested_release: false,
        },
        compare_context,
        invocation: Invocation {
            source,
            harness: None,
            model: None,
            author: None,
            iteration: 1,
        },
        reserved: Reserved::default(),
        policy_hash: policy.policy_hash()?,
        results,
        completeness: Completeness::Complete,
        verdict: VerdictSummary {
            // The spike computes three size counts and no findings, so it has
            // no verdict of its own to give. `pass` with no reasons is the
            // honest shape; P5a assembles a real one, and P9 composes it with
            // the attestation axis (advisor F2).
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
    };
    Ok((record, range))
}

/// The tuple a record claims, for callers that only need that.
pub fn claimed_tuple(record: &MeasurementRecord) -> &CompareContext {
    &record.compare_context
}

/// Severity worth blocking on, for the attest record's verdict line.
pub(crate) const TAMPER_SEVERITY: Severity = Severity::Critical;

/// `YYYY-MM-DDTHH:MM:SSZ` from the system clock.
///
/// Hand-rolled for the same reason [`andon_core::date`] is: a date crate would
/// pull a timezone database into a binary whose trust story is that it is small.
/// A clock that reads before the epoch yields the epoch rather than failing —
/// unlike registry expiry, nothing branches on this field, so refusing to
/// measure over it would trade a real answer for a cosmetic one.
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
    fn timestamps_render_as_rfc_3339() {
        let stamp = now_rfc3339();
        assert_eq!(stamp.len(), 20, "{stamp}");
        assert!(stamp.ends_with('Z') && stamp.contains('T'), "{stamp}");
        assert!(
            stamp.starts_with("202") || stamp.starts_with("203"),
            "{stamp} is not a plausible measurement time"
        );
    }

    #[test]
    fn the_build_oid_is_a_full_length_object_id() {
        // Whether or not the build was told its provenance, the field has to be
        // shaped like an OID: a consumer that parses it should not have to
        // handle two lengths.
        assert_eq!(BUILD_OID.len(), 40, "{BUILD_OID}");
        assert!(BUILD_OID.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
