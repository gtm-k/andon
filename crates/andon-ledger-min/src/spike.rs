//! The spike engine: three byte counts, and nothing that could hide behind a
//! seed.
//!
//! # Why this engine exists, and what it deliberately is not
//!
//! P1.5 has to prove that a self-report and an independent recompute produce
//! **byte-identical per-result digests** across three operating systems. That
//! proof needs metrics, and it needs them before P2 builds any. Anything with a
//! parser, a grammar version, a hash-map traversal, or a wall clock in it would
//! be testing the engine rather than the trust kernel — and if the matrix went
//! red nobody could say which half was at fault.
//!
//! So the metric set is the smallest one that is still real:
//!
//! - `spike.changed-files` — how many paths the change touches.
//! - `spike.file-bytes` — the byte length of each changed file's head blob.
//! - `spike.file-lines` — the count of `0x0A` bytes in that blob, plus one for a
//!   final line with no terminator.
//!
//! All three are `deterministic: true` in the registry, which is what puts them
//! in the digest compare set — and what makes them the right subject for the E4
//! fixture, where a self-report flips the flag to `false` and must not be
//! believed.
//!
//! # The one property that carries the phase
//!
//! **Every byte these numbers are computed from comes out of a git blob.**
//! [`SpikeEngine::for_change`] reads through [`BlobBatch`], which takes an OID
//! and has no path argument, so there is no expressible way for a checkout's
//! line-ending conversion to reach a digest (PREMORTEM T1). A file committed
//! with CRLF has CRLF in its blob on every platform, so `spike.file-bytes`
//! counts the `\r` on Linux exactly as it does on Windows, and `spike.file-lines`
//! counts `\n` on both. That is the whole cross-OS argument, and it is why line
//! counting is defined on `0x0A` bytes rather than on "lines" in any richer
//! sense.
//!
//! # What is not in the regime, and why that is load-bearing
//!
//! [`MeasurementRegime::Static`] carries no git version. That is deliberate here:
//! the three matrix legs run whatever git their runner image ships, so binding
//! the git version into the regime would make every leg mutually
//! `unwitnessed-version-skew` and the digest compare would never execute. Blob
//! bytes do not depend on the git version, so the omission is honest rather than
//! convenient. `CompareContext::git_version` still records what resolved the
//! tuple; it is outside [`andon_core::schema::payload::ResultDigestInput`], so it
//! records without comparing.
//!
//! The *engine* version is in the regime, which is what PREMORTEM S4 needs: two
//! binaries at different versions produce `unwitnessed-version-skew`, never
//! `divergent`. [`engine_version`] reads an override from the environment so a
//! fixture can stage that skew without shipping a second build.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use andon_core::date::Date;
use andon_core::engine::{
    EngineDescriptor, EngineError, MeasureContext, MeasureEngine, MetricDescriptor,
};
use andon_core::git::{BlobBatch, BlobError, ChangedEntry, ChangedSet, Git};
use andon_core::registry::{lint, parse_file, EngineRegistryFile, Registry};
use andon_core::schema::enums::{
    Completeness, EngineClass, EngineFamily, MetricClass, Severity,
};
use andon_core::schema::payload::{
    CacheState, Freshness, MeasurementResult, MetricValue, ResultScope, ScopeKind,
};
use andon_core::schema::regime::MeasurementRegime;

/// Engine id. Matches the `engine` field of the crate-local registry file.
pub const ENGINE_ID: &str = "spike-size";

/// Revision of the counting rules below. Part of the regime, so changing how a
/// line is counted makes old and new numbers incomparable rather than silently
/// different.
pub const SPEC_REVISION: &str = "p1.5-spike-1";

/// Environment override for the engine version.
///
/// The PREMORTEM S4 fixture needs two binaries at different versions without
/// building two binaries. Reading the override here rather than in the fixture
/// means the skew travels through the same regime field a real version
/// difference would, so the verifier is answering the real question.
pub const ENGINE_VERSION_ENV: &str = "ANDON_SPIKE_ENGINE_VERSION";

/// Metric id for the change-level path count.
pub const METRIC_CHANGED_FILES: &str = "spike.changed-files";
/// Metric id for the per-file blob length.
pub const METRIC_FILE_BYTES: &str = "spike.file-bytes";
/// Metric id for the per-file line count.
pub const METRIC_FILE_LINES: &str = "spike.file-lines";

/// The crate-local evidence registry, compiled in.
///
/// Embedded rather than read from disk because the verifier must resolve
/// `deterministic` from **its own** registry load and never from the record it is
/// examining (PLAN P9 / DEFERRED-APPROVALS E4). A path on disk is one more thing
/// a hostile checkout could move; `include_str!` binds the registry to the binary
/// at build time.
const REGISTRY_TOML: &str = include_str!("../registry/spike.toml");

/// Something the spike engine could not read.
#[derive(Debug, thiserror::Error)]
pub enum SpikeError {
    /// A blob read failed.
    #[error(transparent)]
    Blob(#[from] BlobError),
    /// The embedded registry does not parse or does not lint. A build-time bug,
    /// surfaced at runtime because `include_str!` cannot be validated earlier.
    #[error("the compiled-in spike registry is invalid: {0}")]
    Registry(String),
    /// The system clock could not be read, so claim expiry cannot be evaluated.
    #[error(transparent)]
    Clock(#[from] andon_core::date::ClockError),
}

/// The engine version this *process* reports, honouring the environment
/// override.
///
/// Read at the binary's entry point and then passed down explicitly, never
/// consulted deep in the call graph. `std::env::set_var` is a process-global
/// mutation and the scenario suite runs its cases in parallel threads, so a
/// skew staged by setting the variable mid-run would leak into whichever other
/// case happened to be measuring at the time — a flaky fixture in the one phase
/// whose whole output is "these numbers agree".
pub fn engine_version() -> String {
    std::env::var(ENGINE_VERSION_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default_engine_version().to_string())
}

/// The version this build reports when nothing overrides it.
pub fn default_engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The compiled-in registry, parsed and linted once.
///
/// Linting at load is not ceremony: the drift check in
/// [`Registry::check_engine`] compares the file against the engine's compiled
/// descriptors, and a file that failed to parse would make that check vacuous.
pub fn registry_file() -> Result<&'static EngineRegistryFile, SpikeError> {
    static PARSED: OnceLock<Result<EngineRegistryFile, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| parse_file("spike.toml", REGISTRY_TOML).map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| SpikeError::Registry(e.clone()))
}

/// The merged registry for the spike's own claims, resolved against `as_of`.
pub fn registry(as_of: Date) -> Result<Registry, SpikeError> {
    let file = registry_file()?;
    let files = vec![("spike.toml".to_string(), file.clone())];
    let (registry, report) = lint(&files, &andon_core::policy::RegistryPolicy::default(), as_of);
    if report.failed() {
        let messages: Vec<String> = report
            .errors()
            .map(|d| format!("{}: {}", d.code, d.message))
            .collect();
        return Err(SpikeError::Registry(messages.join("; ")));
    }
    Ok(registry)
}

/// Facts about one changed file, read from its blobs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFacts {
    /// Repository-relative path as git spells it.
    path: String,
    /// Head-side blob OID the numbers were computed from.
    blob_oid: String,
    /// Byte length of the head blob.
    bytes: u64,
    /// LF count of the head blob, plus one for an unterminated final line.
    lines: u64,
    /// The same two numbers on the base side, where the base has this path.
    base: Option<(u64, u64)>,
}

/// The spike engine, holding what it read.
///
/// Content access is done in [`SpikeEngine::for_change`] rather than inside
/// `measure`, because P0's [`MeasureContext`] carries no content handle — it was
/// specified thin, and widening it belongs to a phase that owns
/// `crates/andon-core`. Reading first and formatting second costs nothing and
/// keeps this phase inside its declared file scope.
#[derive(Debug, Clone)]
pub struct SpikeEngine {
    version: String,
    changed_paths: u64,
    files: Vec<FileFacts>,
}

impl SpikeEngine {
    /// Read every changed file's blobs and compute the counts. One git spawn.
    ///
    /// Entries with no head-side blob — deletions, submodule pointers, and the
    /// all-zero OID git reports for an unhashed working-tree file — contribute to
    /// `spike.changed-files` and to nothing else. A deleted file has no bytes to
    /// count, and reporting zero would be a fabricated measurement rather than an
    /// absent one.
    pub fn for_change(
        git: &Git,
        changed: &ChangedSet,
        engine_version: &str,
    ) -> Result<Self, SpikeError> {
        let mut files = Vec::new();
        let readable: Vec<&ChangedEntry> = changed
            .entries
            .iter()
            .filter(|e| e.readable_blob().is_some())
            .collect();

        if !readable.is_empty() {
            let mut batch = BlobBatch::open(git).map_err(BlobError::from)?;
            for entry in readable {
                let oid = entry.readable_blob().expect("filtered above");
                let head = batch.read(oid)?;
                let (bytes, lines) = count(head.bytes());
                let base = match base_blob(entry) {
                    Some(base_oid) => {
                        let content = batch.read(base_oid)?;
                        Some(count(content.bytes()))
                    }
                    None => None,
                };
                files.push(FileFacts {
                    path: entry.path.clone(),
                    blob_oid: oid.to_string(),
                    bytes,
                    lines,
                    base,
                });
            }
        }

        // Sorted so the emitted result order is a property of the data rather
        // than of enumeration. Digests are per-result and pairing is by
        // `(metric_id, scope)`, so order cannot change a verdict — but an
        // engine whose output order drifts is an engine whose output diffs are
        // unreadable, and unreadable diffs are how a real change hides.
        files.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(SpikeEngine {
            version: engine_version.to_string(),
            changed_paths: changed.entries.len() as u64,
            files,
        })
    }
}

/// The base-side blob OID worth reading, if there is one.
///
/// Mirrors [`ChangedEntry::readable_blob`] for the source side: a gitlink's OID
/// names a commit in another repository, and a null OID names nothing.
fn base_blob(entry: &ChangedEntry) -> Option<&str> {
    if entry.is_gitlink() {
        return None;
    }
    entry
        .src_oid
        .as_deref()
        .filter(|oid| !oid.bytes().all(|b| b == b'0'))
}

/// Byte length and line count of a blob.
///
/// A line is a `0x0A` byte. A final line with no terminator counts as one more,
/// which is the convention that makes "add a line" change the number by one
/// whether or not the file ends in a newline. Nothing here looks at `\r`: a CRLF
/// file's carriage returns are content, they are in the blob on every platform,
/// and they are counted by `bytes` exactly as they should be.
fn count(bytes: &[u8]) -> (u64, u64) {
    let newlines = bytes.iter().filter(|b| **b == b'\n').count() as u64;
    let unterminated = u64::from(!bytes.is_empty() && bytes[bytes.len() - 1] != b'\n');
    (bytes.len() as u64, newlines + unterminated)
}

/// Descriptors for the three metrics, in registry order.
pub fn metric_descriptors() -> Vec<MetricDescriptor> {
    [
        (METRIC_CHANGED_FILES, "andon.spike.changed-files"),
        (METRIC_FILE_BYTES, "andon.spike.file-bytes"),
        (METRIC_FILE_LINES, "andon.spike.file-lines"),
    ]
    .into_iter()
    .map(|(metric_id, implementation)| MetricDescriptor {
        metric_id: metric_id.to_string(),
        claim_id: format!("{implementation}@1|any|change-size"),
        // Context-informational throughout, and not as a shrug: policy may only
        // escalate a diff-actionable metric to MED+ (PREMORTEM A4), and "this
        // file is 412 bytes" is not something an agent should ever be asked to
        // act on. The spike proves the trust path, not a feedback loop.
        class: MetricClass::ContextInformational,
        // The flag that makes these metrics the right E4 subject: the verifier
        // reads it from here, so a self-report saying otherwise changes nothing
        // except what appears in `flag_disagreements`.
        deterministic: true,
    })
    .collect()
}

impl MeasureEngine for SpikeEngine {
    fn descriptor(&self) -> EngineDescriptor {
        EngineDescriptor {
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Static,
            // Nothing here executes repository code. Blobs are read, bytes are
            // counted, and the class says so at the trait boundary (Codex #19).
            class: EngineClass::StaticSafe,
            version: self.version.clone(),
        }
    }

    fn metrics(&self) -> Vec<MetricDescriptor> {
        metric_descriptors()
    }

    fn regime(&self) -> MeasurementRegime {
        MeasurementRegime::Static {
            engine_version: self.version.clone(),
            spec_revision: SPEC_REVISION.to_string(),
            // No grammars: nothing is parsed. An empty `BTreeMap` rather than an
            // omitted field, because the shape of a record must not vary with
            // its content.
            grammars: BTreeMap::new(),
        }
    }

    fn measure(&self, ctx: &MeasureContext) -> Result<Vec<MeasurementResult>, EngineError> {
        let as_of = Date::today_utc().map_err(|e| EngineError::Failed {
            engine_id: ENGINE_ID.to_string(),
            reason: e.to_string(),
        })?;
        let registry = registry(as_of).map_err(|e| EngineError::Failed {
            engine_id: ENGINE_ID.to_string(),
            reason: e.to_string(),
        })?;
        let descriptors = metric_descriptors();
        let evidence_for = |metric_id: &str| {
            let descriptor = descriptors
                .iter()
                .find(|d| d.metric_id == metric_id)
                .expect("every emitted metric has a descriptor");
            registry
                .claims
                .get(&descriptor.claim_id)
                .expect("the registry lint proved every claim resolves")
                .to_evidence_ref()
        };
        let _ = ctx;

        let mut results = Vec::with_capacity(1 + self.files.len() * 2);
        results.push(self.result(
            METRIC_CHANGED_FILES,
            ResultScope {
                kind: ScopeKind::Change,
                path: None,
                blob_oid: None,
                symbol: None,
                line_span: None,
            },
            MetricValue::Count(self.changed_paths),
            None,
            evidence_for(METRIC_CHANGED_FILES),
        ));

        for file in &self.files {
            let scope = |_: ()| ResultScope {
                kind: ScopeKind::File,
                path: Some(file.path.clone()),
                // The blob the number came from, named on the wire. A reader who
                // doubts a digest can fetch exactly these bytes.
                blob_oid: Some(file.blob_oid.clone()),
                symbol: None,
                line_span: None,
            };
            results.push(self.result(
                METRIC_FILE_BYTES,
                scope(()),
                MetricValue::Count(file.bytes),
                file.base
                    .map(|(bytes, _)| MetricValue::Integer(file.bytes as i64 - bytes as i64)),
                evidence_for(METRIC_FILE_BYTES),
            ));
            results.push(self.result(
                METRIC_FILE_LINES,
                scope(()),
                MetricValue::Count(file.lines),
                file.base
                    .map(|(_, lines)| MetricValue::Integer(file.lines as i64 - lines as i64)),
                evidence_for(METRIC_FILE_LINES),
            ));
        }
        Ok(results)
    }
}

impl SpikeEngine {
    fn result(
        &self,
        metric_id: &str,
        scope: ResultScope,
        value: MetricValue,
        delta: Option<MetricValue>,
        evidence: andon_core::schema::payload::EvidenceRef,
    ) -> MeasurementResult {
        let descriptor = metric_descriptors()
            .into_iter()
            .find(|d| d.metric_id == metric_id)
            .expect("every emitted metric has a descriptor");
        MeasurementResult {
            metric_id: metric_id.to_string(),
            claim_id: descriptor.claim_id.clone(),
            engine_id: ENGINE_ID.to_string(),
            family: EngineFamily::Static,
            engine_class: EngineClass::StaticSafe,
            metric_class: descriptor.class,
            scope,
            value,
            delta,
            // Never above `Info`. A size count has no business stopping a line,
            // and the policy that decides severity is the verifier's anyway —
            // `severity` is outside the digest input for exactly that reason.
            severity: Severity::Info,
            completeness: Completeness::Complete,
            measurement_regime: self.regime(),
            evidence,
            deterministic: descriptor.deterministic,
            // Filled by `MeasurementResult::seal`, which `run_engine` calls.
            digest: String::new(),
            freshness: Freshness {
                // Freshness never enters a digest, which is why a wall clock is
                // allowed to appear in a phase about determinism at all.
                measured_at: String::new(),
                duration_ms: 0,
                lane: andon_core::schema::enums::Lane::Fast,
                cache: CacheState::Cold,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_compiled_registry_parses_and_lints() {
        // `include_str!` is checked by the compiler for existence and by nothing
        // for content. Without this test a malformed registry ships and fails on
        // the first measurement.
        let as_of: Date = "2026-08-17".parse().expect("a valid date");
        let registry = registry(as_of).expect("the compiled registry must lint clean");
        assert_eq!(registry.metrics.len(), 3);
        assert_eq!(registry.claims.len(), 3);
    }

    #[test]
    fn every_emitted_metric_resolves_to_a_claim() {
        // The drift check that makes the declarative manifest trustworthy: the
        // engine's compiled descriptors and the registry file must agree, in
        // both directions.
        let engine = SpikeEngine {
            version: "0.1.0".to_string(),
            changed_paths: 0,
            files: Vec::new(),
        };
        Registry::check_engine(registry_file().expect("parses"), &engine)
            .expect("the engine and its registry file must not drift");
    }

    #[test]
    fn line_counting_is_defined_on_lf_bytes_alone() {
        // The cross-OS property in miniature. CRLF and LF files with the same
        // logical content have different byte counts and the same line count,
        // and both numbers are the same on every platform because both are
        // computed from blob bytes.
        assert_eq!(count(b"a\nb\n"), (4, 2));
        assert_eq!(count(b"a\r\nb\r\n"), (6, 2));
        assert_eq!(count(b"a\nb"), (3, 2), "an unterminated final line counts");
        assert_eq!(count(b""), (0, 0), "an empty file has no lines");
        assert_eq!(count(b"\n"), (1, 1));
        // A lone CR is content, not a terminator: old-Mac endings are not
        // silently reinterpreted into a different number on a different host.
        assert_eq!(count(b"a\rb\rc"), (5, 1));
    }

    #[test]
    fn the_engine_version_override_reaches_the_regime() {
        // PREMORTEM S4's staging mechanism. If this ever stops working the
        // version-skew fixture silently becomes a second honest run.
        let engine = SpikeEngine {
            version: "0.0.1-old".to_string(),
            changed_paths: 0,
            files: Vec::new(),
        };
        match engine.regime() {
            MeasurementRegime::Static { engine_version, .. } => {
                assert_eq!(engine_version, "0.0.1-old");
            }
            other => panic!("the spike engine is a static regime, got {other:?}"),
        }
    }

    #[test]
    fn the_regime_carries_no_git_version() {
        // Load-bearing for the matrix: three runners ship three gits, and a git
        // version in the regime would make every leg mutually skewed and the
        // digest compare would never run.
        let engine = SpikeEngine {
            version: "0.1.0".to_string(),
            changed_paths: 0,
            files: Vec::new(),
        };
        let json = serde_json::to_string(&engine.regime()).expect("regimes serialize");
        assert!(
            !json.contains("git_version"),
            "the static regime must not bind a git version: {json}"
        );
    }
}
