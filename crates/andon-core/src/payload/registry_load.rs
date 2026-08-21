//! The runtime registry loader — the evidence gate, live in the measurement
//! path rather than only in CI.
//!
//! # What this adds that the lint did not have
//!
//! `andon-registry-lint` has shipped since P0 and is required green from P2
//! onward. It runs in CI, over the checked-out `registry/` directory, and fails
//! the build when a metric cites a claim nobody declares. That is one actor —
//! the contributor reading a red check — and it leaves the other two unserved:
//! the agent mid-loop and the human reading a report both consume numbers
//! produced by a *binary*, and a binary that loaded a broken registry and
//! carried on would report numbers whose evidence nobody had checked.
//!
//! So the rule is the same rule, applied at a second boundary: [`load`] refuses
//! to return a registry that the lint would fail the build over. There is one
//! implementation of the rule ([`crate::registry::lint`]) and two call sites, so
//! the CI gate and the runtime gate cannot drift into disagreeing — and
//! `the_loader_refuses_what_the_lint_refuses` pins that against the lint crate's
//! own must-reject fixture, rather than against a copy of it.
//!
//! # A re-review schedule is not a reason to refuse to measure
//!
//! One lint rule is not about evidence at all. `registry.expiry-stagger` counts
//! how many claims fall due for re-review in one calendar month and fails the
//! build above the limit, so that a year from now somebody is not handed six
//! re-reviews in one week (PREMORTEM S2). That is a scheduling property of the
//! repository, and in CI it should absolutely fail the build.
//!
//! Applied here it did something else: a binary whose registry had four claims
//! expiring in March **refused to measure anything at all**. The tool would stop
//! working, on every change, for a reason that has nothing to do with the change
//! and nothing to do with whether any number is trustworthy — the strongest
//! version of PREMORTEM A4's uninstall loop this codebase can produce, arriving
//! through a housekeeping rule.
//!
//! So [`SCHEDULING_HYGIENE_CODES`] are demoted to notices at this boundary and
//! stay errors in the standalone lint. The evidence rules — a metric with no
//! claim, a claim over budget, a malformed tuple — are unchanged and still
//! refuse: those are about whether a number may be reported at all.
//!
//! # Notices are not failures, deliberately
//!
//! An expired claim demotes to a visible `evidence: stale` and the load
//! succeeds (PREMORTEM S2). Halting a measurement because a citation aged is
//! how the tool becomes the thing nobody runs. [`LoadedRegistry::notices`]
//! carries them so a surface can render them; discarding them here would make
//! the demotion silent, which is the one outcome S2 rules out.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::date::Date;
use crate::policy::RegistryPolicy;
use crate::registry::{lint, parse_file, Diagnostic, DiagnosticSeverity, EngineRegistryFile};
use crate::registry::{Registry, RegistryError};

/// Lint codes that are about the re-review schedule rather than about evidence.
///
/// Errors in CI, notices here. See the module documentation: a binary that
/// refuses to measure because six claims come due in the same month has stopped
/// working for a reason unrelated to any number it would have reported.
pub const SCHEDULING_HYGIENE_CODES: &[&str] = &["registry.expiry-stagger"];

/// A registry directory that could not be turned into an evidence gate.
#[derive(Debug, thiserror::Error)]
pub enum RegistryLoadError {
    /// The directory could not be read, or one of its files could not.
    ///
    /// Read errors are propagated rather than skipped, for the reason the lint
    /// binary gives: a registry file dropped from the load is a set of claims
    /// nobody checked and a budget silently undercounted.
    #[error("registry {path}: {reason}")]
    Io {
        /// The path being read.
        path: String,
        /// What went wrong.
        reason: String,
    },
    /// A file is not valid TOML for the registry schema.
    #[error(transparent)]
    Parse(#[from] RegistryError),
    /// The registry parsed but does not satisfy the lint. The build-failing
    /// rule, applied at the measurement boundary.
    #[error("registry {path} failed the evidence lint: {}", errors.join("; "))]
    Lint {
        /// The directory that failed.
        path: String,
        /// One entry per lint error, in the lint's own words.
        errors: Vec<String>,
    },
}

/// A merged registry, and what the lint said about it on the way through.
#[derive(Debug, Clone)]
pub struct LoadedRegistry {
    /// The merged claims and metric declarations.
    pub registry: Registry,
    /// Every engine the registry declares a file for.
    ///
    /// The roster assembly holds itself to: each of these must appear exactly
    /// once in a payload, as an output or as a named failure
    /// ([`crate::payload::prepare`]). Derived from the `engine =` header of each
    /// file rather than written down as a list of five, so an engine added to
    /// the registry is expected the day its file lands, and a deployment
    /// carrying four registry files expects four engines rather than failing
    /// against a constant nobody updated.
    pub expected_engines: BTreeSet<String>,
    /// The family each declared engine's file states, keyed by engine id.
    ///
    /// Read by [`crate::payload::prepare`] to decide which declared engines a
    /// given measurement expects: the `tests` family is the code-exec lane,
    /// which joins a roster only where the policy in force switches it on.
    pub engine_families: std::collections::BTreeMap<String, crate::schema::enums::EngineFamily>,
    /// Non-fatal findings — stale claims, uncited claims. Carried rather than
    /// dropped so a surface can show them; a demotion nobody renders is a
    /// demotion that did not happen.
    pub notices: Vec<Diagnostic>,
    /// The date expiries were evaluated against.
    pub as_of: Date,
}

impl LoadedRegistry {
    /// Claim ids the loader marked stale at [`Self::as_of`].
    ///
    /// The report surface needs the list; the payload carries the flag per
    /// result, but a reader wants to know that six claims aged, not to infer it
    /// from six results.
    pub fn stale_claim_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .registry
            .claims
            .values()
            .filter(|resolved| resolved.stale)
            .map(|resolved| resolved.claim.claim_id.clone())
            .collect();
        ids.sort();
        ids
    }
}

/// Load and lint a registry directory, refusing anything the lint fails.
///
/// `as_of` decides staleness and is a parameter for the reason the lint's is: a
/// gate whose verdict depends on the day it runs cannot be tested. Callers in
/// the measurement path pass [`Date::today_utc`], so that a claim ages visibly
/// in a real run.
pub fn load(
    dir: &Path,
    policy: &RegistryPolicy,
    as_of: Date,
) -> Result<LoadedRegistry, RegistryLoadError> {
    let files = read_dir(dir)?;
    load_files(&files, policy, as_of, &dir.display().to_string())
}

/// [`load`], over registry files a caller already holds.
///
/// The seam engines use: each compiles its own registry file in, so it has the
/// parsed value and no directory. Same rule, same one implementation of it.
pub fn load_files(
    files: &[(String, EngineRegistryFile)],
    policy: &RegistryPolicy,
    as_of: Date,
    location: &str,
) -> Result<LoadedRegistry, RegistryLoadError> {
    let (registry, report) = lint(files, policy, as_of);
    let fatal: Vec<String> = report
        .errors()
        .filter(|d| !SCHEDULING_HYGIENE_CODES.contains(&d.code))
        .map(|d| format!("{}[{}]: {}", d.code, d.location, d.message))
        .collect();
    if !fatal.is_empty() {
        return Err(RegistryLoadError::Lint {
            path: location.to_string(),
            errors: fatal,
        });
    }
    // Hygiene breaches ride along as notices rather than vanishing: the surface
    // still shows them, and the standalone lint still fails the build over them.
    let notices = report
        .diagnostics
        .into_iter()
        .filter(|d| {
            d.severity == DiagnosticSeverity::Notice || SCHEDULING_HYGIENE_CODES.contains(&d.code)
        })
        .collect();
    Ok(LoadedRegistry {
        registry,
        expected_engines: files.iter().map(|(_, file)| file.engine.clone()).collect(),
        engine_families: files
            .iter()
            .map(|(_, file)| (file.engine.clone(), file.family))
            .collect(),
        notices,
        as_of,
    })
}

/// Every `*.toml` in a directory, parsed, in sorted order.
fn read_dir(dir: &Path) -> Result<Vec<(String, EngineRegistryFile)>, RegistryLoadError> {
    let io = |path: &Path, e: std::io::Error| RegistryLoadError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    };

    let entries = std::fs::read_dir(dir).map_err(|e| io(dir, e))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| io(dir, e))?.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "toml") {
            paths.push(path);
        }
    }
    // Sorted so that two loads of the same directory produce diagnostics in the
    // same order. Directory iteration order is a filesystem detail and differs
    // across the three operating systems the matrix runs on.
    paths.sort();

    let mut files = Vec::new();
    for path in paths {
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let text = std::fs::read_to_string(&path).map_err(|e| io(&path, e))?;
        files.push((label.clone(), parse_file(&label, &text)?));
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The repository's own registry directory.
    fn real_registry_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("registry")
    }

    /// The lint crate's must-reject fixture: one metric, no claim behind it.
    ///
    /// Deliberately *the same directory* the lint's own test suite asserts on,
    /// not a copy. Two gates that enforce one rule have to agree about what
    /// violates it, and a duplicated fixture is how they stop agreeing.
    fn lint_must_reject_fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../andon-registry-lint/tests/fixtures/reject-unmapped-metric/registry")
    }

    fn as_of() -> Date {
        "2026-08-17".parse().expect("a valid date")
    }

    #[test]
    fn the_shipped_registry_loads() {
        let loaded = load(&real_registry_dir(), &RegistryPolicy::default(), as_of())
            .expect("the shipped registry must load in the measurement path");
        assert!(
            loaded.registry.claims.len() <= RegistryPolicy::default().claim_budget as usize,
            "{} claims",
            loaded.registry.claims.len()
        );
        assert!(
            !loaded.registry.metrics.is_empty(),
            "five engines have shipped metrics"
        );
    }

    #[test]
    fn the_loader_refuses_what_the_lint_refuses() {
        let fixture = lint_must_reject_fixture();
        assert!(
            fixture.is_dir(),
            "the lint's must-reject fixture moved: {}",
            fixture.display()
        );
        let err = load(&fixture, &RegistryPolicy::default(), as_of())
            .expect_err("a metric with no claim behind it must not load");
        let RegistryLoadError::Lint { errors, .. } = err else {
            panic!("expected a lint refusal, got {err:?}");
        };
        assert!(
            errors
                .iter()
                .any(|e| e.contains("registry.unmapped-metric")),
            "{errors:?}"
        );
    }

    #[test]
    fn a_directory_that_is_not_there_is_an_error_not_an_empty_registry() {
        // The failure this rules out: a mistyped path yielding zero files, zero
        // claims, and a clean lint over nothing — every metric then unmapped, or
        // worse, an assembly with no evidence to resolve against succeeding
        // because there was nothing to disagree with.
        let err = load(
            Path::new("no-such-registry-directory"),
            &RegistryPolicy::default(),
            as_of(),
        )
        .expect_err("a missing directory is not an empty registry");
        assert!(matches!(err, RegistryLoadError::Io { .. }), "{err:?}");
    }

    #[test]
    fn an_expired_claim_is_a_notice_and_still_loads() {
        // Staleness demotes, it does not stop the line (PREMORTEM S2).
        let far_future: Date = "2099-01-01".parse().unwrap();
        let loaded = load(&real_registry_dir(), &RegistryPolicy::default(), far_future)
            .expect("expiry must never fail a load");
        assert!(
            !loaded.stale_claim_ids().is_empty(),
            "every claim is past expiry in 2099"
        );
        assert!(loaded
            .notices
            .iter()
            .any(|d| d.code == "registry.evidence-stale"));
        assert!(loaded.registry.claims.values().all(|c| c.stale));
    }

    #[test]
    fn a_budget_breach_refuses_to_load() {
        // The enforced count is enforced here too, not only in CI: a binary
        // built from a branch that added a twenty-fifth claim must not measure
        // with it.
        let tight = RegistryPolicy {
            claim_budget: 1,
            ..RegistryPolicy::default()
        };
        let err = load(&real_registry_dir(), &tight, as_of())
            .expect_err("over budget must refuse at runtime as well as in CI");
        let RegistryLoadError::Lint { errors, .. } = err else {
            panic!("expected a lint refusal, got {err:?}");
        };
        assert!(
            errors.iter().any(|e| e.contains("registry.claim-budget")),
            "{errors:?}"
        );
    }
}
