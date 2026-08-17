//! Self-measurement semantics (PREMORTEM S3).
//!
//! Andon must pass its own measurement, which creates a circularity: a broken
//! detector would be judging the fix to itself. The rule is that self-measurement
//! runs the **last attested release** binary, never the working tree's build.
//!
//! Overriding that rule is sometimes legitimate and must never be quiet. An
//! override carries a [`OverrideReason`] from a closed set and lands in the
//! ledger, so "we skipped the gate" is a queryable fact rather than a decision
//! someone remembers making. The prose lives in `docs/self-measure.md`; the enum
//! is here so the ledger records a code and not free text.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Why a self-measure gate was bypassed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OverrideReason {
    /// No attested release exists yet. The bootstrap exception from the decision
    /// log: legal only until the first attested release ships, and self-expiring
    /// by construction because it stops being true.
    BootstrapNoAttestedRelease,
    /// The change under measurement is to an engine, so the attested binary's
    /// verdict is about the old detector. Pairs with the two-binary comparison.
    EngineChangeUnderReview,
    /// A detector defect is known, filed, and firing on this change.
    KnownDetectorDefect,
    /// The attested binary could not be fetched or run. Infrastructure, not
    /// judgement.
    InfrastructureUnavailable,
    /// A finding was reviewed and found to be a false positive. Feeds the
    /// PREMORTEM S6 false-positive budget.
    ReviewedFalsePositive,
}

/// A recorded override. Every field is required: an override with no issue
/// reference and no named approver is indistinguishable from a silent bypass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SelfMeasureOverride {
    /// Which closed-set reason applies.
    pub reason: OverrideReason,
    /// Free text explaining this instance.
    pub justification: String,
    /// Issue or PR the decision is recorded against.
    pub reference: String,
    /// Who approved it. A named person, not a role.
    pub approved_by: String,
    /// Commit the override applies to. Overrides do not carry forward.
    pub head_oid: String,
}

/// Which binary a self-measurement ran, and whether that was the rule or an
/// exception.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SelfMeasureProvenance {
    /// Version of the binary that measured.
    pub measuring_binary_version: String,
    /// Commit it was built from.
    pub measuring_binary_oid: String,
    /// Whether that binary was an attested release.
    pub attested: bool,
    /// Present when the attested-binary rule was not followed.
    pub override_record: Option<SelfMeasureOverride>,
    /// Paths excluded from self-measurement, from
    /// `policy.self_measure.excluded_paths`.
    pub excluded_paths: Vec<String>,
    /// Set when the excluded set grew since the last attested run. An exclusion
    /// list that widens quietly is how the dogfood gate stops meaning anything.
    pub exclusion_drift: bool,
}

impl SelfMeasureProvenance {
    /// Whether this run satisfied the attested-binary rule without an override.
    pub fn is_clean(&self) -> bool {
        self.attested && self.override_record.is_none() && !self.exclusion_drift
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_is_never_clean_even_when_attested() {
        let provenance = SelfMeasureProvenance {
            measuring_binary_version: "0.1.0".into(),
            measuring_binary_oid: "a".repeat(40),
            attested: true,
            override_record: Some(SelfMeasureOverride {
                reason: OverrideReason::KnownDetectorDefect,
                justification: "detector 3 misfires on generated code".into(),
                reference: "gtm-k/andon#12".into(),
                approved_by: "gtm-k".into(),
                head_oid: "b".repeat(40),
            }),
            excluded_paths: vec![],
            exclusion_drift: false,
        };
        assert!(!provenance.is_clean());
    }

    #[test]
    fn exclusion_drift_alone_makes_a_run_unclean() {
        let provenance = SelfMeasureProvenance {
            measuring_binary_version: "0.1.0".into(),
            measuring_binary_oid: "a".repeat(40),
            attested: true,
            override_record: None,
            excluded_paths: vec!["fixtures/gamed/**".into()],
            exclusion_drift: true,
        };
        assert!(!provenance.is_clean());
    }
}
