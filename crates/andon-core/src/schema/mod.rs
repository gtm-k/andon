//! Payload schema v1 — the published contract.
//!
//! Documented in `schemas/README.md`; the JSON Schema artifacts in `schemas/`
//! are generated from these types and pinned by a drift test.

pub mod agent_profile;
pub mod enums;
pub mod payload;
pub mod regime;

use schemars::schema::RootSchema;

/// Generate the JSON Schema for a full [`payload::MeasurementRecord`].
pub fn measurement_record_schema() -> RootSchema {
    schemars::schema_for!(payload::MeasurementRecord)
}

/// Generate the JSON Schema for the named agent-mode view.
pub fn agent_profile_schema() -> RootSchema {
    schemars::schema_for!(agent_profile::AgentProfile)
}

/// Generate the JSON Schema for `.andon.toml`.
pub fn policy_schema() -> RootSchema {
    schemars::schema_for!(crate::policy::Policy)
}

/// Generate the JSON Schema for one engine's registry file.
pub fn registry_schema() -> RootSchema {
    schemars::schema_for!(crate::registry::EngineRegistryFile)
}
