//! Payload assembly: five engines' results become one record.
//!
//! Two pieces are here so far, both of which the verdict needs before there is
//! anything to assemble:
//!
//! - [`registry_load`] — the evidence gate, applied at the measurement boundary
//!   rather than only in CI. No number reaches a payload whose claim nobody
//!   declared.
//! - [`tamper_signals`] — which detectors fired, read back off the results
//!   rather than passed in, so a record recovered from a git note carries the
//!   same answer as one just measured.

pub mod registry_load;
pub mod tamper_signals;
