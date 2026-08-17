//! Where the hotspot metric gets its complexity half.
//!
//! A hotspot is churn × complexity, and this crate owns neither the parsers nor
//! the grammars that produce a complexity number — those are P2's
//! `crates/engines/static-metrics`, built in parallel with this phase and
//! assembled alongside it at P5a. Depending on that crate from here would couple
//! two phases that are meant to be independent, and it would fail outright while
//! P2's crate does not yet exist.
//!
//! So the dependency is inverted into this trait. P5a supplies an implementation
//! backed by the static engine's own results; anything without one gets
//! [`NoComplexity`].
//!
//! # Degrading cleanly means saying so, not filling in
//!
//! [`NoComplexity`] answers `None` for every path, and the engine turns that into
//! a hotspot result with `completeness: unwitnessed` and no number. It does
//! **not** fall back to churn alone. A hotspot that quietly becomes a churn
//! count is the worst of both: the reader sees a value where a measurement is
//! missing, the number is systematically wrong for every file, and nothing in the
//! payload says which of the two things it is. Absence of an input is reported as
//! absence, which is the same rule shallow history gets (PLAN P4).

/// Complexity per path, in whatever unit the supplying engine measures.
///
/// The unit is deliberately unnamed and integral. Hotspot is a *ranking* signal —
/// which of these files is the risky place to change — so the product only has
/// to be monotonic in both factors, and an integer keeps the arithmetic exact
/// and the digest platform-independent.
pub trait ComplexitySource {
    /// Complexity of `path`, or `None` when this source has no number for it.
    fn complexity(&self, path: &str) -> Option<u64>;
}

/// No complexity input at all. The default until P5a wires the static engine in.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoComplexity;

impl ComplexitySource for NoComplexity {
    fn complexity(&self, _path: &str) -> Option<u64> {
        None
    }
}

impl ComplexitySource for std::collections::BTreeMap<String, u64> {
    fn complexity(&self, path: &str) -> Option<u64> {
        self.get(path).copied()
    }
}
