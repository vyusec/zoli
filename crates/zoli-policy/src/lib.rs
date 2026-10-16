//! Install decisions layered on top of verified feed verdicts.
//!
//! A verdict (from `zoli-intel`) says what the feed knows. A decision (from
//! this crate) says what Zoli does about it. Policy reads verdicts and never
//! rewrites them, so verdict parity with the Go client survives any policy
//! setting. Defaults are in `docs/configuration.md`; the decision table and
//! audit records land in Phase 1.

pub use zoli_intel::{Classification, Freshness, QueryStatus};

/// What Zoli does with one package version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Let the package manager proceed. A banner may still accompany it.
    Allow,
    /// Proceed, print a warning, and record the decision.
    Warn,
    /// Refuse the version and record the decision.
    Block,
}

/// Where Zoli runs. CI escalates some warnings to blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A developer terminal.
    Interactive,
    /// A CI job (`--ci` shims or a detected CI environment).
    Ci,
}
