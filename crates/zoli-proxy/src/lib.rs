//! Registry-scoped, localhost-only interception proxy (`zoli serve`).
//!
//! Phase 2 builds this on tokio, rustls and an rcgen-generated local CA. The
//! proxy terminates TLS only for allowlisted registry hosts. Every other
//! `CONNECT` is tunnelled byte-for-byte without inspection. For allowlisted
//! hosts it enforces the policy decision on metadata (min-age version
//! suppression) and on tarball downloads (block). See
//! `docs/decisions/ADR-002-interception.md`.

/// Registry hosts intercepted by default for npm-family package managers.
/// Configured registries extend this list; nothing else is ever intercepted.
pub const NPM_DEFAULT_HOSTS: &[&str] = &["registry.npmjs.org"];

pub mod registry;
