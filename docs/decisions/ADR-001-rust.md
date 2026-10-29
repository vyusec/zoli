# ADR-001: Rust single binary

- Status: Accepted, 16 October 2026.

## Context

Zoli runs on developer machines and in CI. It sits between package managers and registries and parses untrusted registry traffic in a long-running TLS-terminating proxy. It must install as one file, need no account or token, and start quickly enough to wrap every `npm` invocation.

## Decision

Zoli is a single Rust binary, `zoli`, built from a Cargo workspace of small crates:

| Crate | Responsibility |
| --- | --- |
| `zoli-cli` | Argument parsing, command dispatch, exit codes. The only binary |
| `zoli-intel` | Verified feed client and verdicts, a faithful Go port (ADR-004) |
| `zoli-inspect` | Bounded, network-free archive and JS/TS static inspection |
| `zoli-policy` | Decisions over verdicts; audit records |
| `zoli-proxy` | Registry-scoped interception proxy (ADR-002) |
| `zoli-pms` | Package-manager adapters: identification, environment, pre-flight arguments |
| `zoli-shell` | Shell shims and rc-file management |

Baseline rules:

- **Toolchain:** pinned in `rust-toolchain.toml` (1.98.0 at baseline), edition 2024, `rust-version` equal to the pinned toolchain.
- **Code:** `unsafe_code = "forbid"` workspace-wide. `unwrap`, `expect`, `panic!`, `todo!` and `unimplemented!` are denied outside tests, so a stub cannot crash its way into an allow.
- **Dependencies:** `cargo-deny` gates advisories, licenses, bans and sources. A new license needs an explicit allowlist entry.
- **Linking:** Linux releases target musl and are fully static. macOS releases link only system libraries; macOS does not support fully static binaries.
- **TLS:** rustls with ring in Phase 1, no runtime OpenSSL dependency. Musl build cost remains a release-build gate. The controlled test registry carries test-only certificates and a public fixture key; those are never used as production trust material.
- **Platforms:** v1 supports Linux and macOS only.

## Consequences

- The Go reference client cannot be reused, so Zoli carries a faithful reimplementation and its conformance suite (ADR-004). This is the main cost of the decision.
- Release engineering needs per-target builds: x86_64 Linux musl, x86_64 macOS and aarch64 macOS (Phase 4).

## Alternatives considered

- **Go.** The strongest alternative. Zoli could import `intel-feed/pkg/client` directly and remove the cross-language parity risk, and Go also builds static binaries with a mature TLS stack. Rust was chosen for memory safety without a garbage collector in the long-running proxy, small binaries, and an explicit type-level policy core.
- **Node.js or Python.** These need a runtime on the machine, and they run inside the ecosystems being protected, so a compromised dependency could tamper with the guard.

## Revisit trigger

If the Phase 1 conformance gate cannot be met within its budget, revisit this ADR before Phase 2. One option is a Go component for the trust chain only.
