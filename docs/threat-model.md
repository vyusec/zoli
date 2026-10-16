# Threat model

Baseline: 16 October 2026. Scope: Zoli v1 on Linux and macOS, npm family first.

## What Zoli protects

The developer's or CI runner's machine. Zoli stops a known-malicious or too-new package version before its tarball is fetched, and so before its install scripts run.

## Assets

| Asset | Why it matters |
| --- | --- |
| Pinned feed key in `config.json` | It decides which intelligence Zoli trusts |
| Verified cache and high-water sequence | They decide what Zoli knows right now |
| Local CA private key | Wrapped processes trust it for registry hosts |
| Audit log | The record of what was allowed, blocked and overridden |
| The `zoli` binary and shims | They decide whether interception happens at all |

## Adversaries in scope

1. **Malicious package author.** Publishes a typosquat or a compromised version of a legitimate package.
2. **Network attacker** between Zoli and the feed, or between the package manager and the registry. Can drop, delay, replay or modify traffic.
3. **Compromised feed hosting** without the signing key. Can serve old, partial or altered files.
4. **A malicious dependency already running** inside a wrapped package manager, for example in a lifecycle script. It tries to disable or bypass Zoli for later installs.

## Out of scope

- A local attacker with write access to `~/.zoli`, the `zoli` binary or shell rc files. They can change the pinned key or remove shims.
- Compromise of the feed's signing key. Detection and rotation are covered by ADR-005; prevention belongs to intel-feed.
- A registry serving a tarball that does not match its own metadata. The package manager's integrity check covers that.
- Packages missing from the feed. `no_known_match` is never a safety verdict (ADR-003).

## Threats and mitigations

| # | Threat | Mitigation | Status |
| --- | --- | --- | --- |
| T1 | Forged manifest or artifact | Ed25519 over the exact manifest bytes; SHA-256 and size of each artifact before decoding; records hash after delta application (ADR-004) | Phase 1 |
| T2 | Rollback to an older, validly signed publication | Sequence must not decrease, with the high-water mark kept separately from the cache. Old publications are also `stale`, which never yields `no_known_match` | Phase 1 |
| T3 | Freeze: the attacker blocks updates | Freshness is visible on every verdict; installs block beyond the staleness bound | Phase 1 (banner), Phase 5 (bound) |
| T4 | Equivocation: same sequence, different content | Logged as a security event; the update fails | Phase 1 |
| T5 | Rust verdict differs from Go and silently allows | Fixed-wire serializer plus a Go-generated query matrix, including npm semver edge cases; divergences allowed only in the fail-closed direction (ADR-004) | Phase 1 |
| T6 | Install bypasses the proxy (unaliased binary, `HTTPS_PROXY` cleared, package manager ignores the proxy) | PATH shims; `zoli doctor`; per-manager adapters. Partly residual | Phase 2, Phase 4 |
| T7 | Lockfile install fetches a tarball without reading metadata | Tarball requests are evaluated and blocked by the proxy, not only metadata | Phase 2 |
| T8 | Theft of the local CA key | Generated per machine, mode 0600, trusted only by wrapped processes, name-constrained to registry hosts (to verify) | Phase 2 |
| T9 | Proxy used as an open relay or listening beyond localhost | Binds `127.0.0.1` only; accepts CONNECT only; inspects allowlisted hosts and tunnels the rest unchanged | Phase 2 |
| T10 | A malicious lifecycle script edits shims or config for later runs | Out of scope as a local write (see above), but `zoli doctor` reports shim state, the active key ID and config changes | Phase 2 |
| T11 | Malformed input crashes Zoli into allowing | No error path allows. `unwrap`, `panic!` and `todo!` are denied by lint, and stubs exit 3 | Phase 0 (lints), every phase |
| T12 | Decompression bomb or oversized feed files | Go's limits mirrored: 2 MiB manifest, 256 MiB artifact, 512 MiB expansion, 2 MiB rows | Phase 1 |
| T13 | Leaking the dependency list to a service | No hosted lookups; verdicts come from the local cache only (ADR-003) | Phase 1 |

## Residual risks carried from the plan

1. **Cross-language parity** (ADR-004). Hash divergence fails closed and costs availability. Matching divergence can fail open, so the query matrix is the gate.
2. **TLS configuration escape hatches.** `python -m pip`, `uv --native-tls`, users unaliasing, and explicit `ca`/`cafile` in `.npmrc`. See [shell integration](shell-integration.md#what-shims-do-not-cover-residual-risk).
3. **Bun and Yarn Berry.** Bun is best-effort, as the plan states. Yarn Berry's proxy and CA handling also differs from npm's. Neither is claimed as protected until it has its own gate evidence, and the same applies to pnpm and npx beyond the npm Docker gate.
4. **The window between a malware discovery and the next update.** It is bounded by the feed's publication interval plus Zoli's update interval, made visible through freshness, and capped by the staleness bound.
