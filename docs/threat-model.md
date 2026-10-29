# Threat model

Updated: 30 October 2026 for the implemented Phase 1 assessment and locked npm guard in [ADR-006](decisions/ADR-006-local-package-analysis.md). Scope: v1 Linux/macOS target, npm first; new implementation tested locally on Linux. Enforcement covers explicit wrapped npm ci only; [progress](progress.md) distinguishes the evidence.

## What Zoli protects

The developer's or CI runner's machine. Known blocked or too-new versions can be refused before download. The expanded target also inspects unknown package archives in quarantine before releasing them to the package manager, without executing package code. A static scan does not prove safety.

## Assets

| Asset | Why it matters |
| --- | --- |
| Pinned feed key in `config.json` | It decides which intelligence Zoli trusts |
| Verified cache and high-water sequence | They decide what Zoli knows right now |
| Local CA private key | Wrapped processes trust it for registry hosts |
| Audit log | The record of what was allowed, blocked and overridden |
| The `zoli` binary and shims | They decide whether interception happens at all |
| Quarantined package archives and local reports | Untrusted bytes must not escape the inspection boundary; report identity and completeness determine whether a decision is usable |

## Adversaries in scope

1. **Malicious package author.** Publishes a typosquat or a compromised version of a legitimate package.
2. **Network attacker** between Zoli and the feed, or between the package manager and the registry. Can drop, delay, replay or modify traffic.
3. **Compromised feed hosting** without the signing key. Can serve old, partial or altered files.
4. **A malicious dependency already running** inside a wrapped package manager, for example in a lifecycle script. It tries to disable or bypass Zoli for later installs.

## Out of scope

- A local attacker with write access to `~/.zoli`, the `zoli` binary or shell rc files. They can change the pinned key or remove shims.
- Compromise of the feed's signing key. Detection and rotation are covered by ADR-005; prevention belongs to intel-feed.
- A registry and its trusted metadata both lying about publisher identity. Phase 1 verifies strong lockfile integrity and actual archive identity, but a computed hash alone cannot authenticate a publisher.
- Unreported behavior beyond the local analyzer's supported checks. Packages missing from the feed may still produce local findings, but `no_known_match` and a completed static scan without findings are never proofs of safety (ADR-003, ADR-006).
- Runtime detonation of packages. Local inspection executes no package code; any future runtime analyzer needs a separate isolation design.

## Threats and mitigations

| # | Threat | Mitigation | Status |
| --- | --- | --- | --- |
| T1 | Forged manifest or artifact | Ed25519 over the exact manifest bytes; SHA-256 and size of each artifact before decoding; records hash after delta application (ADR-004) | Phase 1 |
| T2 | Rollback to an older, validly signed publication | Sequence must not decrease, with the high-water mark kept separately from the cache. Old publications are also `stale`, which never yields `no_known_match` | Phase 1 |
| T3 | Freeze: the attacker blocks updates | Freshness is visible on every verdict; decisions block beyond the initial staleness bound, which local inspection cannot reset | Phase 1 (initial bound), Phase 5 (extended checks) |
| T4 | Equivocation: same sequence, different content | Logged as a security event; the update fails | Phase 1 |
| T5 | Rust verdict differs from Go and silently allows | Fixed-wire serializer plus a Go-generated query matrix, including npm semver edge cases; divergences allowed only in the fail-closed direction (ADR-004) | Phase 1 |
| T6 | Install bypasses the proxy (unaliased binary, `HTTPS_PROXY` cleared, package manager ignores the proxy) | PATH shims; `zoli doctor`; per-manager adapters. Partly residual | Phase 2, Phase 4 |
| T7 | Lockfile install fetches a tarball without reading metadata | Guard reads exact-version metadata, checks age plus lock/registry SRI, inspects bytes, then releases only approved artifacts into an offline private cache | Implemented for npm ci |
| T8 | Theft of the local CA key | Generated per machine, mode 0600, trusted only by wrapped processes, name-constrained to registry hosts (to verify) | Phase 2 |
| T9 | Proxy used as an open relay or listening beyond localhost | Binds `127.0.0.1` only; accepts CONNECT only; inspects allowlisted hosts and tunnels the rest unchanged | Phase 2 |
| T10 | A malicious lifecycle script edits shims or config for later runs | Out of scope as a local write (see above), but `zoli doctor` reports shim state, the active key ID and config changes | Phase 2 |
| T11 | Malformed input crashes Zoli into allowing | No error path allows. `unwrap`, `panic!` and `todo!` are denied by lint, and stubs exit 3 | Phase 0 (lints), every phase |
| T12 | Decompression bomb or oversized feed files | Go's limits mirrored: 2 MiB manifest, 256 MiB artifact, 512 MiB expansion, 2 MiB rows | Phase 1 |
| T13 | Leaking the dependency list to a service | No hosted lookups; verdicts come from the local cache only (ADR-003) | Phase 1 |
| T14 | Malicious archive attacks the local analyzer | Strong integrity, no extraction/execution, raw entry checks, bounded expansion and monitored isolated worker | Implemented; synthetic archive/worker tests pass |
| T15 | Unsupported or skipped contents are presented as inspected | Explicit completion/gaps, executable/opaque-format rejection, bundled inventory accounting; incomplete required work is non-zero | Implemented; inventory and CLI tests pass |
| T16 | Benign package is labelled malicious by weak local patterns | Separate feed/local channels, located bounded flow, confidence/limitations; hooks/eval alone informational | Implemented; controlled benign/suspicious cases, no accuracy claim |
| T17 | Stale, mismatched or partial analysis result is reused | No analysis-result cache initially; bind artifact/rule provenance and recompute feed policy at the final clock | Implemented; result reuse deferred |
| T18 | Package-manager cache bypasses registry interception | Complete preflight and invocation-private offline cache; cache flags/config overrides refuse; user caches cannot supply artifacts | Real npm warm-cache and release-boundary tests pass |
| T19 | Package-controlled registry URL leaks npm credentials or reaches intranet services | Explicit HTTPS origin allowlist, public-address checks/DNS pinning, operator private-network opt-in, independently scoped redirect auth and CA validation | Controlled HTTPS redirect, TLS, scope and redaction tests pass |
| T20 | Crash/concurrent writes lose rollback state or release unaudited approval | Separate sequence/digest state, locked durable replacements, state before cache; locked/synced audit before output | Interrupted-cache/restart, concurrent store and process-audit tests pass; not a power-cut test |

The parser worker is process isolation with monitored resource budgets, not an OS security sandbox. Its environment is cleared and its code contains no network or package execution. Cross-file data flow, arbitrary runtime behavior and unrecognized concealed payloads remain outside the declared static checks. A finite synthetic corpus cannot establish detection accuracy or eliminate parser vulnerabilities.

The npm guard is not a runtime sandbox. The local project and approved lifecycle scripts execute with user permissions. They can make network requests, write local files or start another installer; nested installation is not protected by this initial-install gate. The npm/Node binaries and absolute PATH entries are trusted local tools. Input fingerprints catch changes during assessment but do not defend against a hostile local writer racing the final process start. Registry publication times are trusted registry metadata bound to the acquired archive by strong integrity.

## Residual risks carried from the plan

1. **Cross-language parity** (ADR-004). Hash divergence fails closed and costs availability. Matching divergence can fail open, so the query matrix is the gate.
2. **TLS configuration escape hatches.** `python -m pip`, `uv --native-tls`, users unaliasing, and explicit `ca`/`cafile` in `.npmrc`. See [shell integration](shell-integration.md#what-shims-do-not-cover-residual-risk).
3. **Bun and Yarn Berry.** Bun is best-effort, as the plan states. Yarn Berry's proxy and CA handling also differs from npm's. Neither is claimed as protected until it has its own gate evidence, and the same applies to pnpm and npx beyond the npm Docker gate.
4. **The window between a malware discovery and the next update.** It is bounded by the feed's publication interval plus Zoli's update interval, made visible through freshness, and capped by the staleness bound.
