# Architecture

Updated: 30 October 2026 (Asia/Kolkata). Phase 1 assessment and the locked npm ci guard are implemented and validated locally. The broader proxy flow below remains a Phase 2 target. [Progress](progress.md) distinguishes the gates.

## Implemented locked install flow

`wrap npm -- ci` captures project/config inputs, assesses all recorded dependencies against the verified feed, checks full registry publication metadata and the 24-hour age floor, verifies archive integrity and performs static inspection. Approved archives populate a private cache through `npm cache add --offline --ignore-scripts` outside the project. A second verified-feed/policy pass and unchanged-input check precede durable authorization and `npm ci --offline`. User caches and operational npm configuration cannot supply artifacts. No listener or local CA is needed for this path. See [configuration](configuration.md#guarded-npm-ci) for its explicit limits.

## Planned broader install flow

```text
developer / CI / agent
   │  npm install foo
   ▼
shim (shell function or PATH shim)
   │  zoli wrap npm -- install foo
   ▼
zoli wrap ── pre-flight: exact versions in the direct arguments ──► policy ──► block early
   │  spawn real npm with HTTPS_PROXY + NODE_EXTRA_CA_CERTS
   ▼
npm ── CONNECT registry.npmjs.org ──► zoli serve (127.0.0.1)
                                        │ TLS with local-CA leaf certificate
                                        ├─ packument: drop blocked / too-new versions, fix dist-tags
                                        └─ tarball:   evaluate name@version, 403 on block
npm ── CONNECT anything-else ─────────► zoli serve ── tunnel untouched ──► upstream
```

Verdicts come only from the verified local feed cache (ADR-003). `zoli update` refreshes that cache through the trust chain described in ADR-004. Every decision is appended to the audit log.

## Verdicts versus decisions

The most important internal boundary.

- **Verdict** (`zoli-intel`): what the feed knows about a package version. It must be byte-identical to the Go reference client's `api.Query` output for the same verified feed, query and clock (ADR-004).
- **Decision** (`zoli-policy`): what Zoli does about the verdict: allow, warn or block. It is computed from the verdict, the configuration (including the minimum publish age and the staleness bound) and the mode (interactive or CI).

Policy reads verdicts and never rewrites them. Zoli-specific behaviour therefore cannot break verdict parity, and the parity suite needs no knowledge of policy.

## Package assessment (Phase 1)

The user confirmed local package inspection alongside feed checks. [ADR-006](decisions/ADR-006-local-package-analysis.md) specifies the implemented boundary: local observations stay separate from unchanged Go-compatible feed verdicts.

```text
supported npm lockfile ──► dependency graph with exact identities and parent paths
                                      │
                 ┌────────────────────┴────────────────────┐
                 ▼                                         ▼
       verified local feed                     integrity-checked artifact
           zoli-intel                           acquired by zoli-proxy
                 │                                         │
       unchanged Go verdict                     local static inspection
                 │                                  zoli-inspect
                 └────────────────────┬────────────────────┘
                                      ▼
                         aggregate report and policy
                          reasons, gaps, audit, exit
```

`zoli-inspect` is network-free. It parses bounded tar/tgz and supported JS/TS with Oxc without extracting or executing package code. The CLI launches this same binary as a worker with a cleared environment and monitors its deadline/RSS. Local scope is bounded per-file flow, with explicit limitations rather than a whole-program safety claim. Native/opaque/unsupported content refuses completion.

`scan --lockfile <path>` includes every recorded dependency scope, acquires approved registry artifacts with scoped npmrc authentication, checks strong SRI, and queries exact identities against one verified snapshot. Bundled content must agree with the inventory; bundled packages receive feed queries without an invented independent archive hash. `inspect <archive> ...` is local-only, and `check ...` is feed-only. Neither partial scope grants installation approval.

Publication/source freshness is checked before downloads and again after expensive analysis. Decisions prioritize runtime errors over policy blocks over incomplete work. Reports retain manifest/key provenance, artifact/rule digests, findings, graph paths, gaps and timings. The CLI durably appends the audit record before releasing the report.

The locked guard now uses this assessment before npm starts. Known blocked or too-young packages can be rejected before artifact download. Unsupported sources refuse installation; only approved quarantine bytes enter the private npm cache. Wider proxy-based resolution remains planned.

## Crates

| Crate | Depends on | Responsibility | Lands in |
| --- | --- | --- | --- |
| `zoli-intel` | — | Envelope and artifact verification, delta application, fixed-wire serializer, records hash, cache, query and matching | Phase 1 |
| `zoli-policy` | `zoli-intel`, `zoli-inspect` | Immutable-evidence decisions, one-hour freshness bound, suspicious/CI and completeness rules | Phase 1; guard adds the configured publish-age floor |
| `zoli-proxy` | `zoli-intel` | Approved registry acquisition, scoped credentials, redirects, integrity | Phase 1; interception listener/CA/metadata rewriting remain Phase 2 |
| `zoli-pms` | `zoli-intel` | Package-manager identification and exact npm lockfile inventory | Phase 1; wrapping/Python adapters later |
| `zoli-inspect` | `zoli-intel` | Bounded archives, Oxc AST, versioned local evidence and coverage; no sockets or package execution | Phase 1 |
| `zoli-shell` | `zoli-pms` | rc-file blocks for bash, zsh and fish; PATH shim directory; uninstall | Phase 2, Phase 4 (CI) |
| `zoli-cli` | all | The `zoli` binary | Phase 0 (surface) |

Dependencies point one way, with `zoli-intel` at the bottom. Network access exists only in `zoli-intel` (feed) and `zoli-proxy` (registries); no other crate opens sockets.

## Planned terminal interface

The user selected [Ratatui](https://ratatui.rs/) for Zoli's TUI on 30 October 2026. It will present the existing assessment, feed-status and audit models while verification and policy remain independent of rendering. Plain CLI/JSON output stays available for automation; approved npm processes receive a restored terminal and normal streams. [ADR-007](decisions/ADR-007-terminal-interface.md) records the choice and implementation gates. No TUI is implemented yet.

## Python adapter foundation

[Phase 3](phase3-python.md) now exposes PyPI feed-only checks with concrete Go-compatible comparison, exact/event-range matching and optional artifact SHA-256 selectors. Constraint-string ranges refuse until parity is implemented. A separate `zoli-pms::requirements` reader inventories a strict hash-pinned pip subset without executing Python, following includes or resolving dependencies. Python artifact inspection and installer execution retain their own acceptance gates.

## Commands

| Command | Purpose | Phase |
| --- | --- | --- |
| `zoli wrap npm -- ci` | Complete assessment, private cache, release recheck, then npm offline; other commands refuse | 2, implemented |
| `zoli serve` | Registry-scoped interception proxy | 2 |
| `zoli check --eco npm\|PyPI --name X --ver Y [--sha256 HASH]` | One verdict and decision from the verified cache | 1 |
| `zoli update` | Fetch, verify and atomically store the latest publication | 1 |
| `zoli status` | Cache sequence, record count, freshness and source state | 1 |
| `zoli inspect <archive> --eco npm --name X --ver Y` | Local artifact inspection only, optional `--integrity` | 1 |
| `zoli scan --lockfile <path> [--npmrc <trusted-file>]` | Aggregate feed, graph, acquisition and local inspection | 1 |
| `zoli shims install\|uninstall (--shell <sh> \| --ci)` | Install or remove shell shims, or PATH shims for CI | 2 (shell), 4 (CI) |
| `zoli doctor` | Check that the shim is active, the proxy is reachable, the CA is trusted by the wrapped process, and the feed is fresh | 2 |

## Exit codes

Global `--json`, `--ci` and `--suspicious warn\|block` apply to assessment commands.

| Code | Meaning |
| --- | --- |
| 0 | Complete allow/warn within the stated scope, or successful metadata operation; no install approval is implied |
| 1 | Runtime error. Nothing was allowed |
| 2 | Usage error |
| 3 | Command not implemented in this build. Nothing was checked, allowed or run |
| 10 | Policy block, including malicious, CI suspicion or unusable intelligence |
| 12 | Incomplete required artifact/inventory evidence |

Before installation, any nonzero approval stops npm. Once authorized, the wrapper propagates npm's exit status (including lifecycle failures); those statuses may overlap Zoli codes and do not imply that nothing ran. A post-install audit failure also returns an error. The audit scopes identify the stage.

## Files

| Path (under `$ZOLI_HOME`, default `~/.zoli`) | Contents | Mode |
| --- | --- | --- |
| `config.json` | Feed URL, pinned key, policy, registries ([configuration](configuration.md)) | 0600 |
| `cache/feed.json` | Verified snapshot in Go `Snapshot` shape (ADR-004 §7) | 0600 |
| `state.json` | Highest verified sequence, pinned key ID and raw-manifest digest (ADR-005) | 0600 |
| `update.lock` | Shared-reader/exclusive-updater filesystem lock | 0600 |
| `ca/` | Local proxy CA key and certificate (ADR-005) | 0700 / 0600 |
| `shims/` | Generated shell snippets and the PATH shim directory | 0755 |
| `log/audit.jsonl` | Append-only decision log | 0600 |

The earlier, unpublished Python prototype also uses `~/.zoli/config.json` and `~/.zoli/audit.jsonl`, with a different schema. v1 marks its configuration with `config_version` and keeps its audit log under `log/`, so neither file is ever misread.

## Network egress

In Phase 1, only `zoli-intel` connects to the configured public feed on HTTPS port 443, and only `zoli-proxy` connects to approved registry/artifact origins. Redirect targets are independently checked, DNS addresses are pinned, private access is explicit per origin, and credentials are recomputed per hop. No hosted package queries or telemetry are sent. Phase 2's forwarding/tunnelling behavior is not implemented.
