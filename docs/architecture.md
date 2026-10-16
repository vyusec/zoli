# Architecture

Baseline: 16 October 2026 (Asia/Kolkata). This document describes the v1 target. [Progress](progress.md) records what exists today.

## Install flow

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

## Crates

| Crate | Depends on | Responsibility | Lands in |
| --- | --- | --- | --- |
| `zoli-intel` | — | Envelope and artifact verification, delta application, fixed-wire serializer, records hash, cache, query and matching | Phase 1 |
| `zoli-policy` | `zoli-intel` | Decision table, staleness bound, minimum age, audit records | Phase 1 (table), Phase 2 (minimum age), Phase 5 (bound) |
| `zoli-proxy` | `zoli-policy`, `zoli-intel` | Localhost listener, CONNECT handling, host allowlist, local CA, packument rewrite, tarball block | Phase 2 |
| `zoli-pms` | — | Package-manager identification, environment injection, pre-flight argument parsing | Phase 2 (npm family), Phase 3 (Python) |
| `zoli-shell` | `zoli-pms` | rc-file blocks for bash, zsh and fish; PATH shim directory; uninstall | Phase 2, Phase 4 (CI) |
| `zoli-cli` | all | The `zoli` binary | Phase 0 (surface) |

Dependencies point one way, with `zoli-intel` at the bottom. Network access exists only in `zoli-intel` (feed) and `zoli-proxy` (registries); no other crate opens sockets.

## Commands

| Command | Purpose | Phase |
| --- | --- | --- |
| `zoli wrap <pm> -- args…` | Shim entry point: pre-flight, then run the real package manager through the proxy | 2 |
| `zoli serve` | Registry-scoped interception proxy | 2 |
| `zoli check --eco npm --name X --ver Y [--suspicious=block]` | One verdict and decision from the verified cache | 1 |
| `zoli update` | Fetch, verify and atomically store the latest publication | 1 |
| `zoli status` | Cache sequence, record count, freshness and source state | 1 |
| `zoli shims install\|uninstall (--shell <sh> \| --ci)` | Install or remove shell shims, or PATH shims for CI | 2 (shell), 4 (CI) |
| `zoli doctor` | Check that the shim is active, the proxy is reachable, the CA is trusted by the wrapped process, and the feed is fresh | 2 |

## Exit codes

Provisional until Phase 1 fixes the decision table.

| Code | Meaning |
| --- | --- |
| 0 | Success. For `wrap`, the package manager's own exit code is passed through |
| 1 | Runtime error. Nothing was allowed |
| 2 | Usage error |
| 3 | Command not implemented in this build. Nothing was checked, allowed or run |
| 10–19 | Reserved for policy outcomes (block, CI-escalated warning). Defined in Phase 1 |

No error path exits 0. Every exit code is chosen so that a script treating "non-zero" as "not allowed" is safe.

## Files

| Path (under `$ZOLI_HOME`, default `~/.zoli`) | Contents | Mode |
| --- | --- | --- |
| `config.json` | Feed URL, pinned key, policy, registries ([configuration](configuration.md)) | 0600 |
| `cache/feed.json` | Verified snapshot in Go `Snapshot` shape (ADR-004 §7) | 0600 |
| `state.json` | Highest verified sequence (ADR-005) | 0600 |
| `ca/` | Local proxy CA key and certificate (ADR-005) | 0700 / 0600 |
| `shims/` | Generated shell snippets and the PATH shim directory | 0755 |
| `log/audit.jsonl` | Append-only decision log | 0600 |

The earlier, unpublished Python prototype also uses `~/.zoli/config.json` and `~/.zoli/audit.jsonl`, with a different schema. v1 marks its configuration with `config_version` and keeps its audit log under `log/`, so neither file is ever misread.

## Network egress

Zoli connects only to the configured feed host (port 443) and, through the proxy, to the hosts the wrapped package manager asks for. Allowlisted registries are inspected; every other host is tunnelled unchanged. Zoli sends no telemetry.
