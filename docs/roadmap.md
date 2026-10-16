# Roadmap

Baseline: 16 October 2026 (Asia/Kolkata), from the v0 plan. [Progress](progress.md) records status; [validation](validation.md) records what was actually run.

## Locked decisions

| ADR | Decision |
| --- | --- |
| [ADR-001](decisions/ADR-001-rust.md) | Rust single static binary |
| [ADR-002](decisions/ADR-002-interception.md) | Proxy plus pre-flight interception |
| [ADR-003](decisions/ADR-003-intel-sources.md) | Zoli feed as the only v1 intelligence source |
| [ADR-004](decisions/ADR-004-feed-client-faithfulness.md) | Faithful port of the Go feed client, gated by Go-generated fixtures |
| [ADR-005](decisions/ADR-005-trust-bootstrap.md) | Pinned key, local CA, rollback state |

npm ecosystem first. Linux and macOS for v1.

## Phases and exit gates

| Phase | Deliverable | Exit gate | Current state |
| --- | --- | --- | --- |
| 0 — Baseline | Repo skeleton, ADR-001…005, CI (rustfmt, clippy, deny, test), docs set | Docs pinned to a dated baseline; `cargo build` and CI green | **Complete, 16 October.** Docs dated; `make ci` green locally; hosted run [38869463032](https://github.com/vyusec/zoli/actions/runs/38869463032) green on `3bbfe88` |
| 1 — Decision core | `zoli check`, verified feed client, Rust conformance suite | Verdicts byte-identical to Go (ADR-004 gate 1–3); tamper, rollback, stale and withdraw fixtures handled; live agreement (gate 4) | Not started. Needs the fixture generator in intel-feed. Gate 4 needs a public HTTPS staging feed |
| 2 — npm guard | `zoli serve`, npm-family shims, minimum age, block UX, `zoli doctor` | Real `npm install` (direct and transitive) blocked in Docker against a mock registry; `zoli doctor` passes; package-manager output unaffected | Not started |
| 3 — Python guard | pip, uv, poetry and pipx via CA injection (`PIP_CERT`, `SSL_CERT_FILE` for uv, `pip.conf` merge) | Same Docker gate with real pip and a relisted fixture | Not started. Needs a PEP 440 port (ADR-004 §6) |
| 4 — Install/CI | Checksum-pinned installer, `--ci` PATH shims, GitHub Actions recipe, uninstall | CI matrix (x86_64-linux, x86_64-mac, aarch64-mac) green | Not started |
| 5 — Hardening | Key rotation, staleness bound, audit log, degraded mode | Trust regression suite passes; every failure path proven never to allow silently | Not started |

Phases run in order. Phase 1 can start on fixtures and the serializer before intel-feed has a staging deployment; only gate 4 waits for it.

## Phase 1 work order

1. **Fixture generator in intel-feed** (`cmd/conformance-gen`) for all families in ADR-004, with provenance hashes. Output goes to `testdata/conformance/`.
2. **Wire types and the fixed-wire serializer** (hash and marshal modes), proven first against the snapshot-encoding fixtures. This is the cheapest strong signal.
3. **Trust chain:** envelope, artifacts, multistream gzip, row splitting, deltas, snapshot fallback, against the negative fixtures.
4. **Matching:** normalization, the npm semver port, `MatchAffected` and `Query`, against the query matrix.
5. **Cache and state:** Go-shaped cache, `state.json`, cross-load checks with Go.
6. **Commands:** `zoli check`, `update` and `status`, the policy table and the audit log.
7. **Gate 4** against intel-feed's staging feed, once deployed.

## Open questions

| ID | Question | Proposed answer | Decide by |
| --- | --- | --- | --- |
| OQ-1 | How should policy treat `insufficient_information` with uncertain matches? | Malicious: block everywhere. Suspicious: warn interactively, block in CI | Phase 1 review |
| OQ-2 | Default minimum publish age | Value to be chosen; the plan fixes only the mechanism | Phase 2 |
| OQ-3 | Banner threshold, given that Go marks `degraded` whenever any source is over an hour old or failing | Banner from signed timestamps past a display threshold; the verdict stays unchanged | Phase 1 review |
| OQ-4 | Default staleness bound before installs block | To be chosen with the feed's actual publication cadence | Phase 5 |
| OQ-5 | Proxy lifecycle: one per `wrap`, or long-lived `zoli serve` | Measure startup cost in Phase 2 | Phase 2 |
| OQ-6 | `dist-tags.latest` points at a removed version | Retarget to the highest remaining stable version, with a notice | Phase 2 |

## Plan corrections found in Phase 0

Each was found by reading the intel-feed Go source at the baseline, which is identical to [`vyusec/intel-feed@7919b85`](https://github.com/vyusec/intel-feed/tree/7919b8586cd7d8e2d9777be43d9beb5102154601) for the files involved. None of it has been executed yet; the Phase 1 fixtures confirm or refute each point.

- **PC-1: risk ranking.** Hash parity fails closed (an availability cost); matching parity can fail open. Matching is therefore the silent-allow risk, and the query matrix is its gate (ADR-004).
- **PC-2: live gate target.** `client-check` cannot reach a locally deployed feed: Go `netfetch` allows only port 443 on public addresses. The live gate needs a public HTTPS staging feed (ADR-004).
- **PC-3: generator location.** The generator must live inside the intel-feed module, because `feed.Sign`, `RecordsHash`, `ApplyDelta` and `api.Query` are `internal/`.
- **PC-4: policy coverage.** The v1 policy defaults did not cover `insufficient_information`. A full table is in [configuration](configuration.md#policy-defaults-v1), with OQ-1 and OQ-3 open.
- **PC-5: CI evidence.** "CI green" could not be observed without a Git remote. Resolved on 16 October: the repository was pushed to `vyusec/zoli`, and run 38869463032 passed.
- **PC-6: npm-family coverage.** The Phase 2 gate covers npm only. pnpm, npx and Yarn need their own evidence before Zoli claims to protect them.
- **PC-7: path collision.** The Python prototype also uses `~/.zoli/config.json` and `~/.zoli/audit.jsonl`. v1 adds `config_version` and moves the audit log to `log/`.

## Upstream observations for intel-feed

- **U-1: hash order.** Snapshot hash order follows PostgreSQL collation (`ORDER BY id`), while the client sorts delta results byte-wise. The two agree only while every ID has the generated `ZOLI-<hex>` form.
- **U-2: path rule.** `safePath` admits `.` and `..` as artifact paths. This is harmless, because bytes are hash-pinned, but a stricter rule would be clearer.
- **U-3: equivocation.** An equal sequence returns the previous snapshot without comparing manifest bytes, so equivocation goes unnoticed by the Go client.
