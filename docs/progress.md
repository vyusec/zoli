# Progress

Updated: 16 October 2026 (Asia/Kolkata). Audience: Zoli maintainers.

Rule: **implemented** means the code or document exists. **Validated** means the gate evidence exists and is linked. Nothing counts as done on implementation alone.

## Capability baseline

| Area | Implemented | Validated | Evidence | Remaining gate |
| --- | --- | --- | --- | --- |
| Workspace and crates | Cargo workspace, six crates, `zoli` binary, toolchain 1.98.0 pinned | Local build from clean, plus hosted CI run 38869463032, 16 October | [Local](validation.md#phase-0--16-october-2026), [hosted](validation.md#hosted-ci--16-october-2026) | — |
| Command surface | `wrap`, `serve`, `check`, `update`, `status`, `shims`, `doctor`; every command exits 3 without checking, allowing or running anything | 5 CLI integration tests, including a fake `npm` that is never executed | `crates/zoli-cli/tests/cli.rs` | — |
| Contract vocabulary | Exact Go wire strings for status, classification, certainty, freshness and ecosystem | Unit tests against strings read from the Go source | `crates/zoli-intel/src/lib.rs` | Phase 1 fixtures confirm them against Go output |
| Quality gates | rustfmt, clippy `-D warnings`, cargo-deny (advisories, licenses, bans, sources), lint denials for `unsafe`, `unwrap`, `expect`, `panic!`, `todo!` | Passed locally and in hosted CI; a deliberately narrowed license list failed as expected, then was restored | [Local](validation.md#phase-0--16-october-2026), [hosted](validation.md#hosted-ci--16-october-2026) | — |
| CI workflow | `.github/workflows/ci.yaml`: lint, deny, and tests on Ubuntu and macOS, with checkout pinned by commit | Run [38869463032](https://github.com/vyusec/zoli/actions/runs/38869463032) on `3bbfe88`: all four jobs green, 11/11 tests on Ubuntu 24.04 and on macOS 26 arm64 | [Hosted CI](validation.md#hosted-ci--16-october-2026) | x86_64 macOS joins in Phase 4 |
| Documentation | Architecture, roadmap, threat model, configuration, shell integration, ADR-001…005, all dated 16 October | Reviewed against the intel-feed Go source | `docs/` | — |
| Feed client, policy, proxy, shims, installer | Not started | — | — | Phases 1–5 |

## Phase 0 gate

| Criterion | State |
| --- | --- |
| Docs pinned to a dated baseline | Met |
| `cargo build` green | Met locally |
| CI green | Met: `make ci` green locally, and hosted run 38869463032 green on `3bbfe88` |

**Phase 0 is complete** as of 16 October 2026.

## Blockers

| Gate | Blocker | Next action |
| --- | --- | --- |
| Phase 1 live agreement (gate 4) | Needs a public HTTPS staging feed, which intel-feed has not deployed (its own Phase 1 blocker) | Generate fixtures first; gate 4 waits for the staging feed |

## Integration contract with intel-feed

Zoli follows the "Zoli handoff contract" in intel-feed's `docs/progress.md`. At this baseline that file existed only in the local intel-feed workspace, not in [`vyusec/intel-feed@7919b85`](https://github.com/vyusec/intel-feed/tree/7919b8586cd7d8e2d9777be43d9beb5102154601). It asks for:

- base URL ending in `/feed`;
- pinned key;
- persisted sequence, with saves only after verification;
- the three statuses preserved, along with classification, certainty, coverage and freshness;
- corrections and withdrawals handled;
- stale intelligence never reported as safe.

ADR-004 records the client behaviour in detail.

Update this file after every completed gate, with the date and a link to its validation evidence.
