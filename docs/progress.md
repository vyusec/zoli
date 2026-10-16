# Progress

Updated: 16 October 2026 (Asia/Kolkata). Audience: Zoli maintainers.

Rule: **implemented** means the code or document exists. **Validated** means the gate evidence exists and is linked. Nothing counts as done on implementation alone.

## Capability baseline

| Area | Implemented | Validated | Evidence | Remaining gate |
| --- | --- | --- | --- | --- |
| Workspace and crates | Cargo workspace, six crates, `zoli` binary, toolchain 1.98.0 pinned | Local build from clean, 16 October | [Validation](validation.md#phase-0--16-october-2026) | Hosted CI run |
| Command surface | `wrap`, `serve`, `check`, `update`, `status`, `shims`, `doctor`; every command exits 3 without checking, allowing or running anything | 5 CLI integration tests, including a fake `npm` that is never executed | `crates/zoli-cli/tests/cli.rs` | — |
| Contract vocabulary | Exact Go wire strings for status, classification, certainty, freshness and ecosystem | Unit tests against strings read from the Go source | `crates/zoli-intel/src/lib.rs` | Phase 1 fixtures confirm them against Go output |
| Quality gates | rustfmt, clippy `-D warnings`, cargo-deny (advisories, licenses, bans, sources), lint denials for `unsafe`, `unwrap`, `expect`, `panic!`, `todo!` | Passed locally; a deliberately narrowed license list failed as expected, then was restored | [Validation](validation.md#phase-0--16-october-2026) | Hosted CI run |
| CI workflow | `.github/workflows/ci.yaml`: lint, deny, and tests on Ubuntu and macOS, with checkout pinned by commit | **Not observed.** A workflow definition is not a CI result | — | Push to a remote and record the run |
| Documentation | Architecture, roadmap, threat model, configuration, shell integration, ADR-001…005, all dated 16 October | Reviewed against the intel-feed Go source | `docs/` | — |
| Feed client, policy, proxy, shims, installer | Not started | — | — | Phases 1–5 |

## Phase 0 gate

| Criterion | State |
| --- | --- |
| Docs pinned to a dated baseline | Met |
| `cargo build` green | Met locally |
| CI green | Local equivalent met (`make ci` runs the same steps in the same order). Hosted run pending: no Git remote exists |

## Blockers

| Gate | Blocker | Next action |
| --- | --- | --- |
| Hosted CI (Phase 0) | No Git remote or commit | Create the repository, commit, push, and record the run in [validation](validation.md) |
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
