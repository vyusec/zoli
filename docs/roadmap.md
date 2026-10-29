# Roadmap

Updated: 30 October 2026 (Asia/Kolkata). [Progress](progress.md) records capability status; [validation](validation.md) records executed checks. The user approved npm feed checks plus local static analysis, with correctness before speed, and the locked npm guard with a 24-hour minimum age. The 29 October live check authenticated a degraded feed; healthy deployed acceptance remains open.

## Locked decisions

| ADR | Decision |
| --- | --- |
| [ADR-001](decisions/ADR-001-rust.md) | One Rust binary; Linux/macOS target |
| [ADR-002](decisions/ADR-002-interception.md) | Approved offline cache for locked npm ci; proxy for wider resolution remains planned |
| [ADR-003](decisions/ADR-003-intel-sources.md) | Zoli signed feed is the only external v1 intelligence source |
| [ADR-004](decisions/ADR-004-feed-client-faithfulness.md) | Go-compatible wire/hash/query semantics with generated oracle fixtures |
| [ADR-005](decisions/ADR-005-trust-bootstrap.md) | Pinned key, independent rollback state; proxy CA later |
| [ADR-006](decisions/ADR-006-local-package-analysis.md) | npm artifact inspection, separate local evidence, explicit coverage and conservative aggregate policy |
| [ADR-007](decisions/ADR-007-terminal-interface.md) | Ratatui for the planned interactive TUI; shared assessment/policy models and preserved CLI/JSON/npm behavior |

Malicious matches block even when uncertain. Suspicion warns interactively and blocks in CI. Publication and every source must be within one hour; errors/missing freshness evidence block immediately. Unsupported executable/opaque content refuses completion. Private HTTPS registries use explicitly approved origins, scoped trusted npmrc credentials and per-origin private-network permission. Package code never executes during assessment; approved npm ci lifecycle scripts execute normally.

The user authorized beginning [Phase 3](phase3-python.md) on 30 October after the local foundation pass. The [foundation acceptance matrix](foundations.md) retains unresolved release/operational gates. A 30 October real npm negative control confirms that warm-cache lifecycle execution bypasses a dead proxy. The locked npm guard now addresses it with a private approved cache.

## Phases and exit gates

| Phase | Deliverable | Exit gate | Current state |
| --- | --- | --- | --- |
| 0 — Baseline | Workspace, ADRs, pinned toolchain, CI, docs | Dated baseline; build and CI green | Complete since 16 October; local revalidation passed before Phase 1; original [hosted run](https://github.com/vyusec/zoli/actions/runs/38869463032) |
| 1 — Decision core and package assessment | Verified feed, npm inventory/acquisition, local inspection, policy, audit and CLI | Local conformance, trust/recovery, inventory, artifact and aggregate gates; shared deployed feed comparison | Implementation/local checks complete. Live gate explicitly deferred; no new hosted run claimed |
| 2 — npm guard | `serve`, wrapping/shims, quarantine until decision, minimum age, block UX, doctor | Real npm direct/transitive, lockfile and warm-cache Docker tests; unapproved bytes never released; normal output preserved | Locked npm ci implemented and locally tested; broader entry points, shims/doctor and deployment gates remain |
| 3 — Python guard | pip/uv/poetry/pipx adapters and PEP 440 parity | Real pip and relisted-package gate | Started: concrete PyPI comparison, exact/event feed checks and pip hash-pinned input reader; Python installation remains gated |
| 4 — Install/CI | Checksum-pinned installer, CI PATH shims, release matrix and uninstall | Static Linux musl, x86_64/arm64 macOS releases and recipe gates | Not started |
| 5 — Hardening | Rotation/recovery and extended resource/freshness abuse checks | Trust regression suite and failure-path evidence | Not started; Phase 1 already enforces initial freshness, storage and resource bounds |

On-demand assessment does not establish installation protection. Phases 2–5 keep their own acceptance gates.

## Phase 1 work order

| Milestone | Dependency and implementation | Acceptance evidence | State |
| --- | --- | --- | --- |
| 1A — Reference and encoding | Execute actual Go functions in an inventoried temporary module; implement full fixed-wire types, times, omission/null/empty, two JSON modes and ordered hashes | Six reproducible families; Rust byte comparisons; malformed inputs fail closed | Complete locally |
| 1B — Trust and storage | After encoding, authenticate raw manifest, compressed artifact, decoded rows and final records; apply Go delta/fallback rules; independent high-water sequence/digest, locks and atomic durable replacements | Signature/artifact/delta negatives; corrupt/missing cache, interrupted state/cache, rollback/equivocation, failed update and concurrent writer tests; Go↔Rust cache loading | Complete locally; simulated interruption is not a physical power-loss test |
| 1C — npm matching | Port reference normalization, npm comparison/constraints and affected/query ordering, selectors, uncertainty, withdrawals, coverage and freshness | 15 identities, 36 exact query responses, 2,072 constraint cases, 1,369 comparisons; all npm semantics custom-ported | Complete for declared npm scope; other ecosystem matching deferred |
| 1D — CLI, policy and audit | Config, `update/status/check`, schema-1 reports, final-clock freshness, suspicious/CI table and durable audit | Exit-code/process tests, one-hour boundary, degraded/missing evidence, immutable verdict, trust/audit failures and concurrent audit tests | Complete locally |
| 1E — npm graph | Read existing lock v2/v3 and sibling manifest; honor shrinkwrap; preserve installed paths, alias targets, multiple versions, dependency kinds and origins | Synthetic nested/scoped/aliased/private graph, missing optional/workspace/source gaps and shrinkwrap tests | Complete for supported lockfiles; no independent resolver |
| 1F — Acquisition and inspection | Approved HTTPS registry downloads with scoped auth and strongest SRI; bounded tar/tgz and JS/TS AST in the same binary's isolated worker | Real controlled HTTPS redirects/TLS/auth/integrity tests; located rules, benign examples, no hook execution, path/link/format/parse/resource rejection | Complete locally; production registry and detection accuracy not claimed |
| 1G — Aggregate scan | Combine unchanged feed verdicts, local findings, graph and source completeness; account for bundled identities; audited human/JSON report with provenance and timings | Full private-registry scan, benign/suspicious/CI/malicious uncertainty, bundled coverage, missing integrity and failure priority tests | Complete locally |
| 1H — Live agreement and measurements | Compare Rust/Go on one deployed publication; record first/repeated fixture timings before optimization | Four-package cold/repeated measurement recorded; 24 downloads across six runs, no result reuse | Timing complete; public HTTPS live comparison deferred by user |

The generator overlays development-only Go code and an in-memory transport seam in a temporary source copy. It never changes the upstream handoff or production Go verification. Source commits remain null when Git metadata is absent; exact inventoried hashes identify the executed reference.

### Phase 1 completion criteria

- ADR-004 gates 1–3 pass locally against the generated corpus, including actual Go loading of Rust caches.
- Gate 4 has limited public HTTPS/cache/lookup evidence against a degraded feed. Healthy source completion, broader hosted agreement and live correction/withdrawal replay remain required; offline/loopback evidence does not replace them.
- Updates verify before advancing trust. Missing/corrupt state is never silently reset, and modeled restart/concurrent-write failures cannot lower the high-water sequence.
- Every lockfile dependency and bundled identity has evidence or a visible gap. Missing optional artifacts remain incomplete.
- Local rules emit reproducible artifact/file/line evidence without package execution. Unsupported work refuses completion.
- Policy preserves feed verdicts, applies the chosen freshness/suspicion defaults, and refuses unaudited success.
- Required local quality gates pass; new hosted platform and release evidence are not inferred.
- First/repeated stage timings are recorded without a latency target.

### Next work

1. Repeat the shared-feed comparison after homelab source health is repaired, including broader queries and correction/withdrawal replay.
2. Observe hosted CI for these changes before relying on new macOS behavior.
3. Complete remaining Phase 2 entry-point and operational gates using the locked npm guard as the tested foundation.
4. Continue [Phase 3](phase3-python.md) with constraint parity, wheel inspection and a guarded pip path; keep heavy local work capped at half of one CPU core.
5. Profile representative real projects before indexes, bounded concurrency, incremental scans or result caching. A future faster mode must disclose omissions and retain trust, integrity and policy checks.

## Open questions

| ID | Resolution or remaining question | Phase |
| --- | --- | --- |
| OQ-1 | Resolved: uncertain malicious blocks; suspicious warns interactively, blocks CI | Implemented |
| OQ-2 | Resolved: user selected 24 hours; missing timestamps block | 2 |
| OQ-3 | Resolved: degraded sources block immediately; no permissive banner grace period | Implemented |
| OQ-4 | Resolved: one-hour hard bound on publication and every source, including local final-clock check | Implemented |
| OQ-5 | Per-wrap versus long-lived proxy lifecycle; measure startup cost | 2 |
| OQ-6 | Retarget removed `dist-tags.latest` to highest remaining stable version with notice | 2 |
| OQ-7 | Resolved: three versioned local flow rules, informational hooks/eval, bounded archive/worker/AST defaults; see configuration | Implemented |
| OQ-8 | Resolved for locked npm ci: complete preflight, byte-verified quarantine and private offline cache; broader entry points still need gates | Before Phase 2 completion |
| OQ-9 | Resolved: SHA-256/384/512, strongest wins; SHA-1-only/missing/unsupported work incomplete | Implemented |

## Plan corrections found in Phase 0

These were originally source-reading observations. Phase 1 generated fixtures now exercise both JSON modes, file-order snapshot hashes, delta sorting and the documented safePath/equivocation differences.

- **PC-1:** hash mode preserves `<`, `>` and `&`; marshal mode escapes them.
- **PC-2:** full snapshots hash file order; deltas sort by ID.
- **PC-3:** the live Go client requires public HTTPS port 443, so loopback tests are fixture evidence only.
- **PC-4:** policy covers uncertain matches, degraded sources and the hard one-hour bound explicitly.
- **U-1:** Go delta sorting is byte-wise while publisher SQL ordering depends on collation; generated IDs currently avoid divergence.
- **U-2:** Go safePath admits `.` and `..`; Rust matches that predicate, with byte integrity still mandatory.
- **U-3 resolved 30 October:** both clients reject different raw manifests at the same sequence. Identical signed publications still reuse the verified cache.
