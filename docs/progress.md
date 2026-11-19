# Progress

Updated: 20 November 2026 (Asia/Kolkata). **Phase 0 is complete. Phase 1 implementation and local validation are complete; healthy live-feed acceptance remains pending. Phase 2 (npm guard) is implemented and locally validated for `ci`, `install`, `npx`, shims and `doctor`.** Phase 3 remains at its first matching/input milestone.

## Phase 2 completion — 20 November 2026

Supported npm entry points now share one approval model. Locked `npm ci` retains its ten real-npm regressions. Ad-hoc `npm install` resolves metadata only in a temporary project, assesses the exact resolved tree, writes approved inputs, and installs offline from the private cache; `npm install pkg@version`, ranges/tags and `--save-dev`/`--save-exact` are covered. `npx` resolves, assesses, installs offline and executes only the selected package's declared executable. Bundled dependencies inherit the containing archive's publication time and integrity. Interactive bash/zsh/fish shims, CI PATH shims and `doctor` are implemented; `serve` and non-npm managers still refuse.

Local evidence: `make ci` passes; **172 tests pass, 0 fail, 1 manual timing test ignored**; `make npm-guard-container` passes **19 tests** (10 locked/ad-hoc guard, 9 ad-hoc/npx) as uid 65534 with no external network or host mounts. No healthy live feed was available (the configured tunnel did not resolve), so deployed-feed acceptance and hosted CI remain open. Details are in [validation](validation.md#phase-2-completion--20-november-2026).

## Earlier status — 30 October 2026

The [live tunnel check](validation.md#live-tunnel-connection--29-october-2026) authenticated publication 347 with 17,459 records using the existing pinned key. Rust and Go cache objects agreed, and one Go/local/hosted lookup agreed. GitHub/OSV ingestion errors still make the feed degraded, so Rust correctly blocks package checks. The user will apply server repairs manually.

The [29 October dense revalidation](validation.md#dense-local-revalidation--29-october-2026) passes the full local CI gate with 61 tests, plus the separately run timing test and 40 concurrency stress executions. Seven new boundary tests cover malformed archives, exact resource ceilings, invalid configuration, CI policy and avoiding registry downloads when intelligence is stale. Two TLS dependencies were patched for new RustSec advisories. The Go reference provenance was refreshed against the current handoff; all fixture bytes remain unchanged and all 16 Rust caches authenticate in Go.

Implemented means code exists. Validated means the linked evidence was actually run. Historical hosted CI proves the Phase 0 baseline only.

| Capability | Implementation and local evidence | Remaining gate |
| --- | --- | --- |
| Workspace and quality gates | Seven crates, one binary, pinned Rust 1.98.0; `make ci` passes formatting, provenance, Clippy, dependency policy, build and tests (**172 passed, 1 manual timing test ignored**) | Observe hosted Linux/macOS CI for these changes; release/static builds remain Phase 4 |
| Go compatibility | Fixed-wire serializers, timestamps, ordered hashes, identity normalization, custom npm semantics and unchanged query results | Finite synthetic corpus is not exhaustive semantic proof |
| Reference corpus | Nine generated families: 43 strings, 5 records, 15 identities, 66 queries, 47 signed feed/update cases, 2,072 npm constraint checks, 1,369 npm comparisons, 6,084 PyPI comparisons, 29,973 PyPI constraints and 100,000 seeded PyPI cases | Regenerate whenever the inventoried reference source changes; parity is not PEP 440 compliance |
| Feed trust and storage | Raw-byte Ed25519 verification, compressed size/hash verification, bounded gzip/rows, deltas/fallback; independent durable sequence/digest, atomic replacements and filesystem locks | Public HTTPS transport verified against a degraded feed; healthy-source acceptance remains open. Power-loss behavior is modeled by interrupted state/cache tests |
| Cross-language cache | Rust loads Go caches; real Go `client.Load` authenticated 21 caches written by Rust, including five new PyPI snapshots; regeneration reproduces exactly | No cache migration feature is promised |
| npm inventory | Lockfile v2/v3 and shrinkwrap precedence; installed paths, multiple versions, alias targets, scopes, dev/optional/peer flags and parent chains; unresolved entries remain gaps | Workspaces/local/Git sources and resolution without a lockfile remain unsupported |
| Registry acquisition | Scoped user npmrc Bearer/Basic auth, explicit registry/artifact origins, private-network opt-in, custom HTTPS ports and CA bundles, TLS verification, strongest SHA-256/384/512 SRI | Controlled HTTPS tests are synthetic; no production private registry was contacted |
| Local inspection | Same-binary worker, cleared environment, deadline/RSS monitoring; bounded tar/tgz without extraction; JS/TS/JSX/TSX AST and three versioned local flow rules | No runtime detonation, cross-file reachability proof or measured detection accuracy |
| Coverage and policy | Informational hooks/eval; suspicious warns interactively and blocks CI; all malicious matches block; one-hour publication/source bound; degraded/missing source evidence blocks | Unknown executable formats, opaque archives, unsupported syntax and missing artifacts refuse completion |
| CLI and audit | Working `update`, `status`, `check`, `inspect`, `scan`, `wrap npm -- ci|install`, `wrap npx`, `shims` and `doctor`, human/JSON results where applicable, deterministic exit codes; locked durable JSONL audit before report release | Other managers and `serve` still refuse; healthy deployed-feed operation remains open |
| Ad-hoc npm and npx | Metadata-only temporary resolution, registry-route validation, exact-tree assessment, approved-input write, private-cache offline install; npx executes only the declared executable; nine real-npm regressions including malicious/young/cache/option refusals | Representative real-project coverage and supported hosted CI |
| Shell integration and doctor | Idempotent bash/zsh/fish blocks with backups and marker safety, executable CI PATH shims, `$GITHUB_PATH` append, prerequisite diagnostics (feed, npm, permissions, audit, shims, project) | Representative version-manager/IDE setups and macOS observation |
| Aggregate assessment | Per-node feed/local decisions, root paths, artifact/rule provenance, bundled-package accounting and inherited container age evidence, explicit gaps, stage timings; runtime error > policy block > incomplete | Guarded npm ci has separate quarantine/release and warm-cache tests |
| Timing baseline | First and five repeated four-package assessments against controlled HTTPS; every artifact reacquired and inspected | No latency target; no internet-latency or production-performance claim |

Validation commands, counts, environment and limits are in [validation](validation.md#phase-1-implementation--18-october-2026). The implementation order and acceptance criteria are in the [roadmap](roadmap.md#phase-1-work-order).

## Expanded Python testing — 30 October

Added 51 Rust tests, four top-level Go model tests and 100,000 seeded Go/Rust comparisons/constraints. The full local `make ci` passes 145 tests, including all nine npm guard regressions, with one manual timing test intentionally ignored. Model/API/client Go regressions pass 23 top-level tests (47 including subtests). Matching endpoint storage, encoding-header refusal and Unicode whitespace handling were corrected. Independent PyPA checks explicitly document eight reference differences, including the repeated-exclusion defect. See the [test report](phase3-test-report.md) and [validation](validation.md#expanded-python-testing--30-october-2026). This strengthens the first Phase 3 milestone without claiming guarded Python installation.

## Phase 3 matching and input milestone — 30 October

The first of [five acceptance milestones](phase3-python.md#acceptance-milestones) supplies the requested 20% checkpoint: Go-compatible constraint matching and strict pinned-input completeness, with resource limits and process-level regression evidence. This checklist percentage is not an estimate of implementation effort or Python installation coverage. The initial eight-family corpus included 29,488 PyPI constraint cases and 66 total exact-response queries; expanded testing is recorded above. The [milestone validation](validation.md#phase-3-matching-and-input-milestone--30-october-2026) records that checkpoint's executed checks and reference quirks.

## Phase 3 kickoff — 30 October (historical)

The user resumed Phase 3 and requested low CPU usage. PyPI feed-only checks now support concrete version comparison, exact/OSV event matching, name/registry normalization and optional SHA-256 artifact selectors. The reference corpus adds 6,084 Go comparisons and 15 byte-exact PyPI queries. At kickoff, unsupported constraint-string ranges and malformed event boundaries refused the query; the later milestone above adds constraint support. A bounded pip requirements reader preserves unsupported declarations as gaps without execution or resolution.

Python artifact inspection and install enforcement are still pending. See the [implementation plan](phase3-python.md) and [focused validation](validation.md#phase-3-kickoff--30-october-2026). Heavy local commands run sequentially with one compiler/test worker, low priority and a 50%-of-one-core cgroup quota.

## Foundation hardening — 30 October

The [foundation gate](foundations.md) records the earlier hold, subsequently lifted for development by the user on 30 October. Local hardening passes 74 Rust tests and the full quality gate. Go/Rust now share same-sequence equivocation rejection, missing-source handling and a five-minute future-clock tolerance. The 36-query corpus uses an explicit common clock and includes nanosecond boundary checks. Malformed dependency declarations refuse assessment; workspace declarations remain visible gaps even without link entries.

A real npm negative control installed a cached transitive package and executed its inert hook with the registry stopped and proxies unreachable. This disproves proxy-only fail-closed protection. The implemented `wrap npm -- ci` guard prevents that bypass through complete preflight and an invocation-private offline cache. Nine real npm tests cover direct/transitive installs, scopes/aliases/shrinkwrap/private authentication, publish age, mismatched artifact bytes, warm-cache malicious blocking, changed inputs/feed, audit failure and lifecycle output/status. The user selected a 24-hour default. See [current validation](validation.md#foundation-hardening--30-october-2026).

## Phase gates

| Phase | Status |
| --- | --- |
| 0 | Complete since 16 October; original [hosted CI](https://github.com/vyusec/zoli/actions/runs/38869463032), locally revalidated before Phase 1 |
| 1 | All local implementation milestones complete. ADR-004 gates 1–3 pass against the generated corpus. Gate 4 now has public HTTPS, full cache agreement and one live lookup comparison; healthy-source acceptance and a broader live query set remain pending |
| 2 | **Complete locally for npm (20 November 2026):** locked `ci`, ad-hoc `install`, `npx`, bundled age evidence, shims and doctor pass local and Docker gates. `serve`, non-npm managers, healthy deployed-feed operation and hosted CI remain open |
| 3 | Matching/input milestone implemented and tested; see the 20% acceptance checklist. Wheel inspection, dependency selection, pip enforcement and other adapters remain open |
| 4–5 | Release distribution and broader hardening remain planned |

The fixture source is the local intel-feed handoff without Git metadata. [PROVENANCE.json](../testdata/conformance/PROVENANCE.json) identifies the exact executed build inputs; no upstream commit is inferred. No external threat-intelligence service receives package queries.

## Deferred work

- Repair server ingestion and repeat live Rust/Go/hosted comparisons with healthy sources and a broader query set.
- Observe hosted CI and a healthy deployed publication before claiming cross-platform or deployed acceptance.
- Add pnpm/yarn/bun and `serve` only after each has equivalent resolution, cache, route and bypass tests; keep unsupported entry points refusing until then.
- Profile representative real projects before implementing indexes, bounded concurrency or reusable analysis reports.
