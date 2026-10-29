# Progress

Updated: 30 October 2026 (Asia/Kolkata). **Phase 0 is complete. Phase 1 implementation and local validation are complete; healthy live-feed acceptance remains pending.** Phase 2 now includes a guarded locked npm installation path with a 24-hour minimum age.

The [live tunnel check](validation.md#live-tunnel-connection--29-october-2026) authenticated publication 347 with 17,459 records using the existing pinned key. Rust and Go cache objects agreed, and one Go/local/hosted lookup agreed. GitHub/OSV ingestion errors still make the feed degraded, so Rust correctly blocks package checks. The user will apply server repairs manually.

The [29 October dense revalidation](validation.md#dense-local-revalidation--29-october-2026) passes the full local CI gate with 61 tests, plus the separately run timing test and 40 concurrency stress executions. Seven new boundary tests cover malformed archives, exact resource ceilings, invalid configuration, CI policy and avoiding registry downloads when intelligence is stale. Two TLS dependencies were patched for new RustSec advisories. The Go reference provenance was refreshed against the current handoff; all fixture bytes remain unchanged and all 16 Rust caches authenticate in Go.

Implemented means code exists. Validated means the linked evidence was actually run. Historical hosted CI proves the Phase 0 baseline only.

| Capability | Implementation and local evidence | Remaining gate |
| --- | --- | --- |
| Workspace and quality gates | Seven crates, one binary, pinned Rust 1.98.0; `make ci` passes formatting, provenance, Clippy, dependency policy, build and tests | Observe hosted Linux/macOS CI for these changes; release/static builds remain Phase 4 |
| Go compatibility | Fixed-wire serializers, timestamps, ordered hashes, identity normalization, custom npm semantics and unchanged query results | Finite synthetic corpus is not exhaustive semantic proof |
| Reference corpus | Seven generated families: 43 strings, 5 records, 15 identities, 51 queries, 42 signed feed/update cases, 2,072 npm constraint checks, 1,369 npm comparisons and 6,084 PyPI comparisons | Regenerate whenever the inventoried reference source changes |
| Feed trust and storage | Raw-byte Ed25519 verification, compressed size/hash verification, bounded gzip/rows, deltas/fallback; independent durable sequence/digest, atomic replacements and filesystem locks | Public HTTPS transport verified against a degraded feed; healthy-source acceptance remains open. Power-loss behavior is modeled by interrupted state/cache tests |
| Cross-language cache | Rust loads Go caches; real Go `client.Load` authenticated 16 caches written by Rust; regeneration reproduces exactly | No cache migration feature is promised |
| npm inventory | Lockfile v2/v3 and shrinkwrap precedence; installed paths, multiple versions, alias targets, scopes, dev/optional/peer flags and parent chains; unresolved entries remain gaps | Workspaces/local/Git sources and resolution without a lockfile remain unsupported |
| Registry acquisition | Scoped user npmrc Bearer/Basic auth, explicit registry/artifact origins, private-network opt-in, custom HTTPS ports and CA bundles, TLS verification, strongest SHA-256/384/512 SRI | Controlled HTTPS tests are synthetic; no production private registry was contacted |
| Local inspection | Same-binary worker, cleared environment, deadline/RSS monitoring; bounded tar/tgz without extraction; JS/TS/JSX/TSX AST and three versioned local flow rules | No runtime detonation, cross-file reachability proof or measured detection accuracy |
| Coverage and policy | Informational hooks/eval; suspicious warns interactively and blocks CI; all malicious matches block; one-hour publication/source bound; degraded/missing source evidence blocks | Unknown executable formats, opaque archives, unsupported syntax and missing artifacts refuse completion |
| CLI and audit | Working `update`, `status`, `check`, `inspect`, `scan`, human/JSON results, deterministic exit codes; locked durable JSONL audit before report release; runtime errors audited when possible | `wrap npm -- ci` is implemented; other wrappers, `serve`, `shims`, `doctor` still refuse |
| Aggregate assessment | Per-node feed/local decisions, root paths, artifact/rule provenance, bundled-package accounting, explicit gaps, stage timings; runtime error > policy block > incomplete | Guarded npm ci has separate quarantine/release and warm-cache tests |
| Timing baseline | First and five repeated four-package assessments against controlled HTTPS; every artifact reacquired and inspected | No latency target; no internet-latency or production-performance claim |

Validation commands, counts, environment and limits are in [validation](validation.md#phase-1-implementation--18-october-2026). The implementation order and acceptance criteria are in the [roadmap](roadmap.md#phase-1-work-order).

## Phase 3 kickoff — 30 October

The user resumed Phase 3 and requested low CPU usage. PyPI feed-only checks now support concrete version comparison, exact/OSV event matching, name/registry normalization and optional SHA-256 artifact selectors. The reference corpus adds 6,084 Go comparisons and 15 byte-exact PyPI queries. Unsupported constraint-string ranges and malformed event boundaries refuse the query. A bounded pip requirements reader preserves unsupported declarations as gaps without execution or resolution.

Python artifact inspection and install enforcement are still pending. See the [implementation plan](phase3-python.md) and [focused validation](validation.md#phase-3-kickoff--30-october-2026). Heavy local commands run sequentially with one compiler/test worker, low priority and a 50%-of-one-core cgroup quota.

## Foundation hardening — 30 October

The [foundation gate](foundations.md) records the earlier hold, subsequently lifted for development by the user on 30 October. Local hardening passes 74 Rust tests and the full quality gate. Go/Rust now share same-sequence equivocation rejection, missing-source handling and a five-minute future-clock tolerance. The 36-query corpus uses an explicit common clock and includes nanosecond boundary checks. Malformed dependency declarations refuse assessment; workspace declarations remain visible gaps even without link entries.

A real npm negative control installed a cached transitive package and executed its inert hook with the registry stopped and proxies unreachable. This disproves proxy-only fail-closed protection. The implemented `wrap npm -- ci` guard prevents that bypass through complete preflight and an invocation-private offline cache. Nine real npm tests cover direct/transitive installs, scopes/aliases/shrinkwrap/private authentication, publish age, mismatched artifact bytes, warm-cache malicious blocking, changed inputs/feed, audit failure and lifecycle output/status. The user selected a 24-hour default. See [current validation](validation.md#foundation-hardening--30-october-2026).

## Phase gates

| Phase | Status |
| --- | --- |
| 0 | Complete since 16 October; original [hosted CI](https://github.com/vyusec/zoli/actions/runs/38869463032), locally revalidated before Phase 1 |
| 1 | All local implementation milestones complete. ADR-004 gates 1–3 pass against the generated corpus. Gate 4 now has public HTTPS, full cache agreement and one live lookup comparison; healthy-source acceptance and a broader live query set remain pending |
| 2 | Locked npm ci guard implemented and validated locally. Broader manager/command support, shims, doctor and healthy deployed-feed acceptance remain open |
| 3 | Started at the user’s request: PyPI feed checks and pip input foundation implemented; constraint parity, wheel inspection and installer enforcement remain open |
| 4–5 | Release distribution and broader hardening remain planned |

The fixture source is the local intel-feed handoff without Git metadata. [PROVENANCE.json](../testdata/conformance/PROVENANCE.json) identifies the exact executed build inputs; no upstream commit is inferred. No external threat-intelligence service receives package queries.

## Deferred work

- Repair server ingestion and repeat live Rust/Go/hosted comparisons with healthy sources and a broader query set.
- Observe hosted CI on the implementation before relying on cross-platform behavior.
- Extend the locked npm guard only after each new command/source/manager has equivalent bypass tests; finish shims/diagnostics and hosted acceptance before claiming those capabilities ready.
- Profile representative real projects before implementing indexes, bounded concurrency or reusable analysis reports.
