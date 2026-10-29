# Validation evidence

Each entry records what was actually run, the results, and what the evidence does not show.

## Phase 3 kickoff — 30 October 2026

The user authorized starting Phase 3 and requested low CPU usage. This supersedes the earlier development hold, while healthy deployment and remaining Phase 2 acceptance gates stay open. The first slice adds PyPI feed-only checks, concrete version comparison and a strict nonexecuting pip requirements reader. Python installation is not enabled.

All compute-heavy commands ran sequentially through `systemd-run --user --scope --quiet -p CPUQuota=50% -p CPUWeight=10 nice -n 15`, with `CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=1` and `GOMAXPROCS=1`. The quota applies to the entire subprocess tree and limits it to half of one CPU core. Go generation also uses `-p=1`. No Docker, full workspace suite, database/race suite, live registry install or dependency upgrade was run in this kickoff.

| Check | Result |
| --- | --- |
| `cargo test -p zoli-intel --test conformance --locked` | 7 tests passed: **6,084 PyPI comparisons**, 51 exact-response queries (15 new PyPI cases), existing npm semantics, record/identity encoding and signed-cache checks |
| Final query recheck | `query_bytes_match_go` passed after adding refusal for unsupported event boundaries |
| `cargo test -p zoli-pms --lib --locked` | 6 tests passed, including 3 requirements-reader tests: normalized pins/multiple hashes, explicit unsupported input gaps, duplicate/continuation/budget rejection |
| CLI regression selection | Existing `--test assessment --test cli`: 8 assessment and 5 CLI tests passed |
| `cargo test -p zoli-cli --test pypi --locked` | 3 tests passed: normalization/event boundaries/withdrawal, hash-scoped versus package-wide findings, unsupported work/stale evidence refusal |
| `cargo test -p zoli-policy --test assessment --locked` | 5 tests passed, including explicit PyPI coverage, missing mode/source rejection and existing freshness/suspicion rules |
| Targeted Clippy | `cargo clippy -p zoli-intel -p zoli-pms -p zoli-policy -p zoli-cli --all-targets --locked -- -D warnings` passed; final requirements-only change rechecked with `-p zoli-pms` |
| Oracle reproduction | `python3 tools/generate-conformance.py --intel-feed ../intel-feed --check` reproduces all **7 families** and provenance exactly; `--verify` passes |
| Hygiene | rustfmt, `git diff --check`, Python wrapper syntax and local documentation links checked |

There are **34 distinct passing focused tests**, with no skips in those selected targets. This is not a new full-workspace or hosted CI result. Initial PyPI CLI tests exposed the npm-only coverage check in policy; the supported ecosystem set now includes PyPI, and tests still require valid coverage mode and fresh sources. Synthetic signed test publications explicitly declare both ecosystems.

The comparator follows the pinned Go implementation, including epoch bounds and local-label ordering. Arbitrary PyPI constraint strings and malformed event boundaries refuse the query instead of emitting a different verdict. A different SHA-256 can exclude only an artifact-scoped claim; it cannot erase a package/version-wide finding. Passing feed-only checks never authorize installation. The pip reader is an adapter library component; it neither resolves transitives nor inspects/installs wheels.

Environment remains Linux x86_64, Rust/Cargo 1.98.0 and Go 1.26.10-X:nodwarf5. No Python runtime is required for the new Rust comparison/reader. Logs are under `/tmp/zoli-phase3-20261030`: `conformance.log`, `focused.log`, `pypi-final.log`, `requirements-final.log` and `reproduce.log`. See [Phase 3 work and gates](phase3-python.md). Remaining work includes constraint parity, wheel acquisition/inspection/dependency completeness, real pip cache/relisting enforcement and the other Python adapters.

## Foundation hardening — 30 October 2026

This pass hardens Phase 1/2 in both local workspaces and implements the user-requested npm guard with a **24-hour minimum publish age**. Phase 3 remains on hold. No production service, signing key or live database was changed; these are local working-tree results, not a hosted CI or homelab deployment claim.

Environment: Linux x86_64, Rust/Cargo 1.98.0, Go 1.26.10-X:nodwarf5, Node v22.23.1, npm 10.9.8, PostgreSQL 18.6, Docker 29.9.1. Existing uncommitted work is retained.

| Check | Executed result |
| --- | --- |
| `CARGO_BUILD_JOBS=2 make ci cache-conformance` | Passed formatting, generated provenance, Clippy `-D warnings`, cargo-deny, build, **74 tests**, and exact fixture reproduction; one manual timing test intentionally ignored |
| Cross-language oracle | 36 fixed-clock query cases including exact one-hour/five-minute and nanosecond boundaries; missing sources degrade; both clients reject same-sequence equivocation; Go authenticates all 16 Rust-written caches |
| Inventory refusal | Invalid declaration maps/specs reject; workspace declarations remain explicit gaps even without link entries |
| `make npm-cache-probe` | Negative control: unguarded offline npm executes a cached transitive hook with its registry stopped and proxy addresses unreachable; [saved result](../testdata/benchmarks/phase2-warm-cache-linux.json) |
| Real npm guard suite | **9 passed**: direct/transitive approval, cold/private-cache installation, populated user-cache malicious block, scoped alias/shrinkwrap/private auth, young version refusal, metadata/archive digest mismatch, changed project/feed, audit/config failures, preserved stdout/stderr/exit status and ignore-scripts |
| Age boundary unit check | Exactly 24 hours passes the age gate; one nanosecond younger, future and missing timestamps block |
| `CARGO_BUILD_JOBS=2 make npm-guard-container` | The same **9 tests passed** as uid 65534, no external network or host mounts, read-only root, dropped capabilities, no-new-privileges, bounded memory/pids and a private writable tmpfs |
| Sibling intel-feed | **60 top-level race tests (84 with subtests), no failures/skips**, including all **9 PostgreSQL integration tests**; formatting, vet, build and synthetic evaluation pass; disposable database helper also passes |

The container gate packages this host's compiled test/Zoli, Node/npm and required runtime libraries into a temporary scratch image, then removes the image. It tests isolated runtime behavior, not portable release packaging or macOS. An initial harness omitted the distribution-specific Node interpreter path; the corrected harness includes it. No guard failure was relaxed to make the gate pass.

Supported installation is explicit `zoli wrap npm -- ci` with npm 10 and supported v2/v3 locks. Only approved quarantine bytes enter an invocation-private offline cache. Publication metadata supplies both exact-version age and a strong archive digest; the archive must match it and the lockfile. Final release reloads verified feed state and checks unchanged project/config inputs before audit and npm execution. Project files are preserved. Unsupported commands/options/sources and incomplete evidence refuse installation.

The local project and approved scripts execute with normal user permissions after approval; runtime networking, nested installers and hostile local writes are outside this initial-install guarantee. Workspaces/bundled-age support, ad-hoc installs/npx, other managers, shims and doctor remain open Phase 2 work. Healthy live ingestion, broad deployed Rust/Go/hosted agreement, observed hosted CI and representative package coverage also remain gates. Static fixture success is not malware-detection accuracy evidence.

Working logs: `/tmp/zoli-foundations-20261030/zoli-final-ci.log`, `npm-guard-3.log`, `guard-container.log`, `go-final.json`, `feed-final-quality.log`, and `ephemeral-db.log`. This section and the [acceptance matrix](foundations.md) are the durable summary; temporary logs are not required to reproduce the gates. CI now provisions Node 22/npm 10.9.8 and runs the Linux container gate; no hosted run was triggered or observed.

## Live tunnel connection — 29 October 2026

The user supplied a replacement public HTTPS tunnel and authorized connecting the local client. The manifest authenticated with the already pinned Ed25519 key. Updated only the feed URL in the existing client configuration, retaining the key, independent rollback state and cache; saved the previous configuration beside it. No server changes were performed: the user requested manual homelab instructions.

- Normal Rust `zoli --json update` succeeded through the public HTTPS transport: **publication 347, 17,459 records**, manifest generated at `2026-10-29T17:58:22.286561153Z`. The first update replayed several hundred deltas from local sequence 2.
- The Go `examples/client-check` used the same pinned URL/key and queried `npm/left-pad@1.3.0`. It independently downloaded and verified publication 347, matched the hosted lookup, and authenticated its saved/reloaded cache.
- Complete parsed Go and Rust cache JSON objects were equal, including all records and the signed envelope.
- Rust's local check returned the same degraded/insufficient-information verdict and correctly blocked with exit 10. The signed source state reported GitHub HTTP 403 and an OSV failure on `MAL-2022-2.json`; neither source had successful freshness evidence. npm coverage was `reports_only`.
- Installed the supplied user service/timer for five-minute verified updates, using the existing client home. Exposed that home through `~/.zoli` and the current development binary through `~/.local/bin/zoli`.

This establishes real HTTPS transport, authenticated cache agreement and one live lookup comparison. It does **not** establish healthy ingestion, complete backfill, selective analysis readiness, a broad live query matrix, installation enforcement or production readiness. The original deferred live gate is now partially exercised; healthy-source acceptance remains open. Quick Tunnel hostnames are temporary and must be updated if the server's tunnel address changes.

## Dense local revalidation — 29 October 2026

Tested the existing uncommitted Phase 1 working tree on Linux GNU, with Rust/Cargo 1.98.0, Python 3.14.8 and Go `go1.26.10-X:nodwarf5 linux/amd64`. Builds used `CARGO_BUILD_JOBS=2`; Go oracle runs used `GOMAXPROCS=2` to limit pressure on the laptop. No changes were committed or pushed.

### Failures found and repaired

- The initial `make ci` passed formatting, fixture integrity and Clippy, then failed dependency policy on [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382) and [RUSTSEC-2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381). Updated only `rustls-webpki` 0.103.15 → 0.103.16 and `webpki-roots` 1.0.9 → 1.0.10 in the pre-existing lockfile. No advisory suppression or policy relaxation was added.
- The first `make cache-conformance` authenticated all 16 Rust caches and reproduced every fixture, but rejected stale `PROVENANCE.json`: the reference source and Go version had changed since 18 October. Regenerated through `tools/generate-conformance.py`, then reproduced successfully with `--check`. All six fixture-family hashes remain unchanged; only provenance changed.

Final `Cargo.lock` SHA-256: `32bff2a9f41cae2f4b6b0d09293e72a8ff1097638af788f75bf0c518f4b4613a`. Reference source inventory SHA-256: `1074e0c9d1cf8c8c7371d124afaf378ede45ee3753d12545073579c33286eefd`. The intel-feed source still has no Git metadata; no remote commit equivalence is inferred.

### Results

| Check | Command / procedure | Result |
| --- | --- | --- |
| Original behavior baseline | `cargo test --workspace --locked` before dependency changes | 54 passed, 0 failed, 1 timing test ignored |
| Final required gates | `CARGO_BUILD_JOBS=2 make ci` | Passed: formatting, provenance, Clippy with warnings denied, dependency policy, build, tests |
| Expanded workspace suite | Test stage of final `make ci` | **61 passed, 0 failed, 1 intentionally ignored timing test**, run separately below |
| Dependency policy | `cargo deny --locked check` within `make ci` | `advisories ok, bans ok, licenses ok, sources ok`; existing permitted duplicate-version warnings remain |
| Go compatibility | `CARGO_BUILD_JOBS=2 GOMAXPROCS=2 make cache-conformance INTEL_FEED=../intel-feed` after regeneration | All fixture/provenance bytes reproduce; Go authenticates **16 Rust-written caches** |
| Concurrency stress | 20 runs each of `concurrent_updates_and_readers_agree_on_one_verified_cache` and `concurrent_processes_append_complete_audit_records`, selected with `--exact` | **40 successful test executions**: 480 concurrent cache update/read pairs and 160 audited child-process reports; no failures |
| Timing test | `cargo test -p zoli-cli --locked --offline --test baseline -- --ignored --nocapture` | 1 passed; all six four-package assessments complete; 24 artifact requests |

Seven new test functions exercise additional boundaries:

- Every strict byte prefix of a valid gzip package is rejected as incomplete, as is corruption of each of the eight footer bytes.
- A concatenated gzip member cannot hide a second package root.
- Duplicate manifest identity fields and non-UTF-8 JavaScript refuse completion.
- Exact compressed/expanded/source-byte and entry-count limits pass; lowering each by one refuses completion.
- Stale or failed source intelligence blocks a full scan **before any request reaches the controlled registry**.
- Fifteen invalid configuration variants produce error reports, including unsupported versions, invalid public keys, disallowed URL forms, unsupported policy values and zero budgets.
- Seven `CI` environment values verify interactive versus CI behavior; an explicit `--suspicious=warn` never weakens CI blocking.

The saved [timing measurement](../testdata/benchmarks/2026-10-29-linux-debug.json) records 260 ms for the first assessment and 262, 267, 266, 267, 267 ms for repeated assessments. First-run stages: feed verification 17 ms, inventory 1 ms, acquisition 25 ms, inspection 204 ms, query/policy 2 ms, reported total 255 ms. These are synthetic debug-profile loopback measurements with OS caches intact, not a production latency or detection-quality result.

To reproduce the extra timing measurement from the repository root, use an absolute output path (Cargo runs this integration test from its crate directory):

```sh
CARGO_BUILD_JOBS=2 make ci
CARGO_BUILD_JOBS=2 GOMAXPROCS=2 make cache-conformance INTEL_FEED=../intel-feed
ZOLI_BASELINE_OUT="$PWD/testdata/benchmarks/local-linux-debug.json" \
  cargo test -p zoli-cli --locked --offline --test baseline -- --ignored --nocapture
```

The additional concurrency stress can be repeated in Bash:

```sh
set -e
for ((round=1; round<=20; round++)); do
  cargo test -p zoli-intel --locked --offline --test storage \
    concurrent_updates_and_readers_agree_on_one_verified_cache -- --exact
  cargo test -p zoli-cli --locked --offline --test assessment \
    concurrent_processes_append_complete_audit_records -- --exact
done
```

This is repeated behavioral stress, not a race-detector or exhaustive interleaving proof.

### Limits

This does not validate a deployed homelab feed, live Rust/Go agreement, production registry behavior, macOS, release/static builds, installation interception, exhaustive fuzzing or malware detection accuracy. No untrusted package code ran. The separate Intel Feed homelab runbook's Compose files were validated with placeholder credentials; its PostgreSQL acceptance and live ingestion still need to run on the server.

## Phase 0 — 16 October 2026

### Environment

| Item | Value |
| --- | --- |
| OS | Fedora 44, Linux 7.2.7-200.fc44.x86_64 |
| Rust | rustc 1.98.0 (88d9e12ae 2026-08-18), cargo 1.98.0 (797e8a9bc 2026-08-05), selected through `rust-toolchain.toml` |
| rustup | 1.29.1 |
| cargo-deny | 0.20.2, installed with `cargo install --locked cargo-deny@0.20.2` |
| `Cargo.lock` | SHA-256 `cc77f412858ba10e89c87f552f9acd519b74885c50ae04fb4de192b194faaa8e` |
| Git | Local runs used the uncommitted tree that was later committed as `3bbfe88` and pushed to `vyusec/zoli` |

### Results

| Check | Command | Result |
| --- | --- | --- |
| Full local CI from a clean target directory | `cargo clean && make ci` | Passed (exit 0) |
| Formatting | `cargo fmt --all --check` | Passed |
| Lints | `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed, no warnings |
| Supply chain | `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok` |
| License policy is enforced | Allowlist narrowed to `Apache-2.0` only, then restored | Failed as expected (`error[rejected]: failed to satisfy license requirements`); passed again after restore |
| Build | `cargo build --workspace --locked` | Passed |
| Tests | `cargo test --workspace --locked` | 11 passed, 0 failed, 0 ignored: 5 CLI integration, 3 `zoli-intel`, 3 `zoli-pms` |
| Fail-closed stubs | `zoli check --eco npm --name left-pad --ver 1.3.0`, `zoli serve` | Exit 3, nothing on stdout, explanatory stderr |
| Wrap never runs the package manager | Integration test with a fake `npm` first on `PATH` | The marker file was never created |
| Documentation links | Relative links and anchors in every Markdown file | All resolve (checked with a local script) |

### What this does not show

- **Hosted CI.** Not shown by these local runs. It is recorded separately [below](#hosted-ci--16-october-2026).
- **Release builds.** Release, musl static and macOS builds were not attempted; they belong to Phase 4.
- **Go-side claims.** Statements in ADR-004 and in the roadmap's plan corrections about Go behaviour come from reading the intel-feed source at the 16 October baseline. For the files cited, that source is blob-identical to `vyusec/intel-feed@7919b85`. No Go code was executed in this pass. The Phase 1 fixtures turn those readings into evidence.
- **Behaviour.** No feed, proxy, shim or policy behaviour exists yet, so none was validated.

### Reproduce

```sh
rustup toolchain install          # reads rust-toolchain.toml
cargo install --locked cargo-deny@0.20.2
cargo clean
make ci
```

## Hosted CI — 16 October 2026

GitHub Actions run [38869463032](https://github.com/vyusec/zoli/actions/runs/38869463032), triggered by the push of commit `3bbfe88` to `vyusec/zoli` `main`. Conclusion: **success**.

| Job | Runner image | Result | Evidence from the log |
| --- | --- | --- | --- |
| rustfmt + clippy | ubuntu-24.04 (20261012.334.1) | Success | Toolchain `1.98.0-x86_64-unknown-linux-gnu` installed from `rust-toolchain.toml`; `make fmt-check clippy` passed |
| cargo-deny | ubuntu-24.04 (20261012.334.1) | Success | `cargo-deny@0.20.2` built with `--locked`; `advisories ok, bans ok, licenses ok, sources ok` |
| test (ubuntu-latest) | ubuntu-24.04 (20261012.334.1) | Success | 11 passed, 0 failed |
| test (macos-latest) | macos-26-arm64 (20261012.601) | Success | Toolchain `1.98.0-aarch64-apple-darwin`; 11 passed, 0 failed, including the Unix-only fake-`npm` test |

### What this does not show

- **x86_64 macOS.** Not covered; it joins the Phase 4 matrix.
- **Runner drift.** GitHub warned that `ubuntu-latest` moves to Ubuntu 26 from 19 October 2026, so later runs may use a different image than this evidence.
- **Release and static builds.** Not attempted (Phase 4).

## Phase 0 revalidation — 17 October 2026

On the clean working tree at `7d3b37e20b73b8551b17afb0276af78e94251e80`, before Phase 1 changes, `make ci` passed: formatting, Clippy with `-D warnings`, cargo-deny, build and all 11 tests. No remaining Phase 0 gate was found. The hosted evidence above remains the 16 October run; no new hosted run was requested or observed.

The local environment is Linux `7.2.11-200.fc44.x86_64`, Rust/Cargo `1.98.0`, and cargo-deny `0.20.2`. The baseline `Cargo.lock` SHA-256 remains `cc77f412858ba10e89c87f552f9acd519b74885c50ae04fb4de192b194faaa8e`. Cargo required advisory-database cache access outside the workspace for its lock file.

## Phase 1 kickoff — 17 October 2026

These results cover the Phase 1 working tree based on `7d3b37e`, including the new generator, committed fixtures and Rust string writer. They are local results; the changes have not been pushed and have no new hosted CI evidence.

### Environment and reference source

- Rust/Cargo `1.98.0`; cargo-deny `0.20.2`; Python `3.14.8`.
- Go `go1.26.9-X:nodwarf5 linux/amd64`, used only for reference fixture generation.
- Source: the local `/home/vegeta/Documents/intel-feed` module. It has no `.git` metadata, so the fixture provenance records a null commit. The [provenance inventory](../testdata/conformance/PROVENANCE.json) hashes the generator, wrapper, copied build inputs and all output files. No equality with a specific GitHub commit is asserted for these fixtures.
- Generation copies the build inputs to a temporary module, overlays `cmd/conformance-gen` there, and does not edit the original source. Go module downloads are disabled; the existing module cache was used. The compiler required access to its ccache outside the workspace.

### Results

| Check | Command or procedure | Result |
| --- | --- | --- |
| Generate reference fixtures | `python3 tools/generate-conformance.py --intel-feed /home/vegeta/Documents/intel-feed` | Passed: 43 string cases, 5 validated/normalized record encodings, 12 normalization cases, 27 query cases |
| Reproduce the reference corpus | Same command with `--check` | Passed: every fixture and provenance file reproduced exactly, holding only the generation timestamp fixed |
| CI fixture integrity | `make conformance-check` (also part of `make ci`) | Passed: fixture, generator/wrapper and inventoried tree hashes consistent; requires neither Go nor upstream source |
| Negative integrity check | Copied the corpus to a temporary directory, appended one byte to `queries.json`, invoked the verifier | Rejected the changed fixture as expected; original files were untouched |
| Full workspace quality gates | `make ci` | Passed: formatting, fixture checks, Clippy `-D warnings`, cargo-deny, build and tests |
| Tests | `cargo test --workspace --locked`, as part of `make ci` | 13 passed, 0 failed: original 11 plus 2 new string-writer integration tests |
| Go string conformance | `strings_match_go_in_both_modes` | All 43 strings matched Go bytes in both hash-row and marshal modes (86 comparisons) |
| Writer composition | `string_writer_appends_without_adding_row_delimiters` | Passed: the primitive appends to existing JSON without adding a row newline |
| Operational refusal | Existing CLI integration tests in the workspace run | Passed: no operational command checks/allows/runs an install; fake `npm` is never executed |
| Tooling and documentation | Python AST parse, relative documentation path checks, `git diff --check` | Passed |

The string corpus demonstrates that marshal mode escapes `<`, `>` and `&`, while hash mode preserves them. ADR-004's incomplete HTML table entry was corrected accordingly.

### What this does not show

- **Full Go parity.** Rust has no complete record/time serializer, normalization, version matching, envelope verification, artifact/delta processing or cache implementation yet. The record, identity and query corpora were generated from Go, but are not yet compared with Rust implementations.
- **Complete fixture coverage.** Envelope, artifact, delta, cache and live-delivery families are pending, along with a larger query/selector matrix. Future-dated query inputs avoid the moving one-hour freshness boundary and do not prove exact boundary behavior.
- **Package inspection or enforcement.** No dependency inventory, local scanner, aggregate policy, proxy or shim behavior is implemented. `scan` and `inspect` are planned command names, not working commands.
- **Live feed delivery and hosted CI.** Neither was run in this pass. A public HTTPS staging feed and trusted public key remain prerequisites for the live acceptance gate.
- **Detection quality or performance.** Synthetic reference cases are not malware-detection accuracy evidence. The local scanner and its cold/repeated timing baseline have not been built.

## Phase 1 implementation — 18 October 2026

This entry supersedes the implementation limits in the historical kickoff above. It covers the uncommitted Phase 1 implementation on the existing workspace. The user explicitly deferred the live feed comparison; it was not attempted and no transport restriction was weakened. No changes were pushed and no new hosted run is claimed.

### Environment and provenance

- Linux `7.2.11-200.fc44.x86_64`; Rust `1.98.0 (88d9e12ae 2026-08-18)`; Cargo `1.98.0 (797e8a9bc 2026-08-05)`; cargo-deny `0.20.2`; Python `3.14.8`.
- Go `go1.26.9-X:nodwarf5 linux/amd64`, development-only oracle.
- `Cargo.lock` SHA-256: `013e45f3b02dad8ff86ed70c7f3cbefe6fb19c688cf818a649ff785955edc60e`.
- Executed local intel-feed build-input inventory SHA-256: `0024352b0d32064c3d13de946464e497a968f72f062507447a29909fb6906926`. The handoff has no Git metadata; [PROVENANCE.json](../testdata/conformance/PROVENANCE.json) records its commit as null. Generation disables Go module downloads and edits only the temporary copy.
- Ring/Go compiler caches and cargo-deny's advisory database required approved access outside the workspace. Controlled registry tests used only loopback HTTPS with explicit private-network and CA configuration.

### Executed results

| Check | Command or evidence | Result |
| --- | --- | --- |
| All required local gates | `make ci` | Exit 0: rustfmt, fixture provenance, Clippy `-D warnings`, cargo-deny, build and tests |
| Test suite | `cargo test --workspace --locked` inside `make ci` | **54 passed, 0 failed, 1 intentionally ignored timing test**; the timing test was run separately |
| Dependency policy | `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok`; duplicate-version warnings remain allowed by existing policy |
| Licenses | `deny.toml` and `NOTICE` | Explicit Phase 1 allowances: BSD-3-Clause for dalek/subtle, BSL-1.0 for dragonbox, ISC for TLS dependencies, CDLA-Permissive-2.0 for root data; no advisory ignore added |
| Oracle generation | `python3 tools/generate-conformance.py --intel-feed ../intel-feed` | Six families: 43 strings, 5 records, 15 identities, 27 queries, 42 feed/update cases, 2,072 npm constraint checks and 1,369 comparisons |
| Reproduction and reverse cache loading | `make cache-conformance INTEL_FEED=../intel-feed` | All fixtures/provenance reproduced exactly; **Go `client.Load` authenticated 16 Rust-written caches** |
| Forward cache loading and byte parity | `zoli-intel/tests/conformance.rs` | Go positive caches verify in Rust; exact encoding/hash/query/cache bytes agree. Shared negatives reject; same-sequence equivocation is an intentional stricter Rust rejection |
| Trust/recovery | `zoli-intel/tests/storage.rs` | Failed updates preserve state/cache; missing/corrupt/interrupted cache refuses load and recovers through verified update; corrupt/lost state never resets automatically; concurrent readers/writers agree |
| Resource/destination limits | `zoli-intel/tests/limits.rs`, inspector/CLI suites | Oversize rows/descriptors, broken gzip, disallowed IPs, unsafe/duplicate/link/special paths, invalid source/identity, unsupported executables/opaque formats and worker RSS failure refuse success |
| npm graph | `zoli-pms/tests/inventory.rs` | v2/v3, shrinkwrap precedence, nested versions, aliases/scopes/private identities, dev/optional/peer flags, bundled metadata, stale roots and unsupported/missing sources |
| Static rules and benign controls | `zoli-inspect/tests/inspection.rs` | All three flow rules have original file/line evidence; TSX/inline hooks, exports, environment collections, benign networking/comments/shadowing and informational eval tested |
| HTTPS/authentication | `zoli-cli/tests/registry.rs` | Real controlled TLS, CA rejection, private opt-in, same/cross-origin redirects, scoped authorization, no token forwarding, unapproved/HTTP redirect and loop rejection |
| Aggregate CLI and audit | `zoli-cli/tests/assessment.rs` | Feed/local/aggregate scopes, malicious/suspicious interactive/CI exits, source freshness failures, strong SRI failures, no hook execution, bundled uncertainty/coverage, redaction, audit failure and eight concurrent process appends |
| Future install commands | Existing CLI contract tests | `wrap/serve/shims/doctor` refuse; fake npm never executes |
| Working-tree/documentation hygiene | `git diff --check`, relative Markdown path/anchor checks | Passed |

Interrupted-cache tests model durable state newer than cache and verify restart behavior. They do not simulate a physical power cut or exhaust every filesystem failure. Resource tests are bounded synthetic inputs, not exhaustive fuzzing.

### First and repeated timing baseline

Executed `cargo test -p zoli-cli --locked --offline --test baseline -- --ignored --nocapture` against the final implementation. The saved [measurement](../testdata/benchmarks/phase1-linux-debug.json) contains all stage timings and conditions.

| Condition | Wall time |
| --- | --- |
| First assessment after fresh Zoli state | 266 ms |
| Five repeated assessments | 267, 265, 266, 266, 284 ms |
| First run stage times | Feed verification 17 ms; inventory 2 ms; acquisition 28 ms; local inspection 205 ms; query/policy 3 ms; reported total 260 ms |

Four packages include nested versions, a scoped development dependency and approximately 44 KiB of benign source each. All six assessments completed with no actionable findings; 24 artifact requests prove reacquisition on every run. There is no analysis-result cache. Times use the debug profile and controlled loopback HTTPS; OS caches were not flushed. They are neither a production latency estimate nor a speed target.

### Remaining evidence

- **Live feed agreement:** ADR-004 gate 4 is deferred at the user's explicit request. Synthetic signed publications and local HTTPS registry tests are not deployed-feed evidence.
- **Platform/release builds:** the implementation was tested locally on Linux GNU. New hosted Linux/macOS tests, musl/static releases and macOS release builds were not run or inferred from the historical Phase 0 workflow.
- **Install enforcement:** no proxy, shims, quarantine-release enforcement, real npm install or warm-cache bypass gate has run; these remain Phase 2.
- **Detection quality:** finite synthetic tests establish behavior for the declared rules. They do not establish recall/precision, arbitrary callback/helper/cross-file data flow, whole-program reachability or absence of hidden malware. The worker has monitored resources and cleared environment, not an OS sandbox.
