# Live feed test — 31 October 2026

Zoli authenticated the supplied feed and correctly blocked the tested package checks and guarded installation. All selected client and API behavior checks passed. Healthy deployment acceptance remains open: the signed publication is approximately 36 hours old even though live ingestion status has newer successful runs. The npm release poller also continues to report errors.

## Target and environment

- Endpoint: `https://wants-specialized-heath-educated.trycloudflare.com`.
- Current working-tree debug binary, built with `cargo build -p zoli-cli --locked --offline`. Base commit: `fd941281eb063e38b2802a8c2028caa33f387e72`; pre-existing uncommitted changes were retained. CLI version: `0.0.0`.
- Reused the existing operator-pinned public key, key ID `2e2944b2cc2882a5`. The key did not come from the tested server.
- Isolated client home and evidence: `/tmp/zoli-live-20261031/`. The normal client configuration, cache and updater were not changed.
- Compute-heavy commands ran sequentially through `systemd-run --user --scope --quiet -p CPUQuota=50% -p CPUWeight=10 nice -n 15`, with `CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=1`, `GOMAXPROCS=1`; Go build used `-p=1` with module downloads disabled.

## Deployment findings

### Signed publication is not tracking current ingestion

`GET /healthz` returned HTTP 200 with `status: ok`. This endpoint checks database reachability, so that result does not establish feed freshness.

`zoli --json update` succeeded with exit 0 and `assessment_performed: false`:

| Field | Authenticated value |
| --- | --- |
| Publication | 548 |
| Records | 184,366 |
| Generated at | `2026-10-29T21:53:12.805563925Z` |
| Verification report time | `2026-10-31T09:54:28.579493007Z` |
| Freshness | `degraded` |
| Raw manifest SHA-256 | `ccb6da86ae98b5cba0cc0a8bb4649da3d96c87676b32cb68fa5c89d92d59b43d` |
| Stored cache size | 230,612,933 bytes (about 220 MiB) |

The signed manifest still contains the old GitHub HTTP 403 and OSV `MAL-2022-2.json` unsupported-package errors, with no successful freshness evidence for those sources. Its npm poller likewise lacks a successful timestamp and contains old 404 failures.

In contrast, `/v1/status` reported GitHub success at `2026-10-31T09:43:56.056096642Z` and OSV success at `2026-10-31T09:43:57.969723926Z`, without active error fields for those sources. Both the status endpoint and hosted queries still reported publication 548. This establishes a gap between current source state and the signed publication; the specific publisher failure requires server logs and was not established by these client-side tests.

### npm ingestion still has active errors and recorded gaps

Live status reported npm's latest success at `2026-10-31T09:25:40.54700222Z`, followed by errors at `2026-10-31T09:42:05.173648736Z`. Errors include registry response-size limits and package 404 responses. Registry sources also retain rolling-feed outage or potentially missing-release gaps. A new publication alone would therefore not establish healthy-source acceptance.

### Debug CLI checks are expensive on the full feed

The two process-level checks took 81.99 and 82.37 seconds respectively, with peak RSS about 1.11 GiB. `/usr/bin/time -v` measured approximately 49% CPU, consistent with the requested cap. These are debug-build measurements on the complete live cache, not release-performance estimates. No performance change was made.

## Executed checks

| Check | Result |
| --- | --- |
| Public HTTPS signed update | Exit 0; signature, downloaded artifact and complete record hash verified; sequence 548 persisted |
| Health and service status | Both HTTP 200 |
| Hosted single queries for npm `left-pad@1.3.0` and PyPI `requests@2.32.3` | Both HTTP 200, `insufficient_information`, `degraded` |
| Unknown request field | HTTP 400 |
| Empty query batch | HTTP 400 |
| Go reads Rust's live cache | `client.Load` authenticated all 184,366 records |
| Go batch versus hosted batch | All seven complete verdict objects matched |
| Rust CI check: npm `left-pad@1.3.0` | Exit 10, block, incomplete; complete feed verdict equals Go and hosted result |
| Rust CI check: PyPI `capmonstercloudclieent@1.0.0` | Exit 10, block, incomplete; exact malicious feed match; complete feed verdict equals Go and hosted result |
| Guarded npm install against the live cache | Exit 10; marker confirmed npm was never invoked; lockfile unchanged; no `node_modules` created |
| Wrong pinned signing key | Exit 1, `invalid manifest signature`; no trusted state or cache created |
| Client file permissions | Configuration, independent state, cache and audit log are mode 0600 |
| Audit persistence | Four readable records: update, both feed checks and blocked `npm_ci_assessment`; wrong-key failure recorded in its separate test home |

The install check used an isolated one-dependency v3 lockfile and a fake npm executable that would write a marker if called. The reported inventory had one package and zero inventory gaps. Its placeholder integrity value was not an authenticated package artifact: the purpose was to exercise refusal before acquisition. The audit report recorded zero acquisition and local-inspection time, with 80.943 seconds spent verifying the feed. The overall guard took 81.83 seconds. This establishes refusal under the actual degraded feed; it does not exercise a successful registry download or install.

The Go reference was built from the local sibling `intel-feed` source with Go `1.26.10-X:nodwarf5`. This does not establish which source revision is deployed remotely. It authenticated the Rust-written cache; an independent Go full download was not repeated in this run.

The seven Go/hosted comparisons were:

| Identity | Verdict | Match |
| --- | --- | --- |
| npm `left-pad@1.3.0` | `insufficient_information` | None |
| PyPI `requests@2.32.3` | `insufficient_information` | None |
| PyPI `capmonstercloudclieent@1.0.0` | `known_match` | Exact, classified malicious by the feed |
| npm `@tendable/ui-kit@99.0.1` | `known_match` | Exact, classified malicious by the feed |
| Alias/case input `pypi/Requests@2.32.3` | `insufficient_information` | None |
| npm `zoli-live-check-nonexistent-20261031@1.0.0` | `insufficient_information` | None |
| PyPI `zoli-live-check-nonexistent-20261031@1.0.0` | `insufficient_information` | None |

All seven had `freshness: degraded`. Only the two explicitly listed Rust CLI checks were compared across all three implementations; the other five comparisons were Go/hosted.

## Evidence and remaining acceptance

Captured commands, stdout/stderr, HTTP bodies/headers, timings and test helpers are under `/tmp/zoli-live-20261031/`. Key files include `update.json`, `http-summary.json`, `service-status.json`, `identities.json`, `go-verdicts.json`, `hosted-batch.json`, `checks-summary.json` and `rust/log/audit.jsonl`. Temporary evidence may be removed by the operating system; this report is the durable summary.

Inspect the server's publisher/scheduler failures, restore publication of current signed source state, resolve or explicitly account for registry ingestion errors/gaps, and repeat healthy-feed acceptance. No server mutation, successful package installation, Python installation protection, hosted CI or release-build validation is claimed by this run.
