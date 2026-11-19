# Expanded Phase 3 test report — 30 October 2026

This pass adds **51 named Rust tests**, **four top-level Go tests** (12 additional Go subtests), and **100,000 reproducible differential cases** to the matching/input milestone. It exercises the implemented Python foundation and the existing npm guard. It does not advance the five-part Phase 3 checklist beyond its first milestone.

## Coverage added

| Layer | New checks | Location |
| --- | --- | --- |
| Version and constraint invariants | Release padding/leading zeroes, suffix aliases, ordinary ordering/transitivity, epoch/integer/overflow boundaries, local numeric labels, all ASCII controls, Unicode lookalikes, 24 permutations of four terms, repeated exclusions, invalid tails after empty intersections, raw byte budgets and minimized epoch regressions | [13 properties](../crates/zoli-intel/tests/pypi_properties.rs) |
| Differential oracle | 25,000 comparison pairs and 75,000 constraints; fixed xorshift seed `0x5a4f4c493033`; suffix combinations, malformed versions, one to nine terms, wildcard/epoch interactions and repeated terms. Go computes every expected result. The compressed fixture is about 1.1 MB | [generator](../tools/conformance-gen/seeded.go), [Rust test](../crates/zoli-intel/tests/pypi_seeded.rs) |
| Requirements input | CRLF and physical line attribution; BOM; first/second-line encoding declarations; Unicode whitespace; escaped/dangling continuations; comment delimiters; invalid later hashes; hash sorting/deduplication; duplicate normalized names; one gap per unsupported line; byte/line boundaries; missing/unreadable/truncated/replaced files and FIFO refusal | [16 input tests](../crates/zoli-pms/tests/requirements_edges.rs) |
| CLI and audit | Five actual Go-signed PyPI fixtures through Rust cache/query/policy/CLI; manifest provenance and exact audit/output equality; valid plus malformed findings; artifact/registry scope; withdrawal; resource failure after an earlier match; unrelated/withdrawn oversized records; cache tampering; missing/future/failed sources; missing PyPI coverage; incomplete audit records; audit open and write faults; concurrent checks and publications | [14 process tests](../crates/zoli-cli/tests/pypi_failures.rs) |
| Durable storage | Cache rename failure after state persistence, recovery without rollback, abandoned temporary files, invalid independent state fields and duplicate JSON cache keys | [four additions](../crates/zoli-intel/tests/storage.rs) |
| Policy | A healthy source cannot mask an unhealthy source in either order; exact one-hour source boundary at nanosecond precision; malicious findings dominate suspicious policy and record order | [three additions](../crates/zoli-policy/tests/assessment.rs) |
| Feed model | Four-term boundaries, malformed range beside exact match, artifact selectors versus package-wide findings, and explicit pinned-library defects | `intel-feed/internal/model/pypi_regression_test.go` |

Existing tests still cover raw version/term/component ceilings, 128 exclusion fragments, oversized work after earlier matches, signed corruption/rollback/equivocation, stale sources, concurrent audit append, registry authentication/redirects and the real npm installation guard.

## Defects fixed

1. **Rust interval construction differed from Go for equal exclusion endpoints.** The first seeded run found five disagreements. Go stores the lower endpoint in both slots of a point interval, including equality involving a plain sentinel and an epoch-qualified version. Rust retained the original upper endpoint and changed later intersections. The corrected construction passes all 100,000 seeded cases plus the explicit matrix; three reduced regressions preserve the cause.
2. **Encoding declarations could disappear as comments.** PEP 263 headers can select a decoder in pip. The strict UTF-8 reader now records `unsupported_encoding_declaration` for such headers in the first two physical lines, including declarations naming UTF-8. It does not claim to implement alternate decoding.
3. **Unicode whitespace could disappear before pin validation.** The reader now trims only supported ASCII space/tab around logical lines, allowing its strict pin validation to reject non-ASCII whitespace explicitly.

## Independent standards check

[The standards tool](../tools/check-pypi-standards.py) uses installed PyPA `packaging` **25.0**, independently of the Go library. It records the input hashes and compares 31,084 version pairs and 104,973 constraints using `SpecifierSet.contains` with its default prerelease behavior. Results: 2,538 comparison differences and 30,227 constraint differences. These include deliberate syntax/limit differences, malformed inputs and prerelease policy differences; they are **not counts of distinct bugs**.

Eight representative differences have explicit expected answers and fail the diagnostic if either implementation changes:

| Input | Pinned Go / Rust | PyPA |
| --- | --- | --- |
| Compare `1.0+ABC` and `1.0+abc` | Less | Equal |
| Compare `1.0.post1+abc` and `1.0.post1+xyz` | Equal | Less |
| Compare `1.0a1` and `1.0a1.post0` | Equal | Less |
| Compare `255!1` and `256!1` | Error | Less |
| `>1,<=1`, version `1` | Match | No match |
| `>=1.0,<2`, version `1.0+abc` | No match | Match |
| `!=1,!=2,!=1,!=2`, version `1` | Match | No match |
| `<2,!=2!0`, version `1` | No match | Match |

The repeated-exclusion behavior was exposed by a new independent invariant, then confirmed in generated Go output. It remains an explicit reference defect rather than a passing standards invariant. Fixing the pinned matcher semantics requires coordinated Go/Rust changes and a fresh corpus. These differences must be addressed before claiming standards-faithful Python installation protection. See [PyPA version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/) and [pip's requirements format](https://pip.pypa.io/en/stable/reference/requirements-file-format/).

## Executed gates

Final workspace and reproduction results are recorded in [validation](validation.md#expanded-python-testing--30-october-2026). Focused runs preceded that gate; their passing counts are not added again to the workspace total.

- Four targeted mutations were killed by assertion failures: reversed version ordering, allowing a 129th constraint term, ignoring input gaps, and releasing output without an audit write. The [mutation runner](../tools/test-phase3-mutations.py) uses a temporary source copy, restores each mutation between runs, reuses dependency artifacts, and does not count compile failures or timeouts as successful detection. This is a bounded negative-control check, not a general mutation score.
- The initial mutation runner shared Cargo's target directory; the subsequent full suite caught its deliberately unaudited CLI binary remaining cached. The runner now copies external dependency artifacts into a separate temporary target and never shares workspace binaries or fingerprints. Affected workspace artifacts were cleaned and rebuilt before final validation. Original source was never mutated.
- The feed's model/API/client packages passed **23 top-level tests, 47 including subtests**, with no failures or skips. All 82 prior inventoried Go/build inputs remain byte-identical; the only added input is the new model test file. No feed runtime, database or deployment changed.
- The Go fixtures use a fixed far-future clock for reproducibility. CLI tests correctly block that evidence while preserving matching/provenance/audit results. Separate tests evaluate the same signed snapshots at their publication clock to verify fresh allow/block policy. Rust-signed current-time fixtures exercise successful real CLI checks.

## Reproduction and limits

All heavy commands were sequential under:

```sh
systemd-run --user --scope --quiet -p CPUQuota=50% -p CPUWeight=10 nice -n 15 \
  env CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 GOMAXPROCS=1 MAKEFLAGS=-j1 COMMAND
```

Run these command bodies from Zoli unless indicated:

```sh
python3 tools/generate-conformance.py --intel-feed ../intel-feed
cargo test --locked -p zoli-intel --test pypi_seeded --test conformance
cargo test --locked -p zoli-intel -p zoli-pms -p zoli-policy -p zoli-cli \
  --test pypi_properties --test storage --test requirements_edges \
  --test assessment --test pypi_failures
python3 tools/check-pypi-standards.py --output /tmp/zoli-standards.json
python3 tools/test-phase3-mutations.py --output /tmp/zoli-mutations
make ci
make cache-conformance INTEL_FEED=../intel-feed
# From intel-feed:
go test -p=1 -count=1 -json ./internal/model ./internal/api ./pkg/client
```

Local logs are under `/tmp/zoli-expanded-tests-20261030/`; these are ephemeral evidence, not required source artifacts. Toolchain: Rust/Cargo 1.98.0, Go 1.26.10-X:nodwarf5, Node 22.23.1, npm 10.9.8, PyPA packaging 25.0. The permission test ran as uid 1000; elevated users cannot exercise Unix mode-000 refusal. Small concurrency tests share the same CPU quota and do not constitute a stress or performance benchmark.

No Docker, database/race suite, internet package installation, production feed change or unbounded fuzzing was needed. Wheel inspection, real pip/uv/poetry/pipx enforcement, Ratatui screens and healthy live-feed acceptance remain separate milestones. Truncation/replacement tests cover changes between reads; they do not establish protection against hostile filesystem races during a read. Storage interruption tests model persisted states and rename failures, not physical power loss. No new hosted CI result or push is claimed.
