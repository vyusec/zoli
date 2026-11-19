# Conformance fixtures

Generated from the intel-feed Go source by [the generator](../../tools/conformance-gen/main.go). **Never edit these files by hand.** Regenerate them and review the diff.

The wrapper runs the generator as `cmd/conformance-gen` inside a temporary copy of the intel-feed module, without editing the original. Go module dependencies must already be cached; generation deliberately disables module downloads. Go is development tooling only, not a Zoli runtime dependency.

```sh
python3 tools/generate-conformance.py --intel-feed ../intel-feed
python3 tools/generate-conformance.py --intel-feed ../intel-feed --check
make conformance-check
make cache-conformance INTEL_FEED=../intel-feed
```

`--check` reproduces every fixture and its provenance (holding only the generation timestamp fixed). It does not modify committed fixtures. A Go toolchain or source change requires deliberate regeneration. `make conformance-check` checks committed file hashes and generator provenance without requiring Go or an intel-feed checkout, and is part of `make ci`.

Every generation writes `PROVENANCE.json` with:

- SHA-256 hashes of the generator and wrapper;
- the intel-feed commit when available, plus a complete inventory and tree hash of the copied build inputs, including local replacement modules and embedded SQL;
- Go version, generation time and hashes of all output files;
- explicit limits of the generated corpus.

The local intel-feed handoff on 17 October has no Git metadata. Its commit is null; the inventoried build-input hashes identify what was actually executed. This is not a claim of equality with a particular GitHub commit.

## Current corpus (30 October 2026)

| File | Contents | Rust comparison |
| --- | --- | --- |
| `wire-strings.tsv` | 43 strings in hash-row and marshal modes: all controls, HTML, Unicode separators, quotes, backslash and Unicode boundaries | Compared byte-for-byte by `zoli-intel/tests/wire_strings.rs` |
| `record-encoding.json` | Five validated/normalized records, timestamps, encoded bytes and `feed.RecordsHash` | Both wire modes and ordered hashes match |
| `identities.json` | Fifteen valid/invalid identities, normalization and errors, including malformed registry URLs | Matches normalized Go identities/errors |
| `queries.json` | Sixty-six `api.QueryAt` cases and exact marshal bytes in hex, including npm ranges/prereleases, 30 PyPI exact/event/constraint/hash/withdrawal cases, uncertainty, selectors, coverage and freshness | Exact Rust query bytes match |
| `feed-cases.json` | Forty-seven actual `Client.Update` cases: signed envelopes, artifacts, file order, gzip/rows, rollback/equivocation, deltas/fallback, edited caches and five signed PyPI scenarios | Shared negatives reject; positives have identical cache bytes; both clients reject same-sequence equivocation |
| `npm-matrix.json` | 2,072 constraint/version checks and 1,369 comparisons from deps.dev npm semantics | Matches results and parse-error categories |
| `pypi-matrix.json` | 6,084 concrete comparison/error cases from the Go PyPI matcher, including epochs, prereleases, post/dev/local labels and invalid inputs | Matches ordering and parse-error categories |
| `pypi-constraints.json` | 29,973 constraint/version checks from the actual Go parser and matcher: operators, conjunctions, exclusions, wildcards, epochs, suffixes, malformed syntax and minimized regressions | Matches booleans and parse-error categories, including documented reference quirks |
| `pypi-seeded.json.gz` | 25,000 comparisons and 75,000 constraints, seed `0x5a4f4c493033`, with up to nine terms, repeated terms and randomized versions | Exact Go/Rust results and error categories; compact deterministic gzip avoids a large JSON diff |

Signed values are stored as exact hex bytes. Pretty-printing a signed raw manifest can invalidate its signature, so tests must not reconstruct those messages through a generic JSON value.

`make cache-conformance` exports 21 positive Rust-written caches plus public fixture keys under `target/rust-caches`, then runs real Go `client.Load` and regenerates all fixtures with `--check`. Go-to-Rust cache verification is also part of the ordinary Rust conformance tests. This development gate requires cached Go modules; it is separate from CI's source-independent provenance check.

`tools/check-pypi-standards.py --output /tmp/standards.json` separately compares the corpus against installed PyPA `packaging`, records its version, and asserts eight known differences. `packaging` is development tooling only. Go parity is not a claim of standards compliance; see the [test report](../../docs/phase3-test-report.md).

The full families and acceptance gates are defined in [ADR-004](../../docs/decisions/ADR-004-feed-client-faithfulness.md#conformance-fixtures). Live-delivery agreement is deferred by the user. Go and Rust query fixtures use the same fixed clock and exercise exact one-hour freshness and five-minute future-skew boundaries, including one nanosecond beyond each. Rust policy independently rechecks the final clock. Resource abuse, crash-state models, auth redirects and aggregate CLI tests are maintained in the relevant crate suites. None of this proves real-world malware-detection accuracy or exhaustive semantic equivalence.
