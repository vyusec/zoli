# ADR-004: Feed-client faithfulness

- Status: Accepted, 16 October 2026. Items marked *(proposed)* need confirmation at the Phase 1 review.
- Reference: the Go client in [`vyusec/intel-feed`](https://github.com/vyusec/intel-feed) at commit [`7919b85`](https://github.com/vyusec/intel-feed/tree/7919b8586cd7d8e2d9777be43d9beb5102154601). The files this ADR relies on are byte-identical (same Git blob hashes) between that commit and the local workspace read on 16 October 2026: `pkg/client/client.go`, `internal/feed/{feed,consumer}.go`, `internal/model/{model,match}.go`, `internal/api/server.go`, `internal/netfetch/client.go`, `docs/feed-format.md` and `third_party/semver/`. `examples/client-check` existed only in the local workspace at that date.

## Context

Zoli's verdicts come from the Zoli intel feed (ADR-003). The feed ships a Go reference client. Its integrity check depends on Go: `records_sha256` is the SHA-256 of the record set as Go's `encoding/json` writes it. Zoli is Rust (ADR-001), so it reimplements that client.

The v0 plan rates cross-language hash parity as the highest risk. The Go code shows the risk has two parts that fail in opposite directions:

- **Hash parity fails closed.** A Rust serializer bug produces a hash that does not match the signed `records_sha256`, so the update is rejected. Zoli keeps its previous cache and goes stale. That is an availability cost. When the Rust hash does match, the Rust in-memory records re-encode to exactly the signed bytes, so they hold the signed content.
- **Matching parity fails open.** The verdict comes from `api.Query`, which calls `model.MatchAffected`, which uses deps.dev semver. If Rust compares versions or evaluates ranges differently, it can return `no_known_match` where Go returns `known_match`. No signature catches that.

This ADR therefore treats hash parity as the main availability risk and matching parity as the main silent-allow risk. Go-generated fixtures cover both.

## Decision

Rust reproduces the Go client's observable behaviour. The Go code is the specification, and Go-generated fixtures settle disputes. Where exact replication is impractical, Rust may reject inputs that Go accepts (fail closed), but must never accept an input Go rejects. Every such divergence is listed in this ADR.

### 1. Fixed-wire serializer

Every type that is hashed or compared byte-for-byte gets a hand-written serializer: `Record` and its nested types, `Delta`, `Manifest`, `QueryResponse`, `Match`, `Coverage` and `SourceState`. No serde derive is used on the write path. The serializer follows Go `encoding/json`:

| Rule | Go behaviour to reproduce |
| --- | --- |
| Field order | Struct declaration order, not alphabetical |
| `omitempty` | Omits `""`, `0`, a nil pointer, and a nil or empty slice. It never omits struct values: a zero `published_at` is written as `"0001-01-01T00:00:00Z"` |
| Slices without `omitempty` | nil is written as `null`, empty as `[]`. Parsing must keep the difference (absent or `null` versus `[]`) |
| Times | RFC 3339 with up to nine fractional digits. Trailing fractional zeros are trimmed, and the fraction is dropped when zero. A zero UTC offset is written as `Z`; other offsets as `±hh:mm`, keeping the parsed offset. Years outside 0–9999 are an encoding error |
| Strings | `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`. Other bytes below 0x20 are written `\u00xx` with lowercase hex. U+2028 and U+2029 are always escaped. DEL and other non-ASCII characters are written raw |
| HTML | Hash mode (`Encoder.SetEscapeHTML(false)`, used by `RecordsHash` and published rows) writes `<`, `>` and `&` raw. Marshal mode (`json.Marshal`, used by `client-check` comparisons and `Snapshot.Save`) writes `<`, `>` and `&` |
| Rows | `Encoder.Encode` appends `\n` after every row, including the last |

### 2. Hash input order

- **Full snapshot:** records are hashed in file order, as `Snapshot.Verify` does. Do not sort them.
- **After deltas:** records are sorted by ID byte-wise (`sort.Slice` with `<`), as `ApplyDelta` does.

Upstream observation: the publisher orders records with PostgreSQL `ORDER BY id`, which follows the column collation rather than byte order. The two orders agree today only because every generated ID is `ZOLI-` followed by 24 lowercase hex characters. A manually imported ID with mixed case or punctuation could make a delta-updated hash disagree with the publisher's. This should be reported to intel-feed. Rust mirrors Go either way.

### 3. Normalization before hashing

`Record.Validate` changes records before they are hashed, on the snapshot path and for every delta record:

- defaults `schema_version`;
- canonicalizes ecosystem names;
- folds PyPI names and lowercases Cargo and Conda names;
- fills default registries and re-serializes registry URLs through Go `net/url`;
- lowercases `sha256`;
- sets an empty scope to `unknown`.

Records loaded from a verified cache are not re-validated. Rust replicates these steps.

*(proposed)* For registry URLs, Rust accepts only values already in the form Go would produce: `https`, lowercase host, no credentials, query, fragment or trailing slash. Anything else fails closed, so Rust does not have to reimplement `net/url` re-serialization. Honest publisher output is already normalized, so this costs nothing in practice.

### 4. Parsing differences (fail closed)

Go's decoder matches field names case-insensitively, keeps the last of duplicate keys, ignores unknown fields, and replaces invalid UTF-8 with U+FFFD.

- **Unknown fields:** Rust ignores them too. This is required for parity, because Go drops unknown fields before hashing.
- **Case-insensitive names, duplicate keys and invalid UTF-8:** Rust rejects these.

Signed Go output never contains any of the three, so this only rejects input that Go would silently rewrite.

### 5. Trust chain (mirror exactly)

1. Fetch `<feed>/latest.json`, at most 2 MiB.
2. Decode `signature` as padded standard base64. Go skips embedded `\r` and `\n`; Rust rejects them (fail closed).
3. `key_id` must equal the first 16 lowercase hex characters of SHA-256 over the pinned 32-byte public key.
4. Verify Ed25519 over the exact bytes of the `manifest` value: Go's `json.RawMessage`, Rust's `serde_json::value::RawValue`. Never verify a re-serialization. Rust uses `ed25519-dalek` `verify_strict`, which should accept only signatures Go accepts. It also rejects small-order and non-canonical encodings that an honest publisher never produces. Envelope fixtures pin this.
5. Check the manifest:
   - `schema_version` is `1.0`.
   - `sequence` is greater than the previous sequence minus one. An equal sequence is a no-op that returns the previous snapshot. A lower sequence is a rollback and is rejected.
   - Each file passes Go's exact `safePath` rule, has a 64-character `sha256`, and has `bytes ≥ 0`. `safePath` admits `.` and `..`. That is harmless because the bytes are hash-pinned. Mirror the rule and report it upstream.
6. Check each artifact before decompressing: its size equals `bytes` and is at most 256 MiB, and the SHA-256 of the compressed bytes equals `sha256`.
7. Decompress gzip **including concatenated members**. Go's reader is multistream, so use `flate2::read::MultiGzDecoder`, not `GzDecoder`. The expansion limit is 512 MiB, and reaching exactly the limit is already an error.
8. Split rows the way `bufio.ScanLines` does:
   - strip one trailing `\r`;
   - accept a final row without `\n`;
   - fail on any blank row;
   - fail on any row that does not fit the 2 MiB scanner buffer.
9. Follow the delta chain. Starting from the current sequence, take the **first** descriptor in manifest file order with `kind == "delta"`, `from_sequence == current` and `to_sequence > current`.
   - No such descriptor: fall back to the full snapshot.
   - Fetch, checksum, decode or apply error on a delta: hard error, no fallback.
   - Chain ends beyond the manifest sequence: fall back to the full snapshot.
   - Count or hash mismatch after the chain: hard error.
10. Apply delta rows:
    - `upsert` and `withdraw` need a `record` whose `id` matches the row's `id`.
    - `withdraw` also needs `status == "withdrawn"`.
    - The record is validated, and therefore normalized, before it is stored.
    - `remove` must not carry a record.
    - Any other operation is an error.
11. Full snapshot: use the **first** descriptor with `kind == "snapshot"` and an empty ecosystem. Decode and validate each row, then check the record count and hash. If there is no such descriptor, fail.
12. Persist only after the count and hash check, and do it atomically: a temporary file in the same directory, mode 0600, fsync, then rename.

### 6. Query semantics (mirror exactly)

`api.Query` produces the verdict:

- **Normalization:** the query is normalized first. Aliases such as `pip` and `pnpm` map to canonical names, and the same validation rules apply.
- **`coverage`:** the *last* manifest coverage entry for the ecosystem. If there is none, the zero value `{"ecosystem":"","mode":"","limitations":null}`.
- **`freshness`:**
  - `stale` when `generated_at` is more than one hour old.
  - `degraded`, overriding `stale`, when any source has no `last_success`, a `last_success` more than one hour old, or a non-empty `error`.
- **Record selection:** records are visited in order. A record is skipped unless `status == "published"` and `withdrawn_at` is absent.
- **Certainty per record:** the best certainty across its affected entries. `exact` wins immediately, then `range`, then `uncertain`, which keeps the reasons of the first uncertain entry. `exact` and `range` clear the reasons.
- **Status:**
  - Any exact or range match gives `known_match`.
  - Only uncertain matches give `insufficient_information`.
  - A would-be `no_known_match` becomes `insufficient_information` when the version is empty, freshness is not `current`, or a Conda query lacks channel, subdir or build.
- **Clock:** Go reads the wall clock (`time.Since`). Rust takes `now` as a parameter. Fixtures use timestamps far in the past or future, so Go's output does not depend on when the generator runs.

*(proposed)* For version comparison and range evaluation, Rust ports the npm system of the vendored `deps.dev/util/semver`. That code is in `intel-feed/third_party/semver`: an unmodified Apache-2.0 subset of about 2.8k lines on the npm path. Zoli does not adopt an existing Rust semver crate, because those parse versions with different leniency and prerelease rules. PyPI (PEP 440) is ported the same way in Phase 3.

### 7. Cache format *(proposed)*

Rust writes its cache in Go's `Snapshot` JSON shape, `{"envelope":{…},"records":[…]}`, and keeps the manifest's raw bytes. Each client can then load the other's cache. This exists as a conformance check, not as a migration feature.

## Conformance fixtures

Go `internal/` visibility means `feed.Sign`, `feed.RecordsHash`, `feed.ApplyDelta` and `api.Query` can only be called from inside the `zoli.dev/intel-feed` module. The generator therefore lives in intel-feed, for example as `cmd/conformance-gen`. It writes into `Zoli/testdata/conformance/` and records the intel-feed commit, plus SHA-256 hashes of itself and of the source tree it ran against. The tree hash catches uncommitted local changes. Fixtures are generated and never hand-edited.

| Family | Cases |
| --- | --- |
| Envelope | Valid; bad signature; wrong `key_id`; schema mismatch; paths `/abs`, `../x`, `a/../b`, `.`, `..`, backslash; short `sha256`; negative `bytes` |
| Snapshot encoding | HTML characters, U+2028/U+2029, control characters, non-ASCII, zero `published_at`, nanosecond and trimmed fractions, non-UTC offsets, nil versus empty slices, unknown fields |
| Delta chains | Upsert, correction, withdraw, remove; withdraw without withdrawn status; remove with a record; unknown operation; missing link (fallback); overshoot; equal sequence; multi-member gzip; CRLF rows; blank row |
| Tampering | Flipped artifact byte; size mismatch; record count mismatch; records hash mismatch; edited cache |
| Rollback and staleness | Lower sequence; stale manifest; degraded source |
| Query matrix | Identities × records → Go `api.Query` JSON, including npm prereleases, build metadata, x-ranges, `\|\|`, hyphen ranges, `introduced: "0"`, `last_affected`, `limit` and unparsable versions |

## Phase 1 acceptance gate

1. For every query fixture, Rust's response in marshal mode is byte-identical to Go's `json.Marshal` of `api.Query`.
2. Both clients reject every negative fixture. Both accept every positive fixture with the same resulting sequence, record count and records hash.
3. A cache written by either client loads and verifies in the other.
4. Live check: on the same deployed feed, Rust `zoli check` and Go `client-check` agree on `sequence`, `record_count`, `status` and `freshness`.

**Plan correction for gate 4.** `client-check` cannot target a locally deployed feed. Go's `netfetch` connects only to port 443 on public, globally routable addresses and refuses loopback and private destinations. Gate 4 therefore needs a publicly reachable HTTPS staging feed, which intel-feed's own Phase 1 needs anyway. A local comparison through the generator's in-memory transport counts as fixture evidence, not live evidence.

## Consequences

- Every change to the Go client is a change for Zoli. Regenerate and diff the fixtures whenever intel-feed changes `internal/model`, `internal/feed`, `internal/api` or `third_party/semver`.
- Divergences are allowed only in the fail-closed direction, and only when this ADR lists them.
- The serializer will be long and repetitive, and should stay that way. Reviewers must be able to compare it to the Go struct tags line by line.

## Alternatives considered

- **serde derive plus serde_json for hashing.** serde_json differs from Go on U+2028/U+2029, time formatting, nil versus empty slices and field omission. Each difference can be configured away, but the configuration is invisible in review. Rejected for the write path; serde stays on the parse path.
- **Hash the snapshot's original uncompressed rows** (the option `feed-format.md` offers). This works for full snapshots only, because any delta forces re-encoding the record set. Rejected as the sole mechanism; kept as a cross-check on the snapshot path.
- **Call the Go client through FFI or a sidecar.** Removes the parity risk but breaks the single static binary (ADR-001).
- **Use an existing Rust npm-semver crate.** Its parsing and prerelease rules differ from deps.dev, so parity would depend on luck.
