# ADR-005: Trust bootstrap

- Status: Accepted 16 October; feed state/storage implementation updated 18 October 2026. Proxy CA proposals marked *(verify in Phase 2)* still need evidence before Zoli relies on them.

## Context

Zoli's guarantees rest on three anchors: the pinned feed key, the Zoli binary, and the local proxy CA. Each needs a defined origin, storage, rotation path and failure behaviour.

## Decision

### Feed key and URL

- **Storage.** `~/.zoli/config.json` (or `$ZOLI_HOME/config.json`) holds the feed URL and the base64 Ed25519 public key (32 bytes). The installer writes it from the release (Phase 4), and release artifacts are checksum-pinned at immutable URLs.
- **Sources Zoli never accepts a key from:** a manifest, an HTTP response, an environment variable, or a command-line flag.
- **Key ID.** Derived as in Go: the first 16 lowercase hex characters of SHA-256 over the raw public key.
- **Feed URL.** HTTPS only, with no credentials, query or fragment, ending in `/feed`. This mirrors Go `client.New`.
- **Rotation (Phase 5).** The config holds the current key and at most one announced next key, and a manifest is verified with the key its `key_id` names. The Go client supports one key, so rotation fixtures compare Rust's verdict with Go's verdict under the matching single key.

### Rollback and missing state

- **High-water mark** (implemented 18 October). The highest verified sequence, pinned key ID and raw-manifest digest live separately in `~/.zoli/state.json`. Missing/corrupt cache does not reset protection; corrupt/missing state beside a cache requires explicit recovery. Updates use an exclusive filesystem lock and commit durable state before durable cache replacement. Interrupted pairs fail closed and a verified update can repair them. Shared locks protect readers.
- **Equivocation.** The same sequence with different manifest bytes is recorded as a security event, and the update fails. Go keeps the previous snapshot silently, so verdicts are identical and only Zoli's audit trail differs.
- **No verified cache** (first run, failed load). No verdict is possible. `zoli check` reports "no verified feed", and policy blocks with an instruction to run `zoli update`. This state is never reported as `no_known_match`.

Feed networking remains public HTTPS port 443 only. Registry private-network/custom-port access is a separate, explicit per-origin operator permission; it cannot relax feed transport or replace the pinned key. Runtime trust failures are audited when the log is writable, and remain visible nonzero errors when auditing is unavailable.

### Proxy CA

- **Origin.** Generated locally on first use (rcgen). It is never shipped and never shared between machines.
- **Storage.** The private key is kept at mode 0600 under `~/.zoli/ca/`. Leaf certificates are short-lived and held in memory.
- **Scope of trust.** Only processes launched by `zoli wrap` trust the CA, through `NODE_EXTRA_CA_CERTS` and per-manager equivalents. It is never added to system or keychain trust stores in v1.
- **Name constraints** *(proposed, verify in Phase 2)*. The CA certificate carries X.509 name constraints that limit it to allowlisted registry hosts, so a stolen CA key cannot impersonate other sites to wrapped processes. Zoli relies on this only after the Phase 2 gate shows Node and OpenSSL enforce constraints on a trust anchor.

### The binary itself

Release checksums are published at immutable URLs (Phase 4). An attacker who can write to `~/.zoli` or to the binary is out of scope (see the threat model).

## Consequences

- **Config edits.** Changing the pinned key in `config.json` changes whom Zoli trusts. `zoli doctor` reports the active key ID so users can compare it with the published one.
- **Cache loss.** Losing the cache costs a full snapshot download but never weakens rollback protection.
- **Lost CA material.** Deleting `~/.zoli/ca/` is safe: a new CA is generated, and nothing outside wrapped processes trusted the old one.

## Alternatives considered

- **Key compiled into the binary only.** Rotation would need a new release, and a pinned binary could no longer follow a rotation. Embedding the release's key as a cross-check on `config.json` remains possible later.
- **Trust on first use from the feed.** An attacker positioned at first contact would choose the key.
- **System trust store for the CA.** Every process on the machine would trust a locally held key.
