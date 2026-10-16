# ADR-003: Zoli feed as the only v1 intelligence source

- Status: Accepted, 16 October 2026.

## Context

Zoli needs to know which package versions are malicious or suspicious. The candidates differ in trust, privacy and availability. The Zoli intel feed (`intel-feed`) publishes signed snapshots and deltas with explicit uncertainty, freshness and withdrawal semantics.

## Decision

v1 uses only the Zoli intel feed, consumed locally from a verified cache.

- **Tokenless.** Feed downloads are public, and Zoli needs no account or API key.
- **No hosted lookups.** Zoli does not call `/v1/query` or `/v1/querybatch` at install time. Every verdict comes from the local verified cache.
- **One trust root.** One pinned Ed25519 key (ADR-005) authenticates everything Zoli acts on.
- **Verdict vocabulary.** The feed's own: `known_match`, `no_known_match` and `insufficient_information`, with classification, certainty, coverage and freshness. A `no_known_match` is never a safety verdict.

## Consequences

- **Privacy.** Installing a package reveals nothing about the project's dependencies to any intelligence service.
- **Availability.** Installs never wait on a live intelligence service, only on the registry.
- **Coverage.** Zoli sees only what the feed covers: reports plus selective analysis for npm and PyPI, and reports only for Cargo and Maven. The docs and CLI output say so.
- **Detection latency.** A finding reaches Zoli after the feed's publication interval plus Zoli's update interval. The bounded staleness rules in `configuration.md` keep that window visible.
- **New sources.** Adding a source needs a new ADR. The preferred route is to add it upstream to the feed, so the single trust root holds.

## Alternatives considered

- **Hosted `/v1/query`.** Sends every dependency name to a server and couples installs to its uptime. It can also require an API key (`ZOLI_API_KEYS`).
- **Flint package-intelligence API**, used by the earlier, unpublished Python prototype. It needs a sensor token and a live service, which conflicts with tokenless operation.
- **OSV directly.** Not signed for Zoli, and it has no review or withdrawal workflow. The feed already ingests OSV `MAL-*` reports with attribution.
- **Commercial feeds.** They need accounts and licensing, and they bring a second trust root.
