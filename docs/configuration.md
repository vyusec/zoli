# Configuration

Baseline: 16 October 2026. The schema and defaults are **provisional** until the phase that implements each setting passes its gate. Open questions are numbered (OQ-n) and tracked in the [roadmap](roadmap.md#open-questions).

## `config.json`

Location: `$ZOLI_HOME/config.json`, default `~/.zoli/config.json`, mode 0600.

```json
{
  "config_version": 1,
  "feed": {
    "url": "https://feed.example.org/feed",
    "public_key": "<base64 Ed25519 public key, 32 bytes>"
  },
  "policy": {
    "suspicious": "warn",
    "min_publish_age_hours": null,
    "max_staleness_hours": null
  },
  "registries": {
    "npm": ["https://registry.npmjs.org"]
  }
}
```

| Key | Meaning | Rules |
| --- | --- | --- |
| `config_version` | Schema version | Required. A file without it (for example one written by the Python prototype) is rejected with a migration message, never used in part |
| `feed.url` | Feed base URL | HTTPS, no credentials, query or fragment, ends in `/feed` (ADR-005) |
| `feed.public_key` | Pinned Ed25519 key | Base64, exactly 32 bytes. Never taken from any other source |
| `policy.suspicious` | Interactive handling of suspicious matches | `warn` or `block`. CI always blocks |
| `policy.min_publish_age_hours` | Hide versions younger than this | `null` disables the check. Default value: OQ-2 |
| `policy.max_staleness_hours` | Upper bound on feed age before installs block | `null` uses the built-in default (OQ-4) |
| `registries.npm` | Hosts the proxy inspects for npm-family managers | `registry.npmjs.org` is always included |

Unknown keys are an error, so a mistyped setting cannot silently fall back to a default.

## Environment

| Variable | Effect |
| --- | --- |
| `ZOLI_HOME` | Relocates `~/.zoli` |
| `CI` | Any value other than empty, `0` or `false` selects CI mode. `--ci` shims set CI mode explicitly |

No environment variable can change the feed key or URL.

## Policy defaults (v1)

Rules are written over verdict fields: `status`, `matches[].certainty`, `matches[].record.classification` and `freshness`. Policy never changes the verdict itself.

| Verdict | Interactive | CI |
| --- | --- | --- |
| `known_match`, any malicious match | **Block** | **Block** |
| `known_match`, suspicious matches only | Warn (`--suspicious=block` blocks) | **Block** |
| `insufficient_information`, uncertain malicious match | OQ-1 (proposed: **block**) | **Block** |
| `insufficient_information`, uncertain suspicious match only | Warn | OQ-1 (proposed: **block**) |
| `insufficient_information`, no matches, feed stale or degraded, within the staleness bound | Allow with a banner, logged | Allow with a banner, logged |
| Same, beyond the staleness bound | **Block** (Phase 5) | **Block** (Phase 5) |
| `no_known_match` | Allow, logged | Allow, logged |
| Version younger than the minimum publish age | Removed from metadata with a notice; a direct tarball request is blocked | Same |
| No verified feed cache | **Block**, with an instruction to run `zoli update` | **Block** |

Every row writes one audit record. No row allows silently.

### Why freshness needs its own rule

Go's `api.Query` reports `degraded` whenever *any* source has an error or has not succeeded within one hour. It then turns every would-be `no_known_match` into `insufficient_information`. With hourly ingestion that will be common, so a banner on every degraded verdict would train users to ignore banners (OQ-3).

Proposed handling: keep the verdict exactly as Go reports it. Compute the banner and the staleness bound from the signed `generated_at` and per-source `last_success` timestamps, which the verdict and cache already carry. Policy then shows the banner when the feed is older than a small display threshold, and blocks beyond `max_staleness_hours`.

## Audit log

`$ZOLI_HOME/log/audit.jsonl`, append-only, mode 0600. Each line records:

- time and mode;
- command;
- package identity;
- verdict status, freshness and feed sequence;
- matched record IDs with classification and certainty;
- decision and the rule that produced it;
- any override.

The format is defined in Phase 1 and versioned with a `schema` field on every line.
