# Configuration

Implemented assessment and locked npm guard, 30 October 2026. Configuration lives at `$ZOLI_HOME/config.json`, default `~/.zoli/config.json`. Keep this user-owned file private (0600). Unknown keys, unsupported versions and invalid settings are errors.

## `config.json`

```json
{
  "config_version": 1,
  "feed": {
    "url": "https://feed.example.org/feed",
    "public_key": "<base64 Ed25519 public key, exactly 32 bytes>"
  },
  "policy": {
    "suspicious": "warn",
    "max_staleness_hours": 1,
    "min_publish_age_hours": 24
  },
  "registries": {
    "npm": ["https://registry.npmjs.org"]
  },
  "analysis": {
    "max_artifact_bytes": 20971520,
    "max_expanded_bytes": 104857600,
    "max_files": 10000,
    "max_source_bytes": 8388608,
    "worker_seconds": 120,
    "worker_memory_bytes": 536870912
  }
}
```

This is a template, not a deployed feed endpoint/key. Feed commands require the real operator-pinned values. No environment variable, CLI flag or server response supplies or overrides that trust anchor. `inspect` can run without a config file, using default local limits and policy.

| Setting | Implemented behavior |
| --- | --- |
| `config_version` | Required, exactly 1 |
| `feed.url` | HTTPS base ending in `/feed`, port 443, no credentials/query/fragment; all resolved addresses must be public |
| `feed.public_key` | Standard base64 encoding of a 32-byte Ed25519 public key |
| `policy.suspicious` | `warn` (default) or `block`; `--suspicious=block` overrides; CI always blocks suspicion |
| `policy.max_staleness_hours` | Omitted, null or 1; the chosen Phase 1 bound is always one hour |
| `policy.min_publish_age_hours` | Guard default 24 when omitted/null; explicit integers 1–8760 override. Applies to guarded installation, not standalone assessment |
| `analysis.*` | Positive resource ceilings; unspecified fields take the defaults above |
| `registries.npm` | Explicit registry bases, as strings or detailed objects; public npm is included implicitly |

## Private registries and authentication

```json
{
  "npm": [{
    "url": "https://packages.example.org:8443/team/npm",
    "allow_private_network": true,
    "ca_file": "/home/user/certs/company-ca.pem",
    "artifact_hosts": [{
      "url": "https://artifacts.example.org",
      "allow_private_network": false
    }]
  }]
}
```

Use this object as the value of `registries`. An omitted `allow_private_network` is false; `ca_file` is optional. Registry/artifact permission applies to that HTTPS origin, including its port. Additional artifact origins require their own entry, private-network permission and CA settings. DNS answers are checked and pinned before connection. TLS verification stays enabled; there is no insecure override or inherited proxy environment.

Registry identity includes the approved repository path. npm routing must match an approved base exactly. Public and private registry identities remain distinct during feed matching. As npm specifies, a lockfile's public npm origin can follow the configured registry; other download origins need explicit artifact-host permission.

Authentication is read from the user npmrc, `npm_config_userconfig`/`NPM_CONFIG_USERCONFIG`, or explicit `scan --npmrc <path>`. A project's `.npmrc` supplies routing only, unless explicitly selected as the trusted file. `npm_config_registry`/`NPM_CONFIG_REGISTRY` can select an approved route; they do not authorize new egress.

Supported credentials are origin/path-scoped `:_authToken` (Bearer) and `:_auth` (base64 Basic), including `${VAR}` references and optional `${VAR?}` references. Variables expand only for the selected credential. Unscoped credentials, username/password configurations, client-certificate auth and `strict-ssl=false` are rejected. CA configuration comes from Zoli's explicit `ca_file` setting.

Credentials are selected independently on every redirect by scheme, host, port and path boundary. A token for `/team` cannot go to `/teammate` or another origin. Ambiguous encoded separators refuse authentication. Credentials, source values and signed download queries are omitted from reports and audit output.

## Policy defaults (v1)

Policy borrows the unchanged feed verdict. It never reclassifies a local observation as confirmed feed malware.

| Evidence | Interactive | CI |
| --- | --- | --- |
| Any malicious feed match, including uncertain | Block, exit 10 | Block, exit 10 |
| Suspicious feed/local finding, all required work complete | Warn, exit 0; `--suspicious=block` gives 10 | Block, exit 10 |
| Informational lifecycle/eval observation only | Allow within scope, exit 0 | Allow within scope, exit 0 |
| Publication or any required source more than one hour old | Block, incomplete, exit 10 | Same |
| Any source error, missing source timestamp/list, degraded verdict, unknown status or missing/unknown ecosystem coverage | Block, incomplete, exit 10 | Same |
| Required local work, dependency identity/source or strong integrity metadata unavailable | Incomplete, exit 12 | Same; an independently blocking finding still gives 10 |
| No verified cache, failed trust/download/integrity check, config/runtime/audit error | Error, exit 1 | Same |
| No known feed match and completed required checks | Allow within scope, exit 0 | Same |

Exactly one hour is within the bound; one nanosecond beyond it is old. Publication or source timestamps more than five minutes ahead of the final clock block as degraded; exactly five minutes is tolerated for clock skew. Freshness is evaluated again after artifact work. An already stale/degraded feed prevents registry acquisition. Local analysis cannot make intelligence current. A successful `status`/`update` reports verified metadata with `assessment_performed: false`; its exit 0 grants no package approval.

`CI` selects CI mode for values other than empty, `0` or `false`; `--ci` also selects it. `check` is feed-only, `inspect` is local-only, and `scan` requires both. Conflicting outcomes use runtime error (1), then policy block (10), then incomplete (12), then success/warn (0). Usage errors give 2; future command stubs give 3.

## Inspection scope and limits

Acquisition requires SHA-256/384/512 SRI and checks the strongest supplied algorithm. SHA-1-only or absent metadata makes a scan incomplete; a mismatching strong digest is a runtime error. `inspect` can optionally receive `--integrity`; its computed digest alone does not authenticate a publisher.

The analyzer reads tar/tgz without extraction. It rejects unsafe/duplicate paths, links and special entries, including PAX/GNU extension headers. Supported source is JS/TS/JSX/TSX and Node shebang scripts. Native/WASM executables, other executable languages, opaque/nested archives, encrypted files, unsupported syntax and missing entrypoints produce gaps. Ordinary non-executable data is counted without being parsed as code. Every JS/TS file is examined; whole-program reachability and arbitrary runtime behavior are outside the declared checks.

The worker is this same binary with a cleared environment and no package execution. The parent polls RSS and the deadline every 50 ms and kills failed/over-budget workers. These are monitored budgets, not a kernel memory sandbox or an OS network sandbox. The analyzer contains no networking implementation. Constant decoding is limited to three base64/hex layers and 64 KiB; expression depth is 64, export-target depth 32 and visited expressions one million. Worker JSON is capped at 16 MiB; accumulated tree reports have a 64 MiB ceiling checked before the next artifact. No successful result cache or faster mode exists.

## State, reports and audit

`cache/feed.json` uses Go's Snapshot shape. `state.json` independently stores the pinned key ID, highest sequence and raw-manifest digest. Updates verify fully in memory, take an exclusive lock, durably stage the cache, then commit state before cache. A crash gap refuses reads and can recover through a verified update at the known sequence or above. Corrupt/missing state beside an existing cache requires explicit operator recovery; Zoli never silently resets it.

Reports have `schema: 1`, a named scope, effective suspicion policy, decisions/completeness/reasons, unchanged feed verdicts, publication provenance, artifact/rule digests, analysis budgets/platform, located local evidence and limitations. Tree nodes preserve dependency paths and bundled-container references without inventing a separate hash for bundled bytes. Dependency download URLs are internal and never serialized.

`log/audit.jsonl` contains the released schema-1 reports. Appends take a filesystem lock and sync before stdout is released. New directories/files use 0700/0600 on Unix. A partial trailing record or write failure refuses success. Runtime errors are recorded when possible; failure to record them is itself visible. Zoli does not automatically truncate, rotate or repair a damaged audit log.

## Guarded npm ci

`zoli wrap npm -- ci` supports npm 10 and existing npm v2/v3 locks, including shrinkwrap precedence and scoped aliases. All recorded scopes are assessed. Missing publication time or age below the configured minimum blocks. A timestamp exactly 24 hours old passes the default age gate; future timestamps block. Full packument metadata must identify the exact version and contain strong integrity matching the acquired archive, so an old timestamp cannot approve different bytes.

Zoli requires complete feed/local evidence and an intact audit log before starting npm. It creates a private temporary quarantine/cache, seeds only approved archives with scripts disabled, reloads verified intelligence, rechecks project/config fingerprints, then invokes npm offline. The temporary directory is removed when the wrapper returns. Package manifests, locks and npmrc files are not edited; npm itself replaces node_modules as normal.

Only `--ignore-scripts` and `--foreground-scripts` are accepted after `ci`. Project npmrc supports `registry` and `@scope:registry` routing only. Operational overrides, missing/inconsistent locks, workspaces/local/Git sources, bundled dependencies without independent age evidence, and unsupported analysis content refuse installation. User npmrc credentials are used by Zoli's approved-origin downloader; npm receives empty user/global config files. Inherited `npm_config_*`, `NODE_OPTIONS` and `NODE_PATH` are removed, and the child uses the private cache with offline mode forced. Existing proxies are not used by Zoli's downloader.

Use `--ci` for automatic runs so suspicious evidence blocks. npm stdout/stderr and its exit code are inherited; `--json wrap` is a usage error. Audit scopes are `npm_ci_assessment`, `npm_ci_release`, `npm_ci_authorization` and `npm_ci_exit`. Authorization records bind project/config hashes, signed manifest hash/sequence, npm version, age policy and package count. A post-install audit failure returns an error even if npm already ran.

This gate controls the initial dependency installation. The local project scripts and approved dependency scripts run with normal user permissions; their arbitrary runtime network access, nested installers and local file changes are outside this guard's protection. A direct unwrapped npm invocation is also outside it. `serve`, shims and doctor remain unimplemented.
