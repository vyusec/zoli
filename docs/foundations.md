# Phase 1 and Phase 2 foundation gates

Updated 30 October 2026 (Asia/Kolkata). The user subsequently authorized beginning [Phase 3](phase3-python.md). Local foundation hardening and the first locked npm guard are implemented; deployment and broader Phase 2 scope retain separate acceptance gates.

| Foundation | Evidence now | Remaining acceptance |
| --- | --- | --- |
| Authenticated intelligence | Signature/artifact/delta/cache checks; independent Rust rollback state; both clients reject same-sequence equivocation | Healthy deployed publication, broad Rust/Go/hosted agreement and withdrawal replay |
| Honest freshness | Common-clock Go/Rust query fixtures; missing sources and future timestamps over five minutes degrade; final-clock policy recheck | Observe healthy configured sources on the homelab |
| Complete assessment scope | Typed declarations; unsupported workspaces stay incomplete; bounded integrity-checked inspection | Representative real-project corpus; each new source format needs its own gate |
| Feed static lifecycle | Nine PostgreSQL integration tests in sibling intel-feed, including discovery → worker → review → signed publication → withdrawal, stale leases, rollback, budgets/retries/skips | Deployment and observed real discovery/review cycles |
| Locked npm enforcement | `wrap npm -- ci`: full recorded inventory, 24-hour age floor, metadata/lock/archive integrity binding, private approved cache, final input/feed recheck and durable audit; nine real npm integration tests | Hosted Linux/macOS CI and healthy deployed-feed operation |
| Broader npm entry points | Unsupported commands, options, workspaces and bundled-age gaps refuse execution | Ad-hoc install/npx, other managers, supported bundled publication evidence, shell/PATH integration and doctor |
| Reproducibility | `make ci`, `make cache-conformance`, `make npm-guard-container`; feed `make ci` and disposable PostgreSQL gate | Release matrix remains Phase 4 |

## Measured cache bypass and its guard

`make npm-cache-probe` builds two inert packages, seeds a temporary npm cache with scripts disabled, stops its loopback registry, removes node_modules, points proxy settings at an unreachable port, and runs `npm ci --offline`. The transitive package installs and writes its local lifecycle marker.

The [recorded negative control](../testdata/benchmarks/phase2-warm-cache-linux.json) used Node v22.23.1/npm 10.9.8. It disproves the original proxy-only assumption. The guard addresses that path by approving the complete inventory before npm starts and giving npm only its private approved cache. A real populated user cache cannot bypass a malicious transitive verdict. Registry request counters establish that npm fetches no extra artifact after approval.

## Supported guard contract

1. Run `zoli wrap npm -- ci` explicitly with npm 10. Only `--ignore-scripts` and `--foreground-scripts` are supported options. Unsupported entry points refuse.
2. Preserve existing manifest/lock/npmrc files. Bind approval to their fingerprints, exact installed identities, artifact digests, local rule provenance, registry metadata and signed publication.
3. Require at least 24 hours of publish age by default. Missing/future timestamps, mismatched metadata integrity, stale/degraded intelligence, unsupported content and audit failure stop installation.
4. Populate an invocation-private offline cache only with approved bytes, then reload intelligence and check unchanged inputs before npm starts. Do not inherit the user's cache or operational npm configuration.
5. Preserve npm output and status, with diagnostics on stderr and structured audit records. Approved lifecycle scripts execute normally. This is not an OS sandbox: the local project, executable PATH and scripts remain trusted, and nested installers are not covered.

See [configuration](configuration.md#guarded-npm-ci), [ADR-002](decisions/ADR-002-interception.md) and [dated evidence](validation.md#foundation-hardening--30-october-2026). A successful fixture run does not establish live feed health, general malware-detection accuracy or support for unimplemented managers. Those claims continue to require their own evidence during Phase 3 development.
