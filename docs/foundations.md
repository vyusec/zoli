# Phase 1 and Phase 2 foundation gates

Updated 20 November 2026 (Asia/Kolkata). Phase 2's supported npm guard is implemented and locally validated, including locked `ci`, ad-hoc `install`, `npx`, shims and `doctor`. Other managers and `serve` remain unsupported; healthy deployed publication remains an operational gate. Hosted Linux/macOS CI passed for commit `00eb581` ([run](https://github.com/vyusec/zoli/actions/runs/44621477457)).

| Foundation | Evidence now | Remaining acceptance |
| --- | --- | --- |
| Authenticated intelligence | Signature/artifact/delta/cache checks; independent Rust rollback state; both clients reject same-sequence equivocation | Healthy deployed publication, broad Rust/Go/hosted agreement and withdrawal replay |
| Honest freshness | Common-clock Go/Rust query fixtures; missing sources and future timestamps over five minutes degrade; final-clock policy recheck | Observe healthy configured sources on the homelab |
| Complete assessment scope | Typed declarations; unsupported workspaces stay incomplete; bounded integrity-checked inspection | Representative real-project corpus; each new source format needs its own gate |
| Feed static lifecycle | Nine PostgreSQL integration tests in sibling intel-feed, including discovery → worker → review → signed publication → withdrawal, stale leases, rollback, budgets/retries/skips | Deployment and observed real discovery/review cycles |
| Locked npm enforcement | `wrap npm -- ci`: full recorded inventory, 24-hour age floor, metadata/lock/archive integrity binding, private approved cache, final input/feed recheck and durable audit; ten real npm integration tests | Healthy deployed-feed operation |
| Broader npm entry points | `wrap npm -- install` resolves with metadata only, assesses the exact tree, writes only approved inputs and installs offline; `wrap npx` runs only the declared executable; nine ad-hoc/npx tests; bash/zsh/fish and CI PATH shims; `doctor` | Non-npm managers, `serve`, and representative real-project coverage |
| Reproducibility | `make ci`, `make cache-conformance`, `make npm-guard-container` (19 guard/ad-hoc tests) | Release matrix remains Phase 4 |

## Ad-hoc install and npx design

Ad-hoc resolution is deliberately not a TLS interception proxy. `zoli wrap npm -- install` builds a temporary manifest, asks npm to resolve metadata with scripts disabled, then treats the resulting lockfile as untrusted input: it runs the same feed, freshness, age, integrity and local-inspection gates as `ci`. The project's `package.json` and lockfile are written only after complete approval, and npm installs offline from the approved cache. `npx` resolves into a temporary project, assesses it, installs offline, and executes only the selected package's declared `bin` with the approved tree on `PATH`.

Registry routes are checked before resolution, including scoped routes the requested tree does not use. Resolution metadata and approved artifacts use separate temporary caches. Source specs (`file:`, `link:`, `workspace:`, Git and URL forms), workspaces, unsupported options and `npm-shrinkwrap.json` edits for ad-hoc installs refuse. `npx` requires one package spec with an unambiguous executable. These constraints are tested; they are not a general npm resolver or a runtime sandbox.

## Measured cache bypass and its guard

`make npm-cache-probe` builds two inert packages, seeds a temporary npm cache with scripts disabled, stops its loopback registry, removes node_modules, points proxy settings at an unreachable port, and runs `npm ci --offline`. The transitive package installs and writes its local lifecycle marker.

The [recorded negative control](../testdata/benchmarks/phase2-warm-cache-linux.json) used Node v22.23.1/npm 10.9.8. It disproves the original proxy-only assumption. The guard addresses that path by approving the complete inventory before npm starts and giving npm only its private approved cache. A real populated user cache cannot bypass a malicious transitive verdict. Registry request counters establish that npm fetches no extra artifact after approval.

## Supported guard contract

1. Run `zoli wrap npm -- ci` for a locked install, `zoli wrap npm -- install [spec…]` for a project install, or `zoli wrap npx -- <spec> [args]` for an ad-hoc executable. npm 10 only. `ci` accepts only `--ignore-scripts` and `--foreground-scripts`; `install` additionally accepts `--save-dev`/`-D` and `--save-exact`/`-E`. Unsupported entry points, managers and options refuse.
2. Preserve existing manifest/lock/npmrc files during assessment. For ad-hoc installs, resolve metadata in a temporary directory, assess the exact resolved tree, and write the approved `package.json`/`package-lock.json` only after a complete approval.
3. Require at least 24 hours of publish age by default. Missing/future timestamps, mismatched metadata integrity, stale/degraded intelligence, unsupported content and audit failure stop installation. Bundled dependencies inherit the containing archive's publication age and integrity; they are not fetched separately.
4. Populate an invocation-private offline cache only with approved bytes, then reload intelligence and check unchanged inputs before npm starts. Resolution metadata uses a separate temporary cache; the user's npm cache is never used.
5. Preserve npm output and status, with diagnostics on stderr and structured audit records. Approved lifecycle scripts execute normally. This is not an OS sandbox: the local project, executable PATH and scripts remain trusted, and nested installers are not covered. `npx` runs only the selected package's declared executable from a temporary approved installation.
6. `zoli shims install --shell <bash|zsh|fish>` and `zoli shims install --ci` provide command-level integration; `zoli doctor` reports feed, npm, permission, shim and project prerequisites. These do not widen the underlying guard's scope.

`serve` proxy interception is not implemented. The approved-cache design enforces the supported npm entry points without a local CA or TLS interception listener; the proxy remains a deferred option for future managers or resolution modes.

See [configuration](configuration.md#guarded-npm-installation), [ADR-002](decisions/ADR-002-interception.md) and [dated evidence](validation.md#phase-2-completion--20-november-2026). A successful fixture run does not establish live feed health, general malware-detection accuracy, support for unimplemented managers or protection for nested installers. Those claims continue to require their own evidence.
