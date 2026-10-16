# ADR-002: Proxy plus pre-flight interception

- Status: Accepted, 16 October 2026. Items marked *(verify in Phase 2)* are assumptions the Phase 2 Docker gate must confirm.

## Context

Zoli must stop a malicious or too-new package version before its bytes reach the machine. That includes transitive dependencies and installs from lockfiles (`npm ci`), which fetch tarballs from recorded `resolved` URLs without reading registry metadata. Zoli must do this without editing project files, lockfiles or `.npmrc`, and it must cover npm, npx, pnpm and Yarn, with Bun best-effort.

## Decision

Two layers. The proxy enforces; pre-flight gives early, readable answers.

1. **Pre-flight (`zoli wrap`).** Before starting the package manager, Zoli reads direct install arguments such as `npm install foo@1.2.3` or `npx foo@1.2.3`. Exact versions are checked immediately, and a block stops the run before the package manager starts. Names without a version, and ranges, cannot be resolved without the registry. Pre-flight leaves those to the proxy and never treats them as allowed.
2. **Proxy (`zoli serve`).** A listener on `127.0.0.1` only. `zoli wrap` starts the package manager with `HTTPS_PROXY` (plus per-manager equivalents) pointing at it.
   - A `CONNECT` to an allowlisted registry host (npm: `registry.npmjs.org` plus configured registries) is answered with TLS using a leaf certificate from the local CA (ADR-005).
   - A `CONNECT` to any other host is tunnelled byte-for-byte, without inspection.
   - **Metadata responses (packuments):** versions that policy blocks, or that are younger than the minimum publish age, are removed, and `dist-tags` that pointed at them are rewritten. Removal comes with a notice on stderr and in the audit log.
   - **Tarball requests (`/<name>/-/<file>.tgz`):** the URL is mapped to a name and version and evaluated. A block returns HTTP 403 with an explanatory body. This layer catches lockfile installs that skip metadata.
   - Tarballs are never modified. The package manager's own integrity checks stay meaningful.
3. **Process-scoped trust.** The CA is trusted through `NODE_EXTRA_CA_CERTS` in the wrapped process's environment, and only there. v1 never modifies system or keychain trust stores.

## Consequences

- **Fail closed when Zoli is down.** If the proxy is not running, the wrapped package manager cannot reach the registry.
- **Escape hatches remain a residual risk:** unaliased binaries, absolute paths, Corepack shims and environment overrides. They are listed in the threat model and reduced by PATH shims in CI.
- **Explicit `ca`/`cafile` in `.npmrc`.** Node documents that an explicit `ca` option replaces both the default and the extra roots. Wrapped processes with such configuration are expected to fail TLS against the proxy. That fails closed, but breaks corporate setups until Zoli merges the user's CA bundle with its own. *(verify in Phase 2)*
- **Existing proxies.** A corporate `HTTPS_PROXY` must be chained as Zoli's upstream, not replaced.
- **Abbreviated npm metadata** (`application/vnd.npm.install-v1+json`) omits per-version publish times. Minimum-age enforcement then needs the full packument or a separate time lookup, and Phase 2 measures the cost. *(verify in Phase 2)*
- **Yarn Berry and Bun.** Both read proxy and CA settings from their own configuration. Each needs a per-manager adapter in `zoli-pms` and its own gate before it is promoted from best-effort. *(verify in Phase 2)*

## Alternatives considered

- **Registry override** (`npm_config_registry=http://127.0.0.1:<port>`). Needs no CA. However, lockfile `resolved` URLs and host-replacement rules differ between package managers, tarball URLs inside metadata need rewriting, and scoped registries in `.npmrc` take precedence. Kept as a fallback adapter for package managers that ignore proxy variables.
- **Lockfile and manifest scanning only.** Does nothing at fetch time and misses `npx` and ad-hoc installs.
- **Package-manager hooks** (lifecycle scripts, `.pnpmfile.cjs`). They run after the fetch, `--ignore-scripts` disables them, and each package manager needs its own.
- **System-wide CA with a transparent proxy.** The blast radius is too large and the change to the developer's machine too invasive.
