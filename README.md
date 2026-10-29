# Zoli

An install-time package firewall. Zoli is being built to wrap `npm` and related package managers, check resolved package versions against the signed [Zoli intel feed](https://github.com/vyusec/intel-feed), inspect package contents locally, and block disallowed artifacts before they reach the package manager or their install scripts run.

- **One Rust binary.** No Node.js, Python or Go runtime, and no intelligence-service account. Static Linux release builds are a later gate.
- **Local verdicts.** Lookups use a verified local copy of the feed, so installs never reveal your dependencies to a service.
- **Fails closed.** No error path, stale state or unimplemented command ever allows an install silently.

## Status

**Phase 0 complete; Phase 1 implemented and validated locally (hardened and revalidated 30 October 2026).** Working commands verify and cache the signed feed, check exact npm identities, inspect local archives, and assess npm lockfile dependencies using both feed checks and static analysis. Live HTTPS delivery, Rust/Go cache agreement and one hosted lookup were verified against a degraded feed; healthy-source acceptance remains pending. Phase 2 now implements guarded `npm ci` with a 24-hour minimum publish age and a private approved offline cache. Other commands/managers, `serve`, `shims`, and `doctor` still refuse operation. See [progress](docs/progress.md) and [validation](docs/validation.md#foundation-hardening--30-october-2026).

## Assess packages

Configure a pinned public HTTPS feed URL and Ed25519 key in `$ZOLI_HOME/config.json` (default `~/.zoli`). See [configuration](docs/configuration.md) for the exact schema and private registry permissions.

```sh
zoli update
zoli status
zoli check --eco npm --name left-pad --ver 1.3.0
zoli check --eco PyPI --name example-package --ver 1.0.0
zoli inspect ./package.tgz --eco npm --name example --ver 1.0.0
zoli scan --lockfile ./package-lock.json --json --ci
```

`check` uses only the feed for npm or PyPI, with optional `--sha256` artifact selection. PyPI currently supports exact versions and OSV event ranges; constraint-string ranges refuse until parity is implemented. Python installation remains gated.

`check` uses only the feed; `inspect` uses only the local artifact. `scan` combines verified intelligence, the exact dependency graph, integrity-checked registry downloads, and isolated static inspection. npm lockfiles v2/v3 and explicitly approved private HTTPS registries are supported. No package code or lifecycle hook executes during assessment.

Malicious feed matches block, including uncertain matches. Suspicious feed or local findings warn interactively and block in CI. Intelligence older than one hour, degraded sources, or missing freshness evidence block. Unsupported content and missing dependency coverage produce a nonzero incomplete result. Every released report is audited first.

Static checks cover credential data flowing to requests, downloaded data flowing to execution, and decoded constants flowing to dynamic execution. Findings carry artifact identity, file/line evidence, rule versions, and limitations. A completed scan without findings does not prove safety. There is no speed target or analysis-result cache yet.

The [foundation acceptance matrix](docs/foundations.md) records remaining Phase 1/2 acceptance gates. [Phase 3 development](docs/phase3-python.md) has begun at the user’s request.

## Guarded npm installation (Phase 2)

```sh
zoli wrap npm -- ci
zoli --ci wrap npm -- ci --foreground-scripts
```

Requires npm 10, a supported v2/v3 lockfile and a fresh verified feed. Zoli checks every recorded dependency, obtains full registry publication metadata, requires at least **24 hours** of publish age, verifies both lockfile and registry integrity, and statically inspects quarantined artifacts. Only a complete approval populates an invocation-private cache. Zoli then rechecks project inputs and the current feed before running npm offline.

npm output and exit status are preserved; Zoli diagnostics go to stderr and structured reports to the audit log. `--ignore-scripts` and `--foreground-scripts` are the only supported npm options. See [configuration](docs/configuration.md#guarded-npm-ci) for supported routing and explicit refusals. The project and approved lifecycle scripts remain trusted execution; this is not a runtime sandbox.

Ad-hoc installs, npx, other managers, workspaces and bundled dependencies are not yet supported by this guard. Their gates remain open in [foundations](docs/foundations.md).

Verdicts come from a feed client that reproduces the Go reference client exactly. That requirement is the project's main technical risk, described in [ADR-004](docs/decisions/ADR-004-feed-client-faithfulness.md).

## Build

Requires rustup. The toolchain is pinned in `rust-toolchain.toml`. `make ci` also uses Python 3 for fixture provenance checks and Node 22/npm 10.9.8 for real install tests. Go is needed only to regenerate the development fixtures, not to build or run Zoli.

```sh
make build        # cargo build --workspace --locked
make test
make ci           # fmt-check, fixture provenance, clippy -D warnings, cargo-deny, build, test
make npm-guard-container # Linux Docker gate; no external network or host mounts
```

`make deny` needs `cargo install --locked cargo-deny@0.20.2`.

## Layout

```text
crates/
  zoli-cli     the zoli binary
  zoli-intel   verified feed client and verdicts (Go-faithful)
  zoli-inspect bounded archive and JavaScript/TypeScript inspection
  zoli-policy  allow / warn / block decisions, audit
  zoli-proxy   approved registry acquisition; interception in Phase 2
  zoli-pms     package-manager adapters
  zoli-shell   shell shims and CI PATH mode
docs/          architecture, roadmap, progress, validation, threat model,
               configuration, shell integration, decisions/ (ADRs)
testdata/      conformance/ (Go-generated), mock-registry/, fixtures/
```

## Documentation

- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md), [progress](docs/progress.md), [validation](docs/validation.md)
- [Threat model](docs/threat-model.md)
- [Configuration](docs/configuration.md), [shell integration](docs/shell-integration.md)
- Decisions: [ADR-001](docs/decisions/ADR-001-rust.md) · [ADR-002](docs/decisions/ADR-002-interception.md) · [ADR-003](docs/decisions/ADR-003-intel-sources.md) · [ADR-004](docs/decisions/ADR-004-feed-client-faithfulness.md) · [ADR-005](docs/decisions/ADR-005-trust-bootstrap.md)
- [Local package analysis and performance priorities (ADR-006)](docs/decisions/ADR-006-local-package-analysis.md)

## License

[Apache 2.0](LICENSE).
