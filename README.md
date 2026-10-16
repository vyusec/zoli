# Zoli

An install-time package firewall. Zoli wraps `npm` and related package managers, checks every package version they resolve against the signed [Zoli intel feed](https://github.com/vyusec/intel-feed), and blocks known-malicious or too-new versions before their tarballs reach the machine.

- **One static Rust binary.** No account, token or runtime needed.
- **Local verdicts.** Lookups use a verified local copy of the feed, so installs never reveal your dependencies to a service.
- **Fails closed.** No error path, stale state or unimplemented command ever allows an install silently.

## Status

**Phase 0 complete (16 October 2026).** The command surface, crate layout, CI (green) and design documents exist. Nothing intercepts installs yet: every command exits with code 3 and does nothing. See [progress](docs/progress.md) for what is implemented versus validated.

## How it works

1. A shell shim turns `npm install foo` into `zoli wrap npm -- install foo`.
2. **Pre-flight:** exact versions in the arguments are checked before npm starts.
3. npm runs with `HTTPS_PROXY` pointing at a localhost proxy, and `NODE_EXTRA_CA_CERTS` trusting a per-machine CA. Only allowlisted registry hosts are inspected; everything else is tunnelled unchanged.
4. The proxy drops blocked or too-new versions from registry metadata and refuses blocked tarball downloads, which covers transitive dependencies and lockfile installs.

Verdicts come from a feed client that reproduces the Go reference client exactly. That requirement is the project's main technical risk, described in [ADR-004](docs/decisions/ADR-004-feed-client-faithfulness.md).

## Build

Requires rustup. The toolchain is pinned in `rust-toolchain.toml`.

```sh
make build        # cargo build --workspace --locked
make test
make ci           # fmt-check, clippy -D warnings, cargo-deny, build, test
```

`make deny` needs `cargo install --locked cargo-deny@0.20.2`.

## Layout

```text
crates/
  zoli-cli     the zoli binary
  zoli-intel   verified feed client and verdicts (Go-faithful)
  zoli-policy  allow / warn / block decisions, audit
  zoli-proxy   registry-scoped localhost proxy
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

## License

[Apache 2.0](LICENSE).
