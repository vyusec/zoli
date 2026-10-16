# Validation evidence

Each entry records what was actually run, the results, and what the evidence does not show.

## Phase 0 — 16 October 2026

### Environment

| Item | Value |
| --- | --- |
| OS | Fedora 44, Linux 7.2.7-200.fc44.x86_64 |
| Rust | rustc 1.98.0 (88d9e12ae 2026-08-18), cargo 1.98.0 (797e8a9bc 2026-08-05), selected through `rust-toolchain.toml` |
| rustup | 1.29.1 |
| cargo-deny | 0.20.2, installed with `cargo install --locked cargo-deny@0.20.2` |
| `Cargo.lock` | SHA-256 `cc77f412858ba10e89c87f552f9acd519b74885c50ae04fb4de192b194faaa8e` |
| Git | Repository initialised with no commits and no remote, so there is no commit hash to attach |

### Results

| Check | Command | Result |
| --- | --- | --- |
| Full local CI from a clean target directory | `cargo clean && make ci` | Passed (exit 0) |
| Formatting | `cargo fmt --all --check` | Passed |
| Lints | `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed, no warnings |
| Supply chain | `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok` |
| License policy is enforced | Allowlist narrowed to `Apache-2.0` only, then restored | Failed as expected (`error[rejected]: failed to satisfy license requirements`); passed again after restore |
| Build | `cargo build --workspace --locked` | Passed |
| Tests | `cargo test --workspace --locked` | 11 passed, 0 failed, 0 ignored: 5 CLI integration, 3 `zoli-intel`, 3 `zoli-pms` |
| Fail-closed stubs | `zoli check --eco npm --name left-pad --ver 1.3.0`, `zoli serve` | Exit 3, nothing on stdout, explanatory stderr |
| Wrap never runs the package manager | Integration test with a fake `npm` first on `PATH` | The marker file was never created |
| Documentation links | Relative links and anchors in every Markdown file | All resolve (checked with a local script) |

### What this does not show

- **Hosted CI.** No GitHub Actions run has been observed. `.github/workflows/ci.yaml` is a definition, not a result. The macOS test job has not run anywhere.
- **Release builds.** Release, musl static and macOS builds were not attempted; they belong to Phase 4.
- **Go-side claims.** Statements in ADR-004 and in the roadmap's plan corrections about Go behaviour come from reading the intel-feed source at the 16 October baseline. For the files cited, that source is blob-identical to `vyusec/intel-feed@7919b85`. No Go code was executed in this pass. The Phase 1 fixtures turn those readings into evidence.
- **Behaviour.** No feed, proxy, shim or policy behaviour exists yet, so none was validated.

### Reproduce

```sh
rustup toolchain install          # reads rust-toolchain.toml
cargo install --locked cargo-deny@0.20.2
cargo clean
make ci
```
