# Zoli fixtures

Hand-written fixtures for Zoli-only behaviour that has no Go counterpart:

- package-manager argument parsing for pre-flight;
- shell rc files before and after shim install and uninstall;
- policy decision tables;
- audit-log lines.

Phase 1 controlled fixtures are constructed by the Rust integration tests in `zoli-inspect`, `zoli-pms`, `zoli-policy` and `zoli-cli`. They cover archives, local evidence, graph gaps, process exits, HTTPS authentication and audit behavior. The recorded timing output is in `../benchmarks/`.

Anything that defines Go verdict behavior belongs in `../conformance/` and is generated from Go. Package-manager preflight and shell integration fixtures remain Phase 2 work.
