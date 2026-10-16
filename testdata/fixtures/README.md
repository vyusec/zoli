# Zoli fixtures

Hand-written fixtures for Zoli-only behaviour that has no Go counterpart:

- package-manager argument parsing for pre-flight;
- shell rc files before and after shim install and uninstall;
- policy decision tables;
- audit-log lines.

Anything that touches verdicts belongs in `../conformance/` and is generated from Go. Empty until Phase 1.
