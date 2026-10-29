# Mock registry

Phase 1 controlled HTTPS tests live in `crates/zoli-cli/tests/registry.rs` and `assessment.rs`, using `tests/support/mod.rs`. They serve fixture tarballs on a loopback port with real rustls TLS and exercise explicit private-network permission, custom CA trust, redirects, auth scoping, strongest SRI and report redaction.

`tls/ca.pem`, `server.pem` and `server.key` are **public test fixtures only**. Never trust or deploy them outside these controlled tests. The server certificate is for localhost/127.0.0.1. Tests add this CA only to their explicitly configured endpoint; production trust and feed public-network restrictions remain intact. Tests use a local signed synthetic feed cache and do not demonstrate deployed feed delivery.

The Phase 2 registry and real npm tests live in `crates/zoli-cli/tests/npm_guard.rs`. They serve controlled packuments and tarballs for direct/transitive dependencies and exercise the private offline cache, malicious-feed blocking, publish age, artifact integrity, scoped aliases/private authentication, changed inputs, audit failures and npm output/exit status.

`tools/test-npm-guard-container.py` runs the same nine tests in a container without external networking or host mounts. All registry data and lifecycle hooks are synthetic; these tests do not demonstrate production registry or deployed-feed readiness.
