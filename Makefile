.PHONY: build test fmt fmt-check conformance-check cache-conformance clippy deny ci
INTEL_FEED ?= ../intel-feed

build:
	cargo build --workspace --locked

test:
	cargo test --workspace --locked

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

conformance-check:
	python3 tools/generate-conformance.py --verify

# Development gate requiring the pinned Go source and already cached modules.
cache-conformance:
	ZOLI_CONFORMANCE_CACHE_OUT="$(CURDIR)/target/rust-caches" cargo test -p zoli-intel --locked --test conformance signed_snapshots_and_deltas_match_go
	python3 tools/generate-conformance.py --intel-feed "$(INTEL_FEED)" --check --rust-caches target/rust-caches

clippy:
	cargo clippy --workspace --all-targets --locked -- -D warnings

deny:
	cargo deny --locked check

# Core host gates. Linux CI also runs npm-guard-container.
ci: fmt-check conformance-check clippy deny build test

# Negative control: proves why Phase 2 must control the npm cache before execution.
.PHONY: npm-cache-probe
npm-cache-probe:
	python3 tools/probe-npm-cache.py

# Linux development runtime in Docker, no external network or host mounts.
.PHONY: npm-guard-container
npm-guard-container:
	python3 tools/test-npm-guard-container.py
