.PHONY: build test fmt fmt-check clippy deny ci

build:
	cargo build --workspace --locked

test:
	cargo test --workspace --locked

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets --locked -- -D warnings

deny:
	cargo deny --locked check

# Same steps, same order as .github/workflows/ci.yaml.
ci: fmt-check clippy deny build test
