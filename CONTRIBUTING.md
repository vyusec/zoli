# Contributing

## Before opening a change

- Run `make ci` with Node 22/npm 10.9.8 available for real install tests. Linux CI additionally runs `make npm-guard-container`; use that Docker gate for guard changes.
- Keep changes inside the phase being worked on ([roadmap](docs/roadmap.md)).

## Rules that protect the guarantees

- **Never allow silently.** Every new error path, timeout and unknown state must end in a block, an error exit or a logged, visible decision. Add a test that proves it.
- **Verdicts follow Go.** A change to `zoli-intel` verdict behaviour must match the Go reference client and be backed by Go-generated fixtures (ADR-004). Policy changes go in `zoli-policy` and never touch verdicts.
- **Fixtures are generated.** Files under `testdata/conformance/` come from the intel-feed generator. Regenerate them; never edit them by hand.
- **Fixture provenance.** `make conformance-check` verifies committed hashes without Go. For oracle changes, run `python3 tools/generate-conformance.py --intel-feed ../intel-feed`, then repeat with `--check`. See `testdata/conformance/README.md` for coverage and limitations.
- **No new network egress.** Only `zoli-intel` (feed) and `zoli-proxy` (registries) open connections.
- **Dependencies.** A new crate must pass `cargo deny`. A new license needs an allowlist entry in `deny.toml`, with the reason in the commit message.
- **No `unsafe`.** It is forbidden workspace-wide.

## Decisions

Write or amend an ADR in `docs/decisions/` for any change to the trust chain, interception approach, intelligence sources, policy defaults or supported platforms. Mark unconfirmed parts *(proposed)*.

## Progress records

When a gate passes, update [progress](docs/progress.md) and [validation](docs/validation.md) with:

- the date;
- the exact commands and results;
- tool versions;
- what the evidence does *not* show.

A workflow file or passing unit tests are not evidence for a gate that needs a live system.
