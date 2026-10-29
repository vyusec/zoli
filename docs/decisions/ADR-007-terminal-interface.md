# ADR-007: Ratatui for the terminal interface

- Status: Framework selected by the user, 30 October 2026. Integration is planned.
- Reference: [Ratatui official documentation](https://ratatui.rs/).

## Decision

Use Ratatui for Zoli's interactive terminal interface. Ratatui is a Rust TUI library and fits the existing Rust application. The crate version, terminal backend, command entry point and screen design will be chosen during implementation.

The TUI will consume the same assessment, feed-status and audit models as the CLI. Verification, acquisition, inspection, policy and durable audit remain in their existing layers. Rendering and keyboard input must not introduce a second decision path or weaken an incomplete/blocked result.

## Integration requirements

- Keep plain human output and JSON available for automation, redirected output and CI. Interactive rendering requires a suitable terminal.
- Present freshness, dependency paths, findings, completeness and block reasons explicitly. Progress must distinguish assessment from authorization.
- Restore terminal state on normal exit, errors and interruption. Before an approved package manager starts, restore the terminal and hand it normal stdin/stdout/stderr; preserve its exit status.
- Test rendering/state transitions independently from the assessment core, then verify terminal resize, cancellation, non-TTY behavior and npm output handoff.

This records the UI choice without adding a runtime dependency or implementing screens. Phase 1/2 acceptance gates remain recorded; the user subsequently authorized beginning [Phase 3](../phase3-python.md) on 30 October. The intel-feed service continues to supply the existing intelligence contracts.
