# Phase 3: Python adapters

Started 30 October 2026 at the user's request. This supersedes the earlier development hold. Remaining Phase 1/2 acceptance gaps stay visible and do not become passing evidence merely because Phase 3 has started.

## First implemented slice

`zoli check --eco PyPI --name Some_Package --ver 1.0.0` now performs an authenticated, audited feed-only check. Name/ecosystem/registry normalization follows the Go feed. Exact versions and OSV `ECOSYSTEM`/`SEMVER` event ranges use a Rust port of the Go concrete PyPI comparator, with epochs, release padding, prereleases, post/dev releases and local labels. This preserves the reference's actual behavior, including its limits; it does not claim complete equivalence with pip's resolver.

An optional `--sha256 <64-hex-digits>` selects an artifact. Missing hashes preserve uncertainty for hash-scoped findings, and changing the hash cannot bypass a package/version-wide finding. A withdrawn claim is excluded. Freshness, suspicious/CI handling and audit requirements use the existing policy path.

PyPI constraint-string ranges and malformed event boundaries currently refuse the query rather than emit a verdict with different matching semantics. Arbitrary requirement ranges are not resolved. Local Python artifact inspection and Python installation are not implemented by this slice.

`zoli-pms::requirements` adds the first pip input component: a bounded, nonexecuting reader for `name==version --hash=sha256:...` declarations, including multiple hashes, comments and line continuations. Every unsupported line becomes a visible gap. Includes, constraint files, markers/extras, URL/editable/local sources, index overrides, missing hashes and duplicate package pins cannot be silently skipped. This is a library component for the future adapter, not a new CLI command or a complete transitive dependency graph.

## Remaining implementation gates

| Work | Required evidence |
| --- | --- |
| PyPI constraint parity | Go-generated constraint matrix plus documented pip/PEP 440 differences; no permissive fallback |
| Wheel acquisition and inspection | Approved HTTPS indexes/artifact origins; SHA-256, exact metadata identity, bounded ZIP/RECORD handling and Python inspection coverage; no build backend execution |
| Complete dependency selection | Wheel metadata dependencies, extras/markers and target interpreter/platform agreement; absent or unsupported dependencies refuse |
| Guarded pip installation | A private approved wheelhouse, explicit hash pins, disabled index/cache/build resolution and a final feed/input recheck before pip starts; preserve output/status |
| Cache and relisting | Real pip fixtures prove warm caches, replaced artifacts, yanked/relisted releases and changed feeds cannot release unapproved bytes |
| Additional adapters | uv, poetry and pipx each need their own resolution/configuration/cache and execution gates |

Source distributions and PEP 517 build hooks need a separate design because metadata generation may execute code. They must not be used as an implicit shortcut while assessing packages.

Development follows the user's CPU preference: one validation job at a time, one compiler/test worker, low scheduling priority and a 50%-of-one-core cgroup cap for heavy local commands. Ratatui remains the selected future presentation layer; it does not change these enforcement gates.

References: [PyPA version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/), [pip requirements format](https://pip.pypa.io/en/stable/reference/requirements-file-format/), [validation](validation.md#phase-3-kickoff--30-october-2026).
