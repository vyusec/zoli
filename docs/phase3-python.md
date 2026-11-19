# Phase 3: Python adapters

Started 30 October 2026 at the user's request. This supersedes the earlier development hold. Phase 2's supported npm guard was completed locally on 20 November; its healthy deployment and hosted-CI gates remain visible and do not become passing evidence merely because Phase 3 has started.

## Acceptance milestones

The user's 20% goal is the first of five acceptance milestones below. Each milestone counts for 20% of this delivery checklist, not an estimate of elapsed engineering effort. A milestone counts only after all its checks pass; partial implementation is not rounded up.

| Milestone | Required outcome | Status |
| --- | --- | --- |
| 1 — Matching and pinned inputs (20%) | Concrete versions and constraint strings agree with the pinned Go feed; strict requirements input preserves every supported pin or explicit gap; bounded parsers, CLI/audit regressions, npm regressions and documented semantics/limits | Complete locally; [evidence](validation.md#phase-3-matching-and-input-milestone--30-october-2026) |
| 2 — Wheel acquisition and inspection (20%) | Approved destinations, verified hashes and exact wheel metadata, bounded ZIP/RECORD inspection and explicit Python analysis coverage; no build backend execution | Pending |
| 3 — Complete dependency selection (20%) | Dependencies, extras/markers and target interpreter/platform are accounted for; missing or unsupported selections refuse completion | Pending |
| 4 — Guarded pip and bypass tests (20%) | Approved private wheelhouse, final input/feed recheck, real pip execution/output/status tests and warm-cache/replaced/yanked/relisted artifact regressions | Pending |
| 5 — Other Python adapters (20%) | uv, poetry and pipx each pass their own resolution/configuration/cache and execution gates | Pending |

Milestone 1 must include a reproducible Go constraint oracle (operators, intersections, exclusions, wildcard/epoch/local/prerelease boundaries and invalid inputs), process-level checks with signed feed fixtures, resource-limit and input-confusion tests, and readable modules with explicit contracts. Full Python installation protection remains gated on the later milestones.

## Implemented foundation

`zoli check --eco PyPI --name Some_Package --ver 1.0.0` now performs an authenticated, audited feed-only check. Name/ecosystem/registry normalization follows the Go feed. Exact versions and OSV `ECOSYSTEM`/`SEMVER` event ranges use a Rust port of the Go concrete PyPI comparator, with epochs, release padding, prereleases, post/dev releases and local labels. This preserves the reference's actual behavior, including its limits; it does not claim complete equivalence with pip's resolver.

An optional `--sha256 <64-hex-digits>` selects an artifact. Missing hashes preserve uncertainty for hash-scoped findings, and changing the hash cannot bypass a package/version-wide finding. A withdrawn claim is excluded. Freshness, suspicious/CI handling and audit requirements use the existing policy path.

Constraint strings now use the Go-compatible interval matcher. Invalid constraint syntax preserves the Go `uncertain` result and reasons; malicious uncertain findings still block. Oversized inputs/interval work and unsupported event boundaries refuse the whole query, even if another affected entry already matches. Arbitrary requirement ranges are not resolved. Local Python artifact inspection and Python installation are not implemented by this slice.

`zoli-pms::requirements` adds the first pip input component: a bounded, nonexecuting reader for `name==version --hash=sha256:...` declarations, including multiple hashes, comments and line continuations. Every unsupported line becomes a visible gap. Includes, constraint files, markers/extras, URL/editable/local sources, index overrides, missing hashes and duplicate package pins cannot be silently skipped. The `complete_pins()` accessor returns pins only when no gaps remain. File reading rejects symlinks and special files; UTF-8, byte/line limits and control characters are checked. Pin versions must satisfy both the PyPA version grammar and the bounded Go parser; permissive feed-only spellings such as `1..a1` cannot become installer inputs. Configuration errors are distinct from input gaps, and diagnostics never echo source URLs or secrets. This is a library component for the future adapter, not a new CLI command or a complete transitive dependency graph. The eventual installer must bind and recheck input bytes; the reader alone does not protect against concurrent hostile filesystem mutation.

## Matching contract and developer guide

The reference remains the inventoried `intel-feed/third_party/semver` implementation. The oracle executes actual Go comparison, constraint matching and `api.QueryAt`; expected verdicts are never maintained by hand. Current coverage is 6,084 concrete comparisons, 29,973 constraint cases, another 100,000 fixed-seed comparison/constraint cases, and 66 byte-exact queries across both ecosystems. Five signed Go PyPI snapshots also exercise the Rust CLI. See the [expanded test report](phase3-test-report.md). It is a finite compatibility corpus, not a proof for every possible input.

- `zoli-intel/src/pypi.rs` parses and compares concrete versions. `pypi/constraints.rs` owns wildcard boundary construction, interval intersections and Go-specific matching filters. It does not call Python or a resolver.
- `query.rs` keeps policy-independent feed verdicts. Syntax errors remain uncertainty; typed resource errors abort a query. Limits apply before returning a partial result.
- `zoli-pms/src/requirements.rs` owns the stricter installer-input grammar and completeness accessor. Do not reuse permissive feed normalization as permission to execute a package manager.
- CLI/process tests use signed synthetic publications and verify exit status, artifact scope, policy and exact durable audit output. Existing npm tests cover the shared query/policy paths.

The matcher accepts `==`, `!=`, `<`, `<=`, `>`, `>=`, `~=` and conjunctions using the reference's rules. Notable reference behaviors are deliberately visible:

| Case | Pinned Go behavior |
| --- | --- |
| Local versions | A point such as `==1.0+abc` can match. Vector ranges such as `>=1,<2` exclude local versions; this differs from normal PEP 440 local-label handling |
| Prerelease/dev versions | Inclusion depends on the final interval endpoints and whether the lower endpoint is open; it is not pip's candidate-selection policy |
| Conjunction syntax | Adjacent operators and whitespace conjunctions are accepted alongside commas; `===` is unsupported |
| Coincident open endpoints | `>1,<=1` matches `1` because Go turns coincident endpoints into a point; the oracle locks down this compatibility quirk |
| Epochs and numeric overflow | Epochs are limited to 0–255. `<2!0` becomes empty because Go tests its zero release tuple; upper sentinels retain their originating epoch. Suffix overflow and boundary reconstruction also follow the pinned Go code |
| Repeated exclusions | `!=1,!=2` excludes `1`, but repeating the pair restores it in the pinned dependency. This is a confirmed reference defect, retained explicitly for compatibility |
| Equal sentinel boundaries | Go stores a unit interval's lower endpoint in both slots, including when its plain exclusion sentinel compares equal to an epoch-qualified boundary. `<2,!=2!0` consequently excludes `1` |
| Label ordering | Local label case is significant; post-release local labels may compare equal; `1.0a1` and `1.0a1.post0` compare equal. Independent PyPA checks expose these differences |

These are feed-compatibility behaviors, not a claim of complete PEP 440 or pip equivalence. Correcting reference quirks requires coordinated feed/client changes and regenerated fixtures. Source distributions, wheel selection and pip candidate resolution are outside this milestone.

Limits are explicit: 1,024 bytes and 64 release components per version, 8,192 bytes and 128 terms per constraint, and 129 intermediate intervals. Identity validation also retains its existing 200-byte version limit. Requirements files allow at most 1 MiB and 10,000 physical lines, counting comments and continuations. Exhaustion cannot be treated as a successful non-match or a complete input file.

The strict requirements subset treats a BOM, non-ASCII whitespace around pins, and PEP 263 encoding declarations in the first two physical lines as explicit gaps. This includes declarations naming UTF-8: no alternate decoding instruction is interpreted. Ordinary Unicode comments remain comments. `complete_pins()` refuses the whole input when any gap exists.

## Remaining implementation gates

| Work | Required evidence |
| --- | --- |
| Wheel acquisition and inspection | Approved HTTPS indexes/artifact origins; SHA-256, exact metadata identity, bounded ZIP/RECORD handling and Python inspection coverage; no build backend execution |
| Complete dependency selection | Wheel metadata dependencies, extras/markers and target interpreter/platform agreement; absent or unsupported dependencies refuse |
| Guarded pip installation | A private approved wheelhouse, explicit hash pins, disabled index/cache/build resolution and a final feed/input recheck before pip starts; preserve output/status |
| Cache and relisting | Real pip fixtures prove warm caches, replaced artifacts, yanked/relisted releases and changed feeds cannot release unapproved bytes |
| Additional adapters | uv, poetry and pipx each need their own resolution/configuration/cache and execution gates |

Source distributions and PEP 517 build hooks need a separate design because metadata generation may execute code. They must not be used as an implicit shortcut while assessing packages.

Development follows the user's CPU preference: one validation job at a time, one compiler/test worker, low scheduling priority and a 50%-of-one-core cgroup cap for heavy local commands. Ratatui remains the selected future presentation layer; it does not change these enforcement gates.

References: [PyPA version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/), [pip requirements format](https://pip.pypa.io/en/stable/reference/requirements-file-format/), [validation](validation.md#phase-3-matching-and-input-milestone--30-october-2026).
