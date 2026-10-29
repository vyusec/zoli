# ADR-006: Local package analysis alongside verified feed verdicts

- Status: Accepted 17 October; Phase 1 implementation and local validation complete 18 October. The user confirmed static analysis plus feed checks, npm first, and correctness ahead of speed. Live feed comparison was explicitly deferred.

## Context

ADR-003 and the original Phase 1 cover consumption of the signed threat feed. That detects reported packages but does not inspect an unreported package's code. The requested tool must also break down dependencies and find suspicious behavior in package contents.

The local intel-feed source already implements selective static analysis and a separate runtime runner. Its progress record still lists live validation gates. Consuming those reports is useful, but does not establish that any particular package artifact has been analyzed. Zoli needs its own explicit record of what it inspected.

## Decision

Phase 1 adds local static analysis after the verified feed core, before Phase 2 integrates it into installs. npm registry packages come first. The local analyzer executes no package code, lifecycle hooks, imports, builds or package-provided commands. Runtime detonation is a separate future project requiring its own isolation design.

### Evidence stays separate

1. **Feed verdict**: the unchanged Go-compatible query result from `zoli-intel`, including matches, classification, certainty, coverage, sequence and freshness.
2. **Dependency inventory**: resolved identities, parent paths, registry, versions, integrity values, scope and resolution gaps, produced by `zoli-pms`.
3. **Local analysis report**: artifact digest, analyzer/rule versions, effective limits/platform, located evidence, files examined, gaps and completion state, produced by network-free `zoli-inspect`.
4. **Policy decision**: allow, warn or block with a named reason, produced by `zoli-policy` from all the above. A suspicious local signal does not rewrite the feed or become a confirmed-malicious report.

`no_known_match` means only that the feed has no matching report. A completed static scan with no findings also does not prove safety. User output must name both results and describe coverage.

### Dependency breakdown

Start from `package.json` and an existing npm lockfile, initially `lockfileVersion` 2 and 3. Respect `npm-shrinkwrap.json` precedence. The inventory must reproduce the recorded tree, including multiple versions and the paths that introduce them. A bare version range is not a resolved dependency tree.

- Keep direct, transitive, development, optional and peer edges distinguishable. Include workspace links, aliases, bundled dependencies and platform constraints explicitly or record an unsupported edge.
- Use the actual alias target's identity for feed matching. Do not collapse packages by name alone or merge private registries with the public registry.
- Make every unresolved, unsupported, unavailable or excluded artifact visible in the aggregate completion state. Do not turn a missing optional artifact into a silently completed scan.
- The first inventory command requires an existing supported lockfile. Resolution without a lockfile, non-registry sources and install-time enforcement belong to later gates; do not invent a second npm resolver.

The implemented CLI is `zoli scan --lockfile <path> [--npmrc <trusted-file>]` for aggregate assessment, and `zoli inspect <archive> --eco npm --name <name> --ver <version>` for local-only analysis. Both support human/JSON output and interactive/CI policy.

`zoli check` remains an exact-identity feed assessment and must label that scope explicitly, including that local inspection was not performed. Its result alone cannot satisfy the future install gate, which requires the aggregate assessment. Finalize the report contract before either path can be used by an installer.

### Artifact boundary

Package bytes are untrusted. Downloading and inspecting them must not install them.

- Registry downloads stay in `zoli-proxy`; the analyzer opens no sockets. Offline local archives can be analyzed with an explicitly recorded origin.
- Compare the archive against supported lockfile/registry integrity metadata, and compute a SHA-256 content identity for the analysis report. A computed hash alone does not authenticate the publisher. Record missing or unsupported integrity information as a coverage gap.
- Read archive entries without extracting them into a project directory. Reject traversal, absolute paths, duplicate names, links and special files; bound archive size, expansion, file count, per-file bytes, recursion, parse effort and worker resources. Size checks include archive framing, not just retained text files.
- Preserve evidence against the original artifact digest and original file/line locations. Decode constant strings only with bounded transforms; record the transform chain.
- Unsupported syntax, native executables, WebAssembly, encrypted content and skipped large/binary files affect the completion report. Their absence from a text scan is not an all-clear.

Phase 2 must withhold the entire unapproved archive from the package manager until inspection and policy finish. Known blocked packages can be rejected before download; unknown packages may first be downloaded into Zoli's quarantine. Warm package-manager caches, lockfile installs, bundled artifacts and alternate download URLs need explicit bypass tests before install protection is claimed.

### First analysis coverage

Use deterministic, versioned rules with metadata and supported JavaScript/TypeScript syntax analysis. Track behavior combinations and reachability where supported; simple co-occurring patterns are investigation signals with that limitation attached.

| Area | Evidence to inspect | Interpretation |
| --- | --- | --- |
| Install execution | Lifecycle scripts, executable entry points, implicit native build hooks | A hook alone is informational; legitimate build tools use them |
| Credential access and transmission | Reads of credential/config paths or environment values combined with outbound requests | Suspicious evidence needs a trace or an explicit statement that only a pattern combination was observed |
| Payload loading | Network download followed by execution or dynamic import; shell/process launch | Explain the operations and triggering entry point |
| Obfuscation | Encoded constants, dynamic evaluation, concealed commands | Obfuscation or `eval` alone is not proof of malware |
| Artifact structure | Unexpected bundled dependencies, binaries, path tricks and identity mismatches | Reject unsafe structures; report unsupported content |
| Identity and release metadata | Name similarity and unusual metadata, when trustworthy data is available | Context for review; name similarity alone does not block as confirmed malware |

Each finding includes a stable rule ID/version, severity, confidence, explanation, original file/line, artifact digest and limitations. Keep severity and confidence distinct. Do not claim measured detection accuracy from a small synthetic corpus.

### Policy and completeness

The initial mode is thorough. A feed malicious match blocks. Suspicious feed/local findings warn interactively or block when configured; CI blocks suspicious findings. The exact local severity-to-action table is fixed and tested before the analyzer is connected to an allow path.

For the new scan commands, incomplete required analysis, integrity failure, unsupported input and analysis failure produce a non-zero result with a reason. Missing verified feed state cannot produce an allow. Informational observations alone need not become suspicious findings. Audit failures must be visible and cannot result in a silent successful allow.

The selected defaults are implemented: every malicious match blocks, including uncertain matches; suspicious local/feed findings warn interactively and block CI. Publication and all source timestamps have a hard one-hour bound. Any source error or missing freshness evidence blocks immediately. Local analysis does not make stale intelligence current.

### Implemented rule and resource contract

| Rule | Supported evidence | Severity / confidence |
| --- | --- | --- |
| `ZOLI-LOCAL-001` | Sensitive credential/config file reads or credential environment/whole-environment data flowing to recognized request calls | High / medium |
| `ZOLI-LOCAL-002` | Recognized network response flowing to process execution or dynamic evaluation | High / medium |
| `ZOLI-LOCAL-003` | Bounded base64/hex constant transform flowing to dynamic execution | Medium / medium |
| `ZOLI-LOCAL-101`, `102` | Lifecycle hook or uncorrelated eval/Function observation | Informational / high |

All rules are version 1.0.0 with the compiled archive/analysis source digest. Oxc parses JS/TS/JSX/TSX. Flow tracks local symbol aliases, destructuring, assignments, selected transforms, objects and awaited response values within files. It does not prove cross-file reachability, arbitrary helper-function/callback flow, runtime imports or safety of concealed behavior. Conservative object summaries can produce false positives. No accuracy estimate is inferred from synthetic cases.

Defaults are 20 MiB artifact, 100 MiB expansion, 10,000 entries, 8 MiB source, 120 seconds and 512 MiB monitored worker RSS. The same binary's worker clears its environment and executes no package code. Parent sampling every 50 ms is not an OS memory/network sandbox. Constant decoding is at most three layers/64 KiB. [Configuration](../configuration.md#inspection-scope-and-limits) records further AST, report and unsupported-format ceilings.

Registry acquisition supports strongest SHA-256/384/512 SRI and explicitly approved private HTTPS origins/ports/CA bundles. Credentials come only from trusted scoped npmrc sources, are selected afresh per redirect, and never enter analyzer input or serialized URLs. Project routing cannot authorize a new destination. Bundled identities must agree with the inventory or make the aggregate incomplete; parent archive hashes are never substituted for separate child hashes.

### Speed and later optimization

There is no latency target for the first implementation. Resource ceilings remain necessary to handle hostile input and produce an explicit incomplete result rather than hang or exhaust the machine.

- Record wall time by stage, archive bytes, files and dependency counts, peak/resource limits where available, and cache hits. Measure a cold run and a repeated run on the same fixture project.
- Design cache identities now: ecosystem, registry, name, version, artifact SHA-256, analyzer version, rule digest, configuration and platform context. Incomplete/error reports never become reusable successful results. Recompute feed policy against the current verified feed, even when artifact analysis is reusable.
- Start sequentially with reproducible output. Introduce bounded concurrency, indexing, incremental work and reusable artifact reports only after correctness gates pass and profiles show where time goes.
- A future faster mode must explicitly show reduced coverage, and must never skip feed authentication, integrity checks or a policy block. There is no fast-mode implementation in this change.

## Consequences

- ADR-003 still governs external intelligence sources. Local observations form a separate evidence channel and are not added to the signed feed automatically.
- `zoli-intel` remains independent of package scanning and keeps the Go parity gate.
- A new network-free analyzer crate and aggregate report are needed. Phase 1 grows to include their implementation gates; Phase 2 still owns actual install interception.
- False positives and incomplete coverage are first-class validation targets. Include benign build hooks, ordinary networking, minified bundles and documentation containing dangerous-looking examples.
- Publishing local findings upstream, running a hosted analyzer, new external reputation APIs or executing packages requires a separate design decision.

## References

- [npm lockfile format and integrity fields](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/), checked 17 October 2026.
- [npm lifecycle scripts and implicit node-gyp builds](https://docs.npmjs.com/cli/v11/using-npm/scripts/), checked 17 October 2026.
- [Phase 1 milestones and exit gates](../roadmap.md#phase-1-work-order).
