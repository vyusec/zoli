# Shell integration

Baseline: 16 October 2026. Implementation lands in Phase 2 (interactive shells) and Phase 4 (CI). Until then `zoli shims` exits with code 3 and changes nothing.

The implemented entry point is explicit `zoli wrap npm -- ci`. The integration and nested-invocation behavior below describe future work, not installed protection.

## Interactive shells

`zoli shims install --shell bash|zsh|fish` writes one generated file and one marked block.

- **Generated file:** `$ZOLI_HOME/shims/zoli.<shell>` holds one function per wrapped program: `npm`, `npx`, `pnpm`, `pnpx`, `yarn`, `bun` and `bunx` in v1. Each function runs `zoli wrap <program> -- "$@"`.
- **Marked block (bash and zsh):** added to `~/.bashrc` or `~/.zshrc`. It sources the generated file:

  ```sh
  # >>> zoli shims >>>
  [ -f "$HOME/.zoli/shims/zoli.bash" ] && . "$HOME/.zoli/shims/zoli.bash"
  # <<< zoli shims <<<
  ```

- **fish:** gets a dedicated `~/.config/fish/conf.d/zoli.fish` instead of a block.

Functions are used rather than aliases so that arguments, quoting and completion behave identically.

Install and uninstall rules:

- Both are idempotent.
- Zoli edits only text between its own markers, and backs up the rc file before every change.
- If markers are missing or unbalanced, Zoli changes nothing and explains why.

## Recursion and locating the real binary

`zoli wrap` finds the real package manager by searching `PATH` with Zoli's shim directory removed. It sets `ZOLI_WRAPPED=1` in the child environment, so a nested invocation inside the wrapped process (for example `npm run` scripts calling `npx`) runs directly. The nested call inherits the proxy and CA settings, so it stays covered.

## CI mode

`zoli shims install --ci` creates `$ZOLI_HOME/shims/bin/`, with one executable shim per program, and prints the directory to prepend to `PATH`. On GitHub Actions it appends the directory to `$GITHUB_PATH`. PATH shims cover scripts, Makefiles and tools that never load an rc file. The Phase 4 GitHub Actions recipe uses this mode.

## What shims do not cover (residual risk)

| Bypass | Why shims miss it | Mitigation |
| --- | --- | --- |
| `command npm`, `\npm`, `/usr/bin/npm` | Skips functions or PATH lookup | PATH shims in CI; the threat model accepts this for interactive use |
| Scripts and IDE tasks in interactive setups | They do not read rc files | Use PATH mode on developer machines too |
| Version managers (nvm, fnm, Volta) changing `PATH` after Zoli | The manager's bin directory wins | `zoli doctor` checks what `npm` resolves to; place the Zoli block after the version manager's |
| Corepack shims (`corepack pnpm …`) | Different entry point | Phase 2 decides whether `corepack` gets a shim |
| A package manager ignoring `HTTPS_PROXY` (Yarn Berry, Bun) | Its own proxy settings | Per-manager adapter; best-effort until gated |
| Explicit `ca`/`cafile` in `.npmrc` | Replaces Node's extra roots | Expected to fail TLS (closed); Phase 2 adds a merged CA bundle |
| `python -m pip`, `uv --native-tls` (Phase 3) | Interpreter entry point or OS trust store | Documented residual risk; PATH shims for `pip`, `uv` and `python -m pip` patterns in CI |

## Uninstall

`zoli shims uninstall --shell <sh>` removes the marked block (or the fish file) and the generated snippet. `zoli shims uninstall --ci` removes the PATH shim directory. Uninstall never touches anything outside Zoli's markers or files.
