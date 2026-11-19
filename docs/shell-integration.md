# Shell integration

Implemented 20 November 2026. `zoli shims install --shell bash|zsh|fish` and `zoli shims install --ci` now work; `serve` and non-npm managers remain unimplemented. See `docs/shell-integration.md` for the residual bypass list.

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
- Zoli edits only text between its own markers, backs up the rc file before every change (`.bashrc.zoli-backup`), and refuses files with unbalanced or duplicated markers.
- If markers are missing, uninstall treats the file as already clean and removes only the generated snippet.

## Recursion and locating the real binary

`zoli wrap` finds the real package manager by searching `PATH` with Zoli's shim directory removed. It sets `ZOLI_WRAPPED=1` in the child environment. A nested invocation that reaches a shim sees `ZOLI_WRAPPED=1` and executes the real program directly; nested installers are outside the initial-install guarantee. Supported top-level npm/npx entry points are still guarded.

## CI mode

`zoli shims install --ci` creates `$ZOLI_HOME/shims/bin/`, with one executable shim per program, and prints the directory to prepend to `PATH`. When `$GITHUB_PATH` is present, Zoli appends the directory once. PATH shims cover scripts, Makefiles and tools that never load an rc file. The Phase 4 GitHub Actions recipe uses this mode.

`zoli shims uninstall --ci` removes only the known shim files and removes the directory when it becomes empty.

## What shims do not cover (residual risk)

| Bypass | Why shims miss it | Mitigation |
| --- | --- | --- |
| `command npm`, `\npm`, `/usr/bin/npm` | Skips functions or PATH lookup | PATH shims in CI; the threat model accepts this for interactive use |
| Scripts and IDE tasks in interactive setups | They do not read rc files | Use PATH mode on developer machines too |
| Version managers (nvm, fnm, Volta) changing `PATH` after Zoli | The manager's bin directory wins | `zoli doctor` checks what `npm` resolves to; place the Zoli block after the version manager's |
| Corepack shims (`corepack pnpm …`) | Different entry point | Not shimmed; unsupported managers still refuse through `zoli wrap` |
| A package manager ignoring `HTTPS_PROXY` (Yarn Berry, Bun) | Its own proxy settings | No proxy is used; each manager needs its own adapter and gate |
| Explicit `ca`/`cafile` in `.npmrc` | No interception listener or local CA is used | Not applicable to the approved-cache design |
| `python -m pip`, `uv --native-tls` (Phase 3) | Interpreter entry point or OS trust store | Documented residual risk; Phase 3 adapters need their own gates |
| `ZOLI_WRAPPED=1` set by the user | Deliberate nested-invocation marker | Documented trusted-child boundary; a hostile local process can also edit shims/config |

## Uninstall

`zoli shims uninstall --shell <sh>` removes the marked block (or the fish file) and the generated snippet. `zoli shims uninstall --ci` removes the PATH shim directory's known files. Uninstall never touches anything outside Zoli's markers or files.
