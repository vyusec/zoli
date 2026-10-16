//! Shell integration: shim generation, rc-file installation and removal.
//!
//! Interactive mode adds one marked block to the shell rc file (for fish, a
//! dedicated `conf.d` file). The block defines a function for each package
//! manager in
//! [`zoli_pms::PackageManager::ALL`], and each function calls
//! `zoli wrap <pm> -- "$@"`. CI mode puts a directory of executable shims at
//! the front of `PATH`. Install and uninstall touch only the marked block.
//! See `docs/shell-integration.md`.

/// A shell that receives interactive shims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// GNU Bash.
    Bash,
    /// Z shell.
    Zsh,
    /// fish.
    Fish,
}

impl Shell {
    /// The rc file, relative to `$HOME`, that holds the marked block.
    pub const fn rc_file(self) -> &'static str {
        match self {
            Self::Bash => ".bashrc",
            Self::Zsh => ".zshrc",
            Self::Fish => ".config/fish/conf.d/zoli.fish",
        }
    }
}
