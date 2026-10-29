//! Package-manager adapters.
//!
//! For each supported package manager this crate will identify the program
//! being wrapped, compute the environment that routes it through the proxy
//! (`HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS` and per-manager settings), and pull
//! direct install arguments out for the pre-flight check. Phase 0 only
//! identifies programs; each adapter's behaviour is verified in Phase 2.

pub mod inventory;
pub mod requirements;

/// How much Zoli promises for a package manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// A v1 target. Claimed as protected only once its own gate evidence
    /// exists; the Phase 2 Docker gate covers npm first.
    Primary,
    /// Wrapped, with no v1 guarantee. Its proxy and CA handling stays
    /// unverified and second-class until a gate proves otherwise.
    BestEffort,
}

/// A package manager that `zoli wrap` can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    /// `npm`.
    Npm,
    /// `npx` (installs and runs packages on demand).
    Npx,
    /// `pnpm`.
    Pnpm,
    /// `pnpx` / `pnpm dlx`.
    Pnpx,
    /// `yarn` (classic and Berry).
    Yarn,
    /// `bun`.
    Bun,
    /// `bunx`.
    Bunx,
}

impl PackageManager {
    /// Every package manager that receives a shim.
    pub const ALL: &'static [Self] = &[
        Self::Npm,
        Self::Npx,
        Self::Pnpm,
        Self::Pnpx,
        Self::Yarn,
        Self::Bun,
        Self::Bunx,
    ];

    /// The executable name that the shim shadows.
    pub const fn program(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Npx => "npx",
            Self::Pnpm => "pnpm",
            Self::Pnpx => "pnpx",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
            Self::Bunx => "bunx",
        }
    }

    /// Identifies a package manager by its exact executable name.
    pub fn from_program(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|pm| pm.program() == name)
    }

    /// Support tier for this package manager.
    pub const fn support(self) -> Support {
        match self {
            Self::Bun | Self::Bunx => Support::BestEffort,
            _ => Support::Primary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_round_trip() {
        for &pm in PackageManager::ALL {
            assert_eq!(PackageManager::from_program(pm.program()), Some(pm));
        }
    }

    #[test]
    fn identification_is_exact() {
        for name in ["NPM", "npm ", "/usr/bin/npm", "pip", "corepack", ""] {
            assert_eq!(PackageManager::from_program(name), None, "{name:?}");
        }
    }

    #[test]
    fn bun_is_best_effort() {
        assert_eq!(PackageManager::Bun.support(), Support::BestEffort);
        assert_eq!(PackageManager::Npm.support(), Support::Primary);
    }
}
