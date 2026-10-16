//! `zoli`: install-time package firewall.
//!
//! Phase 0 defines the command surface. Every command fails closed until its
//! phase lands: it exits with [`NOT_IMPLEMENTED`], prints nothing to stdout,
//! and never starts a package manager.

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use zoli_pms::PackageManager;

/// Invalid invocation. Matches clap's own usage-error code.
const USAGE: u8 = 2;
/// The command exists but its phase has not landed. Nothing was checked or
/// allowed.
const NOT_IMPLEMENTED: u8 = 3;

#[derive(Parser)]
#[command(name = "zoli", version, about = "Install-time package firewall")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a package manager through Zoli (shim entry point).
    Wrap {
        /// Package manager executable name, for example `npm`.
        pm: String,
        /// Arguments passed to the package manager.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Run the registry-scoped interception proxy.
    Serve,
    /// Evaluate one package version against the verified feed.
    Check(CheckArgs),
    /// Fetch, verify and cache the latest feed publication.
    Update,
    /// Show feed cache state and freshness.
    Status,
    /// Install or remove package-manager shims.
    Shims {
        #[command(subcommand)]
        action: ShimsAction,
    },
    /// Verify shims, proxy, CA trust and feed freshness.
    Doctor,
}

#[derive(Args)]
struct CheckArgs {
    /// Ecosystem, for example `npm`.
    #[arg(long)]
    eco: String,
    /// Package name.
    #[arg(long)]
    name: String,
    /// Exact package version.
    #[arg(long)]
    ver: String,
    /// What to do with a suspicious (not confirmed malicious) match.
    #[arg(long, value_enum, default_value_t = SuspiciousMode::Warn)]
    suspicious: SuspiciousMode,
}

#[derive(Clone, Copy, ValueEnum)]
enum SuspiciousMode {
    Warn,
    Block,
}

#[derive(Subcommand)]
enum ShimsAction {
    /// Install shims for the given shell, or PATH shims for CI.
    Install(ShimsArgs),
    /// Remove shims installed by Zoli.
    Uninstall(ShimsArgs),
}

#[derive(Args)]
struct ShimsArgs {
    /// Shell rc file to modify.
    #[arg(
        long,
        value_enum,
        conflicts_with = "ci",
        required_unless_present = "ci"
    )]
    shell: Option<ShellArg>,
    /// Use a PATH directory of shims instead of shell functions.
    #[arg(long)]
    ci: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ShellArg {
    Bash,
    Zsh,
    Fish,
}

impl From<ShellArg> for zoli_shell::Shell {
    fn from(shell: ShellArg) -> Self {
        match shell {
            ShellArg::Bash => Self::Bash,
            ShellArg::Zsh => Self::Zsh,
            ShellArg::Fish => Self::Fish,
        }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Wrap { pm, args: _ } => {
            if PackageManager::from_program(&pm).is_none() {
                eprintln!("zoli wrap: unsupported package manager {pm:?}");
                return ExitCode::from(USAGE);
            }
            not_implemented("wrap", "Phase 2: npm guard")
        }
        Command::Serve => not_implemented("serve", "Phase 2: npm guard"),
        Command::Check(_) => not_implemented("check", "Phase 1: decision core"),
        Command::Update => not_implemented("update", "Phase 1: decision core"),
        Command::Status => not_implemented("status", "Phase 1: decision core"),
        Command::Shims { action } => {
            let (ShimsAction::Install(args) | ShimsAction::Uninstall(args)) = action;
            match args.shell.map(zoli_shell::Shell::from) {
                Some(_) => not_implemented("shims", "Phase 2: npm guard"),
                None => not_implemented("shims --ci", "Phase 4: install/CI"),
            }
        }
        Command::Doctor => not_implemented("doctor", "Phase 2: npm guard"),
    }
}

fn not_implemented(command: &str, phase: &str) -> ExitCode {
    eprintln!("zoli {command}: not implemented in this build (planned for {phase}).");
    eprintln!("zoli: refusing to continue; nothing was checked, allowed or run.");
    ExitCode::from(NOT_IMPLEMENTED)
}
