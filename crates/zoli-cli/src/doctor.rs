//! Local installation diagnostics. Doctor never assesses a package and never
//! grants installation approval; it reports whether the guard's prerequisites
//! and shell integration are present.
use super::{Cli, config, quality};
use anyhow::Result;
use serde::Serialize;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
};
use zoli_intel::{
    feed::{Store, read_bounded},
    model::GoTime,
};
use zoli_pms::{PackageManager, inventory::Inventory};
use zoli_policy::{
    Mode,
    assessment::{Evidence, decide},
};
use zoli_proxy::registry::{NpmConfig, RegistryClient};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Warn,
    Skip,
    Fail,
}

impl Status {
    const fn rank(self) -> u8 {
        match self {
            Self::Fail => 3,
            Self::Warn => 2,
            Self::Ok => 1,
            Self::Skip => 0,
        }
    }
}

#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

#[derive(Debug, Serialize)]
struct Report {
    schema: u32,
    scope: &'static str,
    time: GoTime,
    zoli_home: PathBuf,
    checks: Vec<Check>,
    status: Status,
    exit_code: u8,
    limitations: Vec<&'static str>,
}

struct Doctor {
    checks: Vec<Check>,
}

impl Doctor {
    fn new() -> Self {
        Self { checks: vec![] }
    }

    fn push(&mut self, name: &'static str, status: Status, detail: impl Into<String>) {
        self.checks.push(Check {
            name,
            status,
            detail: detail.into(),
        });
    }

    fn finish(self, cli: &Cli, home: PathBuf) -> Result<u8> {
        let status = self
            .checks
            .iter()
            .map(|check| check.status)
            .max_by_key(|status| status.rank())
            .unwrap_or(Status::Skip);
        let exit_code = if status == Status::Fail { 10 } else { 0 };
        let report = Report {
            schema: 1,
            scope: "doctor",
            time: GoTime::now(),
            zoli_home: home,
            checks: self.checks,
            status,
            exit_code,
            limitations: vec![
                "Doctor is a local prerequisite check; it does not assess packages or grant installation approval",
                "A healthy feed and shell integration do not prove package safety",
            ],
        };
        if cli.json {
            let mut out = std::io::stdout().lock();
            serde_json::to_writer(&mut out, &report)?;
            out.write_all(b"\n")?;
        } else {
            println!("Zoli doctor");
            println!("Home: {}", report.zoli_home.display());
            for check in &report.checks {
                let label = match check.status {
                    Status::Ok => "ok  ",
                    Status::Warn => "warn",
                    Status::Skip => "skip",
                    Status::Fail => "FAIL",
                };
                println!("{label}  {}: {}", check.name, check.detail);
            }
            let count = |target| {
                report
                    .checks
                    .iter()
                    .filter(|check| check.status == target)
                    .count()
            };
            println!(
                "Summary: {} ok, {} warn, {} skipped, {} failed",
                count(Status::Ok),
                count(Status::Warn),
                count(Status::Skip),
                count(Status::Fail)
            );
            if status == Status::Fail {
                println!("Blocking items must be fixed before relying on guarded installation.");
            }
        }
        Ok(exit_code)
    }
}

fn mode(cli: &Cli) -> Mode {
    if cli.ci
        || std::env::var("CI")
            .is_ok_and(|value| !value.is_empty() && value != "0" && value != "false")
    {
        Mode::Ci
    } else {
        Mode::Interactive
    }
}

fn executable(name: &str, skip: Option<&Path>) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        if !directory.is_absolute() {
            continue;
        }
        if let Some(skip) = skip
            && (directory == skip
                || directory
                    .canonicalize()
                    .ok()
                    .zip(skip.canonicalize().ok())
                    .is_some_and(|(left, right)| left == right))
        {
            continue;
        }
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn npm_version(npm: &Path, home: &Path) -> Result<String> {
    let output = Command::new(npm)
        .arg("--version")
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env_remove("NODE_OPTIONS")
        .env_remove("NODE_PATH")
        .output()?;
    if !output.status.success() {
        anyhow::bail!("npm --version failed");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[cfg(unix)]
fn private_mode(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file() && metadata.permissions().mode() & 0o077 == 0
    })
}

#[cfg(not(unix))]
fn private_mode(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn audit_check(doctor: &mut Doctor, home: &Path) {
    let path = home.join("log/audit.jsonl");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            doctor.push(
                "audit",
                Status::Ok,
                "not initialized yet; the first audited operation creates it with mode 0600",
            );
            return;
        }
        Err(error) => {
            doctor.push(
                "audit",
                Status::Fail,
                format!("cannot inspect audit log: {error}"),
            );
            return;
        }
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        doctor.push("audit", Status::Fail, "audit log is not a regular file");
        return;
    }
    if !private_mode(&path) {
        doctor.push(
            "audit",
            Status::Fail,
            "audit log permissions are broader than 0600",
        );
        return;
    }
    let size = metadata.len();
    if size == 0 {
        doctor.push("audit", Status::Ok, "empty and ready");
        return;
    }
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) => {
            doctor.push(
                "audit",
                Status::Fail,
                format!("cannot read audit log: {error}"),
            );
            return;
        }
    };
    let mut last = [0u8; 1];
    if file.seek(SeekFrom::End(-1)).is_err() || file.read_exact(&mut last).is_err() {
        doctor.push("audit", Status::Fail, "cannot read the audit log tail");
        return;
    }
    if last[0] != b'\n' {
        doctor.push(
            "audit",
            Status::Fail,
            "audit log has an incomplete trailing record; explicit recovery is required",
        );
        return;
    }
    let length = size.min(8 << 20) as usize;
    if size > length as u64 {
        doctor.push(
            "audit",
            Status::Warn,
            format!(
                "{} bytes; trailing newline verified, but the last record was not parsed",
                size
            ),
        );
        return;
    }
    let start = size - length as u64;
    let mut tail = vec![0; length];
    if file.seek(SeekFrom::Start(start)).is_err() || file.read_exact(&mut tail).is_err() {
        doctor.push("audit", Status::Fail, "cannot read the audit log tail");
        return;
    }
    let Some(line) = tail
        .split(|byte| *byte == b'\n')
        .rev()
        .find(|line| !line.is_empty())
    else {
        doctor.push("audit", Status::Ok, "empty and ready");
        return;
    };
    match serde_json::from_slice::<serde_json::Value>(line) {
        Ok(value) if value["schema"].as_u64() == Some(1) => doctor.push(
            "audit",
            Status::Ok,
            format!(
                "{} bytes; last record scope {}",
                size,
                value["scope"].as_str().unwrap_or("?")
            ),
        ),
        Ok(_) => doctor.push(
            "audit",
            Status::Fail,
            "last audit record has an unknown schema",
        ),
        Err(_) => doctor.push("audit", Status::Fail, "last audit record is not valid JSON"),
    }
}

fn feed_check(doctor: &mut Doctor, cli: &Cli, home: &Path, config: &config::Config) -> Result<()> {
    let key = config.key()?;
    let snapshot = Store::new(home.to_owned()).load(&key)?;
    let manifest = snapshot.verify(&key)?;
    let now = GoTime::now();
    let verdict = quality(&manifest, &now)?;
    let decision = decide(
        Evidence {
            verdict: Some(&verdict),
            manifest: Some(&manifest),
            require_feed: true,
            ..Default::default()
        },
        mode(cli),
        config.policy.suspicious,
        &now,
    );
    let age = manifest.generated_at.age(&now).whole_seconds();
    let errors = manifest
        .sources
        .iter()
        .flatten()
        .filter(|source| !source.error.is_empty())
        .count();
    let detail = format!(
        "publication {}; {} records; freshness {}; age {}s; {} source error(s)",
        manifest.sequence, manifest.record_count, verdict.freshness, age, errors
    );
    if decision.exit_code == 0 {
        doctor.push("feed", Status::Ok, detail);
    } else {
        doctor.push(
            "feed",
            Status::Fail,
            format!(
                "{detail}; guard would block: {}",
                decision.reasons.join(", ")
            ),
        );
    }
    Ok(())
}

fn config_check(doctor: &mut Doctor, home: &Path) -> Option<config::Config> {
    match config::Config::load() {
        Ok((_, config)) => {
            if let Some(feed) = &config.feed {
                let key = config.key().ok();
                let key_id = key.map(|key| zoli_intel::feed::key_id(&key));
                doctor.push(
                    "config",
                    Status::Ok,
                    format!(
                        "config_version 1; feed {}; key id {}; minimum age {}h",
                        feed.url,
                        key_id.as_deref().unwrap_or("?"),
                        config.policy.min_publish_age_hours.unwrap_or(24)
                    ),
                );
                for path in [
                    home.join("config.json"),
                    home.join("state.json"),
                    home.join("cache/feed.json"),
                ] {
                    if path.exists() && !private_mode(&path) {
                        doctor.push(
                            "permissions",
                            Status::Fail,
                            format!("{} is accessible by group or others", path.display()),
                        );
                        return Some(config);
                    }
                }
            } else {
                doctor.push(
                    "config",
                    Status::Fail,
                    "no pinned feed is configured; checks and guarded installs cannot run",
                );
            }
            Some(config)
        }
        Err(error) => {
            doctor.push("config", Status::Fail, format!("{error:#}"));
            None
        }
    }
}

fn npm_check(doctor: &mut Doctor, home: &Path, zoli_home: &Path) {
    let shim_directory = zoli_shell::ci_directory(zoli_home);
    let npm = executable("npm", Some(&shim_directory));
    let Some(npm) = npm else {
        doctor.push("npm", Status::Fail, "npm is not on an absolute PATH entry");
        return;
    };
    match npm_version(&npm, home) {
        Ok(version) if version.starts_with("10.") => doctor.push(
            "npm",
            Status::Ok,
            format!("{} (npm {version})", npm.display()),
        ),
        Ok(version) => doctor.push(
            "npm",
            Status::Fail,
            format!(
                "{} reports npm {version}; the install guard supports npm 10 only",
                npm.display()
            ),
        ),
        Err(error) => doctor.push("npm", Status::Fail, format!("{}: {error:#}", npm.display())),
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let first_npm = std::env::split_paths(&path)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join("npm"))
        .find(|candidate| candidate.is_file());
    let shadows = first_npm
        .as_ref()
        .is_some_and(|candidate| candidate.parent() == Some(shim_directory.as_path()));
    doctor.push(
        "path",
        if shadows { Status::Ok } else { Status::Warn },
        if shadows {
            "CI PATH shims precede the real npm".to_owned()
        } else {
            format!(
                "CI PATH shims are not active; prepend {} to PATH for scripts and CI",
                shim_directory.display()
            )
        },
    );
}

fn shim_check(doctor: &mut Doctor, home: &Path, zoli_home: &Path) {
    let mut installed = vec![];
    for shell in [
        zoli_shell::Shell::Bash,
        zoli_shell::Shell::Zsh,
        zoli_shell::Shell::Fish,
    ] {
        let generated = zoli_shell::generated_path(shell, zoli_home);
        let rc = home.join(shell.rc_file());
        let rc_ok = read_bounded(&rc, 4 << 20)
            .map(|bytes| {
                let text = String::from_utf8_lossy(&bytes);
                text.contains(zoli_shell::BEGIN) || text.contains(zoli_shell::HEADER)
            })
            .unwrap_or(false);
        if generated.is_file() && rc_ok {
            installed.push(shell.name());
        }
    }
    let directory = zoli_shell::ci_directory(zoli_home);
    let ci = PackageManager::ALL
        .iter()
        .all(|manager| directory.join(manager.program()).is_file());
    let detail = format!(
        "shells: {}; CI PATH directory: {}",
        if installed.is_empty() {
            "none installed".to_owned()
        } else {
            installed.join(", ")
        },
        if ci {
            directory.display().to_string()
        } else {
            "not installed".to_owned()
        }
    );
    doctor.push(
        "shims",
        if installed.is_empty() && !ci {
            Status::Warn
        } else {
            Status::Ok
        },
        format!("{detail}; explicit `zoli wrap` still protects without them"),
    );
}

fn project_check(doctor: &mut Doctor, config: &config::Config) -> Result<()> {
    let project = std::env::current_dir()?.canonicalize()?;
    let shrinkwrap = project.join("npm-shrinkwrap.json");
    let lockfile = if shrinkwrap.exists() {
        shrinkwrap
    } else {
        project.join("package-lock.json")
    };
    if !lockfile.exists() {
        doctor.push(
            "project",
            Status::Skip,
            format!("no supported npm lockfile in {}", project.display()),
        );
        return Ok(());
    }
    let npm = NpmConfig::load(Some(&project), None);
    let client = npm.and_then(|npm| RegistryClient::new(config.registries.entries()?, npm));
    let inventory =
        client.and_then(|client| Inventory::from_lock(&lockfile, |name| client.registry_for(name)));
    match inventory {
        Ok(inventory) => {
            let bundled = inventory
                .packages
                .iter()
                .filter(|package| package.bundled)
                .count();
            let detail = format!(
                "{}: lockfile v{}; {} packages; {} bundled; {} gap(s)",
                lockfile.file_name().unwrap_or_default().to_string_lossy(),
                inventory.lockfile_version,
                inventory.packages.len(),
                bundled,
                inventory.gaps.len()
            );
            if inventory.gaps.is_empty() {
                doctor.push("project", Status::Ok, detail);
            } else {
                let reasons = inventory
                    .gaps
                    .iter()
                    .map(|gap| gap.reason.as_str())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ");
                doctor.push(
                    "project",
                    Status::Fail,
                    format!("{detail}; guard would refuse: {reasons}"),
                );
            }
        }
        Err(error) => doctor.push(
            "project",
            Status::Fail,
            format!("{error:#}; the guard cannot inventory this project"),
        ),
    }
    Ok(())
}

/// Run local diagnostics and return 0 when no blocking item was found.
pub fn run(cli: &Cli) -> Result<u8> {
    let mut doctor = Doctor::new();
    let home = config::Config::home().unwrap_or_else(|_| PathBuf::from("<unset>"));
    let user_home = std::env::var_os("HOME").map(PathBuf::from);
    if home == Path::new("<unset>") || !home.exists() {
        doctor.push(
            "home",
            Status::Fail,
            format!("Zoli home does not exist: {}", home.display()),
        );
        return doctor.finish(cli, home);
    }
    doctor.push("home", Status::Ok, home.display().to_string());
    let config = config_check(&mut doctor, &home);
    if let Some(config) = &config {
        if let Err(error) = feed_check(&mut doctor, cli, &home, config) {
            doctor.push("feed", Status::Fail, format!("{error:#}"));
        }
        if let Err(error) = project_check(&mut doctor, config) {
            doctor.push("project", Status::Fail, format!("{error:#}"));
        }
    } else {
        doctor.push(
            "feed",
            Status::Skip,
            "feed cannot be checked without a valid configuration",
        );
        doctor.push(
            "project",
            Status::Skip,
            "project cannot be checked without a valid configuration",
        );
    }
    audit_check(&mut doctor, &home);
    let npm_home = user_home.as_deref().unwrap_or(&home);
    npm_check(&mut doctor, npm_home, &home);
    shim_check(&mut doctor, user_home.as_deref().unwrap_or(&home), &home);
    doctor.finish(cli, home)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn status_rank_orders_failures_last() {
        assert!(Status::Fail.rank() > Status::Warn.rank());
        assert!(Status::Warn.rank() > Status::Ok.rank());
        assert!(Status::Ok.rank() > Status::Skip.rank());
    }
}
