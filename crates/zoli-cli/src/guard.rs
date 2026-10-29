//! Locked npm installation through an invocation-private, preapproved cache.
use super::{
    Cli, FeedProvenance, TreeAssessment, Usage, aggregate, assess, config, mode, output, quality,
    suspicious,
};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};
use zoli_intel::{
    feed::{Store, read_bounded, sha256},
    model::GoTime,
};
use zoli_policy::{
    Action,
    assessment::{Decision, Evidence, decide},
};

pub fn apply_age(decision: &mut Decision, published: Option<&GoTime>, hours: u64, now: &GoTime) {
    let reason = match published {
        None => "package_publish_time_missing",
        Some(stamp) if stamp.age(now) < time::Duration::hours(hours as i64) => {
            "package_younger_than_minimum_publish_age"
        }
        Some(_) => return,
    };
    decision.action = Action::Block;
    decision.complete = false;
    if decision.exit_code != 1 {
        decision.exit_code = 10;
    }
    decision.reasons.push(reason.into());
}

fn executable(name: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").context("PATH is required to locate npm")?;
    for dir in std::env::split_paths(&path) {
        // Never resolve a manager from an implicit working-directory entry.
        if !dir.is_absolute() {
            continue;
        }
        let candidate = dir.join(name);
        if candidate.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if candidate.metadata()?.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            return candidate
                .canonicalize()
                .context("cannot resolve npm executable");
        }
    }
    anyhow::bail!("npm executable not found on an absolute PATH entry")
}

struct Inputs(BTreeMap<PathBuf, Option<Vec<u8>>>);
impl Inputs {
    fn capture(project: &Path, home: &Path) -> Result<Self> {
        let mut files = BTreeMap::new();
        for path in [
            project.join("package.json"),
            project.join("package-lock.json"),
            project.join("npm-shrinkwrap.json"),
            project.join(".npmrc"),
            home.join("config.json"),
        ] {
            let bytes = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    ensure!(
                        metadata.is_file() && !metadata.file_type().is_symlink(),
                        "guard input must be a regular file: {}",
                        path.display()
                    );
                    Some(read_bounded(&path, 20 << 20)?)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e.into()),
            };
            files.insert(path, bytes);
        }
        Ok(Self(files))
    }
    fn verify(&self, project: &Path, home: &Path) -> Result<()> {
        ensure!(
            self.0 == Self::capture(project, home)?.0,
            "project or Zoli configuration changed during assessment; run again"
        );
        Ok(())
    }
    fn digest(&self) -> Result<String> {
        Ok(sha256(&serde_json::to_vec(&self.0)?))
    }
}

fn project_config(project: &Path) -> Result<()> {
    let path = project.join(".npmrc");
    if !path.exists() {
        return Ok(());
    }
    let bytes = read_bounded(&path, 1 << 20)?;
    for line in std::str::from_utf8(&bytes)?.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let (key, _) = line
            .split_once('=')
            .context("unsupported project npmrc syntax")?;
        let key = key.trim();
        ensure!(
            key == "registry" || key.starts_with('@') && key.ends_with(":registry"),
            "guarded npm ci supports only registry routing in project .npmrc; remove operational overrides"
        );
    }
    Ok(())
}

fn npm_command(
    program: &Path,
    workspace: &Path,
    cache: &Path,
    user: &Path,
    global: &Path,
) -> Command {
    let mut command = Command::new(program);
    command.current_dir(workspace);
    for (key, _) in std::env::vars_os() {
        let lower = key.to_string_lossy().to_ascii_lowercase();
        if lower.starts_with("npm_config_")
            || [
                "node_options",
                "node_path",
                "npm_execpath",
                "npm_node_execpath",
            ]
            .contains(&lower.as_str())
        {
            command.env_remove(key);
        }
    }
    command
        .env("npm_config_cache", cache)
        .env("npm_config_offline", "true")
        .env("npm_config_userconfig", user)
        .env("npm_config_globalconfig", global)
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .env("npm_config_update_notifier", "false");
    command
}

fn refresh(
    cli: &Cli,
    config: &config::Config,
    home: &Path,
    report: &mut TreeAssessment,
    hours: u64,
) -> Result<()> {
    let key = config.key()?;
    let snapshot = Store::new(home.into()).load(&key)?;
    let manifest = snapshot.verify(&key)?;
    let now = GoTime::now();
    for node in &mut report.packages {
        let mut id = node.package.identity.clone();
        if let Some(local) = &node.local_analysis {
            id.sha256 = local.artifact_sha256.clone();
        }
        let verdict = zoli_intel::query::query(id, &manifest, &snapshot.records, &now)?;
        node.decision = decide(
            Evidence {
                verdict: Some(&verdict),
                manifest: Some(&manifest),
                local: node.local_analysis.as_ref(),
                require_feed: true,
                require_local: true,
                gaps: report
                    .inventory
                    .gaps
                    .iter()
                    .any(|g| g.path == node.package.path),
            },
            mode(cli),
            suspicious(cli, config.policy.suspicious),
            &now,
        );
        apply_age(&mut node.decision, node.published_at.as_ref(), hours, &now);
        node.feed_verdict = Some(verdict);
    }
    let verdict = quality(&manifest, &now)?;
    let base = decide(
        Evidence {
            verdict: Some(&verdict),
            manifest: Some(&manifest),
            require_feed: true,
            gaps: !report.inventory.gaps.is_empty(),
            ..Default::default()
        },
        mode(cli),
        suspicious(cli, config.policy.suspicious),
        &now,
    );
    report.decision = aggregate(base, &report.packages);
    report.feed_provenance = FeedProvenance::new(&snapshot, &manifest);
    report.sequence = manifest.sequence;
    report.record_count = manifest.record_count;
    report.freshness = verdict.freshness;
    report.time = now;
    report.scope = "npm_ci_release";
    Ok(())
}

fn code(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return u8::try_from(code).unwrap_or(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return u8::try_from(128 + signal).unwrap_or(1);
        }
    }
    1
}

pub fn run(cli: &Cli, args: &[String]) -> Result<u8> {
    if cli.json {
        return Err(Usage(
            "wrap preserves npm stdout; use audit.jsonl for structured reports instead of --json"
                .into(),
        )
        .into());
    }
    if args
        .iter()
        .skip(1)
        .any(|a| !["--ignore-scripts", "--foreground-scripts"].contains(&a.as_str()))
    {
        return Err(Usage("guarded npm ci accepts only --ignore-scripts and --foreground-scripts; cache, registry and other overrides are refused".into()).into());
    }
    let project = std::env::current_dir()?.canonicalize()?;
    let home = config::Config::home()?;
    let inputs = Inputs::capture(&project, &home)?;
    let (_, config) = config::Config::load()?;
    project_config(&project)?;
    let lockfile = if project.join("npm-shrinkwrap.json").exists() {
        project.join("npm-shrinkwrap.json")
    } else {
        project.join("package-lock.json")
    };
    let hours = config.policy.min_publish_age_hours.unwrap_or(24);
    let private = tempfile::Builder::new().prefix("zoli-npm-ci-").tempdir()?;
    let quarantine = private.path().join("quarantine");
    std::fs::create_dir(&quarantine)?;
    let mut report = assess(cli, &lockfile, None, Some(&quarantine), Some(hours))?;
    output::guard_report(&report, &home)?;
    if report.decision.exit_code != 0 {
        return Ok(report.decision.exit_code);
    }
    inputs.verify(&project, &home)?;
    let program = executable("npm")?;
    let cache = private.path().join("cache");
    let user = private.path().join("user.npmrc");
    let global = private.path().join("global.npmrc");
    std::fs::write(&user, b"")?;
    std::fs::write(&global, b"")?;
    let version = npm_command(&program, private.path(), &cache, &user, &global)
        .arg("--version")
        .output()?;
    ensure!(
        version.status.success()
            && std::str::from_utf8(&version.stdout)?
                .trim()
                .starts_with("10."),
        "this install guard is validated for npm 10; other npm majors refuse execution"
    );
    // Only approved bytes reach npm. Seeding runs outside the project with
    // scripts disabled; no user cache, npmrc or registry access is inherited.
    for node in &report.packages {
        let local = node
            .local_analysis
            .as_ref()
            .context("approved artifact report missing")?;
        let file = quarantine.join(format!("{}.tgz", local.artifact_sha256));
        let bytes = read_bounded(&file, config.analysis.max_artifact_bytes)?;
        ensure!(
            sha256(&bytes) == local.artifact_sha256,
            "quarantined artifact changed"
        );
        let seeded = npm_command(&program, private.path(), &cache, &user, &global)
            .args([
                "cache",
                "add",
                "--offline",
                "--ignore-scripts",
                "--audit=false",
                "--fund=false",
            ])
            .arg(&file)
            .stdin(Stdio::null())
            .output()?;
        ensure!(
            seeded.status.success(),
            "could not populate the approved private npm cache: {}",
            String::from_utf8_lossy(&seeded.stderr)
        );
    }
    inputs.verify(&project, &home)?;
    refresh(cli, &config, &home, &mut report, hours)?;
    output::guard_report(&report, &home)?;
    if report.decision.exit_code != 0 {
        return Ok(report.decision.exit_code);
    }
    let authorization = json!({"schema":1,"scope":"npm_ci_authorization","time":GoTime::now(),"input_sha256":inputs.digest()?,"sequence":report.sequence,"manifest_sha256":report.feed_provenance.manifest_sha256,"min_publish_age_hours":hours,"cache":"private_approved_artifacts_only","npm_version":std::str::from_utf8(&version.stdout)?.trim(),"package_count":report.packages.len()});
    output::audit(&home, &serde_json::to_vec(&authorization)?)?;
    inputs.verify(&project, &home)?;
    eprintln!(
        "zoli: approved {} dependencies; npm ci uses an isolated offline cache (minimum age {hours}h)",
        report.packages.len()
    );
    let status = npm_command(&program, &project, &cache, &user, &global)
        .args(args)
        .args([
            "--offline",
            "--audit=false",
            "--fund=false",
            "--update-notifier=false",
        ])
        .arg("--cache")
        .arg(&cache)
        .arg("--userconfig")
        .arg(&user)
        .arg("--globalconfig")
        .arg(&global)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    let exit_code = code(status);
    output::audit(
        &home,
        &serde_json::to_vec(
            &json!({"schema":1,"scope":"npm_ci_exit","time":GoTime::now(),"exit_code":exit_code}),
        )?,
    )?;
    Ok(exit_code)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn minimum_age_requires_the_full_24_hours() {
        let now = GoTime::parse("2026-10-30T12:00:00Z").unwrap();
        for (stamp, expected) in [
            (Some("2026-10-29T12:00:00Z"), 0),
            (Some("2026-10-29T12:00:00.000000001Z"), 10),
            (Some("2026-10-31T00:00:00Z"), 10),
            (None, 10),
        ] {
            let mut decision = Decision {
                action: Action::Allow,
                complete: true,
                exit_code: 0,
                reasons: vec![],
            };
            apply_age(
                &mut decision,
                stamp.map(|s| GoTime::parse(s).unwrap()).as_ref(),
                24,
                &now,
            );
            assert_eq!(decision.exit_code, expected);
        }
    }
}
