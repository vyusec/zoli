//! Scoped feed checks, local archive inspection and dependency assessments.
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::PathBuf,
    process::ExitCode,
    time::Instant,
};
use zoli_intel::{
    feed::{Snapshot, Store, read_bounded, sha256},
    model::{Coverage, GoTime, Identity, Manifest, QueryResponse, SourceState},
};
use zoli_pms::{
    PackageManager,
    inventory::{Gap, Inventory, Package},
};
use zoli_policy::{
    Action, Mode,
    assessment::{Decision, Evidence, Suspicious, decide},
};
use zoli_proxy::registry::{NpmConfig, RegistryClient, validate_integrity, verify_integrity};
mod config;
mod guard;
mod output;
mod worker;

#[derive(Parser)]
#[command(
    name = "zoli",
    version,
    about = "Install-time package firewall and package assessor"
)]
struct Cli {
    /// Emit one versioned JSON result on stdout.
    #[arg(long, global = true)]
    json: bool,
    /// Apply CI policy, including blocking suspicious findings.
    #[arg(long, global = true)]
    ci: bool,
    /// Interactive treatment of suspicious findings; CI always blocks.
    #[arg(long, value_enum, global = true)]
    suspicious: Option<SuspiciousArg>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum SuspiciousArg {
    Warn,
    Block,
}
#[derive(Args)]
struct IdentityArgs {
    #[arg(long)]
    eco: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    ver: String,
    /// Exact registry identity; does not initiate a hosted intelligence query.
    #[arg(long)]
    registry: Option<String>,
}
#[derive(Args)]
struct CheckArgs {
    #[command(flatten)]
    identity: IdentityArgs,
    /// Match an exact artifact digest, including hash-scoped PyPI reports.
    #[arg(long)]
    sha256: Option<String>,
}
#[derive(Subcommand)]
enum Command {
    /// Guard locked npm ci with full assessment and an isolated offline cache.
    Wrap {
        pm: String,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Phase 2 interception proxy; refuses operation in this build.
    Serve,
    /// Evaluate one exact identity against the verified local feed only.
    Check(CheckArgs),
    /// Fetch, verify and atomically cache the configured feed.
    Update,
    /// Show authenticated publication state and intelligence freshness.
    Status,
    /// Inspect a local npm tar/tgz without network or package execution.
    Inspect {
        archive: PathBuf,
        #[command(flatten)]
        identity: IdentityArgs,
        #[arg(long)]
        integrity: Option<String>,
    },
    /// Assess dependencies recorded in an npm lockfile.
    Scan {
        #[arg(long)]
        lockfile: PathBuf,
        #[arg(long)]
        npmrc: Option<PathBuf>,
    },
    /// Phase 2/4 shell integration; refuses operation in this build.
    Shims {
        #[command(subcommand)]
        action: ShimsAction,
    },
    /// Phase 2 installation diagnostics; refuses operation in this build.
    Doctor,
    #[command(name = "__inspect-worker", hide = true)]
    Worker {
        archive: PathBuf,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        limits: String,
    },
}
#[derive(Subcommand)]
enum ShimsAction {
    Install(ShimsArgs),
    Uninstall(ShimsArgs),
}
#[derive(Args)]
struct ShimsArgs {
    #[arg(
        long,
        value_enum,
        conflicts_with = "ci",
        required_unless_present = "ci"
    )]
    shell: Option<ShellArg>,
}
#[derive(Clone, Copy, ValueEnum)]
enum ShellArg {
    Bash,
    Zsh,
    Fish,
}

#[derive(Debug)]
struct Usage(String);
impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Usage {}
fn identity(args: &IdentityArgs) -> Result<Identity> {
    let mut id = Identity {
        ecosystem: args.eco.clone(),
        name: args.name.clone(),
        version: args.ver.clone(),
        registry: args.registry.clone().unwrap_or_default(),
        ..Default::default()
    };
    id.normalize().map_err(|e| Usage(e.to_string()))?;
    if !match id.ecosystem.as_str() {
        "npm" => zoli_intel::npm::concrete(&id.version),
        "PyPI" => zoli_intel::pypi::concrete(&id.version),
        _ => false,
    } {
        return Err(Usage("requires an exact concrete npm or PyPI identity".into()).into());
    }
    Ok(id)
}
fn mode(cli: &Cli) -> Mode {
    if cli.ci || std::env::var("CI").is_ok_and(|s| !s.is_empty() && s != "0" && s != "false") {
        Mode::Ci
    } else {
        Mode::Interactive
    }
}
fn suspicious(cli: &Cli, default: Suspicious) -> Suspicious {
    match cli.suspicious {
        Some(SuspiciousArg::Warn) => Suspicious::Warn,
        Some(SuspiciousArg::Block) => Suspicious::Block,
        None => default,
    }
}
fn unimplemented(command: &str) -> u8 {
    eprintln!(
        "zoli {command}: not implemented in this build; refusing to continue. Nothing was checked, allowed or run."
    );
    3
}
fn quality(manifest: &Manifest, now: &GoTime) -> Result<QueryResponse> {
    zoli_intel::query::query(
        Identity {
            ecosystem: "npm".into(),
            name: "zoli-assessment-status".into(),
            version: "0.0.0".into(),
            ..Default::default()
        },
        manifest,
        &[],
        now,
    )
}

#[derive(Serialize)]
struct FeedProvenance {
    key_id: String,
    manifest_sha256: String,
    sequence: i64,
    record_count: i64,
    generated_at: GoTime,
    rule_set_sha256: String,
    sources: Option<Vec<SourceState>>,
    coverage: Option<Vec<Coverage>>,
}
impl FeedProvenance {
    fn new(snapshot: &Snapshot, manifest: &Manifest) -> Self {
        Self {
            key_id: snapshot.envelope.key_id.clone(),
            manifest_sha256: snapshot.envelope.digest(),
            sequence: manifest.sequence,
            record_count: manifest.record_count,
            generated_at: manifest.generated_at.clone(),
            rule_set_sha256: manifest.rule_set_sha256.clone(),
            sources: manifest.sources.clone(),
            coverage: manifest.coverage.clone(),
        }
    }
}
#[derive(Serialize)]
struct Assessment<'a> {
    schema: u32,
    scope: &'a str,
    time: GoTime,
    mode: Mode,
    suspicious_policy: Suspicious,
    identity: Identity,
    feed_verdict: Option<QueryResponse>,
    feed_provenance: Option<FeedProvenance>,
    local_analysis: Option<zoli_inspect::Report>,
    decision: Decision,
    elapsed_ms: u128,
    limitations: Vec<&'a str>,
}
#[derive(Serialize)]
struct NodeAssessment {
    package: Package,
    feed_verdict: Option<QueryResponse>,
    local_analysis: Option<zoli_inspect::Report>,
    analysis_container: Option<String>,
    decision: Decision,
    error: Option<String>,
    published_at: Option<GoTime>,
    registry_integrity: Option<String>,
}
#[derive(Serialize)]
struct TreeAssessment {
    schema: u32,
    scope: &'static str,
    time: GoTime,
    mode: Mode,
    suspicious_policy: Suspicious,
    sequence: i64,
    record_count: i64,
    freshness: String,
    feed_provenance: FeedProvenance,
    inventory: Inventory,
    packages: Vec<NodeAssessment>,
    decision: Decision,
    timings_ms: BTreeMap<String, u128>,
    limitations: Vec<&'static str>,
}

fn run(cli: &Cli) -> Result<u8> {
    match &cli.command {
        Command::Wrap { pm, args } => {
            if PackageManager::from_program(pm).is_none() {
                return Err(Usage("unsupported package manager".into()).into());
            }
            if pm != "npm" || args.first().is_none_or(|s| s != "ci") {
                return Ok(unimplemented("wrap: only locked npm ci is supported"));
            }
            guard::run(cli, args)
        }
        Command::Serve => Ok(unimplemented("serve")),
        Command::Shims { action } => {
            let (ShimsAction::Install(a) | ShimsAction::Uninstall(a)) = action;
            let _ = a.shell;
            Ok(unimplemented("shims"))
        }
        Command::Doctor => Ok(unimplemented("doctor")),
        Command::Worker {
            archive,
            identity,
            limits,
        } => {
            let id: Identity = serde_json::from_str(identity)?;
            let limits: zoli_inspect::Limits = serde_json::from_str(limits)?;
            let bytes = read_bounded(archive, limits.max_artifact_bytes)?;
            let report = zoli_inspect::inspect(&bytes, id, &limits);
            let mut out = std::io::stdout().lock();
            serde_json::to_writer(&mut out, &report)?;
            out.write_all(b"\n")?;
            Ok(0)
        }
        Command::Inspect {
            archive,
            identity: args,
            integrity,
        } => {
            let started = Instant::now();
            let mut id = identity(args)?;
            if id.ecosystem != "npm" {
                return Err(
                    Usage("local artifact inspection currently supports npm only".into()).into(),
                );
            }
            let home = config::Config::home()?;
            let config = if home.join("config.json").exists() {
                config::Config::load()?.1
            } else {
                config::Config::offline()
            };
            let local =
                if std::fs::metadata(archive)?.len() > config.analysis.max_artifact_bytes as u64 {
                    zoli_inspect::Report::unavailable(
                        id.clone(),
                        &config.analysis,
                        "artifact_byte_limit_exceeded_before_acquisition",
                    )
                } else {
                    let bytes = read_bounded(archive, config.analysis.max_artifact_bytes)?;
                    if let Some(integrity) = integrity {
                        verify_integrity(&bytes, integrity)?;
                    }
                    id.sha256 = sha256(&bytes);
                    worker::inspect(&bytes, id.clone(), &config.analysis)
                };
            let now = GoTime::now();
            let decision = decide(
                Evidence {
                    local: Some(&local),
                    require_local: true,
                    ..Default::default()
                },
                mode(cli),
                suspicious(cli, config.policy.suspicious),
                &now,
            );
            let code = decision.exit_code;
            let report = Assessment {
                schema: 1,
                scope: "local_artifact_only",
                time: now,
                mode: mode(cli),
                suspicious_policy: suspicious(cli, config.policy.suspicious),
                identity: id,
                feed_verdict: None,
                feed_provenance: None,
                local_analysis: Some(local),
                decision,
                elapsed_ms: started.elapsed().as_millis(),
                limitations: vec![
                    "Feed checking was not performed; this local result cannot grant installation approval",
                    "A computed archive digest alone does not authenticate its publisher",
                ],
            };
            output::emit(&report, cli.json, &home)?;
            Ok(code)
        }
        Command::Check(args) => {
            let started = Instant::now();
            let mut id = identity(&args.identity)?;
            if let Some(hash) = &args.sha256 {
                id.sha256 = hash.clone();
                if hash.is_empty() {
                    return Err(Usage("artifact SHA-256 must not be empty".into()).into());
                }
                id.normalize().map_err(|e| Usage(e.to_string()))?;
            }
            let (home, config) = config::Config::load()?;
            let key = config.key()?;
            let snapshot = Store::new(home.clone()).load(&key)?;
            let manifest = snapshot.verify(&key)?;
            let now = GoTime::now();
            let verdict = zoli_intel::query::query(id.clone(), &manifest, &snapshot.records, &now)?;
            let decision = decide(
                Evidence {
                    verdict: Some(&verdict),
                    manifest: Some(&manifest),
                    require_feed: true,
                    ..Default::default()
                },
                mode(cli),
                suspicious(cli, config.policy.suspicious),
                &now,
            );
            let code = decision.exit_code;
            let report = Assessment {
                schema: 1,
                scope: "feed_only",
                time: now,
                mode: mode(cli),
                suspicious_policy: suspicious(cli, config.policy.suspicious),
                identity: id,
                feed_verdict: Some(verdict),
                feed_provenance: Some(FeedProvenance::new(&snapshot, &manifest)),
                local_analysis: None,
                decision,
                elapsed_ms: started.elapsed().as_millis(),
                limitations: vec![
                    "Local inspection was not performed; this feed-only result cannot grant installation approval",
                ],
            };
            output::emit(&report, cli.json, &home)?;
            Ok(code)
        }
        Command::Update | Command::Status => {
            let (home, config) = config::Config::load()?;
            let key = config.key()?;
            let store = Store::new(home.clone());
            let snapshot = if matches!(&cli.command, Command::Update) {
                let http = config.feed_http()?;
                store.update(
                    &http,
                    &config
                        .feed
                        .as_ref()
                        .context("feed configuration missing")?
                        .url,
                    &key,
                )?
            } else {
                store.load(&key)?
            };
            let manifest = snapshot.verify(&key)?;
            let now = GoTime::now();
            let response = quality(&manifest, &now)?;
            let report = serde_json::json!({"schema":1,"scope":if matches!(&cli.command,Command::Update){"feed_update"}else{"feed_status"},"time":now,"sequence":manifest.sequence,"record_count":manifest.record_count,"freshness":response.freshness,"generated_at":manifest.generated_at,"key_id":snapshot.envelope.key_id,"feed_provenance":FeedProvenance::new(&snapshot,&manifest),"assessment_performed":false});
            output::emit(&report, cli.json, &home)?;
            Ok(0)
        }
        Command::Scan { lockfile, npmrc } => scan(cli, lockfile, npmrc.as_deref()),
    }
}
fn scan(cli: &Cli, lockfile: &std::path::Path, npmrc: Option<&std::path::Path>) -> Result<u8> {
    let report = assess(cli, lockfile, npmrc, None, None)?;
    output::emit(&report, cli.json, &config::Config::home()?)?;
    Ok(report.decision.exit_code)
}
fn assess(
    cli: &Cli,
    lockfile: &std::path::Path,
    npmrc: Option<&std::path::Path>,
    quarantine: Option<&std::path::Path>,
    min_age: Option<u64>,
) -> Result<TreeAssessment> {
    let started = Instant::now();
    let mut timings = BTreeMap::new();
    let (home, config) = config::Config::load()?;
    let key = config.key()?;
    let snapshot = Store::new(home.clone()).load(&key)?;
    let manifest = snapshot.verify(&key)?;
    timings.insert("feed_verification".into(), started.elapsed().as_millis());
    let registry = RegistryClient::new(
        config.registries.entries()?,
        NpmConfig::load(lockfile.parent(), npmrc)?,
    )?;
    let stage = Instant::now();
    let mut inventory = Inventory::from_lock(lockfile, |name| registry.registry_for(name))?;
    timings.insert("inventory".into(), stage.elapsed().as_millis());
    let mut reports = BTreeMap::new();
    let mut errors = BTreeMap::new();
    let mut published = BTreeMap::new();
    let mut registry_integrity = BTreeMap::new();
    let mut acquisition_ms = 0;
    let mut inspection_ms = 0;
    let mut report_bytes = 0usize;
    let initial_time = GoTime::now();
    let initial_quality = quality(&manifest, &initial_time)?;
    let feed_usable = decide(
        Evidence {
            verdict: Some(&initial_quality),
            manifest: Some(&manifest),
            require_feed: true,
            ..Default::default()
        },
        mode(cli),
        suspicious(cli, config.policy.suspicious),
        &initial_time,
    )
    .exit_code
        == 0;
    for package in inventory.packages.iter().filter(|p| !p.bundled) {
        if !feed_usable {
            continue;
        }
        if inventory.gaps.iter().any(|g| g.path == package.path) {
            continue;
        }
        if let Some(hours) = min_age {
            let verdict = zoli_intel::query::query(
                package.identity.clone(),
                &manifest,
                &snapshot.records,
                &GoTime::now(),
            )?;
            if decide(
                Evidence {
                    verdict: Some(&verdict),
                    manifest: Some(&manifest),
                    require_feed: true,
                    ..Default::default()
                },
                mode(cli),
                suspicious(cli, config.policy.suspicious),
                &GoTime::now(),
            )
            .exit_code
                != 0
            {
                continue;
            }
            match registry.publication(&package.identity) {
                Ok(publication) => {
                    let stamp = publication.published_at;
                    registry_integrity.insert(package.path.clone(), publication.integrity);
                    let old_enough =
                        stamp.age(&GoTime::now()) >= time::Duration::hours(hours as i64);
                    published.insert(package.path.clone(), stamp);
                    if !old_enough {
                        continue;
                    }
                }
                Err(error) => {
                    errors.insert(
                        package.path.clone(),
                        format!("publish time unavailable: {error:#}"),
                    );
                    continue;
                }
            }
        }
        if report_bytes > 64 << 20 {
            inventory.gaps.push(Gap {
                path: package.path.clone(),
                reason: "assessment_report_budget_exceeded".into(),
            });
            continue;
        }
        if validate_integrity(&package.integrity).is_err() {
            inventory.gaps.push(Gap {
                path: package.path.clone(),
                reason: "missing_or_unsupported_strong_integrity".into(),
            });
            continue;
        }
        let Some(resolved) = &package.resolved else {
            continue;
        };
        let stage = Instant::now();
        let acquired = registry
            .acquire(&package.identity, resolved, &package.integrity)
            .and_then(|bytes| {
                if let Some(integrity) = registry_integrity.get(&package.path) {
                    verify_integrity(&bytes, integrity).context(
                        "archive differs from the registry version whose publish age was checked",
                    )?;
                }
                Ok(bytes)
            });
        acquisition_ms += stage.elapsed().as_millis();
        match acquired {
            Ok(bytes) => {
                let mut id = package.identity.clone();
                id.sha256 = sha256(&bytes);
                let stage = Instant::now();
                let report = worker::inspect(&bytes, id, &config.analysis);
                if let Some(dir) = quarantine {
                    std::fs::write(dir.join(format!("{}.tgz", report.artifact_sha256)), &bytes)?;
                }
                inspection_ms += stage.elapsed().as_millis();
                report_bytes = report_bytes.saturating_add(serde_json::to_vec(&report)?.len());
                reports.insert(package.path.clone(), report);
            }
            Err(error) => {
                errors.insert(package.path.clone(), format!("{error:#}"));
            }
        }
    }
    timings.insert("acquisition".into(), acquisition_ms);
    timings.insert("local_inspection".into(), inspection_ms);
    // Local inspection covers all embedded source files. Every discovered
    // bundled identity must also be accounted for by the lockfile/feed query.
    for (parent, report) in &reports {
        for bundle in &report.bundled {
            let relative = bundle.path.strip_prefix("package/").unwrap_or(&bundle.path);
            let installed = format!("{parent}/{relative}");
            if !inventory.packages.iter().any(|p| {
                p.path == installed
                    && p.bundled
                    && p.identity.name == bundle.identity.name
                    && p.identity.version == bundle.identity.version
            }) {
                inventory.gaps.push(Gap {
                    path: parent.clone(),
                    reason: "unrecorded_bundled_package_identity".into(),
                });
            }
        }
    }
    let now = GoTime::now();
    let stage = Instant::now();
    let mut nodes = vec![];
    for package in &inventory.packages {
        let mut local = reports.get(&package.path).cloned();
        let mut container = None;
        if package.bundled {
            let parent = reports
                .iter()
                .filter(|(path, _)| package.path.starts_with(&format!("{path}/node_modules/")))
                .max_by_key(|(path, _)| path.len());
            if let Some((path, parent)) = parent {
                let relative = package
                    .path
                    .strip_prefix(&format!("{path}/"))
                    .context("invalid bundle installation path")?;
                if let Some(bundle) = parent
                    .bundled
                    .iter()
                    .find(|b| b.path == relative || b.path == format!("package/{relative}"))
                    && bundle.identity.name == package.identity.name
                    && bundle.identity.version == package.identity.version
                    && bundle.identity.registry == package.identity.registry
                {
                    let mut inherited = parent.clone();
                    inherited.identity = package.identity.clone();
                    inherited
                        .findings
                        .retain(|f| f.file.starts_with(&format!("{}/", bundle.path)));
                    local = Some(inherited);
                    container = Some(path.clone());
                }
            }
        }
        let mut id = package.identity.clone();
        if !package.bundled
            && let Some(local) = &local
        {
            id.sha256 = local.artifact_sha256.clone();
        }
        let verdict = if id.name.is_empty() || !zoli_intel::npm::concrete(&id.version) {
            None
        } else {
            zoli_intel::query::query(id, &manifest, &snapshot.records, &now).ok()
        };
        let gap = inventory.gaps.iter().any(|g| g.path == package.path)
            || local.is_none()
            || verdict.is_none();
        let mut decision = decide(
            Evidence {
                verdict: verdict.as_ref(),
                manifest: Some(&manifest),
                local: local.as_ref(),
                require_feed: verdict.is_some(),
                require_local: true,
                gaps: gap,
            },
            mode(cli),
            suspicious(cli, config.policy.suspicious),
            &now,
        );
        let error = errors.get(&package.path).cloned();
        if error.is_some() {
            decision = Decision {
                action: Action::Block,
                complete: false,
                exit_code: 1,
                reasons: vec!["artifact_acquisition_failed".into()],
            };
        }
        if package.bundled && local.is_none() {
            inventory.gaps.push(Gap {
                path: package.path.clone(),
                reason: "bundled_artifact_not_accounted_for".into(),
            });
        }
        if let Some(hours) = min_age {
            guard::apply_age(&mut decision, published.get(&package.path), hours, &now);
        }
        nodes.push(NodeAssessment {
            package: package.clone(),
            feed_verdict: verdict,
            local_analysis: if container.is_some() { None } else { local },
            analysis_container: container,
            decision,
            error,
            published_at: published.get(&package.path).cloned(),
            registry_integrity: registry_integrity.get(&package.path).cloned(),
        });
    }
    let feed_quality = quality(&manifest, &now)?;
    let base = decide(
        Evidence {
            verdict: Some(&feed_quality),
            manifest: Some(&manifest),
            require_feed: true,
            gaps: !inventory.gaps.is_empty(),
            ..Default::default()
        },
        mode(cli),
        suspicious(cli, config.policy.suspicious),
        &now,
    );
    let decision = aggregate(base, &nodes);
    timings.insert("query_and_policy".into(), stage.elapsed().as_millis());
    timings.insert("total".into(), started.elapsed().as_millis());
    Ok(TreeAssessment {
        schema: 1,
        scope: if min_age.is_some() {
            "npm_ci_assessment"
        } else {
            "dependency_tree"
        },
        time: now,
        mode: mode(cli),
        suspicious_policy: suspicious(cli, config.policy.suspicious),
        sequence: manifest.sequence,
        record_count: manifest.record_count,
        freshness: feed_quality.freshness,
        feed_provenance: FeedProvenance::new(&snapshot, &manifest),
        inventory,
        packages: nodes,
        decision,
        timings_ms: timings,
        limitations: vec![
            "All recorded dependency scopes were included; unsupported sources remain explicit gaps",
            "Private/public registry identities are not interchangeable; feed coverage is selective",
            "No known match and completed static analysis do not prove safety",
            "No package code executed during assessment",
        ],
    })
}
fn aggregate(base: Decision, nodes: &[NodeAssessment]) -> Decision {
    let mut reasons: BTreeSet<String> = base.reasons.iter().cloned().collect();
    let mut complete = base.complete;
    let mut code = base.exit_code;
    let mut warn = base.action == Action::Warn;
    let rank = |code| match code {
        1 => 4,
        10 => 3,
        12 => 2,
        _ => 0,
    };
    for node in nodes {
        complete &= node.decision.complete;
        warn |= node.decision.action == Action::Warn;
        for reason in &node.decision.reasons {
            reasons.insert(reason.clone());
        }
        if rank(node.decision.exit_code) > rank(code) {
            code = node.decision.exit_code;
        }
    }
    if code != 0 || warn {
        reasons.remove("no_actionable_findings_within_declared_scope");
    }
    Decision {
        action: if code != 0 {
            Action::Block
        } else if warn {
            Action::Warn
        } else {
            Action::Allow
        },
        complete,
        exit_code: code,
        reasons: reasons.into_iter().collect(),
    }
}
fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let code = if error.downcast_ref::<Usage>().is_some() {
                2
            } else {
                1
            };
            let mut value = serde_json::json!({"schema":1,"scope":"error","time":GoTime::now(),"mode":mode(&cli),"error":format!("{error:#}"),"exit_code":code});
            if code == 1 {
                let recorded = config::Config::home()
                    .ok()
                    .and_then(|home| {
                        serde_json::to_vec(&value)
                            .ok()
                            .map(|bytes| output::audit(&home, &bytes))
                    })
                    .is_some_and(|r| r.is_ok());
                if !recorded {
                    value["audit_error"] = serde_json::json!("runtime_error_audit_unavailable");
                }
            }
            if cli.json {
                let mut out = std::io::stdout().lock();
                let _ = serde_json::to_writer(&mut out, &value);
                let _ = out.write_all(b"\n");
            } else {
                eprintln!("zoli: {error:#}");
                if let Some(audit_error) = value["audit_error"].as_str() {
                    eprintln!("zoli: {audit_error}");
                }
            }
            ExitCode::from(code)
        }
    }
}
