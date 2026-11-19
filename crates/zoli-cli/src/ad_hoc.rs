//! Guarded ad-hoc npm operations: resolve with npm metadata only, assess the
//! exact resolved tree, then let npm install/run only from approved bytes.
use super::{Cli, TreeAssessment, Usage, assess, config, guard, output};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zoli_intel::{feed::read_bounded, model::GoTime};
use zoli_proxy::registry::{NpmConfig, RegistryClient};

const MAX_MANIFEST_BYTES: usize = 2 << 20;
const MAX_LOCKFILE_BYTES: usize = 20 << 20;

struct Private {
    directory: tempfile::TempDir,
    quarantine: PathBuf,
    cache: PathBuf,
    metadata_cache: PathBuf,
    user: PathBuf,
    global: PathBuf,
}

impl Private {
    fn new(prefix: &str) -> Result<Self> {
        let directory = tempfile::Builder::new().prefix(prefix).tempdir()?;
        let quarantine = directory.path().join("quarantine");
        std::fs::create_dir(&quarantine)?;
        let cache = directory.path().join("cache");
        let metadata_cache = directory.path().join("metadata-cache");
        let user = directory.path().join("user.npmrc");
        let global = directory.path().join("global.npmrc");
        std::fs::write(&user, b"")?;
        std::fs::write(&global, b"")?;
        Ok(Self {
            directory,
            quarantine,
            cache,
            metadata_cache,
            user,
            global,
        })
    }

    fn root(&self) -> &Path {
        self.directory.path()
    }
}

struct Prepared {
    directory: tempfile::TempDir,
    package_json: PathBuf,
    lockfile: PathBuf,
}

#[derive(Debug, Clone)]
struct Spec {
    name: String,
    spec: String,
}

fn valid_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 214,
        "invalid npm package name"
    );
    ensure!(
        !name.chars().any(|c| c.is_control() || c.is_whitespace()),
        "invalid npm package name"
    );
    ensure!(
        !name.starts_with('.') && !name.starts_with('_'),
        "invalid npm package name"
    );
    if let Some(rest) = name.strip_prefix('@') {
        let (scope, package) = rest
            .split_once('/')
            .context("scoped npm name requires @scope/name")?;
        ensure!(
            !scope.is_empty() && !package.is_empty() && !package.contains('/'),
            "invalid scoped npm package name"
        );
    } else {
        ensure!(!name.contains('/'), "invalid npm package name");
    }
    Ok(())
}

fn valid_spec(spec: &str) -> Result<()> {
    ensure!(!spec.is_empty(), "npm version or range is empty");
    ensure!(
        !spec.chars().any(|c| c.is_control() || c.is_whitespace()),
        "npm version or range contains whitespace or control characters"
    );
    let lower = spec.to_ascii_lowercase();
    for prefix in [
        "file:",
        "link:",
        "workspace:",
        "git:",
        "git+",
        "http:",
        "https:",
        "ssh:",
        "github:",
        "gitlab:",
        "bitbucket:",
    ] {
        ensure!(
            !lower.starts_with(prefix),
            "unsupported npm source: only registry versions, ranges and tags are guarded"
        );
    }
    ensure!(
        !spec.starts_with('.')
            && !spec.starts_with('/')
            && !spec.contains('\\')
            && !spec.contains('#'),
        "unsupported npm source"
    );
    if let Some(alias) = spec.strip_prefix("npm:") {
        ensure!(!alias.is_empty(), "invalid npm alias");
    }
    Ok(())
}

fn parse_spec(raw: &str) -> Result<Spec> {
    ensure!(
        !raw.starts_with('-'),
        "npm package spec must not start with '-'"
    );
    let (name, version) = if raw.starts_with('@') {
        let slash = raw
            .find('/')
            .context("scoped npm name requires @scope/name")?;
        let after = &raw[slash + 1..];
        match after.rfind('@') {
            Some(index) if index > 0 => (&raw[..slash + 1 + index], &after[index + 1..]),
            _ => (raw, "latest"),
        }
    } else {
        match raw.rfind('@') {
            Some(index) if index > 0 => (&raw[..index], &raw[index + 1..]),
            _ => (raw, "latest"),
        }
    };
    valid_name(name)?;
    valid_spec(version)?;
    Ok(Spec {
        name: name.to_owned(),
        spec: version.to_owned(),
    })
}

fn manifest_dependencies(manifest: &Value) -> Result<Vec<(String, String)>> {
    let mut result = vec![];
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(map) = manifest.get(key) else {
            continue;
        };
        let map = map
            .as_object()
            .with_context(|| format!("package.json {key} must be an object"))?;
        for (name, spec) in map {
            let spec = spec
                .as_str()
                .with_context(|| format!("package.json {key}.{name} must be a string"))?;
            valid_name(name)?;
            valid_spec(spec)?;
            result.push((name.clone(), spec.to_owned()));
        }
    }
    if let Some(workspaces) = manifest.get("workspaces") {
        ensure!(
            workspaces.is_null(),
            "workspace projects are not supported by the guarded install adapter"
        );
    }
    Ok(result)
}

fn routing_npmrc(project: &Path) -> Result<Option<String>> {
    let path = project.join(".npmrc");
    if !path.exists() {
        return Ok(None);
    }
    guard::project_config(project)?;
    let bytes = read_bounded(&path, 1 << 20)?;
    let text = std::str::from_utf8(&bytes).context("project .npmrc is not UTF-8")?;
    let mut routing = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("registry=") || line.starts_with('@') && line.contains(":registry=") {
            routing.push_str(line);
            routing.push('\n');
        }
    }
    Ok(Some(routing))
}

fn user_npmrc() -> Option<PathBuf> {
    std::env::var_os("npm_config_userconfig")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".npmrc")))
        .filter(|path| path.is_file())
}

fn check_routes(
    config: &config::Config,
    project: Option<&Path>,
    names: impl IntoIterator<Item = String>,
) -> Result<()> {
    let npm = NpmConfig::load(project, None)?;
    let routes = npm.routes();
    let client = RegistryClient::new(config.registries.entries()?, npm)?;
    for (scope, route) in routes {
        let probe = scope.map_or_else(|| "probe".to_owned(), |scope| format!("{scope}/probe"));
        ensure!(
            client.registry_for(&probe)? == route,
            "npm registry route is not approved in Zoli configuration"
        );
    }
    for name in names {
        client.registry_for(&name)?;
    }
    Ok(())
}

fn copy_project_lock(project: &Path, directory: &Path) -> Result<()> {
    let source = project.join("package-lock.json");
    if source.exists() {
        let bytes = read_bounded(&source, MAX_LOCKFILE_BYTES)?;
        std::fs::write(directory.join("package-lock.json"), bytes)?;
    }
    Ok(())
}

fn resolution_manifest(project: Option<&Path>) -> Result<(Value, bool)> {
    match project {
        Some(project) => {
            let path = project.join("package.json");
            ensure!(
                path.is_file(),
                "guarded npm install requires a package.json in the current directory"
            );
            let bytes = read_bounded(&path, MAX_MANIFEST_BYTES)?;
            let manifest: Value =
                serde_json::from_slice(&bytes).context("invalid project package.json")?;
            ensure!(
                manifest.is_object(),
                "project package.json must be an object"
            );
            Ok((manifest, false))
        }
        None => Ok((
            json!({"name":"zoli-ad-hoc","version":"0.0.0","private":true,"dependencies":{}}),
            true,
        )),
    }
}

fn resolve(
    program: &Path,
    private: &Private,
    project: Option<&Path>,
    specs: &[Spec],
    save_dev: bool,
) -> Result<Prepared> {
    let directory = tempfile::Builder::new()
        .prefix("zoli-npm-resolve-")
        .tempdir()?;
    let (mut manifest, _) = resolution_manifest(project)?;
    manifest_dependencies(&manifest)?;
    let key = if save_dev {
        "devDependencies"
    } else {
        "dependencies"
    };
    if !specs.is_empty() {
        if manifest.get(key).is_none() {
            manifest[key] = json!({});
        }
        let dependencies = manifest[key]
            .as_object_mut()
            .context("package.json dependency section is not an object")?;
        for spec in specs {
            dependencies.insert(spec.name.clone(), Value::String(spec.spec.clone()));
        }
    }
    std::fs::write(
        directory.path().join("package.json"),
        serde_json::to_vec(&manifest)?,
    )?;
    if let Some(project) = project {
        copy_project_lock(project, directory.path())?;
        if let Some(routing) = routing_npmrc(project)? {
            std::fs::write(directory.path().join(".npmrc"), routing)?;
        }
    }
    let user = user_npmrc().unwrap_or_else(|| private.user.clone());
    let output = guard::npm_command(
        program,
        directory.path(),
        &private.metadata_cache,
        &user,
        &private.global,
        false,
    )
    .args([
        "install",
        "--package-lock-only",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--update-notifier=false",
        "--loglevel=error",
    ])
    .stdin(Stdio::null())
    .output()?;
    ensure!(
        output.status.success(),
        "npm could not resolve the requested dependency set: {}",
        tail(&output.stderr)
    );
    let package_json = directory.path().join("package.json");
    let lockfile = directory.path().join("package-lock.json");
    ensure!(
        lockfile.is_file(),
        "npm resolution did not produce a lockfile"
    );
    Ok(Prepared {
        directory,
        package_json,
        lockfile,
    })
}

fn tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    if text.len() <= 2_000 {
        text.to_owned()
    } else {
        text.chars()
            .rev()
            .take(2_000)
            .collect::<String>()
            .chars()
            .rev()
            .collect()
    }
}

fn resolved_version(lockfile: &Value, name: &str) -> Option<String> {
    lockfile
        .get("packages")?
        .get(format!("node_modules/{name}"))?
        .get("version")?
        .as_str()
        .map(str::to_owned)
}

fn sync_requested_specs(
    prepared: &Prepared,
    specs: &[Spec],
    save_dev: bool,
    save_exact: bool,
) -> Result<()> {
    if specs.is_empty() {
        return Ok(());
    }
    let mut manifest: Value =
        serde_json::from_slice(&read_bounded(&prepared.package_json, MAX_MANIFEST_BYTES)?)?;
    let mut lock: Value =
        serde_json::from_slice(&read_bounded(&prepared.lockfile, MAX_LOCKFILE_BYTES)?)?;
    let key = if save_dev {
        "devDependencies"
    } else {
        "dependencies"
    };
    let versions = specs
        .iter()
        .map(|spec| {
            resolved_version(&lock, &spec.name)
                .map(|version| (spec.name.clone(), version))
                .with_context(|| format!("resolved version for {} is missing", spec.name))
        })
        .collect::<Result<Vec<_>>>()?;
    let values = specs
        .iter()
        .zip(versions)
        .map(|(spec, (_, version))| {
            let value = if save_exact {
                version.clone()
            } else if spec.spec == "latest" {
                format!("^{version}")
            } else if zoli_intel::npm::concrete(&spec.spec) {
                format!("^{}", spec.spec)
            } else {
                spec.spec.clone()
            };
            (spec.name.clone(), value, version)
        })
        .collect::<Vec<_>>();
    {
        let dependencies = manifest[key]
            .as_object_mut()
            .context("resolved package.json dependency section missing")?;
        let root = lock
            .get_mut("packages")
            .and_then(Value::as_object_mut)
            .and_then(|packages| packages.get_mut(""))
            .and_then(Value::as_object_mut)
            .context("resolved lockfile root entry missing")?;
        for (name, value, _) in &values {
            dependencies.insert(name.clone(), Value::String(value.clone()));
            if root.get(key).is_none() {
                root.insert(key.to_owned(), json!({}));
            }
            root[key]
                .as_object_mut()
                .context("resolved lockfile root dependency section is not an object")?
                .insert(name.clone(), Value::String(value.clone()));
        }
    }
    if let Some(legacy) = lock.get_mut("dependencies").and_then(Value::as_object_mut) {
        for (name, _, version) in &values {
            if let Some(entry) = legacy.get_mut(name).and_then(Value::as_object_mut) {
                entry.insert("version".into(), Value::String(version.clone()));
            }
        }
    }
    std::fs::write(&prepared.package_json, serde_json::to_vec(&manifest)?)?;
    std::fs::write(&prepared.lockfile, serde_json::to_vec(&lock)?)?;
    Ok(())
}

fn sync_install_scripts(prepared: &Prepared, report: &TreeAssessment) -> Result<()> {
    let mut lock: Value =
        serde_json::from_slice(&read_bounded(&prepared.lockfile, MAX_LOCKFILE_BYTES)?)?;
    let packages = lock
        .get_mut("packages")
        .and_then(Value::as_object_mut)
        .context("resolved lockfile has no packages entry")?;
    let mut changed = false;
    for node in &report.packages {
        let hook = node.local_analysis.as_ref().is_some_and(|local| {
            local
                .findings
                .iter()
                .any(|finding| finding.rule_id == "ZOLI-LOCAL-101")
        });
        if !hook {
            continue;
        }
        if let Some(entry) = packages
            .get_mut(&node.package.path)
            .and_then(Value::as_object_mut)
            && entry.get("hasInstallScript").and_then(Value::as_bool) != Some(true)
        {
            entry.insert("hasInstallScript".into(), Value::Bool(true));
            changed = true;
        }
    }
    if changed {
        std::fs::write(&prepared.lockfile, serde_json::to_vec(&lock)?)?;
    }
    Ok(())
}

fn write_project_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("project path has no parent")?;
    let mode = std::fs::symlink_metadata(path)
        .ok()
        .map(|metadata| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o777
            }
            #[cfg(not(unix))]
            {
                0o644
            }
        })
        .unwrap_or(0o644);
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn check_npm(program: &Path, private: &Private) -> Result<String> {
    let output = guard::npm_command(
        program,
        private.root(),
        &private.cache,
        &private.user,
        &private.global,
        false,
    )
    .arg("--version")
    .output()?;
    ensure!(
        output.status.success()
            && std::str::from_utf8(&output.stdout)?
                .trim()
                .starts_with("10."),
        "this install guard is validated for npm 10; other npm majors refuse execution"
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn age_hours(config: &config::Config) -> u64 {
    config.policy.min_publish_age_hours.unwrap_or(24)
}

fn install_options(args: &[String]) -> Result<(Vec<Spec>, bool, bool, Vec<String>)> {
    let mut specs = vec![];
    let mut save_dev = false;
    let mut save_exact = false;
    let mut passthrough = vec![];
    for arg in args {
        match arg.as_str() {
            "--ignore-scripts" | "--foreground-scripts" => passthrough.push(arg.clone()),
            "--save-dev" | "-D" => save_dev = true,
            "--save-exact" | "-E" => save_exact = true,
            value if value.starts_with('-') => {
                return Err(Usage(format!(
                    "guarded npm install does not support option {value}; cache, registry and execution overrides are refused"
                ))
                .into());
            }
            value => specs.push(parse_spec(value)?),
        }
    }
    Ok((specs, save_dev, save_exact, passthrough))
}

/// Guarded `npm install` (with or without direct package specs).
pub fn install(cli: &Cli, args: &[String]) -> Result<u8> {
    if cli.json {
        return Err(Usage(
            "wrap preserves npm stdout; use audit.jsonl for structured reports instead of --json"
                .into(),
        )
        .into());
    }
    let (specs, save_dev, save_exact, passthrough) = install_options(args)?;
    let project = std::env::current_dir()?.canonicalize()?;
    ensure!(
        !project.join("npm-shrinkwrap.json").exists(),
        "guarded npm install does not edit npm-shrinkwrap.json; use `zoli wrap npm -- ci`"
    );
    let home = config::Config::home()?;
    let (_, config) = config::Config::load()?;
    guard::project_config(&project)?;
    let inputs = guard::Inputs::capture(&project, &home)?;
    let manifest: Value = serde_json::from_slice(&read_bounded(
        &project.join("package.json"),
        MAX_MANIFEST_BYTES,
    )?)
    .context("invalid project package.json")?;
    let declared = manifest_dependencies(&manifest)?;
    let names = declared
        .iter()
        .map(|(name, _)| name.clone())
        .chain(specs.iter().map(|spec| spec.name.clone()))
        .collect::<BTreeSet<_>>();
    check_routes(&config, Some(&project), names)?;
    let program = guard::executable("npm", &home)?;
    let private = Private::new("zoli-npm-install-")?;
    let version = check_npm(&program, &private)?;
    let prepared = resolve(&program, &private, Some(&project), &specs, save_dev)?;
    sync_requested_specs(&prepared, &specs, save_dev, save_exact)?;
    let hours = age_hours(&config);
    let mut report = assess(
        cli,
        &prepared.lockfile,
        None,
        Some(&private.quarantine),
        Some(hours),
        "npm_install_assessment",
    )?;
    output::guard_report(&report, &home)?;
    if report.decision.exit_code != 0 {
        return Ok(report.decision.exit_code);
    }
    inputs.verify(&project, &home)?;
    guard::seed_cache(
        guard::Seed {
            program: &program,
            workspace: private.directory.path(),
            cache: &private.cache,
            user: &private.user,
            global: &private.global,
            quarantine: &private.quarantine,
            max_bytes: config.analysis.max_artifact_bytes,
        },
        &report,
    )?;
    inputs.verify(&project, &home)?;
    guard::refresh(
        cli,
        &config,
        &home,
        &mut report,
        hours,
        "npm_install_release",
    )?;
    output::guard_report(&report, &home)?;
    if report.decision.exit_code != 0 {
        return Ok(report.decision.exit_code);
    }
    sync_install_scripts(&prepared, &report)?;
    let package_bytes = read_bounded(&prepared.package_json, MAX_MANIFEST_BYTES)?;
    let lock_bytes = read_bounded(&prepared.lockfile, MAX_LOCKFILE_BYTES)?;
    let resolved_digest = zoli_intel::feed::sha256(&lock_bytes);
    inputs.verify(&project, &home)?;
    let authorization = json!({"schema":1,"scope":"npm_install_authorization","time":GoTime::now(),"input_sha256":inputs.digest()?,"resolved_lock_sha256":resolved_digest,"sequence":report.sequence,"manifest_sha256":report.feed_provenance.manifest_sha256,"min_publish_age_hours":hours,"cache":"private_approved_artifacts_only","npm_version":version,"package_count":report.packages.len(),"requested":specs.iter().map(|s| format!("{}@{}",s.name,s.spec)).collect::<Vec<_>>()});
    output::audit(&home, &serde_json::to_vec(&authorization)?)?;
    write_project_file(&project.join("package-lock.json"), &lock_bytes)?;
    let existing_manifest = std::fs::read(project.join("package.json"))?;
    if existing_manifest != package_bytes {
        write_project_file(&project.join("package.json"), &package_bytes)?;
    }
    eprintln!(
        "zoli: approved {} dependencies; npm install uses an isolated offline cache (minimum age {hours}h)",
        report.packages.len()
    );
    let status = guard::npm_command(
        &program,
        &project,
        &private.cache,
        &private.user,
        &private.global,
        true,
    )
    .arg("install")
    .args(&passthrough)
    .args([
        "--offline",
        "--audit=false",
        "--fund=false",
        "--update-notifier=false",
    ])
    .arg("--cache")
    .arg(&private.cache)
    .arg("--userconfig")
    .arg(&private.user)
    .arg("--globalconfig")
    .arg(&private.global)
    .stdin(Stdio::inherit())
    .stdout(Stdio::inherit())
    .stderr(Stdio::inherit())
    .status()?;
    let exit_code = guard::code(status);
    output::audit(
        &home,
        &serde_json::to_vec(
            &json!({"schema":1,"scope":"npm_install_exit","time":GoTime::now(),"exit_code":exit_code,"lockfile_sha256":zoli_intel::feed::sha256(&std::fs::read(project.join("package-lock.json"))?)}),
        )?,
    )?;
    Ok(exit_code)
}

fn npx_spec(args: &[String]) -> Result<(Spec, Vec<String>)> {
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--yes" | "-y" => index += 1,
            "--" => {
                index += 1;
                break;
            }
            value if value.starts_with('-') => {
                return Err(Usage(format!(
                    "guarded npx does not support option {value}; only -y/--yes is accepted"
                ))
                .into());
            }
            _ => break,
        }
    }
    let spec = args
        .get(index)
        .context("guarded npx requires one package spec, for example `npx cowsay@1.6.0`")?;
    let spec = parse_spec(spec)?;
    Ok((spec, args[index + 1..].to_vec()))
}

fn find_bin(directory: &Path, name: &str) -> Result<PathBuf> {
    let package = directory.join(format!("node_modules/{name}"));
    let manifest: Value = serde_json::from_slice(&read_bounded(
        &package.join("package.json"),
        MAX_MANIFEST_BYTES,
    )?)
    .with_context(|| format!("installed package {name} has no readable package.json"))?;
    let relative = match manifest.get("bin") {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Object(map)) => {
            let short = name.rsplit('/').next().unwrap_or(name);
            if let Some(value) = map.get(name).or_else(|| map.get(short)) {
                value
                    .as_str()
                    .context("package bin entry is not a string")?
                    .to_owned()
            } else if map.len() == 1 {
                map.values()
                    .next()
                    .and_then(Value::as_str)
                    .context("package bin entry is not a string")?
                    .to_owned()
            } else {
                bail!("package {name} has multiple executables and no matching bin name")
            }
        }
        _ => bail!("package {name} does not declare an executable"),
    };
    ensure!(
        !relative.starts_with('/') && !relative.contains('\\'),
        "package bin path is not relative"
    );
    let path = package.join(&relative);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("package executable is missing: {}", path.display()))?;
    ensure!(
        canonical.starts_with(&package.canonicalize()?),
        "package executable escapes its installation directory"
    );
    ensure!(
        canonical.is_file(),
        "package executable is not a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            canonical.metadata()?.permissions().mode() & 0o111 != 0,
            "package executable is not executable"
        );
    }
    Ok(canonical)
}

/// Guarded `npx`: install and inspect one package, then run only its declared
/// executable from the approved private installation.
pub fn npx(cli: &Cli, args: &[String]) -> Result<u8> {
    let (spec, passthrough) = npx_spec(args)?;
    if cli.json {
        return Err(Usage(
            "npx preserves command stdout; use audit.jsonl for structured reports instead of --json"
                .into(),
        )
        .into());
    }
    let project = std::env::current_dir()?.canonicalize()?;
    let home = config::Config::home()?;
    let (_, config) = config::Config::load()?;
    check_routes(&config, None, [spec.name.clone()])?;
    let program = guard::executable("npm", &home)?;
    let private = Private::new("zoli-npx-")?;
    let version = check_npm(&program, &private)?;
    let prepared = resolve(&program, &private, None, std::slice::from_ref(&spec), false)?;
    let hours = age_hours(&config);
    let mut report = assess(
        cli,
        &prepared.lockfile,
        None,
        Some(&private.quarantine),
        Some(hours),
        "npx_assessment",
    )?;
    output::guard_report(&report, &home)?;
    if report.decision.exit_code != 0 {
        return Ok(report.decision.exit_code);
    }
    guard::seed_cache(
        guard::Seed {
            program: &program,
            workspace: private.directory.path(),
            cache: &private.cache,
            user: &private.user,
            global: &private.global,
            quarantine: &private.quarantine,
            max_bytes: config.analysis.max_artifact_bytes,
        },
        &report,
    )?;
    guard::refresh(cli, &config, &home, &mut report, hours, "npx_release")?;
    output::guard_report(&report, &home)?;
    if report.decision.exit_code != 0 {
        return Ok(report.decision.exit_code);
    }
    sync_install_scripts(&prepared, &report)?;
    let authorization = json!({"schema":1,"scope":"npx_authorization","time":GoTime::now(),"package":format!("{}@{}",spec.name,spec.spec),"sequence":report.sequence,"manifest_sha256":report.feed_provenance.manifest_sha256,"min_publish_age_hours":hours,"cache":"private_approved_artifacts_only","npm_version":version,"package_count":report.packages.len()});
    output::audit(&home, &serde_json::to_vec(&authorization)?)?;
    let installed = guard::npm_command(
        &program,
        prepared.directory.path(),
        &private.cache,
        &private.user,
        &private.global,
        true,
    )
    .args([
        "ci",
        "--offline",
        "--audit=false",
        "--fund=false",
        "--update-notifier=false",
        "--loglevel=error",
    ])
    .stdin(Stdio::null())
    .output()?;
    ensure!(
        installed.status.success(),
        "approved npx package could not be installed from the private cache: {}",
        tail(&installed.stderr)
    );
    let bin = find_bin(prepared.directory.path(), &spec.name)?;
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut entries = vec![prepared.directory.path().join("node_modules/.bin")];
    entries.extend(std::env::split_paths(&path));
    let path = std::env::join_paths(entries)?;
    let mut command = Command::new(&bin);
    command
        .current_dir(&project)
        .args(&passthrough)
        .env("PATH", path)
        .env("ZOLI_WRAPPED", "1")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (key, _) in std::env::vars_os() {
        let lower = key.to_string_lossy().to_ascii_lowercase();
        if lower.starts_with("npm_config_")
            || ["node_options", "node_path"].contains(&lower.as_str())
        {
            command.env_remove(key);
        }
    }
    let status = command.status()?;
    let exit_code = guard::code(status);
    output::audit(
        &home,
        &serde_json::to_vec(
            &json!({"schema":1,"scope":"npx_exit","time":GoTime::now(),"exit_code":exit_code}),
        )?,
    )?;
    Ok(exit_code)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn specs_parse_scoped_names_and_ranges() {
        let spec = parse_spec("@scope/tool@1.2.3").unwrap();
        assert_eq!(spec.name, "@scope/tool");
        assert_eq!(spec.spec, "1.2.3");
        let spec = parse_spec("@scope/tool").unwrap();
        assert_eq!(spec.name, "@scope/tool");
        assert_eq!(spec.spec, "latest");
        let spec = parse_spec("tool@^1.2.0").unwrap();
        assert_eq!(spec.name, "tool");
        assert_eq!(spec.spec, "^1.2.0");
        for value in [
            "file:../x",
            "tool@git+https://x",
            "tool@../x",
            "tool@1.0.0#x",
        ] {
            assert!(parse_spec(value).is_err(), "{value}");
        }
    }

    #[test]
    fn install_options_reject_unknown_overrides() {
        assert!(install_options(&["--cache=/tmp/x".into()]).is_err());
        let (specs, dev, exact, pass) = install_options(&[
            "a@1.0.0".into(),
            "--save-dev".into(),
            "-E".into(),
            "--ignore-scripts".into(),
        ])
        .unwrap();
        assert_eq!(specs.len(), 1);
        assert!(dev && exact);
        assert_eq!(pass, vec!["--ignore-scripts"]);
    }

    #[test]
    fn unapproved_source_specs_are_rejected() {
        for value in [
            "file:../pkg",
            "https://example.invalid/pkg.tgz",
            "git+ssh://example.invalid/pkg",
            "workspace:*",
        ] {
            assert!(valid_spec(value).is_err(), "{value}");
        }
        assert!(valid_spec("^1.2.3").is_ok());
        assert!(valid_spec("latest").is_ok());
    }
}
