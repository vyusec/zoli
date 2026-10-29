//! Exact npm lockfile inventory; no dependency resolution or package execution.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
};
use zoli_intel::{feed::read_bounded, json, model::Identity, npm};

/// One resolved installation location. Different locations/versions stay distinct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// Lockfile installation path, also the node's stable ID.
    pub path: String,
    /// Actual package identity, including the target of an npm alias.
    pub identity: Identity,
    /// Download URL, retained only internally to avoid disclosing signed queries.
    #[serde(skip)]
    pub resolved: Option<String>,
    /// Lockfile integrity, not inferred from an untrusted download.
    pub integrity: String,
    /// Whether npm records a development dependency.
    pub dev: bool,
    /// Whether npm records an optional dependency.
    pub optional: bool,
    /// Whether npm records a peer-only dependency.
    pub peer: bool,
    /// Bytes are contained in a parent package archive.
    pub bundled: bool,
    /// Child installation paths from the recorded dependency declarations.
    pub dependencies: Vec<String>,
    /// Immediate parents; root project is represented by the empty path.
    pub parents: Vec<String>,
    /// One deterministic root-to-node path; full alternatives remain in edges.
    pub introduced_by: Vec<String>,
}
/// Inventory coverage gap, including the installation path it affects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gap {
    /// Affected installation path, or empty for the root project.
    pub path: String,
    /// Stable reason code, without credentials or raw external URLs.
    pub reason: String,
}
/// Full inventory and explicit coverage limitations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    /// Supported source lockfile version.
    pub lockfile_version: u64,
    /// Every observed non-root lockfile entry.
    pub packages: Vec<Package>,
    /// Root dependency installation paths.
    pub roots: Vec<String>,
    /// Unsupported, inconsistent or unresolved entries.
    pub gaps: Vec<Gap>,
}
fn string(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}
fn declared(value: &Value, root: bool) -> Result<BTreeMap<String, String>> {
    ensure!(
        value.is_object(),
        "package manifest/lock entry must be an object"
    );
    let mut result = BTreeMap::new();
    for key in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if key == "devDependencies" && !root {
            continue;
        }
        if let Some(declarations) = value.get(key) {
            let map = declarations
                .as_object()
                .context("dependency declarations must be an object")?;
            for (name, spec) in map {
                let spec = spec
                    .as_str()
                    .filter(|s| !s.trim().is_empty())
                    .context("dependency requirement must be a nonempty string")?;
                result.insert(name.clone(), spec.to_owned());
            }
        }
    }
    Ok(result)
}
fn installed_name(path: &str) -> Option<&str> {
    let suffix = path.rsplit_once("node_modules/")?.1;
    if suffix.starts_with('@') {
        let (scope, name) = suffix.split_once('/')?;
        if !scope.is_empty() && !name.is_empty() && !name.contains('/') {
            Some(suffix)
        } else {
            None
        }
    } else if !suffix.is_empty() && !suffix.contains('/') {
        Some(suffix)
    } else {
        None
    }
}
fn alias(spec: &str) -> Option<(&str, &str)> {
    let target = spec.strip_prefix("npm:")?;
    if let Some(index) = target.rfind('@').filter(|i| *i > 0) {
        Some((&target[..index], &target[index + 1..]))
    } else {
        Some((target, "*"))
    }
}
fn resolve(parent: &str, name: &str, paths: &BTreeSet<String>) -> Option<String> {
    let mut current = parent;
    loop {
        let candidate = if current.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{current}/node_modules/{name}")
        };
        if paths.contains(&candidate) {
            return Some(candidate);
        }
        if current.is_empty() {
            return None;
        }
        current = current.rsplit_once("/node_modules/").map_or("", |p| p.0);
    }
}
impl Inventory {
    /// Read a supported lockfile and its sibling package.json, resolving only
    /// locations already recorded by npm. The callback supplies approved routing.
    pub fn from_lock(path: &Path, registry_for: impl Fn(&str) -> Result<String>) -> Result<Self> {
        let root = path.parent().context("lockfile directory missing")?;
        ensure!(
            path.file_name().is_some_and(|s| s == "npm-shrinkwrap.json")
                || !root.join("npm-shrinkwrap.json").exists(),
            "npm-shrinkwrap.json takes precedence; select it explicitly"
        );
        let lock: Value = json::decode(&read_bounded(path, 20 << 20)?)?;
        let version = lock
            .get("lockfileVersion")
            .and_then(Value::as_u64)
            .context("missing lockfileVersion")?;
        ensure!(
            version == 2 || version == 3,
            "only npm lockfile versions 2 and 3 are supported"
        );
        let entries = lock
            .get("packages")
            .and_then(Value::as_object)
            .context("lockfile has no packages inventory")?;
        ensure!(
            entries.len() <= 100_000,
            "dependency inventory exceeds node limit"
        );
        let project: Value = json::decode(&read_bounded(&root.join("package.json"), 2 << 20)?)?;
        let mut result = Self {
            lockfile_version: version,
            packages: vec![],
            roots: vec![],
            gaps: vec![],
        };
        let project_requirements = declared(&project, true)?;
        let locked_requirements = entries.get("").map(|r| declared(r, true)).transpose()?;
        if locked_requirements.as_ref() != Some(&project_requirements) {
            result.gaps.push(Gap {
                path: String::new(),
                reason: "project_manifest_and_lockfile_disagree".into(),
            });
        }
        if project.get("workspaces").is_some()
            || entries
                .get("")
                .is_some_and(|r| r.get("workspaces").is_some())
        {
            result.gaps.push(Gap {
                path: String::new(),
                reason: "unsupported_workspace_configuration".into(),
            });
        }
        let mut requirements = BTreeMap::new();
        requirements.insert(String::new(), project_requirements);
        for (path, value) in entries {
            if path.is_empty() {
                continue;
            }
            ensure!(
                path.len() <= 1024
                    && !path.starts_with('/')
                    && !path.contains('\\')
                    && !path.chars().any(char::is_control)
                    && path
                        .split('/')
                        .all(|p| !p.is_empty() && p != "." && p != ".."),
                "unsafe installation path in lockfile"
            );
            let name = if !string(value, "name").is_empty() {
                string(value, "name")
            } else {
                installed_name(path).unwrap_or_default().to_owned()
            };
            let mut identity = Identity {
                ecosystem: "npm".into(),
                name,
                version: string(value, "version"),
                ..Default::default()
            };
            let mut reason = None;
            if value.get("link").and_then(Value::as_bool) == Some(true)
                || installed_name(path).is_none()
            {
                reason = Some("unsupported_workspace_or_local_link");
            }
            match registry_for(&identity.name) {
                Ok(registry) => identity.registry = registry,
                Err(_) => reason = Some("registry_route_not_approved"),
            }
            if identity.normalize().is_err() || !npm::concrete(&identity.version) {
                reason = Some("unresolved_package_identity");
            }
            let resolved = string(value, "resolved");
            let bundled = value.get("inBundle").and_then(Value::as_bool) == Some(true);
            if !bundled
                && (resolved.is_empty()
                    || ["git:", "git+", "file:", "workspace:"]
                        .iter()
                        .any(|prefix| resolved.starts_with(prefix)))
            {
                reason = Some("unsupported_or_missing_artifact_source");
            }
            if let Some(reason) = reason {
                result.gaps.push(Gap {
                    path: path.clone(),
                    reason: reason.into(),
                });
            }
            requirements.insert(path.clone(), declared(value, false)?);
            result.packages.push(Package {
                path: path.clone(),
                identity,
                resolved: if resolved.is_empty() {
                    None
                } else {
                    Some(resolved)
                },
                integrity: string(value, "integrity"),
                dev: value["dev"].as_bool().unwrap_or(false),
                optional: value["optional"].as_bool().unwrap_or(false),
                peer: value["peer"].as_bool().unwrap_or(false),
                bundled,
                dependencies: vec![],
                parents: vec![],
                introduced_by: vec![],
            });
        }
        result.packages.sort_by(|a, b| a.path.cmp(&b.path));
        let paths: BTreeSet<_> = result.packages.iter().map(|p| p.path.clone()).collect();
        let index: BTreeMap<_, _> = result
            .packages
            .iter()
            .enumerate()
            .map(|(i, p)| (p.path.clone(), i))
            .collect();
        for (parent, declared) in requirements {
            for (name, spec) in declared {
                let Some(child) = resolve(&parent, &name, &paths) else {
                    result.gaps.push(Gap {
                        path: parent.clone(),
                        reason: format!("unresolved_dependency:{name}"),
                    });
                    continue;
                };
                let child_index = index[&child];
                let (expected_name, constraint) = alias(&spec).unwrap_or((&name, &spec));
                if result.packages[child_index].identity.name != expected_name
                    || !npm::matches(constraint, &result.packages[child_index].identity.version)
                        .unwrap_or(false)
                {
                    result.gaps.push(Gap {
                        path: child.clone(),
                        reason: "dependency_requirement_does_not_match_lock".into(),
                    });
                }
                result.packages[child_index].parents.push(parent.clone());
                if parent.is_empty() {
                    result.roots.push(child.clone());
                } else if let Some(i) = index.get(&parent) {
                    result.packages[*i].dependencies.push(child.clone());
                }
            }
        }
        let mut queue: VecDeque<_> = result
            .roots
            .iter()
            .map(|p| (p.clone(), vec![p.clone()]))
            .collect();
        let mut seen = BTreeSet::new();
        while let Some((path, chain)) = queue.pop_front() {
            if !seen.insert(path.clone()) {
                continue;
            }
            if let Some(i) = index.get(&path) {
                result.packages[*i].introduced_by = chain.clone();
                for child in &result.packages[*i].dependencies {
                    let mut next = chain.clone();
                    next.push(child.clone());
                    queue.push_back((child.clone(), next));
                }
            }
        }
        Ok(result)
    }
}
