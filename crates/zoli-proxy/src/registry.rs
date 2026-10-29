//! Registry routing, credential scoping and integrity-checked acquisition.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use url::Url;
use zoli_intel::{
    feed::read_bounded,
    model::{GoTime, Identity, normalize_registry},
    net::{Endpoint, Http},
};

/// Operator-authorized registry base and optional artifact origins.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// Registry URL including any repository path prefix.
    pub url: String,
    /// Explicit opt-in for this origin to resolve to private addresses.
    #[serde(default)]
    pub allow_private_network: bool,
    /// Additional trusted CA bundle; TLS verification cannot be disabled.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Additional download endpoints, each with independent permissions.
    #[serde(default)]
    pub artifact_hosts: Vec<Endpoint>,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            url: "https://registry.npmjs.org".into(),
            allow_private_network: false,
            ca_file: None,
            artifact_hosts: vec![],
        }
    }
}
impl Registry {
    fn endpoint(&self) -> Endpoint {
        Endpoint {
            url: self.url.clone(),
            allow_private_network: self.allow_private_network,
            ca_file: self.ca_file.clone(),
        }
    }
}
struct Credential {
    scope: Url,
    template: String,
    bearer: bool,
}

/// Read-only supported npm configuration. Credential values are never serializable
/// or included in Debug output; project routing alone cannot authorize egress.
pub struct NpmConfig {
    registry: String,
    scopes: BTreeMap<String, String>,
    credentials: Vec<Credential>,
}
impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            registry: "https://registry.npmjs.org".into(),
            scopes: BTreeMap::new(),
            credentials: vec![],
        }
    }
}
fn environment(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .or_else(|| std::env::var(name.to_ascii_uppercase()).ok())
}
fn expand(value: &str) -> Result<String> {
    let expression = regex::Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(\?)?\}")?;
    let mut out = String::new();
    let mut end = 0;
    for capture in expression.captures_iter(value) {
        let whole = capture.get(0).context("invalid environment reference")?;
        out.push_str(&value[end..whole.start()]);
        let name = capture
            .get(1)
            .context("invalid environment reference")?
            .as_str();
        match std::env::var(name) {
            Ok(v) => out.push_str(&v),
            Err(_) if capture.get(2).is_some() => {}
            Err(_) => bail!("required npm credential/config environment variable is not set"),
        }
        end = whole.end();
    }
    out.push_str(&value[end..]);
    ensure!(!out.contains("${"), "unsupported npm environment reference");
    Ok(out)
}
impl NpmConfig {
    /// Read user credentials (or an explicit trusted npmrc) and project routing.
    /// This never executes npm, reads package code, or persists credentials.
    pub fn load(project: Option<&Path>, explicit: Option<&Path>) -> Result<Self> {
        let mut result = Self::default();
        let selected = explicit
            .map(Path::to_path_buf)
            .or_else(|| environment("npm_config_userconfig").map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".npmrc")));
        if let Some(path) = selected
            && (explicit.is_some()
                || environment("npm_config_userconfig").is_some()
                || path.exists())
        {
            result.read(&path, true)?;
        }
        if let Some(project) = project {
            let path = project.join(".npmrc");
            if path.exists() {
                result.read(&path, false)?;
            }
        }
        if let Some(registry) = environment("npm_config_registry") {
            result.registry = normalize_registry(&registry)?;
        }
        Ok(result)
    }
    fn read(&mut self, path: &Path, trusted: bool) -> Result<()> {
        let bytes = read_bounded(path, 1 << 20)?;
        let text = std::str::from_utf8(&bytes).context("npmrc is not UTF-8")?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            let value = if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                &value[1..value.len() - 1]
            } else {
                value
            };
            if key == "registry" {
                self.registry = normalize_registry(&expand(value)?)?;
            } else if key.starts_with('@') && key.ends_with(":registry") {
                self.scopes.insert(
                    key.trim_end_matches(":registry").to_owned(),
                    normalize_registry(&expand(value)?)?,
                );
            } else if trusted
                && (key == "_authToken"
                    || key == "_auth"
                    || key == "_password"
                    || key == "username")
            {
                bail!("npm credentials must be scoped to a registry origin/path");
            } else if trusted && (key.ends_with(":_authToken") || key.ends_with(":_auth")) {
                let (scope, kind) = key.rsplit_once(':').context("invalid scoped credential")?;
                ensure!(
                    scope.starts_with("//"),
                    "npm credentials require a registry URL scope"
                );
                let scope = Url::parse(&format!("https:{scope}"))?;
                ensure!(
                    scope.username().is_empty()
                        && scope.password().is_none()
                        && scope.query().is_none()
                        && scope.fragment().is_none(),
                    "invalid credential scope"
                );
                self.credentials.retain(|c| c.scope != scope);
                self.credentials.push(Credential {
                    scope,
                    template: value.to_owned(),
                    bearer: kind == "_authToken",
                });
            } else if trusted
                && (key.ends_with(":_password")
                    || key.ends_with(":username")
                    || key == "certfile"
                    || key == "keyfile"
                    || key.ends_with(":certfile")
                    || key.ends_with(":keyfile"))
            {
                bail!(
                    "unsupported npm authentication configuration; use scoped _authToken or _auth"
                );
            } else if key == "strict-ssl" && value == "false" {
                bail!("TLS verification cannot be disabled");
            }
        }
        Ok(())
    }
    /// Effective registry route for a package, without authorizing that route.
    pub fn registry_for(&self, name: &str) -> Result<String> {
        let scope = name
            .strip_prefix('@')
            .and_then(|_| name.split_once('/'))
            .map(|p| p.0);
        normalize_registry(
            scope
                .and_then(|s| self.scopes.get(s))
                .unwrap_or(&self.registry),
        )
    }
    /// Select only credentials belonging to this origin and a matching path.
    pub fn authorization(&self, url: &Url) -> Result<Option<String>> {
        // Registries and reverse proxies can disagree on encoded separators.
        let lower = url.path().to_ascii_lowercase();
        ensure!(
            !["%2f", "%5c", "%25", "%00"]
                .iter()
                .any(|p| lower.contains(p)),
            "ambiguous credential destination path"
        );
        let credential = self
            .credentials
            .iter()
            .filter(|c| c.scope.origin() == url.origin() && path_scope(c.scope.path(), url.path()))
            .max_by_key(|c| c.scope.path().len());
        let Some(c) = credential else { return Ok(None) };
        let value = expand(&c.template)?;
        ensure!(
            !value.is_empty() && !value.chars().any(char::is_control),
            "invalid or empty registry credential"
        );
        if !c.bearer {
            STANDARD
                .decode(&value)
                .context("invalid scoped Basic credential encoding")?;
        }
        Ok(Some(format!(
            "{} {value}",
            if c.bearer { "Bearer" } else { "Basic" }
        )))
    }
}
fn path_scope(scope: &str, path: &str) -> bool {
    let scope = scope.trim_end_matches('/');
    scope.is_empty()
        || path == scope
        || path.strip_prefix(scope).is_some_and(|r| r.starts_with('/'))
}

/// Approved registry acquisition; credentials are chosen afresh on every hop.
pub struct RegistryClient {
    registries: Vec<Registry>,
    npm: NpmConfig,
}
/// Authenticated metadata binding publish age to the exact registry artifact.
pub struct Publication {
    /// Exact version's timestamp from the full packument.
    pub published_at: GoTime,
    /// Strong integrity attached to the same version by the registry.
    pub integrity: String,
}
impl RegistryClient {
    /// Build an explicit allowlist, retaining public npm as the implicit default.
    pub fn new(mut registries: Vec<Registry>, npm: NpmConfig) -> Result<Self> {
        if !registries
            .iter()
            .any(|r| r.url.trim_end_matches('/') == "https://registry.npmjs.org")
        {
            registries.push(Registry::default());
        }
        for r in &mut registries {
            r.url = normalize_registry(&r.url)?;
            r.endpoint().parsed()?;
            for e in &r.artifact_hosts {
                e.parsed()?;
            }
        }
        Ok(Self { registries, npm })
    }
    /// Resolve npm routing only when the operator has approved its registry base.
    pub fn registry_for(&self, name: &str) -> Result<String> {
        let url = self.npm.registry_for(name)?;
        ensure!(
            self.registries.iter().any(|r| r.url == url),
            "npm registry route is not approved in Zoli configuration"
        );
        Ok(url)
    }
    /// Fetch the full packument's exact-version publish time over approved TLS.
    /// Abbreviated metadata cannot establish minimum publish age.
    pub fn publication(&self, identity: &Identity) -> Result<Publication> {
        let mut normalized = identity.clone();
        normalized.normalize()?;
        ensure!(
            normalized.name == identity.name
                && normalized.registry == identity.registry
                && identity.ecosystem == "npm"
                && zoli_intel::npm::concrete(&identity.version),
            "publish metadata requires a normalized exact npm identity"
        );
        let registry = self
            .registries
            .iter()
            .find(|r| r.url == identity.registry)
            .context("package registry is not approved")?;
        let mut url = Url::parse(&format!("{}/", registry.url))?;
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("invalid registry base"))?
            .pop_if_empty()
            .push(&identity.name);
        let http = Http::new(vec![registry.endpoint()])?;
        let bytes = http.get_authenticated(url.as_str(), 20 << 20, |u| {
            // The normalized initial identity may contain an encoded scope
            // separator. Redirects retain the generic ambiguity rejection.
            if u == &url {
                let mut destination = u.clone();
                let prefix = Url::parse(&registry.url)?
                    .path()
                    .trim_end_matches('/')
                    .to_owned();
                destination.set_path(&format!("{prefix}/{}", identity.name));
                self.npm.authorization(&destination)
            } else {
                self.npm.authorization(u)
            }
        })?;
        let metadata: serde_json::Value = zoli_intel::json::decode(&bytes)?;
        ensure!(
            metadata["name"].as_str() == Some(&identity.name),
            "registry publish-time identity mismatch"
        );
        ensure!(
            metadata["versions"][&identity.version]["version"].as_str() == Some(&identity.version),
            "registry exact version is unavailable"
        );
        let stamp = metadata["time"][&identity.version]
            .as_str()
            .context("registry exact version publish time is missing")?;
        let integrity = metadata["versions"][&identity.version]["dist"]["integrity"]
            .as_str()
            .context("registry exact version strong integrity is missing")?;
        validate_integrity(integrity)?;
        Ok(Publication {
            published_at: GoTime::parse(stamp)?,
            integrity: integrity.into(),
        })
    }
    /// Download a resolved lockfile artifact and verify strong integrity before
    /// returning any bytes to the inspection coordinator.
    pub fn acquire(&self, identity: &Identity, resolved: &str, integrity: &str) -> Result<Vec<u8>> {
        integrity_algorithms(integrity)?;
        let registry = self
            .registries
            .iter()
            .find(|r| r.url == identity.registry)
            .context("package registry is not approved")?;
        let base = Url::parse(&format!("{}/", registry.url))?;
        let mut url = base
            .join(resolved)
            .context("invalid resolved artifact URL")?;
        // npm's lockfile magic public-registry origin follows the configured
        // registry. Other origins require an explicit artifact-host entry.
        if url.origin() == Url::parse("https://registry.npmjs.org")?.origin()
            && base.origin() != url.origin()
        {
            let path = url.path().trim_start_matches('/').to_owned();
            let query = url.query().map(str::to_owned);
            url = base.join(&path)?;
            url.set_query(query.as_deref());
        }
        let mut endpoints = vec![registry.endpoint()];
        endpoints.extend(registry.artifact_hosts.clone());
        let http = Http::new(endpoints)?;
        let bytes =
            http.get_authenticated(url.as_str(), 20 << 20, |u| self.npm.authorization(u))?;
        verify_integrity(&bytes, integrity)?;
        Ok(bytes)
    }
}
fn integrity_algorithms(sri: &str) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut candidates = vec![];
    for entry in sri.split_ascii_whitespace() {
        let Some((algorithm, value)) = entry.split_once('-') else {
            bail!("malformed artifact integrity")
        };
        let bits = match algorithm {
            "sha256" => 256,
            "sha384" => 384,
            "sha512" => 512,
            _ => continue,
        };
        let bytes = STANDARD
            .decode(value)
            .context("invalid artifact integrity encoding")?;
        ensure!(
            bytes.len() == usize::from(bits / 8),
            "invalid artifact integrity length"
        );
        candidates.push((bits, bytes));
    }
    ensure!(
        !candidates.is_empty(),
        "missing strong artifact integrity; SHA-1-only metadata is unsupported"
    );
    Ok(candidates)
}
/// Validate supported integrity metadata without downloading an artifact.
pub fn validate_integrity(sri: &str) -> Result<()> {
    integrity_algorithms(sri)?;
    Ok(())
}
/// Check the strongest supplied algorithm; a weaker matching digest never
/// overrides a failed stronger digest.
pub fn verify_integrity(bytes: &[u8], sri: &str) -> Result<()> {
    let candidates = integrity_algorithms(sri)?;
    let strongest = candidates
        .iter()
        .map(|p| p.0)
        .max()
        .context("no strong integrity digest")?;
    let digest = match strongest {
        256 => Sha256::digest(bytes).to_vec(),
        384 => Sha384::digest(bytes).to_vec(),
        512 => Sha512::digest(bytes).to_vec(),
        _ => bail!("unsupported integrity algorithm"),
    };
    ensure!(
        candidates
            .iter()
            .any(|(bits, value)| *bits == strongest && *value == digest),
        "artifact integrity mismatch"
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn npmrc(contents: &str, trusted: bool) -> NpmConfig {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), contents).unwrap();
        let mut config = NpmConfig::default();
        config.read(f.path(), trusted).unwrap();
        config
    }
    #[test]
    fn credentials_follow_origin_port_and_longest_path() {
        let c = npmrc(
            "//registry.example.invalid/:_authToken=root\n//registry.example.invalid/team/:_authToken=team\n//registry.example.invalid:8443/:_authToken=port\n",
            true,
        );
        for (url, expected) in [
            (
                "https://registry.example.invalid/team/pkg",
                Some("Bearer team"),
            ),
            (
                "https://registry.example.invalid/teammate/pkg",
                Some("Bearer root"),
            ),
            (
                "https://registry.example.invalid:8443/team/pkg",
                Some("Bearer port"),
            ),
            ("https://cdn.example.invalid/team/pkg", None),
            ("http://registry.example.invalid/team/pkg", None),
            ("https://registry.example.invalid:9443/team/pkg", None),
        ] {
            assert_eq!(
                c.authorization(&Url::parse(url).unwrap())
                    .unwrap()
                    .as_deref(),
                expected,
                "{url}"
            );
        }
        for path in ["team%2fpkg", "team/%252e%252e/other", "team%5cpkg"] {
            assert!(
                c.authorization(
                    &Url::parse(&format!("https://registry.example.invalid/{path}")).unwrap()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn project_credentials_are_ignored_and_unrelated_variables_are_lazy() {
        let c = npmrc(
            "@team:registry=https://private.example.invalid/npm/\n//private.example.invalid/:_authToken=project-secret",
            false,
        );
        assert_eq!(
            c.registry_for("@team/pkg").unwrap(),
            "https://private.example.invalid/npm"
        );
        assert!(
            c.authorization(&Url::parse("https://private.example.invalid/npm/pkg").unwrap())
                .unwrap()
                .is_none()
        );
        let c = npmrc(
            "//unused.example.invalid/:_authToken=${ZOLI_TEST_MISSING_VARIABLE_847205}\n//registry.example.invalid/:_authToken=working",
            true,
        );
        assert_eq!(
            c.authorization(&Url::parse("https://registry.example.invalid/x").unwrap())
                .unwrap()
                .as_deref(),
            Some("Bearer working")
        );
        let error = c
            .authorization(&Url::parse("https://unused.example.invalid/x").unwrap())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("ZOLI_TEST_MISSING") && !error.contains("${"));
        let c = npmrc("//registry.example.invalid/:_authToken=\"", true);
        assert!(
            c.authorization(&Url::parse("https://registry.example.invalid/x").unwrap())
                .is_ok()
        );
    }
    #[test]
    fn basic_credentials_are_scoped_and_bad_configuration_fails() {
        let c = npmrc("//private.example.invalid/team/:_auth=dXNlcjpwYXNz", true);
        assert_eq!(
            c.authorization(&Url::parse("https://private.example.invalid/team/x").unwrap())
                .unwrap()
                .as_deref(),
            Some("Basic dXNlcjpwYXNz")
        );
        for contents in [
            "_authToken=do-not-echo",
            "strict-ssl=false",
            "//private.example.invalid/:username=user",
        ] {
            let f = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(f.path(), contents).unwrap();
            let error = NpmConfig::default()
                .read(f.path(), true)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("do-not-echo"));
        }
        let client = RegistryClient::new(
            vec![],
            npmrc("registry=https://unapproved.example.invalid", false),
        )
        .unwrap();
        assert!(client.registry_for("fixture").is_err());
    }
    #[test]
    fn strongest_integrity_wins_and_weak_metadata_is_rejected() {
        let bytes = b"synthetic package bytes";
        let good256 = format!("sha256-{}", STANDARD.encode(Sha256::digest(bytes)));
        let good512 = format!("sha512-{}", STANDARD.encode(Sha512::digest(bytes)));
        let bad512 = format!("sha512-{}", STANDARD.encode([0; 64]));
        verify_integrity(bytes, &good512).unwrap();
        verify_integrity(bytes, &format!("{good256} {good512}")).unwrap();
        assert!(verify_integrity(bytes, &format!("{good256} {bad512}")).is_err());
        verify_integrity(bytes, &format!("{bad512} {good512}")).unwrap();
        for sri in ["", "sha1-AAAA", "sha512-AAAA", "sha256-!", "malformed"] {
            assert!(validate_integrity(sri).is_err());
        }
    }
}
