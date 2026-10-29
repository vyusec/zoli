use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::path::PathBuf;
use zoli_intel::{
    feed::read_bounded,
    net::{Endpoint, Http},
};
use zoli_policy::assessment::Suspicious;
use zoli_proxy::registry::Registry;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    pub url: String,
    pub public_key: String,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub suspicious: Suspicious,
    pub max_staleness_hours: Option<u64>,
    pub min_publish_age_hours: Option<u64>,
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RegistryEntry {
    Url(String),
    Detailed(Registry),
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Registries {
    npm: Vec<RegistryEntry>,
}
impl Registries {
    pub fn entries(&self) -> Result<Vec<Registry>> {
        self.npm
            .iter()
            .map(|r| match r {
                RegistryEntry::Url(url) => Ok(Registry {
                    url: url.clone(),
                    ..Default::default()
                }),
                RegistryEntry::Detailed(r) => Ok(r.clone()),
            })
            .collect()
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub config_version: u32,
    #[serde(default)]
    pub feed: Option<Feed>,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub registries: Registries,
    #[serde(default)]
    pub analysis: zoli_inspect::Limits,
}
impl Config {
    pub fn home() -> Result<PathBuf> {
        std::env::var_os("ZOLI_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".zoli")))
            .context("HOME or ZOLI_HOME is required")
    }
    pub fn offline() -> Self {
        Self {
            config_version: 1,
            feed: None,
            policy: Policy::default(),
            registries: Registries::default(),
            analysis: Default::default(),
        }
    }
    pub fn load() -> Result<(PathBuf, Self)> {
        let home = Self::home()?;
        let bytes = read_bounded(&home.join("config.json"), 1 << 20)
            .context("cannot read Zoli config.json; configure a pinned feed URL/key first")?;
        let config: Self = serde_json::from_slice(&bytes).context("invalid Zoli configuration")?;
        ensure!(
            config.config_version == 1,
            "unsupported configuration version; migrate explicitly"
        );
        ensure!(
            config.policy.max_staleness_hours.is_none_or(|h| h == 1),
            "Phase 1 requires the selected one-hour intelligence bound"
        );
        ensure!(
            config
                .policy
                .min_publish_age_hours
                .is_none_or(|h| (1..=8760).contains(&h)),
            "minimum publish age must be between 1 and 8760 hours"
        );
        let l = &config.analysis;
        ensure!(
            l.max_artifact_bytes > 0
                && l.max_expanded_bytes > 0
                && l.max_files > 0
                && l.max_source_bytes > 0
                && l.worker_seconds > 0
                && l.worker_memory_bytes > 0,
            "analysis resource limits must be positive"
        );
        if config.feed.is_some() {
            config.key()?;
            config.feed_http()?;
        }
        Ok((home, config))
    }
    pub fn key(&self) -> Result<[u8; 32]> {
        let feed = self.feed.as_ref().context("no pinned feed configured")?;
        let bytes = STANDARD
            .decode(&feed.public_key)
            .context("invalid pinned feed key encoding")?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("pinned feed key must contain exactly 32 bytes"))
    }
    pub fn feed_http(&self) -> Result<Http> {
        let feed = self.feed.as_ref().context("no pinned feed configured")?;
        let endpoint = Endpoint {
            url: feed.url.clone(),
            allow_private_network: false,
            ca_file: None,
        };
        let url = endpoint.parsed()?;
        ensure!(
            url.port().is_none() && url.path().trim_end_matches('/').ends_with("/feed"),
            "feed URL must end in /feed on public HTTPS port 443"
        );
        Http::new(vec![endpoint])
    }
}
