//! Bounded HTTPS transport with explicit destinations and pinned DNS answers.
use anyhow::{Context, Result, bail, ensure};
use reqwest::{
    blocking::Client,
    header::{AUTHORIZATION, LOCATION},
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    net::{IpAddr, ToSocketAddrs},
    path::PathBuf,
    time::Duration,
};
use url::Url;

/// One operator-approved HTTPS origin. Private access never propagates to others.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// HTTPS registry/feed base URL.
    pub url: String,
    /// Explicit permission to connect this origin to private network addresses.
    #[serde(default)]
    pub allow_private_network: bool,
    /// Optional additional CA bundle; certificate verification stays enabled.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}
impl Endpoint {
    /// Validate a configured destination before any resolution or connection.
    pub fn parsed(&self) -> Result<Url> {
        let u = Url::parse(&self.url)?;
        ensure!(
            self.url.starts_with("https://")
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none(),
            "destination must be an HTTPS base URL without credentials or query"
        );
        Ok(u)
    }
}
/// Whether an IP is eligible for public feed/registry traffic.
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..128).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..32).contains(&b))
                || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2))))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(mapped));
            }
            let s = ip.segments();
            s[0] & 0xe000 == 0x2000 && !(s[0] == 0x2001 && s[1] == 0xdb8)
        }
    }
}
/// Production transport. Tests inject a `Fetch` implementation instead.
#[derive(Debug, Clone)]
pub struct Http {
    endpoints: Vec<Endpoint>,
}
/// Bounded artifact acquisition seam, also used by the Go conformance harness.
pub trait Fetch {
    /// Fetch exact bytes, rejecting over-limit or unsuccessful responses.
    fn get(&self, url: &str, max: usize) -> Result<Vec<u8>>;
}
impl Http {
    /// Construct only from validated operator-approved endpoints.
    pub fn new(endpoints: Vec<Endpoint>) -> Result<Self> {
        ensure!(!endpoints.is_empty(), "no HTTPS destinations configured");
        for e in &endpoints {
            e.parsed()?;
        }
        Ok(Self { endpoints })
    }
    /// Fetch with credentials independently selected for each redirect target.
    pub fn get_authenticated(
        &self,
        raw: &str,
        max: usize,
        authorization: impl Fn(&Url) -> Result<Option<String>>,
    ) -> Result<Vec<u8>> {
        let mut url = Url::parse(raw).context("invalid download URL")?;
        for hop in 0..=3 {
            ensure!(
                url.scheme() == "https"
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none(),
                "invalid HTTPS download destination"
            );
            let endpoint = self
                .endpoints
                .iter()
                .find(|e| e.parsed().is_ok_and(|u| u.origin() == url.origin()))
                .context("download origin is not approved in Zoli configuration")?;
            let host = url.host_str().context("download hostname missing")?;
            let port = url
                .port_or_known_default()
                .context("download port missing")?;
            let addresses: Vec<_> = (host, port)
                .to_socket_addrs()
                .map_err(|_| anyhow::anyhow!("DNS resolution failed for approved destination"))?
                .collect();
            ensure!(!addresses.is_empty(), "destination has no DNS answers");
            ensure!(
                endpoint.allow_private_network || addresses.iter().all(|a| public_ip(a.ip())),
                "destination resolves to a disallowed network address"
            );
            let mut builder = Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(180))
                .connect_timeout(Duration::from_secs(15))
                .resolve_to_addrs(host, &addresses);
            if let Some(ca) = &endpoint.ca_file {
                let pem = crate::feed::read_bounded(ca, 2 << 20)
                    .context("cannot read configured CA bundle")?;
                let certificates =
                    reqwest::Certificate::from_pem_bundle(&pem).context("invalid CA bundle")?;
                ensure!(
                    !certificates.is_empty(),
                    "configured CA bundle contains no certificates"
                );
                for certificate in certificates {
                    builder = builder.add_root_certificate(certificate);
                }
            }
            let client = builder
                .build()
                .context("cannot initialize HTTPS transport")?;
            let mut request = client.get(url.clone()).header("User-Agent", "zoli/0.0.0");
            if let Some(auth) = authorization(&url)? {
                request = request.header(AUTHORIZATION, auth);
            }
            let response = request.send().map_err(|_| {
                anyhow::anyhow!("HTTPS request failed; destination and credentials withheld")
            })?;
            if response.status().is_redirection() {
                ensure!(hop < 3, "too many download redirects");
                let location = response
                    .headers()
                    .get(LOCATION)
                    .context("redirect missing location")?
                    .to_str()
                    .context("invalid redirect location")?;
                url = url.join(location).context("invalid redirect URL")?;
                continue;
            }
            ensure!(
                response.status().as_u16() == 200,
                "HTTPS endpoint returned HTTP {}",
                response.status().as_u16()
            );
            if let Some(length) = response.content_length() {
                ensure!(length <= max as u64, "download exceeds byte limit");
            }
            let mut bytes = vec![];
            response
                .take(max as u64 + 1)
                .read_to_end(&mut bytes)
                .context("cannot read HTTPS response")?;
            ensure!(bytes.len() <= max, "download exceeds byte limit");
            return Ok(bytes);
        }
        bail!("download redirect limit exceeded")
    }
}
impl Fetch for Http {
    fn get(&self, url: &str, max: usize) -> Result<Vec<u8>> {
        self.get_authenticated(url, max, |_| Ok(None))
    }
}
