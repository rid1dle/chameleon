use std::collections::BTreeMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use url::Url;

use super::error::{Error, Result};
use crate::http::H2Settings;
use crate::tls::TlsSettings;

/// Engine configuration. Every field has a default, so a config file only names what it changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Budget for each of DNS, TCP connect and TLS handshake, applied to each step separately.
    pub connect_timeout_ms: u64,
    /// Budget for sending the request and reading the whole response.
    pub request_timeout_ms: u64,
    /// Larger bodies fail with `Error::BodyTooLarge` instead of being truncated silently.
    pub max_body_bytes: usize,
    /// Keep connections open and reuse them for later requests to the same origin.
    pub reuse_connections: bool,
    /// Like curl's `--resolve`: `"host:port"` to the address to connect to. SNI and Host still use `host`.
    pub resolve: BTreeMap<String, SocketAddr>,
    /// Headers sent on every request, in this order, before the target's own headers.
    pub default_headers: Vec<(String, String)>,
    pub tls: TlsSettings,
    pub h2: H2Settings,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            request_timeout_ms: 30_000,
            max_body_bytes: 8 * 1024 * 1024,
            reuse_connections: true,
            resolve: BTreeMap::new(),
            default_headers: vec![
                ("user-agent".into(), concat!("cfprobe/", env!("CARGO_PKG_VERSION")).into()),
                ("accept".into(), "*/*".into()),
            ],
            tls: TlsSettings::default(),
            h2: H2Settings::default(),
        }
    }
}

impl Config {
    pub fn from_json(text: &str) -> Result<Self> {
        serde_json::from_str(text).map_err(|e| Error::Config(e.to_string()))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.connect_timeout_ms == 0 || self.request_timeout_ms == 0 {
            return Err(Error::Config("timeouts must be greater than 0".into()));
        }
        if self.tls.alpn.is_empty() {
            return Err(Error::Config("tls.alpn must name at least one protocol".into()));
        }
        for p in &self.tls.alpn {
            if p != "h2" && p != "http/1.1" {
                return Err(Error::Config(format!(
                    "tls.alpn entry {p:?} is not supported (only \"h2\" and \"http/1.1\")"
                )));
            }
        }
        Ok(())
    }
}

/// One request to make: method, URL, extra headers in send order, optional body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub method: String,
    pub url: Url,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default, skip_serializing)]
    pub body: Option<Vec<u8>>,
}

impl Target {
    pub fn get(url: &str) -> Result<Self> {
        let url = Url::parse(url).map_err(|e| Error::Target(format!("{url}: {e}")))?;
        match url.scheme() {
            "https" | "http" => {}
            other => return Err(Error::Target(format!("unsupported scheme {other:?}"))),
        }
        if url.host_str().is_none() {
            return Err(Error::Target(format!("{url}: no host")));
        }
        Ok(Self { method: "GET".into(), url, headers: Vec::new(), body: None })
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

impl TryFrom<&str> for Target {
    type Error = Error;
    fn try_from(url: &str) -> Result<Self> {
        Target::get(url)
    }
}
