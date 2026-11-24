use std::collections::BTreeMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use url::Url;

use super::error::{Error, Result};
use crate::http::{H1Settings, H2Settings};
use crate::proxy::ProxyConfig;
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
    pub h1: H1Settings,
    pub h2: H2Settings,
    /// Empty: no proxy, direct connections (announced). Otherwise every connection uses the selected
    /// proxy and nothing else.
    pub proxy: ProxyConfig,
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
            h1: H1Settings::default(),
            h2: H2Settings::default(),
            proxy: ProxyConfig::default(),
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
        // h2 panics on these instead of returning an error (h2 0.4.20 src/frame/settings.rs:91).
        if let Some(v) = self.h2.max_frame_size {
            if !(16_384..=16_777_215).contains(&v) {
                return Err(Error::Config(format!("h2.max_frame_size {v} is outside 16384..=16777215 (RFC 9113 6.5.2)")));
            }
        }
        for (name, v) in [
            ("initial_stream_window_size", self.h2.initial_stream_window_size),
            ("initial_connection_window_size", self.h2.initial_connection_window_size),
        ] {
            if v.is_some_and(|v| v > 0x7fff_ffff) {
                return Err(Error::Config(format!("h2.{name} is above 2^31-1 (RFC 9113 6.9.1)")));
            }
        }
        if self.h1.max_response_headers == Some(0) {
            return Err(Error::Config("h1.max_response_headers must be greater than 0".into()));
        }
        for key in self.resolve.keys() {
            let port = key.rsplit_once(':').and_then(|(h, p)| (!h.is_empty()).then_some(p));
            if port.and_then(|p| p.parse::<u16>().ok()).is_none() {
                return Err(Error::Config(format!("resolve key {key:?} is not HOST:PORT (IPv6 hosts in brackets)")));
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
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::Target(
                "credentials in the URL are not supported (they would reach reports and HTTP/2 :authority); send an authorization header".into(),
            ));
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
