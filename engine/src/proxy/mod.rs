//! Proxy routing: the one place a route out is decided.
//!
//! - **A proxy is configured**: every connection the engine opens goes through it. The destination
//!   name is never resolved locally (HTTP proxies get it in `CONNECT host:port`, SOCKS5 proxies as a
//!   domain address), and any proxy failure is reported as `Error::Proxy`. There is no direct path
//!   in this mode, so nothing can fall back to one.
//! - **No proxy is configured**: the engine connects directly, as it did before proxies existed, and
//!   says so (`Route::Direct`, recorded on every connection and announced by the CLI). This is the
//!   user's decision (2026-11-24) instead of failing closed.
//!
//! Schemes: `http://` (CONNECT), `https://` (TLS to the proxy, verified, then CONNECT), `socks5://`
//! and `socks5h://` (both send the destination name to the proxy: no local DNS for the destination).
//! Credentials come from the URL or the `username`/`password` fields and are held in `Secret`, which
//! never prints its value.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::Engine;
use boring::ssl::{SslConnector, SslMethod};
use serde::{Deserialize, Serialize, Serializer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::core::{Error, Result};

/// A value that never appears in output: `Debug` and `Serialize` print its length only.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(v: impl Into<String>) -> Self {
        Self(v.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted {} bytes>", self.0.len())
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&format!("<redacted {} bytes>", self.0.len()))
    }
}

/// The proxy section of the config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    pub proxies: Vec<ProxySpec>,
    /// Id of the proxy to use. Required when more than one is listed; with one, that one.
    pub select: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySpec {
    pub id: String,
    /// `scheme://[user:pass@]host:port`, or `env:NAME` to read it from an environment variable so
    /// credentials stay out of config files. Serialized with credentials removed.
    #[serde(serialize_with = "serialize_url")]
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<Secret>,
    /// Extra trust anchor for an `https://` proxy's certificate. Verification is always on.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

/// Hand-written so the URL's credentials never reach a log through `{:?}`.
impl fmt::Debug for ProxySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxySpec")
            .field("id", &self.id)
            .field("url", &crate::http::redact_url(&self.url))
            .field("username", &self.username)
            .field("password", &self.password)
            .field("ca_file", &self.ca_file)
            .finish()
    }
}

fn serialize_url<S: Serializer>(url: &str, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&crate::http::redact_url(url))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyScheme {
    Http,
    Https,
    Socks5,
}

/// A validated proxy.
#[derive(Clone)]
pub struct Proxy {
    pub id: String,
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
    auth: Option<(String, Secret)>,
    tls: Option<SslConnector>,
    pub ca_file: Option<PathBuf>,
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("id", &self.id)
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth", &self.auth.as_ref().map(|(u, p)| (u, p)))
            .finish()
    }
}

/// How the engine reaches destinations.
#[derive(Debug, Clone)]
pub enum Route {
    /// No proxy configured: direct connections.
    Direct,
    Proxy(Proxy),
}

/// The route as recorded on a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RouteRecord {
    /// No proxy was configured.
    Direct,
    Proxy { id: String, scheme: ProxyScheme },
}

impl Route {
    pub fn record(&self) -> RouteRecord {
        match self {
            Route::Direct => RouteRecord::Direct,
            Route::Proxy(p) => RouteRecord::Proxy { id: p.id.clone(), scheme: p.scheme },
        }
    }

    /// One line for humans, without credentials.
    pub fn describe(&self) -> String {
        match self {
            Route::Direct => "no proxy defined: running in no-proxy mode (direct connections)".into(),
            Route::Proxy(p) => format!("routing every connection through proxy {:?} ({:?} {}:{})", p.id, p.scheme, p.host, p.port),
        }
    }
}

impl ProxyConfig {
    /// The route this config asks for. A listed proxy that is invalid is an error, never a reason
    /// to go direct.
    pub fn route(&self) -> Result<Route> {
        let bad = |m: String| Err(Error::Config(format!("proxy: {m}")));
        let spec = match (self.proxies.len(), &self.select) {
            (0, None) => return Ok(Route::Direct),
            (0, Some(id)) => return bad(format!("select is {id:?} but no proxies are listed")),
            (1, None) => &self.proxies[0],
            (_, None) => return bad("several proxies listed: set select to one id".into()),
            (_, Some(id)) => match self.proxies.iter().find(|p| &p.id == id) {
                Some(p) => p,
                None => return bad(format!("select {id:?} matches no listed proxy id")),
            },
        };
        Ok(Route::Proxy(spec.validate()?))
    }
}

impl ProxySpec {
    pub fn validate(&self) -> Result<Proxy> {
        let bad = |m: String| Err(Error::Config(format!("proxy {:?}: {m}", self.id)));
        let raw = match self.url.strip_prefix("env:") {
            Some(var) => match std::env::var(var) {
                Ok(v) if !v.trim().is_empty() => v,
                _ => return bad(format!("environment variable {var} is not set")),
            },
            None => self.url.clone(),
        };
        let url = match url::Url::parse(raw.trim()) {
            Ok(u) => u,
            Err(e) => return bad(format!("url is not valid: {e}")),
        };
        let scheme = match url.scheme() {
            "http" => ProxyScheme::Http,
            "https" => ProxyScheme::Https,
            "socks5" | "socks5h" => ProxyScheme::Socks5,
            other => return bad(format!("scheme {other:?} is not supported (http, https, socks5, socks5h)")),
        };
        let host = match url.host() {
            Some(url::Host::Domain(d)) => d.to_string(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            None => return bad("url has no host".into()),
        };
        let port = url.port().unwrap_or(match scheme {
            ProxyScheme::Http => 8080,
            ProxyScheme::Https => 443,
            ProxyScheme::Socks5 => 1080,
        });
        let decode = |s: &str| percent_decode(s);
        let auth = match (&self.username, &self.password, url.username()) {
            (Some(u), p, _) => Some((u.clone(), p.clone().unwrap_or_else(|| Secret::new("")))),
            (None, Some(_), _) => return bad("password given without username".into()),
            (None, None, "") => None,
            (None, None, u) => Some((decode(u), Secret::new(decode(url.password().unwrap_or(""))))),
        };
        if scheme == ProxyScheme::Socks5 && auth.as_ref().is_some_and(|(u, p)| u.len() > 255 || p.expose().len() > 255) {
            return bad("SOCKS5 username and password are limited to 255 bytes".into());
        }
        let tls = if scheme == ProxyScheme::Https {
            let mut b = SslConnector::builder(SslMethod::tls()).map_err(Error::TlsSetup)?;
            b.set_alpn_protos(b"\x08http/1.1").map_err(Error::TlsSetup)?;
            if let Some(ca) = &self.ca_file {
                b.set_ca_file(ca).map_err(Error::TlsSetup)?;
            }
            Some(b.build())
        } else {
            None
        };
        Ok(Proxy { id: self.id.clone(), scheme, host, port, auth, tls, ca_file: self.ca_file.clone() })
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = (b[i] == b'%' && i + 2 < b.len()).then(|| std::str::from_utf8(&b[i + 1..i + 3]).ok()).flatten();
        if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Proxy {
    /// The proxy as a URL for another tool (curl's `ALL_PROXY`). **Contains the credentials**: pass
    /// it through the environment, never on a command line or into a record. SOCKS5 is written as
    /// `socks5h` so that tool also leaves destination DNS to the proxy.
    pub fn url_with_credentials(&self) -> String {
        let scheme = match self.scheme {
            ProxyScheme::Http => "http",
            ProxyScheme::Https => "https",
            ProxyScheme::Socks5 => "socks5h",
        };
        let enc = |s: &str| -> String {
            s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
        };
        let auth = self.auth.as_ref().map(|(u, p)| format!("{}:{}@", enc(u), enc(p.expose()))).unwrap_or_default();
        format!("{scheme}://{auth}{}", authority(&self.host, self.port))
    }
}

/// A connection to the destination, through whatever the route needs.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;

/// What opening a tunnel took.
pub struct Tunnel {
    pub io: BoxIo,
    /// The proxy's address (the TCP peer of this connection).
    pub proxy_addr: SocketAddr,
    /// TCP connect to the proxy.
    pub connect_ms: f64,
    /// TLS to the proxy (https proxies) plus CONNECT or SOCKS5 negotiation.
    pub negotiate_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyStage {
    /// Resolving the proxy's own host name.
    Resolve,
    Connect,
    Tls,
    Auth,
    /// The proxy could not or would not reach the destination.
    Tunnel,
    /// The proxy answered something this engine does not understand.
    Protocol,
}

impl fmt::Display for ProxyStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(serde_json::to_value(self).ok().and_then(|v| v.as_str().map(str::to_string)).as_deref().unwrap_or("?"))
    }
}

fn perr(p: &Proxy, stage: ProxyStage, detail: impl Into<String>) -> Error {
    Error::Proxy { proxy: p.id.clone(), stage, detail: detail.into() }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Open a tunnel through `p` to `dest_host:dest_port`. `dest_host` is sent to the proxy as given (a
/// name or an address); it is never resolved here. Each step has the `step` budget.
pub async fn open_tunnel(p: &Proxy, dest_host: &str, dest_port: u16, step: Duration) -> Result<Tunnel> {
    let timed = |stage: ProxyStage| perr(p, stage, format!("timed out after {} ms", step.as_millis()));
    // The proxy's own address may need DNS: that query is about the proxy, not the destination.
    let addrs: Vec<SocketAddr> = tokio::time::timeout(step, tokio::net::lookup_host((p.host.as_str(), p.port)))
        .await
        .map_err(|_| timed(ProxyStage::Resolve))?
        .map_err(|e| perr(p, ProxyStage::Resolve, e.to_string()))?
        .collect();
    let t0 = Instant::now();
    let mut last = None;
    let mut tcp = None;
    for a in &addrs {
        match tokio::time::timeout(step, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                tcp = Some((s, *a));
                break;
            }
            Ok(Err(e)) => last = Some(perr(p, ProxyStage::Connect, format!("{a}: {e}"))),
            Err(_) => last = Some(timed(ProxyStage::Connect)),
        }
    }
    let (tcp, proxy_addr) = tcp.ok_or_else(|| last.unwrap_or_else(|| perr(p, ProxyStage::Resolve, "no addresses")))?;
    tcp.set_nodelay(true).ok();
    let connect_ms = ms(t0.elapsed());

    let t1 = Instant::now();
    let mut io: BoxIo = Box::new(tcp);
    if let Some(conn) = &p.tls {
        let cfg = conn.configure().map_err(Error::TlsSetup)?;
        let s = tokio::time::timeout(step, tokio_boring::connect(cfg, &p.host, io))
            .await
            .map_err(|_| timed(ProxyStage::Tls))?
            .map_err(|e| {
                let mut d = e.to_string();
                if let Some(v) = e.ssl().and_then(|s| s.verify_result().err()) {
                    d.push_str(&format!(" (certificate verify: {})", v.error_string()));
                }
                perr(p, ProxyStage::Tls, d)
            })?;
        io = Box::new(s);
    }
    let negotiate = async {
        match p.scheme {
            ProxyScheme::Http | ProxyScheme::Https => http_connect(p, &mut io, dest_host, dest_port).await,
            ProxyScheme::Socks5 => socks5_connect(p, &mut io, dest_host, dest_port).await,
        }
    };
    tokio::time::timeout(step, negotiate).await.map_err(|_| timed(ProxyStage::Tunnel))??;
    Ok(Tunnel { io, proxy_addr, connect_ms, negotiate_ms: ms(t1.elapsed()) })
}

fn authority(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

async fn http_connect(p: &Proxy, io: &mut BoxIo, host: &str, port: u16) -> Result<()> {
    let target = authority(host, port);
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some((u, pw)) = &p.auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{}", pw.expose()));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    io.write_all(req.as_bytes()).await.map_err(|e| perr(p, ProxyStage::Tunnel, e.to_string()))?;
    // Read the response head byte by byte: nothing after it may be consumed, it belongs to the tunnel.
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = io.read(&mut b).await.map_err(|e| perr(p, ProxyStage::Tunnel, e.to_string()))?;
        if n == 0 {
            return Err(perr(p, ProxyStage::Tunnel, "proxy closed the connection during CONNECT"));
        }
        head.push(b[0]);
        if head.len() > 16 * 1024 {
            return Err(perr(p, ProxyStage::Protocol, "CONNECT response head over 16 KiB"));
        }
    }
    let line = String::from_utf8_lossy(&head);
    let status_line = line.lines().next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let (version, code) = (parts.next().unwrap_or(""), parts.next().and_then(|c| c.parse::<u16>().ok()));
    if !version.starts_with("HTTP/1.") {
        return Err(perr(p, ProxyStage::Protocol, format!("not an HTTP proxy answer: {:?}", status_line.chars().take(60).collect::<String>())));
    }
    match code {
        Some(200..=299) => Ok(()),
        Some(407) => Err(perr(
            p,
            ProxyStage::Auth,
            if p.auth.is_some() { "407: the proxy refused the credentials" } else { "407: the proxy requires credentials and none are configured" },
        )),
        Some(c) => Err(perr(p, ProxyStage::Tunnel, format!("CONNECT {target} answered {c}"))),
        None => Err(perr(p, ProxyStage::Protocol, format!("no status in {status_line:?}"))),
    }
}

async fn socks5_connect(p: &Proxy, io: &mut BoxIo, host: &str, port: u16) -> Result<()> {
    let e = |stage, d: String| perr(p, stage, d);
    let io_err = |err: std::io::Error| perr(p, ProxyStage::Tunnel, err.to_string());
    let methods: &[u8] = if p.auth.is_some() { &[0x00, 0x02] } else { &[0x00] };
    let mut hello = vec![0x05, methods.len() as u8];
    hello.extend_from_slice(methods);
    io.write_all(&hello).await.map_err(io_err)?;
    let mut r = [0u8; 2];
    io.read_exact(&mut r).await.map_err(io_err)?;
    if r[0] != 0x05 {
        return Err(e(ProxyStage::Protocol, format!("not a SOCKS5 proxy (version byte {:#04x})", r[0])));
    }
    match r[1] {
        0x00 => {}
        0x02 => {
            let Some((u, pw)) = &p.auth else { return Err(e(ProxyStage::Protocol, "proxy chose user/password without being offered it".into())) };
            let mut a = vec![0x01, u.len() as u8];
            a.extend_from_slice(u.as_bytes());
            a.push(pw.expose().len() as u8);
            a.extend_from_slice(pw.expose().as_bytes());
            io.write_all(&a).await.map_err(io_err)?;
            let mut ar = [0u8; 2];
            io.read_exact(&mut ar).await.map_err(io_err)?;
            if ar[1] != 0x00 {
                return Err(e(ProxyStage::Auth, "the proxy refused the credentials".into()));
            }
        }
        0xFF => {
            return Err(e(
                ProxyStage::Auth,
                if p.auth.is_some() { "no acceptable authentication method".into() } else { "the proxy requires credentials and none are configured".into() },
            ))
        }
        m => return Err(e(ProxyStage::Protocol, format!("proxy chose unsupported method {m:#04x}"))),
    }
    // The destination as a name (address type 3) so the proxy resolves it; addresses as addresses.
    let mut req = vec![0x05, 0x01, 0x00];
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(e(ProxyStage::Protocol, "destination name over 255 bytes".into()));
            }
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    io.write_all(&req).await.map_err(io_err)?;
    let mut rh = [0u8; 4];
    io.read_exact(&mut rh).await.map_err(io_err)?;
    if rh[1] != 0x00 {
        let why = match rh[1] {
            0x01 => "general failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable (or name not resolved)",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown reply",
        };
        return Err(e(ProxyStage::Tunnel, format!("SOCKS5 reply {:#04x}: {why}", rh[1])));
    }
    let skip = match rh[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            io.read_exact(&mut l).await.map_err(io_err)?;
            l[0] as usize
        }
        t => return Err(e(ProxyStage::Protocol, format!("bound address type {t:#04x}"))),
    };
    let mut rest = vec![0u8; skip + 2];
    io.read_exact(&mut rest).await.map_err(io_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(url: &str) -> ProxySpec {
        ProxySpec { id: "p".into(), url: url.into(), username: None, password: None, ca_file: None }
    }

    #[test]
    fn no_proxy_is_direct_and_bad_proxies_are_errors_not_direct() {
        assert!(matches!(ProxyConfig::default().route(), Ok(Route::Direct)));
        let one = ProxyConfig { proxies: vec![spec("ftp://h:1")], select: None };
        assert!(matches!(one.route(), Err(Error::Config(_))), "an invalid proxy never becomes direct");
        let two = ProxyConfig { proxies: vec![spec("http://a:1"), ProxySpec { id: "q".into(), ..spec("socks5h://b:2") }], select: None };
        assert!(matches!(two.route(), Err(Error::Config(_))), "ambiguous selection");
        let pick = ProxyConfig { select: Some("q".into()), ..two };
        assert!(matches!(pick.route(), Ok(Route::Proxy(p)) if p.scheme == ProxyScheme::Socks5 && p.port == 2));
        let env = ProxyConfig { proxies: vec![spec("env:CFPROBE_TEST_UNSET_VAR")], select: None };
        assert!(matches!(env.route(), Err(Error::Config(m)) if m.contains("CFPROBE_TEST_UNSET_VAR")));
    }

    #[test]
    fn credentials_never_print() {
        let s = ProxySpec { password: Some(Secret::new("hunter2")), username: Some("u".into()), ..spec("http://x:pw-in-url@h:3128") };
        let json = serde_json::to_string(&s).unwrap();
        let dbg = format!("{s:?} {:?}", s.validate().unwrap());
        for out in [&json, &dbg] {
            assert!(!out.contains("hunter2") && !out.contains("pw-in-url"), "{out}");
        }
    }

    #[test]
    fn url_credentials_are_decoded() {
        let p = spec("socks5://us%40er:p%3Ass@h:1").validate().unwrap();
        let (u, pw) = p.auth.unwrap();
        assert_eq!((u.as_str(), pw.expose()), ("us@er", "p:ss"));
    }
}
