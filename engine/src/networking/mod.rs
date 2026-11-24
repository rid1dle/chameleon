//! The engine's own connection stack: DNS, TCP, BoringSSL, then hyper HTTP/1.1 or HTTP/2 by ALPN.
//!
//! This is the one boundary around the network. Everything it returns is plain data (`Exchange`),
//! so the stack behind it can be replaced without touching analysis or reporting.
//!
//! Connection reuse: an HTTP/2 connection is shared by every request to its origin, concurrent ones
//! included (streams are multiplexed, as browsers do). HTTP/1.1 connections carry one request at a
//! time and return to an idle list afterwards. Dials to one origin are serialized, so concurrent
//! first requests wait for one handshake and then share it when it is HTTP/2.

mod exchange;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::{Duration, Instant};

use boring::ssl::SslConnector;
use bytes::Bytes;
use http::header::{CONTENT_ENCODING, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Version};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub use exchange::{
    AddressSource, BodyDecoding, ConnectionRecord, Exchange, Informational, Protocol, RequestRecord, ResponseRecord, Timings,
};

use crate::core::{Config, Error, Result, Stage, Target};
use crate::http::{DecodeError, H1Settings, H2Settings, decode_body, header_list, redact_url, set_cookies};
use crate::tls::{self, TlsObservation};

/// HTTP/2 forbids connection-specific headers (RFC 9113 8.2.2); hyper drops them before sending.
const H2_CONNECTION_HEADERS: [&str; 5] = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

/// The engine. Cheap to share behind an `Arc`; holds the TLS connector and the connection pool.
pub struct CFProbe {
    config: Config,
    /// Decided once, here: every dial uses it. There is no other way out of the engine.
    route: crate::proxy::Route,
    connector: SslConnector,
    /// A synchronous mutex: it is never held across an await, and an async one cost a scheduler
    /// round-trip per contended take/release (profiled, P1).
    pool: SyncMutex<HashMap<PoolKey, Pooled>>,
    /// One dial at a time per origin, so concurrent first requests can share an HTTP/2 connection.
    dialing: Mutex<HashMap<PoolKey, Arc<Mutex<()>>>>,
    next_conn_id: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    scheme: String,
    /// Bare host: a domain (lowercase) or an IP address without brackets. Used for SNI and DNS.
    host: String,
    port: u16,
}

impl PoolKey {
    /// `host:port` as written in `--resolve` (IPv6 in brackets).
    fn resolve_key(&self) -> String {
        if self.host.contains(':') { format!("[{}]:{}", self.host, self.port) } else { format!("{}:{}", self.host, self.port) }
    }
}

#[derive(Default)]
struct Pooled {
    h2: Option<Conn>,
    idle_h1: Vec<Conn>,
}

struct Conn {
    id: u64,
    sender: Sender,
    protocol: Protocol,
    remote_addr: SocketAddr,
    address_source: AddressSource,
    skipped_addresses: Arc<Vec<String>>,
    tls: Option<Arc<TlsObservation>>,
    /// Requests started on this connection, shared by every handle to it.
    requests: Arc<AtomicU32>,
}

impl Conn {
    /// Another handle to a shared HTTP/2 connection.
    fn share(&self) -> Option<Conn> {
        let Sender::H2(s) = &self.sender else { return None };
        Some(Conn {
            id: self.id,
            sender: Sender::H2(s.clone()),
            protocol: self.protocol,
            remote_addr: self.remote_addr,
            address_source: self.address_source,
            skipped_addresses: self.skipped_addresses.clone(),
            tls: self.tls.clone(),
            requests: self.requests.clone(),
        })
    }
}

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>, HeadTap),
    H2(http2::SendRequest<Full<Bytes>>),
}

impl Sender {
    async fn send(&mut self, req: Request<Full<Bytes>>) -> std::result::Result<http::Response<Incoming>, hyper::Error> {
        match self {
            Sender::H1(s, tap) => {
                s.ready().await?;
                // One request at a time on HTTP/1.1, so the next head read is this request's.
                tap.arm();
                s.send_request(req).await
            }
            Sender::H2(s) => {
                s.ready().await?;
                s.send_request(req).await
            }
        }
    }

    fn is_closed(&self) -> bool {
        match self {
            Sender::H1(s, _) => s.is_closed(),
            Sender::H2(s) => s.is_closed(),
        }
    }
}

/// Per-connection timings, only present on the request that opened the connection.
struct DialTimings {
    proxy_ms: Option<f64>,
    /// `None` when no lookup ran: the address came from `resolve` in the config or the host is an IP.
    dns_ms: Option<f64>,
    connect_ms: f64,
    tls_ms: Option<f64>,
}

fn idempotent(m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE | Method::TRACE)
}

impl CFProbe {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let route = config.proxy.route()?;
        let connector = config.tls.build_connector()?;
        Ok(Self {
            config,
            route,
            connector,
            pool: SyncMutex::new(HashMap::new()),
            dialing: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(1),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn route(&self) -> &crate::proxy::Route {
        &self.route
    }

    /// Make one request and return what was sent, what came back, and what the connection showed.
    ///
    /// When a reused connection turns out to be dead before any response arrives (the server closed
    /// an idle keep-alive connection), an idempotent request is sent once more on a new connection,
    /// and `connection.retried_after` says why. A failure on a new connection is never retried.
    pub async fn inspect(&self, target: Target) -> Result<Exchange> {
        let started = Instant::now();
        let key = pool_key(&target)?;
        let method = parse_method(&target)?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(self.config.request_timeout_ms);

        let mut retried_after = None;
        let (conn, dialed, request_number, response, informational, record) = loop {
            let (mut conn, dialed) = self.acquire(&key).await?;
            let request_number = conn.requests.fetch_add(1, Ordering::SeqCst) + 1;
            let (mut request, record) = self.build_request(&target, &method, conn.protocol)?;
            let informational = Arc::new(SyncMutex::new(Vec::new()));
            let sink = informational.clone();
            hyper::ext::on_informational(&mut request, move |res| {
                sink.lock().unwrap().push(Informational { status: res.status().as_u16(), headers: header_list(res.headers()) });
            });
            let sent = tokio::time::timeout_at(deadline, conn.sender.send(request))
                .await
                .map_err(|_| Error::Timeout { stage: Stage::Response, after_ms: self.config.request_timeout_ms })?;
            match sent {
                Ok(response) => break (conn, dialed, request_number, response, informational, record),
                Err(e) if dialed.is_none() && retried_after.is_none() && idempotent(&method) => {
                    self.forget(&key, conn.id).await;
                    retried_after = Some(format!("connection #{} was reused and failed before a response: {e}", conn.id));
                }
                Err(e) => {
                    self.forget(&key, conn.id).await;
                    return Err(e.into());
                }
            }
        };
        let ttfb_ms = ms(started.elapsed());

        let (parts, body) = response.into_parts();
        let limit = self.config.max_body_bytes;
        let body = tokio::time::timeout_at(deadline, Limited::new(body, limit).collect())
            .await
            .map_err(|_| Error::Timeout { stage: Stage::Body, after_ms: self.config.request_timeout_ms })?
            .map_err(|e| {
                if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
                    Error::BodyTooLarge { limit }
                } else {
                    Error::Body(e.to_string())
                }
            })?
            .to_bytes();
        let total_ms = ms(started.elapsed());

        let wire_len = body.len();
        let (body, body_decoding) = match parts.headers.get(CONTENT_ENCODING).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()) {
            None => (body, BodyDecoding::Identity),
            Some(enc) if enc.trim().eq_ignore_ascii_case("identity") => (body, BodyDecoding::Identity),
            Some(enc) => match decode_body(&enc, &body, limit) {
                Ok(decoded) => {
                    let decoded_len = decoded.len();
                    (Bytes::from(decoded), BodyDecoding::Decoded { encoding: enc, decoded_len })
                }
                Err(DecodeError::TooLarge(limit)) => return Err(Error::BodyTooLarge { limit }),
                Err(e) => {
                    let reason = match e {
                        DecodeError::Unsupported(x) => format!("unsupported encoding {x}"),
                        DecodeError::Corrupt(x) => format!("corrupt: {x}"),
                        DecodeError::TooLarge(_) => unreachable!(),
                    };
                    (body, BodyDecoding::NotDecoded { encoding: enc, reason })
                }
            },
        };

        let timings_conn = dialed.as_ref().map(|d| (d.dns_ms, d.connect_ms, d.tls_ms));
        let exchange = Exchange {
            request: record,
            connection: ConnectionRecord {
                id: conn.id,
                protocol: conn.protocol,
                remote_addr: conn.remote_addr,
                address_source: conn.address_source,
                route: self.route.record(),
                skipped_addresses: conn.skipped_addresses.to_vec(),
                reused: dialed.is_none(),
                request_number,
                retried_after,
            },
            configured_tls: (key.scheme == "https").then(|| self.config.tls.clone()),
            configured_h2: (conn.protocol == Protocol::Http2).then(|| self.config.h2.clone()),
            tls: conn.tls.as_deref().cloned(),
            response: ResponseRecord {
                status: parts.status.as_u16(),
                http_version: version_str(parts.version),
                informational: std::mem::take(&mut *informational.lock().unwrap()),
                headers: header_list(&parts.headers),
                wire_header_order: match &conn.sender {
                    Sender::H1(_, tap) => tap.names(),
                    Sender::H2(_) => None,
                },
                set_cookies: set_cookies(&parts.headers),
                raw_set_cookies: parts
                    .headers
                    .get_all(http::header::SET_COOKIE)
                    .iter()
                    .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                    .collect(),
                raw_location: parts.headers.get(http::header::LOCATION).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()),
                body_len: wire_len,
                body_decoding,
                body,
            },
            timings: Timings {
                dns_ms: timings_conn.and_then(|t| t.0),
                connect_ms: timings_conn.map(|t| t.1),
                proxy_ms: dialed.as_ref().and_then(|d| d.proxy_ms),
                tls_ms: timings_conn.and_then(|t| t.2),
                ttfb_ms,
                total_ms,
            },
        };

        self.release(key, conn).await;
        Ok(exchange)
    }

    /// A pooled connection, or a new one with its dial timings.
    async fn acquire(&self, key: &PoolKey) -> Result<(Conn, Option<DialTimings>)> {
        if !self.config.reuse_connections {
            let (conn, t) = self.dial(key).await?;
            return Ok((conn, Some(t)));
        }
        if let Some(c) = self.take_pooled(key).await {
            return Ok((c, None));
        }
        let gate = self.dialing.lock().await.entry(key.clone()).or_default().clone();
        let _held = gate.lock().await;
        if let Some(c) = self.take_pooled(key).await {
            return Ok((c, None));
        }
        let (conn, t) = self.dial(key).await?;
        if let Some(shared) = conn.share() {
            self.pool.lock().unwrap().entry(key.clone()).or_default().h2 = Some(shared);
        }
        Ok((conn, Some(t)))
    }

    async fn take_pooled(&self, key: &PoolKey) -> Option<Conn> {
        let mut pool = self.pool.lock().unwrap();
        let p = pool.get_mut(key)?;
        if let Some(h2) = &p.h2 {
            if h2.sender.is_closed() {
                p.h2 = None;
            } else {
                return h2.share();
            }
        }
        while let Some(c) = p.idle_h1.pop() {
            if !c.sender.is_closed() {
                return Some(c);
            }
        }
        None
    }

    /// Back to the pool after a complete exchange. HTTP/2 connections never left it.
    async fn release(&self, key: PoolKey, conn: Conn) {
        if !self.config.reuse_connections || conn.sender.is_closed() {
            return;
        }
        if let Sender::H1(..) = conn.sender {
            self.pool.lock().unwrap().entry(key).or_default().idle_h1.push(conn);
        }
    }

    /// Drop a connection that failed, so no later request picks it up.
    async fn forget(&self, key: &PoolKey, id: u64) {
        let mut pool = self.pool.lock().unwrap();
        if let Some(p) = pool.get_mut(key) {
            if p.h2.as_ref().is_some_and(|c| c.id == id) {
                p.h2 = None;
            }
            p.idle_h1.retain(|c| c.id != id);
        }
    }

    async fn dial(&self, key: &PoolKey) -> Result<(Conn, DialTimings)> {
        let step = Duration::from_millis(self.config.connect_timeout_ms);
        let timeout = |stage| Error::Timeout { stage, after_ms: self.config.connect_timeout_ms };

        let (io, addr, address_source, skipped, dns_ms, connect_ms, proxy_ms) = match &self.route {
            crate::proxy::Route::Proxy(p) => {
                // The destination is never resolved here: its name (or a pinned address) goes to the
                // proxy. A failure is an error; there is no direct path to try instead.
                let pin = self.config.resolve.iter().find(|(k, _)| k.eq_ignore_ascii_case(&key.resolve_key())).map(|(_, a)| *a);
                let (dest, source) = match pin {
                    Some(a) => (a.ip().to_string(), AddressSource::ResolveOverride),
                    None if key.host.parse::<IpAddr>().is_ok() => (key.host.clone(), AddressSource::IpLiteral),
                    None => (key.host.clone(), AddressSource::Proxy),
                };
                let t = crate::proxy::open_tunnel(p, &dest, key.port, step).await?;
                (t.io, t.proxy_addr, source, Vec::new(), None, t.connect_ms, Some(t.negotiate_ms))
            }
            crate::proxy::Route::Direct => {
                let t0 = Instant::now();
                let (addrs, address_source) =
                    tokio::time::timeout(step, self.resolve(key)).await.map_err(|_| timeout(Stage::Dns))??;
                let dns_ms = (address_source == AddressSource::Dns).then(|| ms(t0.elapsed()));
                // Each address in the order given, each with the full connect budget, until one connects.
                let t1 = Instant::now();
                let mut skipped = Vec::new();
                let mut last_err = None;
                let mut connected = None;
                for addr in &addrs {
                    match tokio::time::timeout(step, TcpStream::connect(addr)).await {
                        Ok(Ok(tcp)) => {
                            connected = Some((tcp, *addr));
                            break;
                        }
                        Ok(Err(source)) => {
                            skipped.push(format!("{addr}: {source}"));
                            last_err = Some(Error::Connect { addr: *addr, source });
                        }
                        Err(_) => {
                            skipped.push(format!("{addr}: timed out after {} ms", self.config.connect_timeout_ms));
                            last_err = Some(timeout(Stage::Connect));
                        }
                    }
                }
                let (tcp, addr) = connected.ok_or_else(|| last_err.expect("resolve returns at least one address"))?;
                tcp.set_nodelay(true).ok();
                let io: crate::proxy::BoxIo = Box::new(tcp);
                (io, addr, address_source, skipped, dns_ms, ms(t1.elapsed()), None)
            }
        };

        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let new_conn = |sender, protocol, tls| Conn {
            id,
            sender,
            protocol,
            remote_addr: addr,
            address_source,
            skipped_addresses: Arc::new(skipped.clone()),
            tls,
            requests: Arc::new(AtomicU32::new(0)),
        };
        if key.scheme == "http" {
            let sender = handshake(io, Protocol::Http1, &self.config.h1, &self.config.h2).await?;
            return Ok((new_conn(sender, Protocol::Http1, None), DialTimings { proxy_ms, dns_ms, connect_ms, tls_ms: None }));
        }

        let t2 = Instant::now();
        let ssl_config = self.connector.configure()?;
        let stream = tokio::time::timeout(step, tokio_boring::connect(ssl_config, &key.host, io))
            .await
            .map_err(|_| timeout(Stage::Tls))?
            .map_err(|e| Error::TlsHandshake(describe_handshake_error(&e)))?;
        let tls_ms = ms(t2.elapsed());

        let observation = tls::observe(stream.ssl());
        let protocol = match observation.alpn.as_deref() {
            Some("h2") => Protocol::Http2,
            _ => Protocol::Http1,
        };
        let sender = handshake(stream, protocol, &self.config.h1, &self.config.h2).await?;
        Ok((new_conn(sender, protocol, Some(Arc::new(observation))), DialTimings { proxy_ms, dns_ms, connect_ms, tls_ms: Some(tls_ms) }))
    }

    /// Addresses to try, in order, and where they came from.
    async fn resolve(&self, key: &PoolKey) -> Result<(Vec<SocketAddr>, AddressSource)> {
        let want = key.resolve_key();
        if let Some((_, addr)) = self.config.resolve.iter().find(|(k, _)| k.eq_ignore_ascii_case(&want)) {
            return Ok((vec![*addr], AddressSource::ResolveOverride));
        }
        if let Ok(ip) = key.host.parse::<IpAddr>() {
            return Ok((vec![SocketAddr::new(ip, key.port)], AddressSource::IpLiteral));
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((key.host.as_str(), key.port))
            .await
            .map_err(|source| Error::Dns { host: key.host.clone(), source })?
            .collect();
        if addrs.is_empty() {
            return Err(Error::Dns {
                host: key.host.clone(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses"),
            });
        }
        Ok((addrs, AddressSource::Dns))
    }

    /// Headers go out in this order: Host (HTTP/1.1 only), config defaults, then the target's own.
    /// A target header replaces a *default* of the same name in place; repeated target headers are
    /// all sent, in order.
    fn build_request(&self, target: &Target, method: &Method, protocol: Protocol) -> Result<(Request<Full<Bytes>>, RequestRecord)> {
        // (name, value, from_defaults)
        let mut ordered: Vec<(String, String, bool)> = Vec::new();
        if protocol == Protocol::Http1 {
            ordered.push(("host".into(), host_header(&target.url), true));
        }
        for (k, v) in &self.config.default_headers {
            let k = k.to_ascii_lowercase();
            match ordered.iter_mut().find(|(n, _, _)| *n == k) {
                Some(slot) => slot.1 = v.clone(),
                None => ordered.push((k, v.clone(), true)),
            }
        }
        for (k, v) in &target.headers {
            let k = k.to_ascii_lowercase();
            match ordered.iter_mut().find(|(n, _, default)| *default && *n == k) {
                Some(slot) => *slot = (k, v.clone(), false),
                None => ordered.push((k, v.clone(), false)),
            }
        }

        let mut not_sent = Vec::new();
        let mut headers = HeaderMap::new();
        for (k, v, _) in &ordered {
            if protocol == Protocol::Http2 && H2_CONNECTION_HEADERS.contains(&k.as_str()) {
                not_sent.push(k.clone());
                continue;
            }
            let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| Error::Target(format!("header {k:?}: {e}")))?;
            let value = HeaderValue::from_str(v).map_err(|e| Error::Target(format!("header {k:?} value: {e}")))?;
            headers.append(name, value);
        }

        // HTTP/2 needs the absolute URI for :scheme and :authority; HTTP/1.1 sends origin-form.
        // Target::get refuses URLs with credentials, so none can reach :authority.
        let mut path = target.url.path().to_string();
        if let Some(q) = target.url.query() {
            path.push('?');
            path.push_str(q);
        }
        let uri = match protocol {
            Protocol::Http2 => format!("{}://{}{path}", target.url.scheme(), host_header(&target.url)),
            Protocol::Http1 => path,
        };
        let mut builder = Request::builder().method(method.clone()).uri(uri).version(match protocol {
            Protocol::Http2 => Version::HTTP_2,
            Protocol::Http1 => Version::HTTP_11,
        });
        *builder.headers_mut().expect("builder has no error yet") = headers.clone();
        let body = Full::new(Bytes::from(target.body.clone().unwrap_or_default()));
        let request = builder.body(body)?;

        let record = RequestRecord {
            method: method.to_string(),
            url: redact_url(target.url.as_str()),
            headers: header_list(&headers),
            not_sent,
        };
        Ok((request, record))
    }
}

fn parse_method(target: &Target) -> Result<Method> {
    Method::from_bytes(target.method.as_bytes()).map_err(|e| Error::Target(format!("method {:?}: {e}", target.method)))
}

/// Copies the bytes of the next final response head read on an HTTP/1.1 connection (1xx heads
/// skipped), so header names can be recorded in wire order and case. hyper exposes only a
/// `HeaderMap`, which groups repeated names (D10). Stops copying at the end of the head: bodies are
/// never kept. Over 256 KiB without a complete head, it gives up for that response.
#[derive(Clone, Default)]
struct HeadTap(Arc<SyncMutex<TapState>>);

#[derive(Default)]
struct TapState {
    armed: bool,
    buf: Vec<u8>,
    head: Option<Vec<u8>>,
}

const TAP_LIMIT: usize = 256 * 1024;

impl HeadTap {
    fn arm(&self) {
        let mut t = self.0.lock().unwrap();
        t.armed = true;
        t.buf.clear();
        t.head = None;
    }

    fn feed(&self, bytes: &[u8]) {
        let mut t = self.0.lock().unwrap();
        if !t.armed {
            return;
        }
        t.buf.extend_from_slice(bytes);
        while let Some(end) = t.buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let status: u16 = t.buf[..end].split(|b| *b == b' ').nth(1).and_then(|c| std::str::from_utf8(c).ok()?.parse().ok()).unwrap_or(0);
            if (100..200).contains(&status) && status != 101 {
                t.buf.drain(..end + 4);
                continue;
            }
            let head = t.buf[..end + 4].to_vec();
            t.head = Some(head);
            t.armed = false;
            t.buf = Vec::new();
            return;
        }
        if t.buf.len() > TAP_LIMIT {
            t.armed = false;
            t.buf = Vec::new();
        }
    }

    /// Header names of the last captured head, as sent (original case, repeats kept, in order).
    fn names(&self) -> Option<Vec<String>> {
        let t = self.0.lock().unwrap();
        let head = String::from_utf8_lossy(t.head.as_ref()?).into_owned();
        Some(head.split("\r\n").skip(1).filter_map(|l| l.split_once(':').map(|(n, _)| n.trim().to_string())).filter(|n| !n.is_empty()).collect())
    }
}

struct TapIo<IO> {
    inner: IO,
    tap: HeadTap,
}

impl<IO: AsyncRead + Unpin> AsyncRead for TapIo<IO> {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &r {
            let new = &buf.filled()[before..];
            if !new.is_empty() {
                self.tap.feed(new);
            }
        }
        r
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for TapIo<IO> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, b: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

async fn handshake<IO>(io: IO, protocol: Protocol, h1: &H1Settings, h2: &H2Settings) -> Result<Sender>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    match protocol {
        Protocol::Http1 => {
            let mut b = http1::Builder::new();
            b.title_case_headers(h1.title_case_headers);
            if let Some(n) = h1.max_response_headers {
                b.max_headers(n);
            }
            let tap = HeadTap::default();
            let (sender, conn) = b.handshake(TokioIo::new(TapIo { inner: io.into_inner(), tap: tap.clone() })).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            Ok(Sender::H1(sender, tap))
        }
        Protocol::Http2 => {
            let mut b = http2::Builder::new(TokioExecutor::new());
            if let Some(v) = h2.header_table_size {
                b.header_table_size(v);
            }
            if let Some(v) = h2.max_concurrent_streams {
                b.max_concurrent_streams(v);
            }
            if let Some(v) = h2.initial_stream_window_size {
                b.initial_stream_window_size(v);
            }
            if let Some(v) = h2.initial_connection_window_size {
                b.initial_connection_window_size(v);
            }
            if let Some(v) = h2.max_frame_size {
                b.max_frame_size(v);
            }
            if let Some(v) = h2.max_header_list_size {
                b.max_header_list_size(v);
            }
            let (sender, conn) = b.handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            Ok(Sender::H2(sender))
        }
    }
}

fn pool_key(target: &Target) -> Result<PoolKey> {
    let url = &target.url;
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.to_ascii_lowercase(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        None => return Err(Error::Target(format!("{}: no host", redact_url(url.as_str())))),
    };
    Ok(PoolKey {
        scheme: url.scheme().to_string(),
        host,
        port: url.port_or_known_default().ok_or_else(|| Error::Target(format!("{}: no port", redact_url(url.as_str()))))?,
    })
}

/// `host[:port]` as it goes in `Host` and `:authority` (IPv6 in brackets, default port omitted).
fn host_header(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    }
}

fn describe_handshake_error<S>(e: &tokio_boring::HandshakeError<S>) -> String {
    let mut s = e.to_string();
    if let Some(ssl) = e.ssl() {
        if let Err(verify) = ssl.verify_result() {
            s.push_str(&format!(" (certificate verify: {})", verify.error_string()));
        }
    }
    s
}

fn version_str(v: Version) -> String {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "unknown",
    }
    .to_string()
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
