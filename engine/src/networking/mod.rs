//! The engine's own connection stack: DNS, TCP, BoringSSL, then hyper HTTP/1.1 or HTTP/2 by ALPN.
//!
//! This is the one boundary around the network. Everything it returns is plain data (`Exchange`),
//! so the stack behind it can be replaced without touching analysis or reporting.

mod exchange;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use boring::ssl::SslConnector;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Version};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub use exchange::{ConnectionRecord, Exchange, Protocol, RequestRecord, ResponseRecord, Timings};

use crate::core::{Config, Error, Result, Stage, Target};
use crate::http::{H2Settings, header_list, set_cookies};
use crate::tls::{self, TlsObservation};

/// The engine. Cheap to share behind an `Arc`; holds the TLS connector and the connection pool.
pub struct CFProbe {
    config: Config,
    connector: SslConnector,
    pool: Mutex<HashMap<PoolKey, PooledConn>>,
    next_conn_id: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    scheme: String,
    host: String,
    port: u16,
}

struct PooledConn {
    id: u64,
    sender: Sender,
    protocol: Protocol,
    remote_addr: SocketAddr,
    tls: Option<Arc<TlsObservation>>,
    requests: u32,
}

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

impl Sender {
    async fn send(&mut self, req: Request<Full<Bytes>>) -> Result<http::Response<Incoming>> {
        Ok(match self {
            Sender::H1(s) => {
                s.ready().await?;
                s.send_request(req).await?
            }
            Sender::H2(s) => {
                s.ready().await?;
                s.send_request(req).await?
            }
        })
    }

    fn is_closed(&self) -> bool {
        match self {
            Sender::H1(s) => s.is_closed(),
            Sender::H2(s) => s.is_closed(),
        }
    }
}

/// Per-connection timings, only present on the request that opened the connection.
struct Dialed {
    conn: PooledConn,
    dns_ms: f64,
    connect_ms: f64,
    tls_ms: Option<f64>,
}

impl CFProbe {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let connector = config.tls.build_connector()?;
        Ok(Self { config, connector, pool: Mutex::new(HashMap::new()), next_conn_id: AtomicU64::new(1) })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Make one request and return what was sent, what came back, and what the connection showed.
    pub async fn inspect(&self, target: Target) -> Result<Exchange> {
        let started = Instant::now();
        let key = pool_key(&target)?;

        let reused = if self.config.reuse_connections { self.take_pooled(&key).await } else { None };
        let (mut conn, timings_conn, was_reused) = match reused {
            Some(conn) => (conn, None, true),
            None => {
                let d = self.dial(&key).await?;
                (d.conn, Some((d.dns_ms, d.connect_ms, d.tls_ms)), false)
            }
        };
        conn.requests += 1;

        let (request, record) = self.build_request(&target, conn.protocol)?;
        let budget = Duration::from_millis(self.config.request_timeout_ms);
        let deadline = tokio::time::Instant::now() + budget;

        let response = tokio::time::timeout_at(deadline, conn.sender.send(request))
            .await
            .map_err(|_| Error::Timeout { stage: Stage::Response, after_ms: self.config.request_timeout_ms })??;
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

        let exchange = Exchange {
            request: record,
            connection: ConnectionRecord {
                id: conn.id,
                protocol: conn.protocol,
                remote_addr: conn.remote_addr,
                reused: was_reused,
                request_number: conn.requests,
            },
            configured_tls: (key.scheme == "https").then(|| self.config.tls.clone()),
            configured_h2: (conn.protocol == Protocol::Http2).then(|| self.config.h2.clone()),
            tls: conn.tls.as_deref().cloned(),
            response: ResponseRecord {
                status: parts.status.as_u16(),
                http_version: version_str(parts.version),
                headers: header_list(&parts.headers),
                set_cookies: set_cookies(&parts.headers),
                body_len: body.len(),
                body,
            },
            timings: Timings {
                dns_ms: timings_conn.map(|t| t.0),
                connect_ms: timings_conn.map(|t| t.1),
                tls_ms: timings_conn.and_then(|t| t.2),
                ttfb_ms,
                total_ms,
            },
        };

        if self.config.reuse_connections && !conn.sender.is_closed() {
            self.pool.lock().await.insert(key, conn);
        }
        Ok(exchange)
    }

    async fn take_pooled(&self, key: &PoolKey) -> Option<PooledConn> {
        let conn = self.pool.lock().await.remove(key)?;
        (!conn.sender.is_closed()).then_some(conn)
    }

    async fn dial(&self, key: &PoolKey) -> Result<Dialed> {
        let step = Duration::from_millis(self.config.connect_timeout_ms);
        let timeout = |stage| Error::Timeout { stage, after_ms: self.config.connect_timeout_ms };

        let t0 = Instant::now();
        let addr = tokio::time::timeout(step, self.resolve(key)).await.map_err(|_| timeout(Stage::Dns))??;
        let dns_ms = ms(t0.elapsed());

        let t1 = Instant::now();
        let tcp = tokio::time::timeout(step, TcpStream::connect(addr))
            .await
            .map_err(|_| timeout(Stage::Connect))?
            .map_err(|source| Error::Connect { addr, source })?;
        tcp.set_nodelay(true).ok();
        let connect_ms = ms(t1.elapsed());

        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        if key.scheme == "http" {
            let sender = handshake(tcp, Protocol::Http1, &self.config.h2).await?;
            let conn = PooledConn { id, sender, protocol: Protocol::Http1, remote_addr: addr, tls: None, requests: 0 };
            return Ok(Dialed { conn, dns_ms, connect_ms, tls_ms: None });
        }

        let t2 = Instant::now();
        let ssl_config = self.connector.configure()?;
        let stream = tokio::time::timeout(step, tokio_boring::connect(ssl_config, &key.host, tcp))
            .await
            .map_err(|_| timeout(Stage::Tls))?
            .map_err(|e| Error::TlsHandshake(describe_handshake_error(&e)))?;
        let tls_ms = ms(t2.elapsed());

        let observation = tls::observe(stream.ssl());
        let protocol = match observation.alpn.as_deref() {
            Some("h2") => Protocol::Http2,
            _ => Protocol::Http1,
        };
        let sender = handshake(stream, protocol, &self.config.h2).await?;
        let conn = PooledConn {
            id,
            sender,
            protocol,
            remote_addr: addr,
            tls: Some(Arc::new(observation)),
            requests: 0,
        };
        Ok(Dialed { conn, dns_ms, connect_ms, tls_ms: Some(tls_ms) })
    }

    async fn resolve(&self, key: &PoolKey) -> Result<SocketAddr> {
        if let Some(addr) = self.config.resolve.get(&format!("{}:{}", key.host, key.port)) {
            return Ok(*addr);
        }
        let mut addrs = tokio::net::lookup_host((key.host.as_str(), key.port))
            .await
            .map_err(|source| Error::Dns { host: key.host.clone(), source })?;
        addrs.next().ok_or_else(|| Error::Dns {
            host: key.host.clone(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses"),
        })
    }

    /// Headers go out in this order: Host (HTTP/1.1 only), config defaults, then the target's own.
    /// A target header replaces a default of the same name in place.
    fn build_request(&self, target: &Target, protocol: Protocol) -> Result<(Request<Full<Bytes>>, RequestRecord)> {
        let method = Method::from_bytes(target.method.as_bytes())
            .map_err(|e| Error::Target(format!("method {:?}: {e}", target.method)))?;

        let mut ordered: Vec<(String, String)> = Vec::new();
        if protocol == Protocol::Http1 {
            ordered.push(("host".into(), host_header(&target.url)));
        }
        for (k, v) in self.config.default_headers.iter().chain(target.headers.iter()) {
            let k = k.to_ascii_lowercase();
            match ordered.iter_mut().find(|(n, _)| *n == k) {
                Some(slot) => slot.1 = v.clone(),
                None => ordered.push((k, v.clone())),
            }
        }

        let mut headers = HeaderMap::new();
        for (k, v) in &ordered {
            let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| Error::Target(format!("header {k:?}: {e}")))?;
            let value = HeaderValue::from_str(v).map_err(|e| Error::Target(format!("header {k:?} value: {e}")))?;
            headers.append(name, value);
        }

        // HTTP/2 needs the absolute URI for :scheme and :authority; HTTP/1.1 sends origin-form.
        let uri = match protocol {
            Protocol::Http2 => target.url.as_str().to_string(),
            Protocol::Http1 => {
                let mut p = target.url.path().to_string();
                if let Some(q) = target.url.query() {
                    p.push('?');
                    p.push_str(q);
                }
                p
            }
        };
        let mut builder = Request::builder().method(method.clone()).uri(uri).version(match protocol {
            Protocol::Http2 => Version::HTTP_2,
            Protocol::Http1 => Version::HTTP_11,
        });
        *builder.headers_mut().expect("builder has no error yet") = headers.clone();
        let body = Full::new(Bytes::from(target.body.clone().unwrap_or_default()));
        let request = builder.body(body)?;

        let record = RequestRecord { method: method.to_string(), url: target.url.to_string(), headers: header_list(&headers) };
        Ok((request, record))
    }
}

async fn handshake<IO>(io: IO, protocol: Protocol, h2: &H2Settings) -> Result<Sender>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    match protocol {
        Protocol::Http1 => {
            let (sender, conn) = http1::Builder::new().handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            Ok(Sender::H1(sender))
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
    Ok(PoolKey {
        scheme: url.scheme().to_string(),
        host: url.host_str().ok_or_else(|| Error::Target(format!("{url}: no host")))?.to_string(),
        port: url.port_or_known_default().ok_or_else(|| Error::Target(format!("{url}: no port")))?,
    })
}

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
