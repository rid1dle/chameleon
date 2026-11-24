//! Local test servers shared by the integration tests: a BoringSSL + hyper echo server with a
//! throwaway certificate, and a raw TCP server that answers with scripted bytes.
#![allow(dead_code)]

use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use boring::ssl::{AlpnError, SslAcceptor, SslMethod, select_next_proto};
use boring::x509::extension::SubjectAlternativeName;
use boring::x509::{X509, X509NameBuilder};
use bytes::Bytes;
use cfprobe::{Config, Target};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const H2_AND_H1: &[u8] = b"\x02h2\x08http/1.1";
pub const H1_ONLY: &[u8] = b"\x08http/1.1";

pub fn self_signed() -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap()).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    let san = SubjectAlternativeName::new().dns("localhost").build(&b.x509v3_context(None, None)).unwrap();
    b.append_extension(&san).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build(), key)
}

pub struct Lab {
    pub addr: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    pub ca: tempfile::NamedTempFile,
}

impl Lab {
    pub async fn start(server_alpn: &'static [u8]) -> Lab {
        Lab::start_on(server_alpn, "127.0.0.1:0").await
    }

    /// `bind` e.g. `"[::1]:0"` for an IPv6-only server.
    pub async fn start_on(server_alpn: &'static [u8], bind: &str) -> Lab {
        let (cert, key) = self_signed();
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(&cert.to_pem().unwrap()).unwrap();

        let mut acc = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acc.set_private_key(&key).unwrap();
        acc.set_certificate(&cert).unwrap();
        acc.set_alpn_select_callback(move |_, client| select_next_proto(server_alpn, client).ok_or(AlpnError::NOACK));
        let acceptor = Arc::new(acc.build());

        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = accepts.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = tokio_boring::accept(&acceptor, tcp).await else { return };
                    let h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");
                    let io = TokioIo::new(tls);
                    if h2 {
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(io, service_fn(echo))
                            .await;
                    } else {
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service_fn(echo)).await;
                    }
                });
            }
        });
        Lab { addr, accepts, ca }
    }

    pub fn config(&self) -> Config {
        let mut c = Config::default();
        c.resolve.insert(format!("localhost:{}", self.addr.port()), self.addr);
        c.tls.ca_file = Some(self.ca.path().to_path_buf());
        c
    }

    pub fn url(&self, path: &str) -> Target {
        Target::get(&format!("https://localhost:{}{path}", self.addr.port())).unwrap()
    }

    pub fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

pub async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let names: Vec<&str> = req.headers().keys().map(|k| k.as_str()).collect();
    let body = if req.uri().path() == "/big" { vec![b'x'; 4096] } else { b"ok".to_vec() };
    if req.uri().path() == "/slow" {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(Response::builder()
        .header("x-seen-uri", req.uri().to_string())
        .header("x-seen-order", names.join(","))
        .header("x-seen-version", format!("{:?}", req.version()))
        .header("set-cookie", "sid=secretvalue; Path=/; HttpOnly")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

pub fn header<'a>(ex: &'a cfprobe::Exchange, name: &str) -> &'a str {
    &ex.response.headers.iter().find(|h| h.name == name).unwrap().value
}


/// A raw TCP server on 127.0.0.1. For each request read, `script` returns the chunks to write
/// (20 ms apart). With `close_after`, the connection is closed after the answer, without warning.
pub async fn raw_server(script: fn(&[u8]) -> Vec<Vec<u8>>, close_after: bool) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                loop {
                    let mut buf = vec![0u8; 65536];
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    for chunk in script(&buf[..n]) {
                        if s.write_all(&chunk).await.is_err() {
                            return;
                        }
                        s.flush().await.ok();
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    if close_after {
                        return;
                    }
                }
            });
        }
    });
    a
}

pub fn http_target(addr: SocketAddr, path: &str) -> Target {
    Target::get(&format!("http://{addr}{path}")).unwrap()
}

/// One HTTP/1.1 response with a body and extra header lines (each ending in CRLF).
pub fn h1_response(status: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    r.extend_from_slice(body);
    r
}

pub fn default_config() -> Config {
    Config::default()
}

/// One request as a scripted server sees it.
pub struct SeenRequest<'a> {
    pub path: &'a str,
    pub raw: &'a str,
    /// Requests this server has seen before this one (0 for the first).
    pub n: usize,
}

/// A raw HTTP/1.1 server with a closure that may keep state; counts requests. Keep-alive is kept.
pub async fn scripted_server<F>(f: F) -> (SocketAddr, Arc<AtomicUsize>)
where
    F: Fn(&SeenRequest) -> Vec<u8> + Send + Sync + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let (f, c) = (Arc::new(f), count.clone());
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let (f, c) = (f.clone(), c.clone());
            tokio::spawn(async move {
                loop {
                    let mut buf = vec![0u8; 65536];
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = raw.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let seen = SeenRequest { path: &path, raw: &raw, n: c.fetch_add(1, Ordering::SeqCst) };
                    if s.write_all(&f(&seen)).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (a, count)
}

/// What a test proxy saw.
#[derive(Default)]
pub struct ProxyLog {
    /// `CONNECT` targets (HTTP) or `name:port` / `ip:port` (SOCKS5, with the address type).
    pub targets: std::sync::Mutex<Vec<String>>,
    pub tunnels: AtomicUsize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TestProxyKind {
    Http,
    /// HTTP CONNECT over TLS with the lab certificate.
    Https,
    Socks5,
    /// Answers every CONNECT with this status.
    HttpRefusing(u16),
}

/// A minimal proxy on 127.0.0.1. Names ending in `.invalid` map to `target` (they cannot resolve
/// anywhere else, so a successful request proves the proxy did the resolving). `auth`: required
/// credentials (Basic for HTTP, RFC 1929 for SOCKS5).
pub async fn test_proxy(kind: TestProxyKind, auth: Option<(&'static str, &'static str)>, target: SocketAddr) -> (SocketAddr, Arc<ProxyLog>, Option<tempfile::NamedTempFile>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let log = Arc::new(ProxyLog::default());
    let (acceptor, ca) = if kind == TestProxyKind::Https {
        let (cert, key) = self_signed();
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(&cert.to_pem().unwrap()).unwrap();
        let mut acc = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acc.set_private_key(&key).unwrap();
        acc.set_certificate(&cert).unwrap();
        (Some(Arc::new(acc.build())), Some(ca))
    } else {
        (None, None)
    };
    let lg = log.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            let (lg, acceptor) = (lg.clone(), acceptor.clone());
            tokio::spawn(async move {
                let resolve = |host: &str, port: u16| -> SocketAddr {
                    if host.ends_with(".invalid") { target } else { format!("{host}:{port}").parse().unwrap_or(target) }
                };
                match kind {
                    TestProxyKind::Socks5 => {
                        let mut s = tcp;
                        let mut h = [0u8; 2];
                        if s.read_exact(&mut h).await.is_err() {
                            return;
                        }
                        let mut m = vec![0u8; h[1] as usize];
                        s.read_exact(&mut m).await.unwrap();
                        if let Some((u, p)) = auth {
                            if !m.contains(&2) {
                                s.write_all(&[5, 0xFF]).await.ok();
                                return;
                            }
                            s.write_all(&[5, 2]).await.unwrap();
                            let mut v = [0u8; 2];
                            s.read_exact(&mut v).await.unwrap();
                            let mut un = vec![0u8; v[1] as usize];
                            s.read_exact(&mut un).await.unwrap();
                            let mut pl = [0u8; 1];
                            s.read_exact(&mut pl).await.unwrap();
                            let mut pw = vec![0u8; pl[0] as usize];
                            s.read_exact(&mut pw).await.unwrap();
                            let ok = un == u.as_bytes() && pw == p.as_bytes();
                            s.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                            if !ok {
                                return;
                            }
                        } else {
                            s.write_all(&[5, 0]).await.unwrap();
                        }
                        let mut rq = [0u8; 4];
                        s.read_exact(&mut rq).await.unwrap();
                        let host = match rq[3] {
                            1 => {
                                let mut a = [0u8; 4];
                                s.read_exact(&mut a).await.unwrap();
                                format!("ipv4 {}", std::net::Ipv4Addr::from(a))
                            }
                            3 => {
                                let mut n = [0u8; 1];
                                s.read_exact(&mut n).await.unwrap();
                                let mut name = vec![0u8; n[0] as usize];
                                s.read_exact(&mut name).await.unwrap();
                                format!("name {}", String::from_utf8_lossy(&name))
                            }
                            _ => return,
                        };
                        let mut pb = [0u8; 2];
                        s.read_exact(&mut pb).await.unwrap();
                        let port = u16::from_be_bytes(pb);
                        lg.targets.lock().unwrap().push(format!("{host}:{port}"));
                        let h = host.split_once(' ').unwrap().1.to_string();
                        let Ok(mut up) = tokio::net::TcpStream::connect(resolve(&h, port)).await else {
                            s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok();
                            return;
                        };
                        s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.unwrap();
                        lg.tunnels.fetch_add(1, Ordering::SeqCst);
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                    }
                    _ => {
                        let mut s: Box<dyn TestIo> = match &acceptor {
                            Some(a) => match tokio_boring::accept(a, tcp).await {
                                Ok(t) => Box::new(t),
                                Err(_) => return,
                            },
                            None => Box::new(tcp),
                        };
                        let mut head = Vec::new();
                        let mut b = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            if s.read(&mut b).await.unwrap_or(0) == 0 {
                                return;
                            }
                            head.push(b[0]);
                        }
                        let head = String::from_utf8_lossy(&head).to_string();
                        let target_s = head.split_whitespace().nth(1).unwrap_or("").to_string();
                        lg.targets.lock().unwrap().push(target_s.clone());
                        if let TestProxyKind::HttpRefusing(code) = kind {
                            s.write_all(format!("HTTP/1.1 {code} Nope\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.ok();
                            return;
                        }
                        if let Some((u, p)) = auth {
                            use base64::Engine;
                            let want = format!("proxy-authorization: basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))).to_ascii_lowercase();
                            if !head.to_ascii_lowercase().contains(&want) {
                                s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"t\"\r\nContent-Length: 0\r\n\r\n").await.ok();
                                return;
                            }
                        }
                        let (h, p) = target_s.rsplit_once(':').unwrap();
                        let Ok(mut up) = tokio::net::TcpStream::connect(resolve(h.trim_start_matches('[').trim_end_matches(']'), p.parse().unwrap())).await else {
                            s.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await.ok();
                            return;
                        };
                        s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                        lg.tunnels.fetch_add(1, Ordering::SeqCst);
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                    }
                }
            });
        }
    });
    (addr, log, ca)
}

pub trait TestIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TestIo for T {}

pub fn proxied(mut c: Config, id: &str, url: String) -> Config {
    c.proxy.proxies.push(cfprobe::proxy::ProxySpec { id: id.into(), url, username: None, password: None, ca_file: None });
    c
}
