//! A loopback mock server that answers each randomized scenario, faults included.
//!
//! Three listeners on 127.0.0.1: plain HTTP/1.1, TLS with ALPN `http/1.1`, TLS with ALPN `h2`. The
//! HTTP/1.1 listeners write raw bytes, so framing faults (close before the head, close mid-body,
//! slow drip) are exact. HTTP/2 goes through hyper's server. Paths are `/s/<index>/<hop>`.

use std::convert::Infallible;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::PKey;
use boring::ssl::{AlpnError, SslAcceptor, SslMethod, select_next_proto};
use boring::x509::extension::SubjectAlternativeName;
use boring::x509::{X509, X509NameBuilder};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use super::scenario::{Encoding, Fault, Scenario};

pub struct MockServer {
    pub plain: SocketAddr,
    pub tls_h1: SocketAddr,
    pub tls_h2: SocketAddr,
    /// PEM of the self-signed certificate (CN and SAN `localhost`), for clients that should trust it.
    pub ca_file: tempfile_path::TempPem,
}

/// A PEM file removed on drop, without pulling `tempfile` into the library.
pub mod tempfile_path {
    use std::path::{Path, PathBuf};

    pub struct TempPem(PathBuf);

    impl TempPem {
        pub fn write(pem: &[u8]) -> std::io::Result<Self> {
            let p = std::env::temp_dir().join(format!("cfprobe-mock-{}-{}.pem", std::process::id(), rand::random::<u64>()));
            std::fs::write(&p, pem)?;
            Ok(Self(p))
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempPem {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

/// How long the `Timeout` fault holds the head back.
pub const TIMEOUT_FAULT_MS: u64 = 2_500;

impl MockServer {
    pub async fn start(scenarios: Arc<Vec<Scenario>>) -> std::io::Result<MockServer> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(io)?;
        let key = PKey::from_ec_key(EcKey::generate(&group).map_err(io)?).map_err(io)?;
        let mut name = X509NameBuilder::new().map_err(io)?;
        name.append_entry_by_text("CN", "localhost").map_err(io)?;
        let name = name.build();
        let mut b = X509::builder().map_err(io)?;
        b.set_version(2).map_err(io)?;
        let serial = BigNum::from_u32(1).map_err(io)?.to_asn1_integer().map_err(io)?;
        b.set_serial_number(&serial).map_err(io)?;
        b.set_subject_name(&name).map_err(io)?;
        b.set_issuer_name(&name).map_err(io)?;
        b.set_pubkey(&key).map_err(io)?;
        let (from, until) = (Asn1Time::days_from_now(0).map_err(io)?, Asn1Time::days_from_now(1).map_err(io)?);
        b.set_not_before(&from).map_err(io)?;
        b.set_not_after(&until).map_err(io)?;
        let san = SubjectAlternativeName::new().dns("localhost").build(&b.x509v3_context(None, None)).map_err(io)?;
        b.append_extension(&san).map_err(io)?;
        b.sign(&key, MessageDigest::sha256()).map_err(io)?;
        let cert = b.build();
        let ca_file = tempfile_path::TempPem::write(&cert.to_pem().map_err(io)?)?;

        let acceptor = |alpn: &'static [u8]| -> std::io::Result<Arc<SslAcceptor>> {
            let mut a = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(io)?;
            a.set_private_key(&key).map_err(io)?;
            a.set_certificate(&cert).map_err(io)?;
            a.set_alpn_select_callback(move |_, client| select_next_proto(alpn, client).ok_or(AlpnError::NOACK));
            Ok(Arc::new(a.build()))
        };

        let plain = TcpListener::bind("127.0.0.1:0").await?;
        let tls_h1 = TcpListener::bind("127.0.0.1:0").await?;
        let tls_h2 = TcpListener::bind("127.0.0.1:0").await?;
        let addrs = (plain.local_addr()?, tls_h1.local_addr()?, tls_h2.local_addr()?);

        let s = scenarios.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = plain.accept().await {
                // Without it, Nagle plus the client's delayed ACK adds 40 ms to every response.
                tcp.set_nodelay(true).ok();
                tokio::spawn(serve_h1(tcp, s.clone()));
            }
        });
        let (s, acc) = (scenarios.clone(), acceptor(b"\x08http/1.1")?);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = tls_h1.accept().await {
                tcp.set_nodelay(true).ok();
                let (s, acc) = (s.clone(), acc.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = tokio_boring::accept(&acc, tcp).await {
                        serve_h1(tls, s).await;
                    }
                });
            }
        });
        let (s, acc) = (scenarios, acceptor(b"\x02h2")?);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = tls_h2.accept().await {
                tcp.set_nodelay(true).ok();
                let (s, acc) = (s.clone(), acc.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = tokio_boring::accept(&acc, tcp).await {
                        let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let s = s.clone();
                            async move { Ok::<_, Infallible>(h2_response(&s, req.uri().path()).await) }
                        });
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), svc).await;
                    }
                });
            }
        });
        Ok(MockServer { plain: addrs.0, tls_h1: addrs.1, tls_h2: addrs.2, ca_file })
    }
}

fn io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// `/s/<index>/<hop>` -> the scenario and hop.
fn route<'a>(scenarios: &'a [Scenario], path: &str) -> Option<(&'a Scenario, u8)> {
    let mut it = path.trim_start_matches('/').split('/');
    if it.next()? != "s" {
        return None;
    }
    let i: u64 = it.next()?.parse().ok()?;
    let hop: u8 = it.next().and_then(|h| h.parse().ok()).unwrap_or(0);
    scenarios.iter().find(|s| s.index == i).map(|s| (s, hop))
}

/// Status, headers and the (possibly encoded) body for one hop.
pub fn response_parts(s: &Scenario, hop: u8) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut headers: Vec<(String, String)> = Vec::new();
    if s.cloudflare {
        headers.push(("server".into(), "cloudflare".into()));
        headers.push(("cf-ray".into(), format!("{:016x}-LAB", s.index)));
    }
    if hop < s.redirects {
        let next = if s.redirect_loop && hop + 1 == s.redirects { 0 } else { hop + 1 };
        headers.push(("location".into(), format!("/s/{}/{next}", s.index)));
        return (302, headers, Vec::new());
    }
    headers.push(("content-type".into(), s.content_type().into()));
    if matches!(s.body, super::scenario::Body::Challenge { .. }) {
        headers.push(("cf-mitigated".into(), "challenge".into()));
    }
    if (300..400).contains(&s.status) {
        headers.push(("location".into(), "/landing".into()));
    }
    if let Some(ra) = &s.retry_after {
        headers.push(("retry-after".into(), ra.clone()));
    }
    for c in &s.set_cookies {
        headers.push(("set-cookie".into(), c.clone()));
    }
    headers.extend(s.extra_headers.iter().cloned());
    let plain = s.plain_body();
    let body = match s.encoding {
        None => plain,
        Some(e) => {
            let (name, bytes) = encode(e, &plain);
            headers.push(("content-encoding".into(), name.into()));
            bytes
        }
    };
    (s.status, headers, body)
}

fn encode(e: Encoding, plain: &[u8]) -> (&'static str, Vec<u8>) {
    use flate2::Compression;
    match e {
        Encoding::Gzip => {
            let mut w = flate2::write::GzEncoder::new(Vec::new(), Compression::fast());
            w.write_all(plain).unwrap();
            ("gzip", w.finish().unwrap())
        }
        Encoding::Deflate => {
            let mut w = flate2::write::ZlibEncoder::new(Vec::new(), Compression::fast());
            w.write_all(plain).unwrap();
            ("deflate", w.finish().unwrap())
        }
        Encoding::Br => {
            // Quality 11 (the default) takes seconds on large bodies; 4 keeps the mock fast.
            let params = brotli::enc::BrotliEncoderParams { quality: 4, ..Default::default() };
            let mut out = Vec::new();
            brotli::BrotliCompress(&mut &plain[..], &mut out, &params).unwrap();
            ("br", out)
        }
        Encoding::Zstd => ("zstd", zstd::encode_all(plain, 1).unwrap()),
        Encoding::CorruptGzip => ("gzip", plain.to_vec()),
        Encoding::Unknown => ("x-lab-pack", plain.to_vec()),
    }
}

async fn serve_h1<IO: AsyncRead + AsyncWrite + Unpin>(mut io: IO, scenarios: Arc<Vec<Scenario>>) {
    loop {
        // Read one request head (GET/HEAD/POST without bodies in the fuzz runs).
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match io.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            if buf.len() > 64 * 1024 {
                return;
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
        let Some((s, hop)) = route(&scenarios, &path) else {
            let _ = io.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
            continue;
        };
        let final_hop = hop >= s.redirects;
        match s.fault {
            Fault::CloseBeforeHead if final_hop => return,
            Fault::Latency { ms } if final_hop => tokio::time::sleep(Duration::from_millis(ms)).await,
            Fault::Timeout if final_hop => tokio::time::sleep(Duration::from_millis(TIMEOUT_FAULT_MS)).await,
            _ => {}
        }
        let (status, headers, body) = {
            let s = s.clone();
            // Building and compressing a body is CPU work: keep it off the async workers, which the
            // client under test shares.
            match tokio::task::spawn_blocking(move || response_parts(&s, hop)).await {
                Ok(p) => p,
                Err(_) => return,
            }
        };
        let mut out = format!("HTTP/1.1 {status} Lab\r\n");
        for (k, v) in &headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        let cut = final_hop && s.fault == Fault::CloseMidBody;
        let chunked = s.chunked && final_hop && !cut;
        if chunked {
            out.push_str("transfer-encoding: chunked\r\n\r\n");
        } else {
            // A cut body promises more than it sends, so the cut is detectable even when short.
            let declared = if cut { body.len() + 10 } else { body.len() };
            out.push_str(&format!("content-length: {declared}\r\n\r\n"));
        }
        let plain_write = !cut && !chunked && !matches!(s.fault, Fault::SlowDrip { .. } if final_hop);
        if plain_write {
            // Head and body in one write: one segment for small responses.
            let mut all = out.into_bytes();
            all.extend_from_slice(&body);
            if io.write_all(&all).await.is_err() {
                return;
            }
            let _ = io.flush().await;
            continue;
        }
        if io.write_all(out.as_bytes()).await.is_err() {
            return;
        }
        if cut {
            let _ = io.write_all(&body[..body.len() / 2]).await;
            let _ = io.flush().await;
            return;
        }
        let (piece, pause) = match s.fault {
            Fault::SlowDrip { chunk, pause_ms } if final_hop => (chunk.max(1), pause_ms),
            _ => (body.len().max(1), 0),
        };
        for part in body.chunks(piece) {
            let wrote = if chunked {
                let mut c = format!("{:x}\r\n", part.len()).into_bytes();
                c.extend_from_slice(part);
                c.extend_from_slice(b"\r\n");
                io.write_all(&c).await
            } else {
                io.write_all(part).await
            };
            if wrote.is_err() {
                return;
            }
            if pause > 0 {
                let _ = io.flush().await;
                tokio::time::sleep(Duration::from_millis(pause)).await;
            }
        }
        if chunked && io.write_all(b"0\r\n\r\n").await.is_err() {
            return;
        }
        let _ = io.flush().await;
    }
}

type H2Body = http_body_util::combinators::BoxBody<Bytes, Infallible>;

async fn h2_response(scenarios: &[Scenario], path: &str) -> hyper::Response<H2Body> {
    let Some((s, hop)) = route(scenarios, path) else {
        return hyper::Response::builder().status(404).body(Full::new(Bytes::new()).boxed()).unwrap();
    };
    let final_hop = hop >= s.redirects;
    match s.fault {
        Fault::Latency { ms } if final_hop => tokio::time::sleep(Duration::from_millis(ms)).await,
        Fault::Timeout if final_hop => tokio::time::sleep(Duration::from_millis(TIMEOUT_FAULT_MS)).await,
        _ => {}
    }
    let (status, headers, body) = {
        let s = s.clone();
        tokio::task::spawn_blocking(move || response_parts(&s, hop)).await.unwrap_or((500, Vec::new(), Vec::new()))
    };
    let mut b = hyper::Response::builder().status(status);
    for (k, v) in headers {
        b = b.header(k, v);
    }
    b.body(Full::new(Bytes::from(body)).boxed())
        .unwrap_or_else(|_| hyper::Response::builder().status(500).body(Full::new(Bytes::new()).boxed()).unwrap())
}
