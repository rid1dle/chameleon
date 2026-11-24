use std::net::SocketAddr;

use bytes::Bytes;
use serde::Serialize;

use crate::http::{H2Settings, HeaderEntry, SetCookie};
use crate::tls::{TlsObservation, TlsSettings};

/// One request and its response, as plain data. Everything in it is either configured
/// (`configured_*`) or measured by this engine's own stack (the rest).
#[derive(Debug, Clone, Serialize)]
pub struct Exchange {
    pub request: RequestRecord,
    pub connection: ConnectionRecord,
    /// TLS settings in force, `None` for plain HTTP. `None` fields inside mean "library default".
    pub configured_tls: Option<TlsSettings>,
    /// HTTP/2 settings in force, `None` when the connection is HTTP/1.1.
    pub configured_h2: Option<H2Settings>,
    /// Client-side view of the handshake that opened this connection. On a reused connection it is
    /// that earlier handshake, not a new one.
    pub tls: Option<TlsObservation>,
    pub response: ResponseRecord,
    pub timings: Timings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Protocol {
    #[serde(rename = "http/1.1")]
    Http1,
    #[serde(rename = "h2")]
    Http2,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestRecord {
    pub method: String,
    pub url: String,
    /// Regular headers in the order handed to hyper. Pseudo-headers are not listed: their order is
    /// fixed by h2 and is measured at the receiver.
    pub headers: Vec<HeaderEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionRecord {
    /// Engine-local connection number, to group requests that shared a connection.
    pub id: u64,
    pub protocol: Protocol,
    pub remote_addr: SocketAddr,
    pub reused: bool,
    /// 1 for the request that opened the connection.
    pub request_number: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseRecord {
    pub status: u16,
    pub http_version: String,
    pub headers: Vec<HeaderEntry>,
    pub set_cookies: Vec<SetCookie>,
    pub body_len: usize,
    /// Kept for analysis, never serialized: bodies can carry tokens.
    #[serde(skip)]
    pub body: Bytes,
}

/// Milliseconds. Connection steps are `None` on a reused connection: they did not happen,
/// which is different from taking 0 ms.
#[derive(Debug, Clone, Serialize)]
pub struct Timings {
    pub dns_ms: Option<f64>,
    pub connect_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    /// From the start of `inspect` to the response head.
    pub ttfb_ms: f64,
    pub total_ms: f64,
}
