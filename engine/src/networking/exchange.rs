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
    /// Headers asked for but not sent: HTTP/2 forbids connection-specific headers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_sent: Vec<String>,
}

/// Where the connected address came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressSource {
    /// The destination name went to the proxy, which resolved it: no local DNS.
    Proxy,
    /// `resolve` in the config (`--resolve`): no DNS lookup.
    ResolveOverride,
    /// The URL host is an IP address.
    IpLiteral,
    Dns,
}

/// A 1xx response received before the final one (HTTP/1.1 only; hyper does not surface them on HTTP/2).
#[derive(Debug, Clone, Serialize)]
pub struct Informational {
    pub status: u16,
    pub headers: Vec<HeaderEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionRecord {
    /// Engine-local connection number, to group requests that shared a connection.
    pub id: u64,
    pub protocol: Protocol,
    pub remote_addr: SocketAddr,
    pub address_source: AddressSource,
    /// How this connection left: through which proxy, or direct because none was configured.
    pub route: crate::proxy::RouteRecord,
    /// Addresses tried before `remote_addr` that failed, with why.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped_addresses: Vec<String>,
    pub reused: bool,
    /// 1 for the request that opened the connection.
    pub request_number: u32,
    /// Set when a reused connection failed before any response and the request was sent again on a
    /// new one: what went wrong on the old connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retried_after: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseRecord {
    pub status: u16,
    pub http_version: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub informational: Vec<Informational>,
    /// Grouped by name in first-seen order (hyper's `HeaderMap`), not wire order: `a, b, a` on the
    /// wire is listed `a, a, b`.
    pub headers: Vec<HeaderEntry>,
    pub set_cookies: Vec<SetCookie>,
    /// Bytes received on the wire (still encoded when `content-encoding` was set).
    pub body_len: usize,
    pub body_decoding: BodyDecoding,
    /// The decoded body when decoding succeeded, else the bytes as received. Kept for analysis,
    /// never serialized: bodies can carry tokens.
    #[serde(skip)]
    pub body: Bytes,
    /// `Set-Cookie` values as received, for a cookie jar. Never serialized: they carry secrets.
    #[serde(skip)]
    pub raw_set_cookies: Vec<String>,
    /// `Location` as received, for following redirects. Never serialized (may carry tokens); the
    /// redacted copy is in `headers`.
    #[serde(skip)]
    pub raw_location: Option<String>,
}

/// What was done with `content-encoding`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum BodyDecoding {
    /// No `content-encoding`: `body` is the body as sent.
    Identity,
    Decoded { encoding: String, decoded_len: usize },
    /// `body` holds the bytes as received; analysis must not read it as text.
    NotDecoded { encoding: String, reason: String },
}

impl ResponseRecord {
    /// The body as text-searchable bytes, or `None` when it is still encoded.
    pub fn inspectable_body(&self) -> Option<&[u8]> {
        match self.body_decoding {
            BodyDecoding::NotDecoded { .. } => None,
            _ => Some(&self.body),
        }
    }
}

/// Milliseconds. Connection steps are `None` on a reused connection: they did not happen,
/// which is different from taking 0 ms.
#[derive(Debug, Clone, Serialize)]
pub struct Timings {
    /// Also `None` when no lookup ran: the address was given (`--resolve`) or the host is an IP.
    pub dns_ms: Option<f64>,
    /// TCP connect to the destination, or to the proxy when routed through one.
    pub connect_ms: Option<f64>,
    /// TLS to the proxy (https proxies) and CONNECT or SOCKS5 negotiation; `None` when direct.
    pub proxy_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    /// From the start of `inspect` to the response head.
    pub ttfb_ms: f64,
    pub total_ms: f64,
}
