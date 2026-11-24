use std::net::SocketAddr;

use serde::Serialize;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The step of an exchange an error or timeout happened in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Dns,
    Connect,
    Tls,
    /// Sending the request and waiting for the response head.
    Response,
    /// Reading the response body.
    Body,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Stage::Dns => "dns",
            Stage::Connect => "connect",
            Stage::Tls => "tls",
            Stage::Response => "response",
            Stage::Body => "body",
        };
        f.write_str(s)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid config: {0}")]
    Config(String),

    #[error("invalid target: {0}")]
    Target(String),

    #[error("dns lookup for {host} failed: {source}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },

    #[error("tcp connect to {addr} failed: {source}")]
    Connect {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("tls setup failed: {0}")]
    TlsSetup(#[from] boring::error::ErrorStack),

    /// Handshake failure, with BoringSSL's reason and the certificate verify result when there is one.
    #[error("tls handshake failed: {0}")]
    TlsHandshake(String),

    #[error("http protocol error: {0}")]
    Http(#[from] hyper::Error),

    #[error("could not build request: {0}")]
    Request(#[from] http::Error),

    #[error("response body exceeded {limit} bytes")]
    BodyTooLarge { limit: usize },

    #[error("reading response body failed: {0}")]
    Body(String),

    /// A receiver record (TrackMe, zone Worker) could not be read or parsed.
    #[error("receiver record: {0}")]
    Receiver(String),

    #[error("timed out in {stage} after {after_ms} ms")]
    Timeout { stage: Stage, after_ms: u64 },

    /// The configured proxy failed at `stage`. Never followed by a direct attempt.
    #[error("proxy {proxy:?}: {stage} failed: {detail}")]
    Proxy { proxy: String, stage: crate::proxy::ProxyStage, detail: String },
}
