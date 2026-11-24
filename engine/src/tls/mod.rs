//! TLS: the ClientHello settings this engine may change, and what the client side of a handshake shows.
//!
//! Settings are explicit and one at a time, for controlled experiments. There are no browser profiles.
//! What the ClientHello looked like on the wire (JA4, extension order) is only visible to the receiver,
//! so it is measured at the lab echo server or zone Worker, not here.

use std::path::PathBuf;

use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::ssl::{NameType, SslConnector, SslConnectorBuilder, SslMethod, SslRef, SslVerifyMode, SslVersion};
use boring::x509::{X509NameRef, X509Ref};
use serde::{Deserialize, Serialize};

use crate::core::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "TLSv1.2")]
    Tls12,
    #[serde(rename = "TLSv1.3")]
    Tls13,
}

impl TlsVersion {
    fn to_boring(self) -> SslVersion {
        match self {
            TlsVersion::Tls12 => SslVersion::TLS1_2,
            TlsVersion::Tls13 => SslVersion::TLS1_3,
        }
    }
}

/// ClientHello and verification settings. `None` means "leave the library default".
///
/// The library default starts from `boring::ssl::SslConnector::builder`, which sets the cipher list to
/// `DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK` (boring 5.6.0
/// `src/ssl/connector.rs:72`). TLS 1.3 suites are not affected by `cipher_list` in BoringSSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsSettings {
    pub min_version: Option<TlsVersion>,
    pub max_version: Option<TlsVersion>,
    /// OpenSSL-style cipher string for TLS 1.2 and below.
    pub cipher_list: Option<String>,
    /// Supported groups, colon separated, e.g. `"X25519:P-256"`.
    pub curves: Option<String>,
    /// Signature algorithms, colon separated, e.g. `"ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256"`.
    pub sigalgs: Option<String>,
    pub grease: Option<bool>,
    pub permute_extensions: Option<bool>,
    /// Offered ALPN protocols in order. Only `"h2"` and `"http/1.1"` are supported.
    pub alpn: Vec<String>,
    pub ocsp_stapling: bool,
    pub signed_cert_timestamps: bool,
    /// Verify the server certificate and hostname. Off only for lab servers with throwaway certs.
    pub verify: bool,
    /// Extra trust anchor in PEM, e.g. a lab CA. System roots stay trusted.
    pub ca_file: Option<PathBuf>,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            min_version: None,
            max_version: None,
            cipher_list: None,
            curves: None,
            sigalgs: None,
            grease: None,
            permute_extensions: None,
            alpn: vec!["h2".into(), "http/1.1".into()],
            ocsp_stapling: false,
            signed_cert_timestamps: false,
            verify: true,
            ca_file: None,
        }
    }
}

impl TlsSettings {
    /// Build the connector once per engine; every connection is configured from it.
    pub(crate) fn build_connector(&self) -> Result<SslConnector> {
        let mut b: SslConnectorBuilder = SslConnector::builder(SslMethod::tls())?;
        if let Some(v) = self.min_version {
            b.set_min_proto_version(Some(v.to_boring()))?;
        }
        if let Some(v) = self.max_version {
            b.set_max_proto_version(Some(v.to_boring()))?;
        }
        if let Some(c) = &self.cipher_list {
            b.set_cipher_list(c)?;
        }
        if let Some(c) = &self.curves {
            b.set_curves_list(c)?;
        }
        if let Some(s) = &self.sigalgs {
            b.set_sigalgs_list(s)?;
        }
        if let Some(g) = self.grease {
            b.set_grease_enabled(g);
        }
        if let Some(p) = self.permute_extensions {
            b.set_permute_extensions(p);
        }
        b.set_alpn_protos(&alpn_wire(&self.alpn))?;
        if self.ocsp_stapling {
            b.enable_ocsp_stapling();
        }
        if self.signed_cert_timestamps {
            b.enable_signed_cert_timestamps();
        }
        if let Some(ca) = &self.ca_file {
            b.set_ca_file(ca)?;
        }
        if !self.verify {
            b.set_verify(SslVerifyMode::NONE);
        }
        Ok(b.build())
    }
}

/// ALPN list in TLS wire format: each name prefixed by its length.
fn alpn_wire(protocols: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in protocols {
        out.push(p.len() as u8);
        out.extend_from_slice(p.as_bytes());
    }
    out
}

/// What the client side of one handshake shows. All of it is read from BoringSSL after the handshake.
#[derive(Debug, Clone, Serialize)]
pub struct TlsObservation {
    /// e.g. `"TLSv1.3"`
    pub version: String,
    pub cipher: Option<CipherInfo>,
    /// Protocol the server picked from our ALPN offer; `None` if it picked none.
    pub alpn: Option<String>,
    pub session_reused: bool,
    pub sni: Option<String>,
    /// Hex of the ClientHello random. Correlates this handshake with a receiver's record of it.
    pub client_random: String,
    pub peer_chain: Vec<CertSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CipherInfo {
    /// IANA name, e.g. `"TLS_AES_128_GCM_SHA256"`
    pub iana: Option<String>,
    /// OpenSSL/BoringSSL name
    pub openssl: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256: String,
}

pub(crate) fn observe(ssl: &SslRef) -> TlsObservation {
    let mut random = [0u8; 32];
    let n = ssl.client_random(&mut random);
    TlsObservation {
        version: ssl.version_str().to_string(),
        cipher: ssl.current_cipher().map(|c| CipherInfo {
            iana: c.standard_name().map(str::to_string),
            openssl: c.name().to_string(),
        }),
        alpn: ssl.selected_alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
        session_reused: ssl.session_reused(),
        sni: ssl.servername(NameType::HOST_NAME).map(str::to_string),
        client_random: hex(&random[..n]),
        peer_chain: ssl
            .peer_cert_chain()
            .map(|chain| chain.iter().map(summarize).collect())
            .unwrap_or_default(),
    }
}

fn summarize(cert: &X509Ref) -> CertSummary {
    CertSummary {
        subject: name_string(cert.subject_name()),
        issuer: name_string(cert.issuer_name()),
        not_before: cert.not_before().to_string(),
        not_after: cert.not_after().to_string(),
        sha256: cert.digest(MessageDigest::sha256()).map(|d| hex(&d)).unwrap_or_default(),
    }
}

fn name_string(name: &X509NameRef) -> String {
    name.entries()
        .map(|e| {
            let key = e.object().nid().short_name().unwrap_or("?");
            let key = if e.object().nid() == Nid::UNDEF { "?" } else { key };
            let val = e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default();
            format!("{key}={val}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
