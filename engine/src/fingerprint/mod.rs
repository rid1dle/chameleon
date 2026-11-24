//! Fingerprints as a receiver saw them, and field-by-field comparison against lab baselines.
//!
//! A client cannot observe its own ClientHello or HTTP/2 frames on the wire, so every value here is
//! **measured by a receiver**: the lab TrackMe server or the zone Worker. Parsers take an allow-list
//! of fingerprint fields only; location, IP and ASN data in the receiver's record are never read.
//!
//! The module never names a browser. It reports which measured fields are equal to a baseline's.
//! Anything computed from measured values is listed under `derived`, with its basis.

mod trackme;
mod worker;

use std::path::Path;

use serde::Serialize;

use crate::core::{Error, Result};
use crate::networking::Exchange;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Receiver {
    /// TrackMe `/api/all` (the code behind tls.peet.ws), run locally in the lab.
    TrackMe,
    /// The `cflab-echo` Worker on the zone: Cloudflare's `request.cf` view.
    ZoneWorker,
}

/// What one receiver measured about one request. `None` means this receiver does not capture it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Fingerprint {
    pub tls: TlsPrint,
    pub http: HttpPrint,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TlsPrint {
    /// Negotiated version, e.g. `"TLSv1.3"`
    pub version: Option<String>,
    pub ja4: Option<String>,
    pub ja3_hash: Option<String>,
    pub peetprint_hash: Option<String>,
    /// Offered cipher suites in order; GREASE values shown as `"GREASE"`.
    pub ciphers: Option<Vec<String>>,
    /// Extensions in the order sent; GREASE values shown as `"GREASE"`.
    pub extensions: Option<Vec<String>>,
    pub groups: Option<Vec<String>>,
    pub sigalgs: Option<Vec<String>>,
    pub alpn: Option<Vec<String>>,
    pub client_hello_len: Option<u32>,
    /// Cloudflare's own hashes (base64 SHA-1). Chrome-like clients vary per connection (E1-4).
    pub ciphers_sha1: Option<String>,
    pub extensions_sha1: Option<String>,
    /// Hex. Ties this record to the client's own view of the same handshake.
    pub client_random: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HttpPrint {
    /// `"h2"` or `"http/1.1"`
    pub protocol: Option<String>,
    /// HTTP/2 SETTINGS in the order sent, e.g. `("INITIAL_WINDOW_SIZE", 6291456)`.
    pub h2_settings: Option<Vec<(String, u64)>>,
    pub h2_window_update: Option<u64>,
    pub akamai: Option<String>,
    /// Stream ID of the first HEADERS frame. Clients normally use 1.
    pub h2_first_stream: Option<u64>,
    /// First letters of the pseudo-headers in order, e.g. `"m,a,s,p"`.
    pub pseudo_order: Option<String>,
    /// Regular header names in the order received, lowercase.
    pub header_order: Option<Vec<String>>,
    pub user_agent: Option<String>,
}

/// A value computed from measured fields, with what it was computed from.
#[derive(Debug, Clone, Serialize)]
pub struct Derived {
    pub name: &'static str,
    pub value: bool,
    pub basis: &'static str,
}

/// A receiver's record of one request.
#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub receiver: Receiver,
    pub fingerprint: Fingerprint,
    pub derived: Vec<Derived>,
}

/// Parse a receiver's response body, detecting which receiver wrote it.
pub fn parse_receiver_body(body: &[u8]) -> Result<Observation> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| Error::Receiver(format!("body is not JSON: {e}")))?;
    let (receiver, fingerprint) = if v.get("cf").is_some() {
        (Receiver::ZoneWorker, worker::parse(&v)?)
    } else if v.get("tls").is_some() && v.get("http_version").is_some() {
        (Receiver::TrackMe, trackme::parse(&v)?)
    } else {
        return Err(Error::Receiver("body is neither a TrackMe nor a zone Worker record".into()));
    };
    let derived = derive(&fingerprint);
    Ok(Observation { receiver, fingerprint, derived })
}

/// The receiver's record of an exchange, checked against the client's own view of the handshake.
#[derive(Debug, Clone, Serialize)]
pub struct ExchangeObservation {
    #[serde(flatten)]
    pub observation: Observation,
    /// `Some(true)` when the receiver's ClientHello random equals the client's: same handshake.
    /// `None` when either side has no random to compare.
    pub same_handshake_as_client: Option<bool>,
}

pub fn observe_exchange(exchange: &Exchange) -> Result<ExchangeObservation> {
    let observation = parse_receiver_body(&exchange.response.body)?;
    let client = exchange.tls.as_ref().map(|t| t.client_random.as_str());
    let receiver = observation.fingerprint.tls.client_random.as_deref();
    let same_handshake_as_client = match (client, receiver) {
        (Some(c), Some(r)) => Some(c.eq_ignore_ascii_case(r)),
        _ => None,
    };
    Ok(ExchangeObservation { observation, same_handshake_as_client })
}

fn derive(fp: &Fingerprint) -> Vec<Derived> {
    let mut out = Vec::new();
    if let Some(c) = &fp.tls.ciphers {
        out.push(Derived {
            name: "grease_in_ciphers",
            value: c.iter().any(|x| x == GREASE),
            basis: "a GREASE value appears in the measured cipher list",
        });
    }
    if let Some(e) = &fp.tls.extensions {
        out.push(Derived {
            name: "grease_in_extensions",
            value: e.iter().any(|x| x == GREASE),
            basis: "a GREASE value appears in the measured extension list",
        });
    }
    out
}

// ---------- comparison ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldStatus {
    Same,
    Differs,
    /// Only one side captured this field; not evidence either way.
    OnlyLeft,
    OnlyRight,
    NeitherCaptured,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldDiff {
    pub field: &'static str,
    pub status: FieldStatus,
    pub left: Option<String>,
    pub right: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub left: String,
    pub right: String,
    pub same: usize,
    pub differs: usize,
    /// Fields only one side captured, or neither did.
    pub not_comparable: usize,
    pub fields: Vec<FieldDiff>,
}

type Extract = fn(&Fingerprint) -> Option<String>;

fn list(v: &Option<Vec<String>>) -> Option<String> {
    v.as_ref().map(|v| v.join(","))
}

/// Compared fields. Extensions are compared as a sorted multiset: Chrome permutes their order per
/// connection, so order is not stable even for one client (the ordered list stays in the data).
const FIELDS: &[(&str, Extract)] = &[
    ("tls.version", |f| f.tls.version.clone()),
    ("tls.ja4", |f| f.tls.ja4.clone()),
    ("tls.ja3_hash", |f| f.tls.ja3_hash.clone()),
    ("tls.peetprint_hash", |f| f.tls.peetprint_hash.clone()),
    ("tls.ciphers", |f| list(&f.tls.ciphers)),
    ("tls.extensions_sorted", |f| {
        f.tls.extensions.as_ref().map(|e| {
            let mut e = e.clone();
            e.sort();
            e.join(",")
        })
    }),
    ("tls.groups", |f| list(&f.tls.groups)),
    ("tls.sigalgs", |f| list(&f.tls.sigalgs)),
    ("tls.alpn", |f| list(&f.tls.alpn)),
    ("tls.client_hello_len", |f| f.tls.client_hello_len.map(|n| n.to_string())),
    ("tls.ciphers_sha1", |f| f.tls.ciphers_sha1.clone()),
    ("tls.extensions_sha1", |f| f.tls.extensions_sha1.clone()),
    ("http.protocol", |f| f.http.protocol.clone()),
    ("http.h2_settings", |f| {
        f.http.h2_settings.as_ref().map(|s| s.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(","))
    }),
    ("http.h2_window_update", |f| f.http.h2_window_update.map(|n| n.to_string())),
    ("http.akamai", |f| f.http.akamai.clone()),
    ("http.h2_first_stream", |f| f.http.h2_first_stream.map(|n| n.to_string())),
    ("http.pseudo_order", |f| f.http.pseudo_order.clone()),
    ("http.header_order", |f| list(&f.http.header_order)),
    ("http.user_agent", |f| f.http.user_agent.clone()),
];

pub fn compare(left_name: &str, left: &Fingerprint, right_name: &str, right: &Fingerprint) -> Comparison {
    let fields: Vec<FieldDiff> = FIELDS
        .iter()
        .map(|(field, get)| {
            let (l, r) = (get(left), get(right));
            let status = match (&l, &r) {
                (Some(a), Some(b)) if a == b => FieldStatus::Same,
                (Some(_), Some(_)) => FieldStatus::Differs,
                (Some(_), None) => FieldStatus::OnlyLeft,
                (None, Some(_)) => FieldStatus::OnlyRight,
                (None, None) => FieldStatus::NeitherCaptured,
            };
            FieldDiff { field, status, left: l, right: r }
        })
        .collect();
    let count = |s: FieldStatus| fields.iter().filter(|f| f.status == s).count();
    Comparison {
        left: left_name.to_string(),
        right: right_name.to_string(),
        same: count(FieldStatus::Same),
        differs: count(FieldStatus::Differs),
        not_comparable: fields.len() - count(FieldStatus::Same) - count(FieldStatus::Differs),
        fields,
    }
}

// ---------- baselines ----------

/// A receiver record saved from an authorized lab run, e.g. `experiments/test-results/L1/*.json`.
#[derive(Debug, Clone, Serialize)]
pub struct Baseline {
    /// File stem, e.g. `"chromium-headful"`
    pub name: String,
    pub observation: Observation,
}

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub file: String,
    pub reason: String,
}

/// Read every `*.json` receiver record in `dir`, live from disk. Files that are not receiver
/// records are listed in the second value, not silently dropped.
pub fn load_baselines(dir: &Path) -> Result<(Vec<Baseline>, Vec<Skipped>)> {
    let entries = std::fs::read_dir(dir).map_err(|e| Error::Receiver(format!("{}: {e}", dir.display())))?;
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    let (mut found, mut skipped) = (Vec::new(), Vec::new());
    for p in paths {
        let name = p.file_stem().unwrap_or_default().to_string_lossy().into_owned();
        let parsed = std::fs::read(&p).map_err(|e| Error::Receiver(e.to_string())).and_then(|b| parse_receiver_body(&b));
        match parsed {
            Ok(observation) => found.push(Baseline { name, observation }),
            Err(e) => skipped.push(Skipped { file: p.display().to_string(), reason: e.to_string() }),
        }
    }
    Ok((found, skipped))
}

// ---------- shared parsing helpers ----------

pub(crate) const GREASE: &str = "GREASE";

/// RFC 8701 GREASE values: both bytes equal and of the form 0x?A.
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// TrackMe writes GREASE as `"TLS_GREASE (0x1a1a)"` in most lists but as a bare `"0x7a7a"` in
/// signature algorithms. Both become `"GREASE"`; everything else is kept as written.
pub(crate) fn normalize_grease(s: &str) -> String {
    if s.contains("GREASE") {
        return GREASE.into();
    }
    let hex = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if s.trim().starts_with("0x") && hex.len() <= 4 {
        if let Ok(v) = u16::from_str_radix(hex, 16) {
            if is_grease(v) {
                return GREASE.into();
            }
        }
    }
    s.to_string()
}

pub(crate) fn pseudo_letters(names: &[String]) -> Option<String> {
    let letters: Vec<String> = names
        .iter()
        .filter_map(|n| n.strip_prefix(':'))
        .filter_map(|n| n.chars().next())
        .map(String::from)
        .collect();
    (!letters.is_empty()).then(|| letters.join(","))
}

pub(crate) fn regular_names(names: &[String]) -> Vec<String> {
    names.iter().filter(|n| !n.starts_with(':')).map(|n| n.to_ascii_lowercase()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_is_recognised_in_both_spellings() {
        assert_eq!(normalize_grease("TLS_GREASE (0x0A0A)"), GREASE);
        assert_eq!(normalize_grease("0x7a7a"), GREASE);
        assert_eq!(normalize_grease("0x904"), "0x904");
        assert_eq!(normalize_grease("0x0a0b"), "0x0a0b");
        assert_eq!(normalize_grease("X25519 (29)"), "X25519 (29)");
    }
}
