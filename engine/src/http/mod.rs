//! HTTP: HTTP/2 SETTINGS this engine may change, and plain-data views of headers and cookies.
//!
//! Cookie and authorization values never enter a report: only their names and byte lengths.

use http::HeaderMap;
use serde::{Deserialize, Serialize};

/// HTTP/2 SETTINGS values. `None` leaves hyper's default.
///
/// SETTINGS order and pseudo-header order are fixed by the `h2` crate (pseudo-headers go out as
/// `:method, :scheme, :authority, :path`, h2 0.4.20 `src/frame/headers.rs:720-732`), so they are not
/// configurable here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct H2Settings {
    pub header_table_size: Option<u32>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_stream_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
}

/// HTTP/1.1 client settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct H1Settings {
    /// Send header names in Title-Case (`User-Agent`), as browsers do. Off: hyper sends lowercase.
    pub title_case_headers: bool,
    /// Most response headers accepted before the response is refused. `None`: hyper's 100.
    pub max_response_headers: Option<usize>,
}

/// A header as it appears in a report. Sensitive values are replaced by their length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

const REDACTED: [&str; 4] = ["cookie", "set-cookie", "authorization", "proxy-authorization"];

/// Headers that carry a URL, which may hold challenge tokens or credentials.
const URL_VALUED: [&str; 3] = ["location", "content-location", "referer"];

pub fn redact(name: &str, value: &[u8]) -> String {
    let name = name.to_ascii_lowercase();
    if REDACTED.contains(&name.as_str()) {
        format!("<redacted {} bytes>", value.len())
    } else if URL_VALUED.contains(&name.as_str()) {
        redact_url(&String::from_utf8_lossy(value))
    } else {
        String::from_utf8_lossy(value).into_owned()
    }
}

/// Headers in the order the map yields them, redacted.
pub fn header_list(map: &HeaderMap) -> Vec<HeaderEntry> {
    map.iter()
        .map(|(k, v)| HeaderEntry { name: k.as_str().to_string(), value: redact(k.as_str(), v.as_bytes()) })
        .collect()
}

/// One `Set-Cookie` header, value withheld.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetCookie {
    pub name: String,
    pub value_len: usize,
    /// Attributes in the order sent, names lowercased, e.g. `("path", Some("/"))`, `("httponly", None)`.
    pub attributes: Vec<(String, Option<String>)>,
}

pub fn parse_set_cookie(raw: &str) -> SetCookie {
    let mut parts = raw.split(';');
    let first = parts.next().unwrap_or("");
    let (name, value) = first.split_once('=').unwrap_or((first, ""));
    let attributes = parts
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), Some(v.trim().to_string())),
            None => (p.to_ascii_lowercase(), None),
        })
        .collect();
    SetCookie { name: name.trim().to_string(), value_len: value.trim().len(), attributes }
}

/// A URL (absolute or relative) as it appears in a report: credentials and Cloudflare challenge
/// tokens (`__cf_chl_*` query values) replaced by their length.
pub fn redact_url(url: &str) -> String {
    let (base, query) = url.split_once('?').map_or((url, None), |(b, q)| (b, Some(q)));
    let mut out = match base.split_once("://") {
        Some((scheme, rest)) => {
            let authority_end = rest.find('/').unwrap_or(rest.len());
            match rest[..authority_end].rfind('@') {
                Some(at) if is_placeholder(&rest[..at]) => base.to_string(),
                Some(at) => format!("{scheme}://<redacted {} bytes>@{}", at, &rest[at + 1..]),
                None => base.to_string(),
            }
        }
        None => base.to_string(),
    };
    if let Some(q) = query {
        let (q, frag) = q.split_once('#').map_or((q, None), |(q, f)| (q, Some(f)));
        let parts: Vec<String> = q
            .split('&')
            .map(|p| match p.split_once('=') {
                Some((k, v)) if k.starts_with("__cf_chl") && !is_placeholder(v) => format!("{k}=<redacted {} bytes>", v.len()),
                _ => p.to_string(),
            })
            .collect();
        out.push('?');
        out.push_str(&parts.join("&"));
        if let Some(f) = frag {
            out.push('#');
            out.push_str(f);
        }
    }
    out
}

/// `<redacted N bytes>`: already redacted, so redacting again must not count the placeholder.
fn is_placeholder(v: &str) -> bool {
    v.strip_prefix("<redacted ").and_then(|r| r.strip_suffix(" bytes>")).is_some_and(|n| n.parse::<usize>().is_ok())
}

/// Why a body could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// An encoding this engine does not decode; the body is kept as received.
    Unsupported(String),
    /// The decoded body would exceed this many bytes.
    TooLarge(usize),
    /// The bytes are not valid for the stated encoding.
    Corrupt(String),
}

/// Undo `Content-Encoding` (applied in the order listed, so undone in reverse). Supports gzip,
/// deflate (zlib, and raw deflate as sent by some servers), br and zstd. The decoded size is capped at
/// `limit`, so a small compressed body cannot expand without bound.
pub fn decode_body(content_encoding: &str, raw: &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
    use std::io::Read;
    let mut data = raw.to_vec();
    for enc in content_encoding.split(',').map(|e| e.trim().to_ascii_lowercase()).rev() {
        let capped = |r: &mut dyn Read| -> Result<Vec<u8>, DecodeError> {
            let mut out = Vec::new();
            r.take(limit as u64 + 1).read_to_end(&mut out).map_err(|e| DecodeError::Corrupt(format!("{enc}: {e}")))?;
            if out.len() > limit {
                return Err(DecodeError::TooLarge(limit));
            }
            Ok(out)
        };
        data = match enc.as_str() {
            "" | "identity" => continue,
            "gzip" | "x-gzip" => capped(&mut flate2::read::MultiGzDecoder::new(&data[..]))?,
            "deflate" => capped(&mut flate2::read::ZlibDecoder::new(&data[..]))
                .or_else(|_| capped(&mut flate2::read::DeflateDecoder::new(&data[..])))?,
            "br" => capped(&mut brotli::Decompressor::new(&data[..], 8192))?,
            "zstd" => {
                let mut d = zstd::stream::read::Decoder::new(&data[..]).map_err(|e| DecodeError::Corrupt(format!("zstd: {e}")))?;
                capped(&mut d)?
            }
            other => return Err(DecodeError::Unsupported(other.to_string())),
        };
    }
    Ok(data)
}

pub fn set_cookies(map: &HeaderMap) -> Vec<SetCookie> {
    map.get_all(http::header::SET_COOKIE)
        .iter()
        .map(|v| parse_set_cookie(&String::from_utf8_lossy(v.as_bytes())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_keeps_attributes_and_drops_value() {
        let c = parse_set_cookie("cf_clearance=abc.def-123; Path=/; Expires=Wed, 25 Nov 2026 12:00:00 GMT; Domain=.riddlelab.dev; HttpOnly; Secure; SameSite=None; Partitioned");
        assert_eq!(c.name, "cf_clearance");
        assert_eq!(c.value_len, 11);
        let names: Vec<_> = c.attributes.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["path", "expires", "domain", "httponly", "secure", "samesite", "partitioned"]);
        assert_eq!(c.attributes[1].1.as_deref(), Some("Wed, 25 Nov 2026 12:00:00 GMT"));
    }

    #[test]
    fn urls_lose_credentials_and_challenge_tokens() {
        assert_eq!(redact_url("https://user:hunter2@h.test/a?x=1"), "https://<redacted 12 bytes>@h.test/a?x=1");
        assert_eq!(redact_url("/next?__cf_chl_rt_tk=SECRET&a=b#f"), "/next?__cf_chl_rt_tk=<redacted 6 bytes>&a=b#f");
        assert_eq!(redact_url("https://h.test/p@x"), "https://h.test/p@x");
        // Found by tests/properties.rs: a second pass must keep the first pass's byte counts.
        let once = redact_url("https://u:p@h.test/?__cf_chl_tk=abcdefgh");
        assert_eq!(redact_url(&once), once);
        assert_eq!(once, "https://<redacted 3 bytes>@h.test/?__cf_chl_tk=<redacted 8 bytes>");
    }

    #[test]
    fn every_supported_encoding_round_trips_and_stacks() {
        use std::io::Write;
        let plain = b"{\"x\":1}".repeat(50);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&plain).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(decode_body("gzip", &gz, 1 << 20).unwrap(), plain);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&plain).unwrap();
        assert_eq!(decode_body("deflate", &z.finish().unwrap(), 1 << 20).unwrap(), plain);
        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(&plain).unwrap();
        assert_eq!(decode_body("deflate", &raw.finish().unwrap(), 1 << 20).unwrap(), plain, "raw deflate");
        let mut br = Vec::new();
        brotli::BrotliCompress(&mut &plain[..], &mut br, &Default::default()).unwrap();
        assert_eq!(decode_body("br", &br, 1 << 20).unwrap(), plain);
        let zs = zstd::encode_all(&plain[..], 3).unwrap();
        assert_eq!(decode_body("zstd", &zs, 1 << 20).unwrap(), plain);
        // gzip applied first, then br: undone in reverse
        let mut both = Vec::new();
        brotli::BrotliCompress(&mut &gz[..], &mut both, &Default::default()).unwrap();
        assert_eq!(decode_body("gzip, br", &both, 1 << 20).unwrap(), plain);
    }

    #[test]
    fn decoding_is_capped_and_unknown_encodings_are_named() {
        let bomb = zstd::encode_all(&vec![0u8; 10 << 20][..], 19).unwrap();
        assert!(bomb.len() < 4096, "{}", bomb.len());
        assert_eq!(decode_body("zstd", &bomb, 1 << 20), Err(DecodeError::TooLarge(1 << 20)));
        assert_eq!(decode_body("compress", b"x", 10), Err(DecodeError::Unsupported("compress".into())));
        assert!(matches!(decode_body("gzip", b"not gzip", 10), Err(DecodeError::Corrupt(_))));
    }

    #[test]
    fn sensitive_headers_are_redacted() {
        assert_eq!(redact("Set-Cookie", b"a=b"), "<redacted 3 bytes>");
        assert_eq!(redact("cf-ray", b"a5f8-AMS"), "a5f8-AMS");
    }
}
