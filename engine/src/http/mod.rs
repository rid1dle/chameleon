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

/// A header as it appears in a report. Sensitive values are replaced by their length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

const REDACTED: [&str; 4] = ["cookie", "set-cookie", "authorization", "proxy-authorization"];

pub fn redact(name: &str, value: &[u8]) -> String {
    if REDACTED.contains(&name.to_ascii_lowercase().as_str()) {
        format!("<redacted {} bytes>", value.len())
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
    fn sensitive_headers_are_redacted() {
        assert_eq!(redact("Set-Cookie", b"a=b"), "<redacted 3 bytes>");
        assert_eq!(redact("cf-ray", b"a5f8-AMS"), "a5f8-AMS");
    }
}
