//! TrackMe `/api/all` records (pagpeter/TrackMe @ 9d2e865). Reads `tls`, `http2`, `http_version`
//! and `user_agent` only; `ip` and `tcpip` are never read.

use serde_json::Value;

use super::{Fingerprint, HttpPrint, TlsPrint, normalize_grease, pseudo_letters, regular_names};
use crate::core::{Error, Result};

pub(super) fn parse(v: &Value) -> Result<Fingerprint> {
    let tls = v.get("tls").ok_or_else(|| Error::Receiver("TrackMe record has no tls".into()))?;
    let s = |o: &Value, k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);

    let extensions = tls.get("extensions").and_then(Value::as_array);
    let ext_field = |name_prefix: &str, key: &str| -> Option<Vec<String>> {
        extensions?
            .iter()
            .find(|e| e.get("name").and_then(Value::as_str).is_some_and(|n| n.starts_with(name_prefix)))?
            .get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(normalize_grease).collect())
    };

    let tls_print = TlsPrint {
        version: tls.get("tls_version_negotiated").and_then(Value::as_str).map(version_name),
        ja4: s(tls, "ja4"),
        ja3_hash: s(tls, "ja3_hash"),
        ja3: s(tls, "ja3"),
        peetprint_hash: s(tls, "peetprint_hash"),
        ciphers: tls
            .get("ciphers")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(normalize_grease).collect()),
        extensions: extensions.map(|a| {
            a.iter().filter_map(|e| e.get("name").and_then(Value::as_str)).map(normalize_grease).collect()
        }),
        groups: ext_field("supported_groups", "supported_groups"),
        sigalgs: ext_field("signature_algorithms", "signature_algorithms"),
        alpn: ext_field("application_layer_protocol_negotiation", "protocols"),
        client_hello_len: None,
        ciphers_sha1: None,
        extensions_sha1: None,
        client_random: s(tls, "client_random").map(|r| r.to_ascii_lowercase()),
    };

    let h2 = v.get("http2").filter(|h| !h.is_null());
    let frames: Vec<&Value> =
        h2.and_then(|h| h.get("sent_frames")).and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
    let frame = |ty: &str| frames.iter().copied().find(|f| f.get("frame_type").and_then(Value::as_str) == Some(ty));

    let h2_settings = frame("SETTINGS").and_then(|f| f.get("settings")).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .filter_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                Some((k.trim().to_string(), v.trim().parse().ok()?))
            })
            .collect()
    });
    let header_names: Option<Vec<String>> = frame("HEADERS")
        .and_then(|f| f.get("headers"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(header_name).collect());

    let http = HttpPrint {
        protocol: s(v, "http_version").map(|p| protocol_name(&p)),
        h2_settings,
        h2_window_update: frame("WINDOW_UPDATE").and_then(|f| f.get("increment")).and_then(Value::as_u64),
        akamai: h2.and_then(|h| s(h, "akamai_fingerprint")),
        h2_first_stream: frame("HEADERS").and_then(|f| f.get("stream_id")).and_then(Value::as_u64),
        pseudo_order: header_names.as_deref().and_then(pseudo_letters),
        header_order: header_names.as_deref().map(regular_names),
        user_agent: s(v, "user_agent"),
    };
    Ok(Fingerprint { tls: tls_print, http })
}

/// `":method: GET"` -> `":method"`, `"user-agent: x"` -> `"user-agent"`.
fn header_name(line: &str) -> String {
    match line.strip_prefix(':') {
        Some(rest) => format!(":{}", rest.split_once(':').map_or(rest, |(n, _)| n)),
        None => line.split_once(':').map_or(line, |(n, _)| n).to_string(),
    }
}

fn version_name(code: &str) -> String {
    match code {
        "772" => "TLSv1.3".into(),
        "771" => "TLSv1.2".into(),
        other => format!("unknown ({other})"),
    }
}

fn protocol_name(p: &str) -> String {
    match p {
        "h2" => "h2".into(),
        p if p.contains("1.1") => "http/1.1".into(),
        other => other.to_string(),
    }
}
