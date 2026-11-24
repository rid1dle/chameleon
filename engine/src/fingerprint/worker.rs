//! Zone Worker echo records (`lab/zone-worker/worker.js`). Reads only the TLS and HTTP fields of
//! `request.cf` and the user agent. Location, ASN and IP fields in `cf` are never read.

use base64::Engine;
use serde_json::Value;

use super::{Fingerprint, HttpPrint, TlsPrint, pseudo_letters, regular_names};
use crate::core::{Error, Result};

pub(super) fn parse(v: &Value) -> Result<Fingerprint> {
    let cf = v.get("cf").filter(|c| c.is_object()).ok_or_else(|| Error::Receiver("Worker record has no cf".into()))?;
    let s = |k: &str| cf.get(k).and_then(Value::as_str).map(str::to_string);

    let names: Option<Vec<String>> = cf
        .get("requestHeaderNames")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect());

    // Bot Management fields exist only on Enterprise zones; on Free `botManagement` is absent or null.
    let ja4 = cf.get("botManagement").and_then(|b| b.get("ja4")).and_then(Value::as_str).map(str::to_string);

    let tls = TlsPrint {
        version: s("tlsVersion"),
        ja4,
        client_hello_len: cf.get("tlsClientHelloLength").and_then(|l| match l {
            Value::String(s) => s.parse().ok(),
            Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
            _ => None,
        }),
        ciphers_sha1: s("tlsClientCiphersSha1"),
        extensions_sha1: s("tlsClientExtensionsSha1"),
        client_random: s("tlsClientRandom")
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
            .map(|raw| crate::tls::hex(&raw)),
        ..TlsPrint::default()
    };
    let http = HttpPrint {
        protocol: s("httpProtocol").map(|p| match p.as_str() {
            "HTTP/2" => "h2".into(),
            "HTTP/1.1" => "http/1.1".into(),
            "HTTP/3" => "h3".into(),
            _ => p,
        }),
        pseudo_order: names.as_deref().and_then(pseudo_letters),
        header_order: names.as_deref().map(regular_names),
        user_agent: v.get("userAgent").and_then(Value::as_str).map(str::to_string),
        ..HttpPrint::default()
    };
    Ok(Fingerprint { tls, http })
}
