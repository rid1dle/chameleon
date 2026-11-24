//! Markdown renderings of engine data. JSON output is plain `serde_json` on the data types.
//!
//! A value a receiver did not capture prints as `not captured`, never as a blank or 0.

use crate::cloudflare::{Analysis, Verdict};
use crate::fingerprint::{Baseline, Comparison, FieldStatus};
use crate::networking::{BodyDecoding, Exchange, Protocol};

pub const NOT_CAPTURED: &str = "not captured";

/// Inline code safe inside a GFM table cell: `|` must be escaped even inside backticks.
fn cell(v: Option<&str>) -> String {
    format!("`{}`", v.unwrap_or(NOT_CAPTURED).replace('|', "\\|"))
}

/// The L1 comparison table (replaces scripts/fingerprint-analysis/summarize_l1.py).
pub fn baseline_table(baselines: &[Baseline]) -> String {
    let mut out = String::from("| client | http | ja4 | akamai_h2 | first_stream |\n|---|---|---|---|---|\n");
    for b in baselines {
        let f = &b.observation.fingerprint;
        let stream = f.http.h2_first_stream.map(|n| n.to_string());
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            cell(Some(&b.name)),
            cell(f.http.protocol.as_deref()),
            cell(f.tls.ja4.as_deref()),
            cell(f.http.akamai.as_deref()),
            cell(stream.as_deref()),
        ));
    }
    out.push_str("\n## Header order (pseudo-headers excluded) and User-Agent\n\n");
    for b in baselines {
        let f = &b.observation.fingerprint;
        let order = f.http.header_order.as_ref().map(|h| h.join(","));
        out.push_str(&format!(
            "- **{}**: `{}`  \n  UA: `{}`\n",
            b.name,
            order.as_deref().unwrap_or(NOT_CAPTURED),
            f.http.user_agent.as_deref().unwrap_or(NOT_CAPTURED),
        ));
    }
    out
}

/// One comparison as a table: differing fields first, then fields that could not be compared.
pub fn comparison_table(c: &Comparison) -> String {
    let mut out = format!(
        "**{}** vs **{}**: {} same, {} differ, {} differ in extension order only, {} not comparable\n\n| field | status | {} | {} |\n|---|---|---|---|\n",
        c.left, c.right, c.same, c.differs, c.order_only, c.not_comparable, c.left, c.right
    );
    let rank = |s: FieldStatus| match s {
        FieldStatus::Differs => 0,
        FieldStatus::OrderOnly => 1,
        FieldStatus::OnlyLeft | FieldStatus::OnlyRight => 1,
        FieldStatus::Same => 2,
        FieldStatus::NeitherCaptured => 3,
    };
    let mut fields: Vec<_> = c.fields.iter().collect();
    fields.sort_by_key(|f| rank(f.status));
    for f in fields {
        let status = match f.status {
            FieldStatus::Same => "same",
            FieldStatus::Differs => "**differs**",
            FieldStatus::OrderOnly => "extension order only",
            FieldStatus::OnlyLeft => "only left captured",
            FieldStatus::OnlyRight => "only right captured",
            FieldStatus::NeitherCaptured => "neither captured",
        };
        out.push_str(&format!("| {} | {} | {} | {} |\n", f.field, status, cell(f.left.as_deref()), cell(f.right.as_deref())));
    }
    out
}

/// The serde name of an enum value (`NORMAL_PAGE`, `managed`, ...): one spelling in JSON and markdown.
fn name<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn verdict_text(a: &Analysis) -> String {
    let mut detail = Vec::new();
    if let Some(k) = a.challenge_kind {
        detail.push(name(&k));
    } else if a.verdict == Verdict::ConfirmedChallengeResponse {
        detail.push("type not stated".into());
    }
    if let Some(code) = a.error_code {
        detail.push(code.to_string());
    }
    let detail = if detail.is_empty() { String::new() } else { format!(" ({})", detail.join(", ")) };
    format!("**{}{detail}**, {} confidence, issued by {}", name(&a.verdict), name(&a.confidence), name(&a.issued_by))
}

/// Milliseconds, or why the step has no number. `why_not` is the reason when the step did not run.
fn ms(v: Option<f64>, reused: bool, why_not: &str) -> String {
    match (v, reused) {
        (Some(v), _) => format!("{v:.1} ms"),
        (None, true) => "not done (reused connection)".into(),
        (None, false) => format!("not done ({why_not})"),
    }
}

/// One exchange as a markdown section: Cloudflare verdict first, then request, connection, TLS, timings.
pub fn inspect_report(ex: &Exchange, a: &Analysis) -> String {
    let c = &ex.connection;
    let proto = match c.protocol {
        Protocol::Http1 => "http/1.1",
        Protocol::Http2 => "h2",
    };
    let opt = |v: Option<&str>| v.unwrap_or(NOT_CAPTURED).to_string();
    let mut rows: Vec<(&str, String)> = vec![
        ("Cloudflare", verdict_text(a)),
        ("Evidence", a.evidence.join("; ")),
        ("Caveats", if a.caveats.is_empty() { "none".into() } else { a.caveats.join("; ") }),
        ("Indicators", if a.indicators.is_empty() { "none".into() } else { a.indicators.iter().map(name).collect::<Vec<_>>().join(", ") }),
        ("Status", ex.response.status.to_string()),
        ("Title", opt(a.title.as_deref())),
        ("cf-ray", opt(a.cf_ray.as_deref())),
    ];
    if let Some(r) = &a.retry_after {
        rows.push(("retry-after", r.clone()));
    }
    if let Some(l) = &a.location {
        rows.push(("Location", l.clone()));
    }
    for i in &ex.response.informational {
        rows.push(("Informational", i.status.to_string()));
    }
    let cookies: Vec<String> = ex.response.set_cookies.iter().map(|s| format!("{} ({} bytes)", s.name, s.value_len)).collect();
    rows.extend([
        ("Set-Cookie", if cookies.is_empty() { "none".into() } else { cookies.join(", ") }),
        ("Body", match &ex.response.body_decoding {
            BodyDecoding::Identity => format!("{} bytes", ex.response.body_len),
            BodyDecoding::Decoded { encoding, decoded_len } => format!("{} bytes {encoding}, {decoded_len} decoded", ex.response.body_len),
            BodyDecoding::NotDecoded { encoding, reason } => format!("{} bytes {encoding}, not decoded: {reason}", ex.response.body_len),
        }),
        ("Connection", format!("#{} {proto}, request {} on it{}, address from {}", c.id, c.request_number, if c.reused { ", reused" } else { "" }, name(&c.address_source))),
    ]);
    if let Some(r) = &c.retried_after {
        rows.push(("Retried", r.clone()));
    }
    if !c.skipped_addresses.is_empty() {
        rows.push(("Skipped addresses", c.skipped_addresses.join("; ")));
    }
    match &ex.tls {
        Some(t) => {
            let cipher = t.cipher.as_ref().map(|c| c.iana.clone().unwrap_or_else(|| c.openssl.clone()));
            rows.push(("TLS", format!("{}, {}, ALPN {}{}", t.version, opt(cipher.as_deref()), opt(t.alpn.as_deref()), if t.session_reused { ", session resumed" } else { "" })));
        }
        None => rows.push(("TLS", "none (plain HTTP)".into())),
    }
    let t = &ex.timings;
    rows.extend([
        ("DNS", ms(t.dns_ms, c.reused, "address given or host is an IP")),
        ("Connect", ms(t.connect_ms, c.reused, "")),
        ("TLS handshake", ms(t.tls_ms, c.reused, "plain HTTP")),
        ("Time to first byte", ms(Some(t.ttfb_ms), c.reused, "")),
        ("Total", ms(Some(t.total_ms), c.reused, "")),
    ]);
    let mut out = format!("### {} {}\n\n| | |\n|---|---|\n", ex.request.method, ex.request.url);
    for (k, v) in rows {
        out.push_str(&format!("| {k} | {} |\n", v.replace('|', "\\|")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipes_are_escaped_and_blanks_say_not_captured() {
        assert_eq!(cell(Some("a|b")), "`a\\|b`");
        assert_eq!(cell(None), "`not captured`");
    }
}
