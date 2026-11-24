//! Networking foundation, proven against a local BoringSSL + hyper server with a throwaway certificate.
//! The server counts TCP accepts (connection reuse) and echoes the header names it received, in order.

mod common;

use cfprobe::networking::Protocol;
use cfprobe::tls::TlsVersion;
use cfprobe::{CFProbe, Config, Error, Stage, Target};
use common::*;
use tokio::net::TcpListener;

#[tokio::test]
async fn h2_is_negotiated_and_the_handshake_is_observed() {
    let lab = Lab::start(H2_AND_H1).await;
    let engine = CFProbe::new(lab.config()).unwrap();
    let ex = engine.inspect(lab.url("/x")).await.unwrap();

    assert_eq!(ex.response.status, 200);
    assert_eq!(ex.response.http_version, "HTTP/2");
    assert_eq!(header(&ex, "x-seen-version"), "HTTP/2.0");
    assert_eq!(ex.connection.protocol, Protocol::Http2);
    let tls = ex.tls.as_ref().unwrap();
    assert_eq!(tls.version, "TLSv1.3");
    assert_eq!(tls.alpn.as_deref(), Some("h2"));
    assert_eq!(tls.sni.as_deref(), Some("localhost"));
    assert!(!tls.session_reused);
    assert_eq!(tls.client_random.len(), 64);
    assert!(tls.cipher.as_ref().unwrap().iana.as_deref().unwrap().starts_with("TLS_"));
    assert_eq!(tls.peer_chain.len(), 1);
    assert_eq!(tls.peer_chain[0].subject, "CN=localhost");
    assert!(ex.configured_h2.is_some());
    assert!(ex.timings.tls_ms.is_some());
    // The address came from config.resolve, so no lookup ran: not done, which is not 0 ms.
    assert_eq!(ex.timings.dns_ms, None);
    // A real response that never passed through Cloudflare.
    let a = cfprobe::cloudflare::analyze_exchange(&ex);
    assert_eq!((a.verdict, a.cloudflare_present), (cfprobe::cloudflare::Verdict::NormalPage, false));
}

#[tokio::test]
async fn h2_connection_is_reused_and_reuse_is_reported() {
    let lab = Lab::start(H2_AND_H1).await;
    let engine = CFProbe::new(lab.config()).unwrap();
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(engine.inspect(lab.url("/x")).await.unwrap());
    }
    assert_eq!(lab.accepts(), 1, "server saw one TCP connection");
    let flags: Vec<_> = seen.iter().map(|e| (e.connection.reused, e.connection.request_number)).collect();
    assert_eq!(flags, [(false, 1), (true, 2), (true, 3)]);
    assert!(seen.iter().all(|e| e.connection.id == seen[0].connection.id));
    // Steps that did not happen are absent, not 0.
    assert!(seen[1].timings.dns_ms.is_none() && seen[1].timings.connect_ms.is_none() && seen[1].timings.tls_ms.is_none());
}

#[tokio::test]
async fn no_reuse_when_disabled() {
    let lab = Lab::start(H2_AND_H1).await;
    let mut config = lab.config();
    config.reuse_connections = false;
    let engine = CFProbe::new(config).unwrap();
    for _ in 0..3 {
        let ex = engine.inspect(lab.url("/x")).await.unwrap();
        assert!(!ex.connection.reused);
    }
    assert_eq!(lab.accepts(), 3);
}

#[tokio::test]
async fn http1_when_server_offers_only_http1_and_it_is_reused() {
    let lab = Lab::start(H1_ONLY).await;
    let engine = CFProbe::new(lab.config()).unwrap();
    let a = engine.inspect(lab.url("/x")).await.unwrap();
    let b = engine.inspect(lab.url("/x")).await.unwrap();
    assert_eq!(a.tls.as_ref().unwrap().alpn.as_deref(), Some("http/1.1"));
    assert_eq!(a.response.http_version, "HTTP/1.1");
    assert_eq!(header(&a, "x-seen-version"), "HTTP/1.1");
    assert!(a.configured_h2.is_none());
    assert!(b.connection.reused);
    assert_eq!(lab.accepts(), 1);
}

#[tokio::test]
async fn headers_arrive_in_configured_order() {
    let lab = Lab::start(H1_ONLY).await;
    let engine = CFProbe::new(lab.config()).unwrap();
    let t = lab.url("/x").header("X-B", "2").header("x-a", "1").header("Accept", "text/html");
    let ex = engine.inspect(t).await.unwrap();
    // Host first, then defaults (accept replaced in place), then the target's own.
    assert_eq!(header(&ex, "x-seen-order"), "host,user-agent,accept,x-b,x-a");
    let sent: Vec<_> = ex.request.headers.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(sent, ["host", "user-agent", "accept", "x-b", "x-a"]);

    let lab2 = Lab::start(H2_AND_H1).await;
    let engine2 = CFProbe::new(lab2.config()).unwrap();
    let ex2 = engine2.inspect(lab2.url("/x").header("x-b", "2").header("x-a", "1")).await.unwrap();
    assert_eq!(header(&ex2, "x-seen-order"), "user-agent,accept,x-b,x-a");
}

#[tokio::test]
async fn tls_settings_take_effect() {
    let lab = Lab::start(H2_AND_H1).await;
    let mut config = lab.config();
    config.tls.max_version = Some(TlsVersion::Tls12);
    config.tls.cipher_list = Some("ECDHE-ECDSA-AES128-GCM-SHA256".into());
    config.tls.alpn = vec!["http/1.1".into()];
    let engine = CFProbe::new(config).unwrap();
    let ex = engine.inspect(lab.url("/x")).await.unwrap();
    let tls = ex.tls.unwrap();
    assert_eq!(tls.version, "TLSv1.2");
    assert_eq!(tls.cipher.unwrap().iana.as_deref(), Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"));
    assert_eq!(tls.alpn.as_deref(), Some("http/1.1"));
}

#[tokio::test]
async fn untrusted_certificate_is_rejected() {
    let lab = Lab::start(H2_AND_H1).await;
    let mut config = lab.config();
    config.tls.ca_file = None;
    let engine = CFProbe::new(config).unwrap();
    match engine.inspect(lab.url("/x")).await {
        Err(Error::TlsHandshake(msg)) => assert!(msg.contains("certificate verify"), "{msg}"),
        other => panic!("expected TlsHandshake, got {other:?}"),
    }
}

#[tokio::test]
async fn tls_stage_times_out() {
    // Accepts TCP, never answers the ClientHello.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(listener.accept().await.unwrap());
        }
    });
    let mut config = Config { connect_timeout_ms: 300, ..Config::default() };
    config.resolve.insert(format!("localhost:{}", addr.port()), addr);
    let engine = CFProbe::new(config).unwrap();
    let t = Target::get(&format!("https://localhost:{}/", addr.port())).unwrap();
    match engine.inspect(t).await {
        Err(Error::Timeout { stage: Stage::Tls, after_ms: 300 }) => {}
        other => panic!("expected TLS timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn body_over_limit_is_an_error_not_a_truncation() {
    let lab = Lab::start(H2_AND_H1).await;
    let mut config = lab.config();
    config.max_body_bytes = 1024;
    let engine = CFProbe::new(config).unwrap();
    assert!(matches!(engine.inspect(lab.url("/big")).await, Err(Error::BodyTooLarge { limit: 1024 })));
}

#[tokio::test]
async fn cookie_values_never_reach_the_report() {
    let lab = Lab::start(H2_AND_H1).await;
    let engine = CFProbe::new(lab.config()).unwrap();
    let ex = engine.inspect(lab.url("/x").header("cookie", "cf_clearance=topsecret")).await.unwrap();
    let json = serde_json::to_string(&ex).unwrap();
    assert!(!json.contains("secretvalue") && !json.contains("topsecret"), "{json}");
    assert_eq!(ex.response.set_cookies[0].name, "sid");
    assert_eq!(ex.response.set_cookies[0].value_len, 11);
}

#[test]
fn config_rejects_unknown_fields_and_bad_alpn() {
    assert!(Config::from_json(r#"{"tls": {"alpn": ["h3"]}}"#).is_ok_and(|c| CFProbe::new(c).is_err()));
    assert!(Config::from_json(r#"{"no_such_field": 1}"#).is_err());
    let c = Config::from_json(r#"{"tls": {"max_version": "TLSv1.2"}, "h2": {"initial_stream_window_size": 65535}}"#).unwrap();
    assert_eq!(c.tls.max_version, Some(TlsVersion::Tls12));
    assert_eq!(c.h2.initial_stream_window_size, Some(65535));
}
