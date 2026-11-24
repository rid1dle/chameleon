//! Adversarial regression tests: one per defect found in the Phase 2 testing pass (2026-11-24).
//! Each test names its defect id (D1..D14, see docs/phase2/REGRESSION_TESTS.md) and was written
//! from a probe that showed the defect before the fix. All servers are local.

mod common;

use std::sync::Arc;
use std::time::Duration;

use cfprobe::cloudflare::{self, Confidence, IssuedBy, Verdict};
use cfprobe::networking::{AddressSource, BodyDecoding, Protocol};
use cfprobe::{CFProbe, Config, Error, Target};
use common::*;

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// D1. A server that closes keep-alive connections without warning. Before: 49 of 100 requests
/// failed with "connection error". Now each failure on a reused connection is retried once on a new
/// connection, and the exchange says so.
#[tokio::test]
async fn d1_dead_pooled_connection_is_retried_once_and_reported() {
    let a = raw_server(|_| vec![h1_response("200 OK", "", b"ok")], true).await;
    let e = CFProbe::new(Config::default()).unwrap();
    let mut retried = 0;
    for i in 0..100 {
        if i % 2 == 1 {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let ex = e.inspect(http_target(a, "/")).await.unwrap_or_else(|err| panic!("request {i}: {err}"));
        assert_eq!(ex.response.status, 200);
        if ex.connection.retried_after.is_some() {
            retried += 1;
            assert!(!ex.connection.reused, "the retry runs on a new connection");
        }
    }
    println!("retried {retried}/100");
}

/// D1, the other side: a POST is not idempotent, so it is never resent.
#[tokio::test]
async fn d1_non_idempotent_request_is_not_retried() {
    let a = raw_server(|_| vec![h1_response("200 OK", "", b"ok")], true).await;
    let e = CFProbe::new(Config::default()).unwrap();
    let mut failures = 0;
    for _ in 0..20 {
        let mut t = http_target(a, "/");
        t.method = "POST".into();
        match e.inspect(t).await {
            Ok(ex) => assert!(ex.connection.retried_after.is_none()),
            Err(Error::Http(_)) => failures += 1,
            Err(other) => panic!("{other}"),
        }
    }
    println!("POST failures without retry: {failures}/20");
}

/// D2. Before: `{"h2":{"max_frame_size":1}}` panicked inside h2. Now the config is refused.
#[test]
fn d2_out_of_range_h2_settings_are_refused_not_panics() {
    for json in [
        r#"{"h2":{"max_frame_size":1}}"#,
        r#"{"h2":{"max_frame_size":16777216}}"#,
        r#"{"h2":{"initial_stream_window_size":4294967295}}"#,
        r#"{"h2":{"initial_connection_window_size":2147483648}}"#,
        r#"{"h1":{"max_response_headers":0}}"#,
    ] {
        let c = Config::from_json(json).unwrap();
        assert!(matches!(CFProbe::new(c), Err(Error::Config(_))), "{json}");
    }
    let ok = Config::from_json(r#"{"h2":{"max_frame_size":16384,"initial_stream_window_size":2147483647}}"#).unwrap();
    assert!(CFProbe::new(ok).is_ok());
}

/// D3. `localhost` resolves to ::1 first on this host; a server only on 127.0.0.1 refused it and the
/// engine gave up. Now every address is tried in order and the failed ones are listed.
#[tokio::test]
async fn d3_every_resolved_address_is_tried() {
    let a = raw_server(|_| vec![h1_response("200 OK", "", b"ok")], false).await;
    let resolved: Vec<_> = tokio::net::lookup_host(("localhost", a.port())).await.unwrap().collect();
    let e = CFProbe::new(Config::default()).unwrap();
    let ex = e.inspect(Target::get(&format!("http://localhost:{}/", a.port())).unwrap()).await.unwrap();
    assert_eq!(ex.connection.address_source, AddressSource::Dns);
    assert_eq!(ex.connection.remote_addr, a);
    if resolved.first().is_some_and(|f| f.is_ipv6()) {
        assert!(ex.connection.skipped_addresses[0].starts_with("[::1]"), "{:?}", ex.connection.skipped_addresses);
    }
}

/// D4. Before: `https://user:pw@host/` printed the password in the report and sent it in HTTP/2
/// `:authority`. Now such URLs are refused before anything is sent.
#[test]
fn d4_urls_with_credentials_are_refused() {
    for u in ["https://user:hunter2@a.test/", "https://user@a.test/", "http://:pw@a.test/"] {
        match Target::get(u) {
            Err(Error::Target(m)) => assert!(!m.contains("hunter2") && m.contains("credentials"), "{m}"),
            other => panic!("{u}: {other:?}"),
        }
    }
}

/// D5. Before: `http://[::1]:port/` failed with "dns lookup for [::1] failed". TLS to an IPv6
/// literal also needs the host without brackets for SNI and verification.
#[tokio::test]
async fn d5_ipv6_literals_work_over_http_and_tls() {
    let lab = Lab::start_on(H2_AND_H1, "[::1]:0").await;
    let mut c = Config::default();
    c.tls.verify = false; // the throwaway certificate names localhost, not ::1
    let e = CFProbe::new(c).unwrap();
    let ex = e.inspect(Target::get(&format!("https://[::1]:{}/x", lab.addr.port())).unwrap()).await.unwrap();
    assert_eq!((ex.response.status, ex.connection.address_source), (200, AddressSource::IpLiteral));
    assert_eq!(header(&ex, "x-seen-uri"), format!("https://[::1]:{}/x", lab.addr.port()));
}

/// D6. Before: a `--resolve` key spelled `LOCALHOST:port` did not match and the engine silently
/// used real DNS. Matching is now case-insensitive and the address source is reported.
#[tokio::test]
async fn d6_resolve_override_matches_case_insensitively_and_is_reported() {
    let a = raw_server(|_| vec![h1_response("200 OK", "", b"ok")], false).await;
    let mut c = Config::default();
    c.resolve.insert(format!("LAB.Example.TEST:{}", a.port()), a);
    let e = CFProbe::new(c).unwrap();
    let ex = e.inspect(Target::get(&format!("http://lab.example.test:{}/", a.port())).unwrap()).await.unwrap();
    assert_eq!((ex.connection.address_source, ex.timings.dns_ms), (AddressSource::ResolveOverride, None));
    let bad = Config::from_json(r#"{"resolve":{"no-port":"127.0.0.1:1"}}"#).unwrap();
    assert!(matches!(CFProbe::new(bad), Err(Error::Config(_))));
}

/// D7. Before: a gzip body stayed compressed; receiver parsing failed and the classifier read
/// compressed bytes. Now bodies are decoded, and an undecodable one is marked, not misread.
#[tokio::test]
async fn d7_encoded_bodies_are_decoded_or_marked() {
    // A Cloudflare block page sent gzipped: must still be ACCESS_DENIED.
    let a = raw_server(
        |_| {
            let page = gzip(b"<html><title>Attention Required! | Cloudflare</title><div id=\"cf-wrapper\"><h1 data-translate=\"block_headline\">Sorry, you have been blocked</h1></div></html>");
            vec![h1_response("403 Forbidden", "Server: cloudflare\r\nCF-RAY: 1-AMS\r\nContent-Encoding: gzip\r\n", &page)]
        },
        false,
    )
    .await;
    let e = CFProbe::new(Config::default()).unwrap();
    let ex = e.inspect(http_target(a, "/").header("accept-encoding", "gzip")).await.unwrap();
    assert!(matches!(ex.response.body_decoding, BodyDecoding::Decoded { .. }), "{:?}", ex.response.body_decoding);
    assert!(ex.response.body.starts_with(b"<html>"));
    let v = cloudflare::analyze_exchange(&ex);
    assert_eq!((v.verdict, v.confidence), (Verdict::AccessDenied, Confidence::High));

    // An encoding the engine does not know: kept as received, analysis says it could not look.
    let a = raw_server(|_| vec![h1_response("200 OK", "Server: cloudflare\r\nContent-Encoding: compress\r\n", b"\x1f\x9d...")], false).await;
    let ex = e.inspect(http_target(a, "/")).await.unwrap();
    assert!(matches!(ex.response.body_decoding, BodyDecoding::NotDecoded { .. }));
    let v = cloudflare::analyze_exchange(&ex);
    assert_eq!((v.verdict, v.confidence), (Verdict::NormalPage, Confidence::Low));
    assert!(v.caveats.iter().any(|c| c.contains("not inspected")));

    // A small body that expands past max_body_bytes is refused, not decoded without bound.
    let a = raw_server(|_| vec![h1_response("200 OK", "Content-Encoding: gzip\r\n", &gzip(&vec![b'a'; 4 << 20]))], false).await;
    let c = Config { max_body_bytes: 1 << 20, ..Config::default() };
    let e = CFProbe::new(c).unwrap();
    assert!(matches!(e.inspect(http_target(a, "/")).await, Err(Error::BodyTooLarge { limit: 1048576 })));
}

/// D9. Before: `-H x-dup: a -H x-dup: b` sent only `b`. Repeated target headers are all sent; a
/// target header still replaces a default of the same name.
#[tokio::test]
async fn d9_repeated_headers_are_all_sent() {
    let a = raw_server(|req| vec![h1_response("200 OK", "", req)], false).await;
    let e = CFProbe::new(Config::default()).unwrap();
    let ex = e.inspect(http_target(a, "/").header("x-dup", "a").header("x-dup", "b").header("accept", "text/html")).await.unwrap();
    let wire = String::from_utf8_lossy(&ex.response.body).to_string();
    assert!(wire.contains("x-dup: a\r\nx-dup: b\r\n"), "{wire}");
    assert_eq!(wire.matches("accept:").count(), 1, "{wire}");
    assert!(wire.contains("accept: text/html"), "{wire}");
}

/// D11. Before: `location: /next?__cf_chl_rt_tk=SECRET` was printed whole. Challenge tokens in URLs
/// are now redacted in the report and the analysis.
#[tokio::test]
async fn d11_challenge_tokens_in_urls_are_redacted() {
    let a = raw_server(|_| vec![h1_response("302 Found", "Location: /next?__cf_chl_rt_tk=SECRETSECRET&a=1\r\nCF-RAY: 1-AMS\r\n", b"")], false).await;
    let e = CFProbe::new(Config::default()).unwrap();
    let ex = e.inspect(http_target(a, "/?__cf_chl_tk=SECRETSECRET")).await.unwrap();
    let v = cloudflare::analyze_exchange(&ex);
    let json = serde_json::to_string(&(&ex, &v)).unwrap();
    assert!(!json.contains("SECRETSECRET"), "{json}");
    assert_eq!(v.verdict, Verdict::ChallengeIndicator);
    // D20: the header arrives redacted and the classifier redacts again; the length must stay the
    // token's (12), not the placeholder's.
    assert_eq!(v.location.as_deref(), Some("/next?__cf_chl_rt_tk=<redacted 12 bytes>&a=1"));
}

/// D12. Before: 20 concurrent requests opened 20 TCP connections and the pool kept one. Now they
/// share one HTTP/2 connection, numbered 1 to 20.
#[tokio::test]
async fn d12_concurrent_requests_multiplex_on_one_h2_connection() {
    let lab = Lab::start(H2_AND_H1).await;
    let e = Arc::new(CFProbe::new(lab.config()).unwrap());
    let jobs: Vec<_> = (0..20)
        .map(|_| {
            let (e, t) = (e.clone(), lab.url("/slow"));
            tokio::spawn(async move { e.inspect(t).await.unwrap() })
        })
        .collect();
    let mut numbers = Vec::new();
    for j in jobs {
        let ex = j.await.unwrap();
        assert_eq!(ex.connection.protocol, Protocol::Http2);
        numbers.push(ex.connection.request_number);
    }
    numbers.sort();
    assert_eq!(numbers, (1..=20).collect::<Vec<_>>());
    assert_eq!(lab.accepts(), 1, "one TCP connection");
}

/// D12, HTTP/1.1: concurrent requests need one connection each, and all of them are kept for reuse.
#[tokio::test]
async fn d12_http1_connections_are_all_returned_to_the_pool() {
    let lab = Lab::start(H1_ONLY).await;
    let e = Arc::new(CFProbe::new(lab.config()).unwrap());
    let run = |n| {
        let jobs: Vec<_> = (0..n)
            .map(|_| {
                let (e, t) = (e.clone(), lab.url("/slow"));
                tokio::spawn(async move { e.inspect(t).await.unwrap() })
            })
            .collect();
        async move {
            for j in jobs {
                j.await.unwrap();
            }
        }
    };
    run(5).await;
    let first = lab.accepts();
    run(5).await;
    assert!(first <= 5);
    assert_eq!(lab.accepts(), first, "second round reused the pooled connections");
}

/// D13. HTTP/1.1 header names go out lowercase by default; browsers send Title-Case. Now selectable.
#[tokio::test]
async fn d13_title_case_header_names_are_selectable() {
    let a = raw_server(|req| vec![h1_response("200 OK", "", req)], false).await;
    let mut c = Config::default();
    c.h1.title_case_headers = true;
    let e = CFProbe::new(c).unwrap();
    let wire = String::from_utf8_lossy(&e.inspect(http_target(a, "/").header("accept-language", "en")).await.unwrap().response.body).to_string();
    assert!(wire.contains("\r\nHost: ") && wire.contains("\r\nUser-Agent: ") && wire.contains("\r\nAccept-Language: en"), "{wire}");
}

/// D14. Before: a 103 Early Hints response vanished, and 150 response headers failed the request.
#[tokio::test]
async fn d14_informational_responses_are_kept_and_header_limit_is_configurable() {
    let a = raw_server(|_| vec![b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n".to_vec(), h1_response("200 OK", "", b"ok")], false).await;
    let e = CFProbe::new(Config::default()).unwrap();
    let ex = e.inspect(http_target(a, "/")).await.unwrap();
    assert_eq!(ex.response.status, 200);
    assert_eq!(ex.response.informational.iter().map(|i| i.status).collect::<Vec<_>>(), [103]);

    let a = raw_server(
        |_| {
            let extra: String = (0..150).map(|i| format!("X-H{i}: v\r\n")).collect();
            vec![h1_response("200 OK", &extra, b"")]
        },
        false,
    )
    .await;
    assert!(matches!(e.inspect(http_target(a, "/")).await, Err(Error::Http(_))), "hyper's default of 100 still applies");
    let mut c = Config::default();
    c.h1.max_response_headers = Some(200);
    let ex = CFProbe::new(c).unwrap().inspect(http_target(a, "/")).await.unwrap();
    assert_eq!(ex.response.headers.len(), 151);
}

/// HTTP/2 forbids connection-specific headers; hyper drops them. The record now says so instead of
/// listing them as sent.
#[tokio::test]
async fn h2_connection_headers_are_reported_as_not_sent() {
    let lab = Lab::start(H2_AND_H1).await;
    let e = CFProbe::new(lab.config()).unwrap();
    let ex = e.inspect(lab.url("/x").header("connection", "keep-alive").header("x-a", "1")).await.unwrap();
    assert_eq!(ex.request.not_sent, ["connection"]);
    assert!(!ex.request.headers.iter().any(|h| h.name == "connection"));
    assert_eq!(header(&ex, "x-seen-order"), "user-agent,accept,x-a");
}

/// A response that is not HTTP, a connection cut mid-body, and a body slower than the budget each
/// fail with their own error instead of hanging or returning a partial body.
#[tokio::test]
async fn malformed_cut_and_slow_responses_fail_cleanly() {
    let e = CFProbe::new(Config { request_timeout_ms: 1000, ..Config::default() }).unwrap();
    let a = raw_server(|_| vec![b"SSH-2.0-OpenSSH\r\n\r\n".to_vec()], true).await;
    assert!(matches!(e.inspect(http_target(a, "/")).await, Err(Error::Http(_))));
    let a = raw_server(|_| vec![b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec()], true).await;
    assert!(matches!(e.inspect(http_target(a, "/")).await, Err(Error::Body(_))));
    let a = raw_server(
        |_| {
            let mut v = vec![b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n".to_vec()];
            v.extend((0..200).map(|_| b"x".to_vec()));
            v
        },
        true,
    )
    .await;
    assert!(matches!(e.inspect(http_target(a, "/")).await, Err(Error::Timeout { stage: cfprobe::Stage::Body, after_ms: 1000 })));
}

/// A plain 403 from a server that is not Cloudflare is the origin's denial, not a Cloudflare block.
#[tokio::test]
async fn origin_403_is_not_a_cloudflare_block() {
    let a = raw_server(|_| vec![h1_response("403 Forbidden", "Server: nginx\r\n", b"<h1>403 Forbidden</h1>")], false).await;
    let ex = CFProbe::new(Config::default()).unwrap().inspect(http_target(a, "/")).await.unwrap();
    let v = cloudflare::analyze_exchange(&ex);
    assert_eq!((v.verdict, v.issued_by, v.cloudflare_present), (Verdict::AccessDenied, IssuedBy::Origin, false));
}

/// D24: Cloudflare's own cookies are indicators (seen on cloudflare.com and BookMyShow: `__cf_bm`;
/// Discord and BookMyShow: `_cfuvid`). Before, the classifier never looked at cookie names.
#[tokio::test]
async fn cloudflare_cookie_names_are_indicators_and_values_stay_out() {
    let a = raw_server(|_| vec![h1_response("200 OK", "CF-RAY: 1-X\r\nSet-Cookie: __cf_bm=BMVALUE; Path=/; HttpOnly\r\nSet-Cookie: _cfuvid=UVVALUE; Path=/\r\nSet-Cookie: cf_clearance=CLVALUE; Path=/\r\n", b"ok")], false).await;
    let ex = CFProbe::new(Config::default()).unwrap().inspect(http_target(a, "/")).await.unwrap();
    let v = cloudflare::analyze_exchange(&ex);
    use cfprobe::cloudflare::Indicator;
    for i in [Indicator::BotManagementCookie, Indicator::RateLimitVisitorCookie, Indicator::ClearanceCookie] {
        assert!(v.indicators.contains(&i), "{i:?}");
    }
    assert_eq!(v.verdict, Verdict::NormalPage, "cookies are indicators, not verdicts");
    let json = serde_json::to_string(&(&ex, &v)).unwrap();
    assert!(!json.contains("BMVALUE") && !json.contains("UVVALUE") && !json.contains("CLVALUE"));
}
