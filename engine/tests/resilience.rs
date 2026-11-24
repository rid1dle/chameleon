//! The resilience layer (`cfprobe::resilience::Session`) against local scripted servers: redirects,
//! loops, cookie jar, retries with backoff and Retry-After, circuit breaker, cancellation.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use cfprobe::cloudflare::Verdict;
use cfprobe::resilience::{CircuitPolicy, Decision, FetchOutcome, Policy, RetryPolicy, Session};
use cfprobe::{CFProbe, Config, Target};
use common::*;
use rand::SeedableRng;

fn session(policy: Policy) -> Session {
    Session::new(Arc::new(CFProbe::new(Config::default()).unwrap()), policy, rand_chacha::ChaCha8Rng::seed_from_u64(1)).unwrap()
}

fn follow(n: u8) -> Policy {
    Policy { max_redirects: n, ..Policy::default() }
}

#[tokio::test]
async fn redirect_chain_is_followed_and_recorded() {
    let (a, _) = scripted_server(|r| match r.path {
        "/a" => h1_response("301 Moved", "Location: /b\r\n", b""),
        "/b" => h1_response("302 Found", "Location: /c?x=1\r\n", b""),
        "/c?x=1" => h1_response("200 OK", "", b"end"),
        _ => h1_response("404 Not Found", "", b""),
    })
    .await;
    let f = session(follow(5)).fetch(http_target(a, "/a")).await;
    assert_eq!(f.outcome, FetchOutcome::Completed);
    let statuses: Vec<_> = f.hops.iter().map(|h| h.attempts[0].exchange.as_ref().unwrap().response.status).collect();
    assert_eq!(statuses, [301, 302, 200]);
    assert_eq!(f.analysis.unwrap().verdict, Verdict::NormalPage);
    // Not followed when the policy says 0 (inspect's behaviour).
    let f = session(follow(0)).fetch(http_target(a, "/a")).await;
    assert_eq!((f.hops.len(), f.analysis.unwrap().verdict), (1, Verdict::Redirect));
}

#[tokio::test]
async fn redirect_loops_and_long_chains_stop() {
    let (a, count) = scripted_server(|r| match r.path {
        "/loop1" => h1_response("302 Found", "Location: /loop2\r\n", b""),
        "/loop2" => h1_response("302 Found", "Location: /loop1\r\n", b""),
        p if p.starts_with("/chain/") => {
            let n: u32 = p[7..].parse().unwrap();
            h1_response("302 Found", &format!("Location: /chain/{}\r\n", n + 1), b"")
        }
        _ => h1_response("404 Not Found", "", b""),
    })
    .await;
    let f = session(follow(10)).fetch(http_target(a, "/loop1")).await;
    assert!(matches!(&f.outcome, FetchOutcome::RedirectLoop { url } if url.ends_with("/loop1")), "{:?}", f.outcome);
    assert_eq!(count.load(Ordering::SeqCst), 2, "loop detected before re-requesting");
    let f = session(follow(5)).fetch(http_target(a, "/chain/0")).await;
    assert_eq!(f.outcome, FetchOutcome::TooManyRedirects { limit: 5 });
    assert_eq!(f.hops.len(), 6, "the original request plus 5 redirects");
}

#[tokio::test]
async fn cookie_jar_keeps_respects_path_and_expiry_and_never_records_values() {
    let (a, _) = scripted_server(|r| match r.path {
        "/set" => h1_response(
            "200 OK",
            "Set-Cookie: sid=s3cr3t; Path=/\r\nSet-Cookie: scoped=1; Path=/only\r\nSet-Cookie: gone=x; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\nSet-Cookie: ;;;bad\r\n",
            b"",
        ),
        _ => {
            let cookie = r.raw.lines().find(|l| l.to_ascii_lowercase().starts_with("cookie:")).unwrap_or("cookie: <none>").to_string();
            h1_response("200 OK", "", cookie.as_bytes())
        }
    })
    .await;
    let s = session(Policy { cookies: true, ..Policy::default() });
    s.fetch(http_target(a, "/set")).await;
    let f = s.fetch(http_target(a, "/check")).await;
    let body = String::from_utf8_lossy(&f.last_exchange().unwrap().response.body).to_string();
    assert_eq!(body, "cookie: sid=s3cr3t", "only the in-scope, unexpired cookie");
    assert_eq!(f.hops[0].attempts[0].jar_cookies_sent, ["sid"]);
    let f = s.fetch(http_target(a, "/only/x")).await;
    let body = String::from_utf8_lossy(&f.last_exchange().unwrap().response.body).to_string();
    assert!(body.contains("sid=s3cr3t") && body.contains("scoped=1"), "{body}");
    assert!(!serde_json::to_string(&f).unwrap().contains("s3cr3t"), "values never in the record");
    // Without the jar nothing is sent back.
    let f = session(Policy::default()).fetch(http_target(a, "/check")).await;
    assert_eq!(String::from_utf8_lossy(&f.last_exchange().unwrap().response.body), "cookie: <none>");
}

#[tokio::test]
async fn credentials_do_not_follow_a_cross_origin_redirect() {
    let (b, _) = scripted_server(|r| {
        let leaked = r.raw.to_ascii_lowercase().contains("authorization:") || r.raw.to_ascii_lowercase().contains("cookie:");
        h1_response("200 OK", "", if leaked { b"leaked" } else { b"clean" })
    })
    .await;
    let (a, _) = scripted_server(move |_| h1_response("302 Found", &format!("Location: http://localhost:{}/\r\n", b.port()), b"")).await;
    let t = http_target(a, "/").header("authorization", "Bearer t").header("cookie", "k=v");
    let f = session(follow(3)).fetch(t).await;
    assert_eq!(String::from_utf8_lossy(&f.last_exchange().unwrap().response.body), "clean");
}

#[tokio::test]
async fn transient_failures_are_retried_with_recorded_waits() {
    let (a, count) = scripted_server(|r| if r.n < 2 { h1_response("503 Service Unavailable", "", b"busy") } else { h1_response("200 OK", "", b"ok") }).await;
    let p = Policy { retry: RetryPolicy { max_attempts: 4, base_delay_ms: 20, max_delay_ms: 200, ..Default::default() }, ..Policy::default() };
    let f = session(p).fetch(http_target(a, "/")).await;
    assert_eq!(count.load(Ordering::SeqCst), 3);
    let a0 = &f.hops[0].attempts;
    assert_eq!(a0.iter().map(|x| x.analysis.verdict).collect::<Vec<_>>(), [Verdict::OriginUnavailable, Verdict::OriginUnavailable, Verdict::NormalPage]);
    assert!(a0[1].waited_ms <= 20 && a0[2].waited_ms <= 40 && a0[2].waited_ms >= 20);
}

#[tokio::test]
async fn denials_and_challenges_are_tried_once() {
    let (a, count) = scripted_server(|r| {
        if r.path == "/challenge" {
            h1_response("403 Forbidden", "cf-mitigated: challenge\r\nCF-RAY: 1-X\r\n", b"window._cf_chl_opt={}")
        } else {
            h1_response("403 Forbidden", "", b"no")
        }
    })
    .await;
    let s = session(Policy::runner_default());
    for path in ["/deny", "/challenge"] {
        let f = s.fetch(http_target(a, path)).await;
        assert_eq!(f.attempts(), 1, "{path}");
        assert!(matches!(f.hops[0].attempts[0].decision, Decision::Stop { .. }));
    }
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn retry_after_is_waited_and_a_long_one_ends_the_fetch() {
    let (a, _) = scripted_server(|r| match (r.path, r.n) {
        ("/short", 0) => h1_response("429 Too Many Requests", "Retry-After: 1\r\n", b""),
        ("/long", _) => h1_response("429 Too Many Requests", "Retry-After: 3600\r\n", b""),
        _ => h1_response("200 OK", "", b"ok"),
    })
    .await;
    let s = session(Policy { retry: RetryPolicy { max_attempts: 3, ..Default::default() }, ..Policy::default() });
    let t0 = Instant::now();
    let f = s.fetch(http_target(a, "/short")).await;
    assert!(t0.elapsed() >= Duration::from_millis(1000), "waited {:?}", t0.elapsed());
    assert_eq!((f.attempts(), f.analysis.unwrap().verdict), (2, Verdict::NormalPage));
    let t0 = Instant::now();
    let f = s.fetch(http_target(a, "/long")).await;
    assert!(t0.elapsed() < Duration::from_millis(500));
    assert!(matches!(&f.hops[0].attempts[0].decision, Decision::Stop { reason } if reason.contains("exceeds the cap")));
}

#[tokio::test]
async fn circuit_opens_after_failures_and_stops_sending() {
    let (a, count) = scripted_server(|_| h1_response("503 Service Unavailable", "", b"down")).await;
    let p = Policy { circuit: Some(CircuitPolicy { failures_to_open: 3, open_ms: 300 }), ..Policy::default() };
    let s = session(p);
    for _ in 0..3 {
        assert_eq!(s.fetch(http_target(a, "/")).await.outcome, FetchOutcome::Completed);
    }
    let f = s.fetch(http_target(a, "/")).await;
    assert!(matches!(f.outcome, FetchOutcome::CircuitOpen { .. }), "{:?}", f.outcome);
    assert_eq!(count.load(Ordering::SeqCst), 3, "the 4th request was not sent");
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(s.fetch(http_target(a, "/")).await.outcome, FetchOutcome::Completed, "half-open lets one through");
    assert!(matches!(s.fetch(http_target(a, "/")).await.outcome, FetchOutcome::CircuitOpen { .. }), "one more failure reopens");
}

#[tokio::test]
async fn cancellation_returns_promptly_and_the_engine_stays_usable() {
    // Answers /slow after 1.5 s (async sleep: a blocking one would stall the test runtime too).
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    if String::from_utf8_lossy(&buf[..n]).contains("GET /slow") {
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                    }
                    if sock.write_all(&h1_response("200 OK", "", b"ok")).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    let s = session(Policy::default());
    let t0 = Instant::now();
    let f = s.fetch_until(http_target(a, "/slow"), tokio::time::sleep(Duration::from_millis(100))).await;
    assert_eq!(f.outcome, FetchOutcome::Cancelled);
    assert!(t0.elapsed() < Duration::from_millis(600), "{:?}", t0.elapsed());
    let f = s.fetch(http_target(a, "/fast")).await;
    assert_eq!(f.analysis.unwrap().verdict, Verdict::NormalPage);
}

#[tokio::test]
async fn refused_connection_and_bad_certificate_get_failure_verdicts() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap(); // dropped: port refuses
    let p = Policy { retry: RetryPolicy { max_attempts: 2, base_delay_ms: 10, max_delay_ms: 10, ..Default::default() }, ..Policy::default() };
    let f = session(p.clone()).fetch(Target::get(&format!("http://{closed}/")).unwrap()).await;
    assert_eq!((f.attempts(), f.analysis.unwrap().verdict), (2, Verdict::ConnectionFailure));

    let lab = Lab::start(H2_AND_H1).await;
    let mut c = lab.config();
    c.tls.ca_file = None; // the lab certificate is not trusted: verification must fail, and stay on
    let s = Session::new(Arc::new(CFProbe::new(c).unwrap()), p, rand_chacha::ChaCha8Rng::seed_from_u64(1)).unwrap();
    let f = s.fetch(lab.url("/x")).await;
    assert_eq!((f.attempts(), f.analysis.unwrap().verdict), (1, Verdict::TlsFailure), "a refused certificate is final");
}

/// D21 (found on the zone): retries of one request opened the circuit for the whole host. A request
/// counts once, so a single request with 3 failing attempts does not open a 3-failure breaker.
#[tokio::test]
async fn one_retried_request_counts_once_toward_the_circuit() {
    let (a, count) = scripted_server(|_| h1_response("503 Service Unavailable", "", b"down")).await;
    let p = Policy {
        retry: RetryPolicy { max_attempts: 3, base_delay_ms: 5, max_delay_ms: 10, ..Default::default() },
        circuit: Some(CircuitPolicy { failures_to_open: 3, open_ms: 60_000 }),
        ..Policy::default()
    };
    let s = session(p);
    let f = s.fetch(http_target(a, "/")).await;
    assert_eq!((f.attempts(), &f.outcome), (3, &FetchOutcome::Completed));
    let f = s.fetch(http_target(a, "/")).await;
    assert_eq!(f.outcome, FetchOutcome::Completed, "second request still sent");
    assert_eq!(count.load(Ordering::SeqCst), 6);
}

/// D22: an unparseable response (not HTTP, or a head over the client's limit) is UNKNOWN, not a
/// connection failure, and is not retried: the server would send the same thing again.
#[tokio::test]
async fn unparseable_responses_are_unknown_and_not_retried() {
    let (a, count) = scripted_server(|r| {
        if r.path == "/ssh" {
            b"SSH-2.0-OpenSSH_9.9\r\n\r\n".to_vec()
        } else {
            let extra: String = (0..150).map(|i| format!("X-H{i}: v\r\n")).collect();
            h1_response("200 OK", &extra, b"")
        }
    })
    .await;
    let s = session(Policy { retry: RetryPolicy { max_attempts: 3, base_delay_ms: 5, max_delay_ms: 10, ..Default::default() }, ..Policy::default() });
    for path in ["/ssh", "/many"] {
        let f = s.fetch(http_target(a, path)).await;
        let n = f.attempts();
        let v = f.analysis.unwrap();
        assert_eq!((n, v.verdict), (1, Verdict::Unknown), "{path}");
        assert!(v.evidence[0].contains("response parsing"), "{:?}", v.evidence);
    }
    assert_eq!(count.load(Ordering::SeqCst), 2);
}
