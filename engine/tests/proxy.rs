//! Proxy-first routing. Every test that expects a failure also checks that the destination saw no
//! connection: a direct fallback would show up there as an accept.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use cfprobe::cloudflare::{self, Verdict};
use cfprobe::networking::AddressSource;
use cfprobe::proxy::{ProxyScheme, ProxyStage, RouteRecord, Secret};
use cfprobe::resilience::{Policy, RetryPolicy, Session};
use cfprobe::{CFProbe, Config, Error, Target};
use common::*;
use rand::SeedableRng;

/// The lab trusted as `localhost` (its certificate's name) but reached as `lab.invalid` through the
/// proxy would fail verification, so lab URLs use `localhost` with a resolve pin, and the
/// name-resolution tests use plain HTTP to `lab.invalid`.
fn lab_target(lab: &Lab, path: &str) -> Target {
    lab.url(path)
}

#[tokio::test]
async fn no_proxy_means_direct_and_is_recorded_as_such() {
    let lab = Lab::start(H2_AND_H1).await;
    let e = CFProbe::new(lab.config()).unwrap();
    assert!(e.route().describe().contains("no proxy defined"));
    let ex = e.inspect(lab.url("/x")).await.unwrap();
    assert_eq!((ex.response.status, &ex.connection.route), (200, &RouteRecord::Direct));
    assert_eq!(ex.timings.proxy_ms, None);
}

#[tokio::test]
async fn http_proxy_carries_every_request_sequential_and_concurrent() {
    let lab = Lab::start(H2_AND_H1).await;
    let (p, log, _) = test_proxy(TestProxyKind::Http, None, lab.addr).await;
    let e = Arc::new(CFProbe::new(proxied(lab.config(), "t-http", format!("http://{p}"))).unwrap());
    for _ in 0..3 {
        let ex = e.inspect(lab_target(&lab, "/x")).await.unwrap();
        assert_eq!(ex.connection.route, RouteRecord::Proxy { id: "t-http".into(), scheme: ProxyScheme::Http });
        assert_eq!(ex.connection.remote_addr, p, "the TCP peer is the proxy");
        assert_eq!(ex.timings.dns_ms, None, "no local DNS for the destination");
    }
    let jobs: Vec<_> = (0..20).map(|_| {
        let (e, t) = (e.clone(), lab.url("/slow"));
        tokio::spawn(async move { e.inspect(t).await.unwrap().connection.route })
    }).collect();
    for j in jobs {
        assert!(matches!(j.await.unwrap(), RouteRecord::Proxy { .. }));
    }
    assert_eq!(lab.accepts(), log.tunnels.load(Ordering::SeqCst), "every connection the lab saw came through the proxy");
    assert!(log.targets.lock().unwrap().iter().all(|t| t.ends_with(&format!(":{}", lab.addr.port()))));
}

#[tokio::test]
async fn destination_names_are_resolved_by_the_proxy_not_locally() {
    let (dest, _) = scripted_server(|_| h1_response("200 OK", "", b"ok")).await;
    for kind in [TestProxyKind::Http, TestProxyKind::Socks5] {
        let (p, log, _) = test_proxy(kind, None, dest).await;
        let scheme = if kind == TestProxyKind::Http { "http" } else { "socks5" };
        let e = CFProbe::new(proxied(Config::default(), "t", format!("{scheme}://{p}"))).unwrap();
        // `.invalid` cannot resolve locally (RFC 6761): success means the proxy resolved it.
        let ex = e.inspect(Target::get(&format!("http://lab.invalid:{}/", dest.port())).unwrap()).await.unwrap();
        assert_eq!((ex.response.status, ex.connection.address_source), (200, AddressSource::Proxy));
        let seen = log.targets.lock().unwrap().clone();
        let want = if kind == TestProxyKind::Http { format!("lab.invalid:{}", dest.port()) } else { format!("name lab.invalid:{}", dest.port()) };
        assert_eq!(seen, [want], "{scheme}: the name, not an address, went to the proxy");
    }
}

#[tokio::test]
async fn a_dead_proxy_is_an_error_and_nothing_goes_direct() {
    let lab = Lab::start(H2_AND_H1).await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let e = CFProbe::new(proxied(lab.config(), "dead", format!("http://{closed}"))).unwrap();
    match e.inspect(lab.url("/x")).await {
        Err(Error::Proxy { proxy, stage: ProxyStage::Connect, .. }) => assert_eq!(proxy, "dead"),
        other => panic!("{other:?}"),
    }
    assert_eq!(lab.accepts(), 0, "the lab is reachable directly, and was not contacted");
}

#[tokio::test]
async fn a_proxy_refusing_the_tunnel_is_an_error_and_nothing_goes_direct() {
    let lab = Lab::start(H2_AND_H1).await;
    let (p, _, _) = test_proxy(TestProxyKind::HttpRefusing(502), None, lab.addr).await;
    let e = CFProbe::new(proxied(lab.config(), "refuser", format!("http://{p}"))).unwrap();
    let err = e.inspect(lab.url("/x")).await.unwrap_err();
    assert!(matches!(&err, Error::Proxy { stage: ProxyStage::Tunnel, detail, .. } if detail.contains("502")), "{err}");
    assert_eq!(cloudflare::analyze_error(&err).verdict, Verdict::ConnectionFailure);
    assert_eq!(lab.accepts(), 0);
}

#[tokio::test]
async fn authentication_failures_are_reported_never_retried_and_never_printed() {
    let lab = Lab::start(H2_AND_H1).await;
    for kind in [TestProxyKind::Http, TestProxyKind::Socks5] {
        let (p, _, _) = test_proxy(kind, Some(("user", "s3cret-pw")), lab.addr).await;
        let scheme = if kind == TestProxyKind::Http { "http" } else { "socks5h" };
        let with = |user: Option<&str>, pw: Option<&str>| {
            let mut c = lab.config();
            c.proxy.proxies.push(cfprobe::proxy::ProxySpec {
                id: "auth".into(),
                url: format!("{scheme}://{p}"),
                username: user.map(str::to_string),
                password: pw.map(Secret::new),
                ca_file: None,
            });
            c
        };
        for (user, pw, want) in [(None, None, "none are configured"), (Some("user"), Some("WRONG-pw"), "refused the credentials")] {
            let c = with(user, pw);
            let s = Session::new(Arc::new(CFProbe::new(c).unwrap()), Policy { retry: RetryPolicy { max_attempts: 3, ..Default::default() }, ..Policy::default() }, rand_chacha::ChaCha8Rng::seed_from_u64(1)).unwrap();
            let f = s.fetch(lab.url("/x")).await;
            assert_eq!(f.attempts(), 1, "{scheme}: an auth failure is not retried");
            let err = f.hops[0].attempts[0].error.clone().unwrap();
            assert!(err.contains("auth failed") && err.contains(want), "{scheme}: {err}");
            assert!(!err.contains("WRONG-pw") && !serde_json::to_string(&f).unwrap().contains("WRONG-pw"));
        }
        let ok = CFProbe::new(with(Some("user"), Some("s3cret-pw"))).unwrap().inspect(lab.url("/x")).await.unwrap();
        assert_eq!(ok.response.status, 200, "{scheme}");
        assert!(!serde_json::to_string(&ok).unwrap().contains("s3cret-pw"));
    }
    assert_eq!(lab.accepts(), 2, "only the two authenticated requests reached the lab");
}

#[tokio::test]
async fn https_proxy_is_verified_and_its_tls_is_kept_apart_from_the_destinations() {
    let lab = Lab::start(H2_AND_H1).await;
    let (p, log, ca) = test_proxy(TestProxyKind::Https, None, lab.addr).await;
    let ca = ca.unwrap();
    // The proxy's certificate names `localhost`; the proxy is addressed by that name.
    let url = format!("https://localhost:{}", p.port());
    let mut c = proxied(lab.config(), "tls", url.clone());
    c.proxy.proxies[0].ca_file = Some(ca.path().to_path_buf());
    let ex = CFProbe::new(c).unwrap().inspect(lab.url("/x")).await.unwrap();
    assert_eq!((ex.response.status, ex.tls.as_ref().unwrap().sni.as_deref()), (200, Some("localhost")));
    assert!(matches!(ex.connection.route, RouteRecord::Proxy { scheme: ProxyScheme::Https, .. }));
    assert_eq!(log.tunnels.load(Ordering::SeqCst), 1);
    // Without trusting the proxy's certificate: a proxy TLS error, never a fallback.
    let before = lab.accepts();
    let err = CFProbe::new(proxied(lab.config(), "tls", url)).unwrap().inspect(lab.url("/x")).await.unwrap_err();
    assert!(matches!(&err, Error::Proxy { stage: ProxyStage::Tls, detail, .. } if detail.contains("certificate verify")), "{err}");
    assert_eq!(lab.accepts(), before);
}

#[tokio::test]
async fn pinned_addresses_go_to_the_proxy_as_addresses() {
    let (dest, _) = scripted_server(|_| h1_response("200 OK", "", b"ok")).await;
    let (p, log, _) = test_proxy(TestProxyKind::Socks5, None, dest).await;
    let mut c = proxied(Config::default(), "s", format!("socks5://{p}"));
    c.resolve.insert(format!("pinned.test:{}", dest.port()), dest);
    let ex = CFProbe::new(c).unwrap().inspect(Target::get(&format!("http://pinned.test:{}/", dest.port())).unwrap()).await.unwrap();
    assert_eq!(ex.connection.address_source, AddressSource::ResolveOverride);
    assert_eq!(log.targets.lock().unwrap().clone(), [format!("ipv4 127.0.0.1:{}", dest.port())]);
}

#[tokio::test]
async fn redirect_hops_and_retries_stay_on_the_proxy() {
    let (b, _) = scripted_server(|_| h1_response("200 OK", "", b"end")).await;
    let (a, _) = scripted_server(move |_| h1_response("302 Found", &format!("Location: http://second.invalid:{}/\r\n", b.port()), b"")).await;
    // One proxy that maps every .invalid name; route by port to the right server.
    let (p, log, _) = test_proxy(TestProxyKind::Http, None, a).await;
    let e = CFProbe::new(proxied(Config::default(), "r", format!("http://{p}"))).unwrap();
    let s = Session::new(Arc::new(e), Policy { max_redirects: 3, ..Policy::default() }, rand_chacha::ChaCha8Rng::seed_from_u64(1)).unwrap();
    let f = s.fetch(Target::get(&format!("http://first.invalid:{}/", a.port())).unwrap()).await;
    // The test proxy sends every .invalid name to `a`, so the second hop also lands on `a` (302 again):
    // what matters is that both hops asked the proxy, by name.
    let seen = log.targets.lock().unwrap().clone();
    assert!(seen.contains(&format!("first.invalid:{}", a.port())) && seen.contains(&format!("second.invalid:{}", b.port())), "{seen:?}");
    assert!(f.hops.iter().flat_map(|h| &h.attempts).all(|at| at.exchange.as_ref().is_none_or(|x| matches!(x.connection.route, RouteRecord::Proxy { .. }))));
}

#[test]
fn proxy_config_errors_never_become_direct() {
    for json in [
        r#"{"proxy":{"proxies":[{"id":"a","url":"ftp://h:1"}]}}"#,
        r#"{"proxy":{"proxies":[{"id":"a","url":"http://h:1"},{"id":"b","url":"http://h:2"}]}}"#,
        r#"{"proxy":{"proxies":[{"id":"a","url":"http://h:1"}],"select":"zzz"}}"#,
        r#"{"proxy":{"proxies":[{"id":"a","url":"env:CFPROBE_TEST_NEVER_SET"}]}}"#,
        r#"{"proxy":{"select":"a"}}"#,
    ] {
        assert!(matches!(CFProbe::new(Config::from_json(json).unwrap()), Err(Error::Config(_))), "{json}");
    }
}

/// Every place in the library that can open a connection, resolve a name or start a process.
/// Adding one anywhere else fails this test: it must go through `networking::dial` (and so the
/// route) or be added here on purpose.
#[test]
fn only_the_central_dialer_opens_connections() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let allowed: &[(&str, &str)] = &[
        ("TcpStream::connect", "networking/mod.rs"), // direct route (no proxy configured)
        ("TcpStream::connect", "proxy/mod.rs"),      // to the proxy itself
        ("lookup_host", "networking/mod.rs"),        // direct route only
        ("lookup_host", "proxy/mod.rs"),             // the proxy's own host name
        ("Command::new", "runner/mod.rs"),           // curl, given the same route
    ];
    let needles = ["TcpStream::connect", "lookup_host", "UdpSocket", "Command::new", "reqwest", "std::net::TcpStream"];
    let mut found = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
            let text = std::fs::read_to_string(&p).unwrap();
            for line in text.lines().filter(|l| !l.trim_start().starts_with("//")) {
                for n in needles {
                    if line.contains(n) && !allowed.contains(&(n, rel.as_str())) {
                        found.push(format!("{rel}: {n}: {}", line.trim()));
                    }
                }
            }
        }
    }
    assert!(found.is_empty(), "outbound networking outside the central dialer:\n{}", found.join("\n"));
}
