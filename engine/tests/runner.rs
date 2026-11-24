//! The matrix runner end to end against a local server, with both client kinds.

mod common;

use cfprobe::Config;
use cfprobe::runner::{self, Matrix, RunOptions};
use common::*;

/// D25: with --save-bodies, curl's body went into the processed results.json (committed), and a
/// challenge page there carried a live __cf_chl_ token. Bodies belong in raw records only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bodies_stay_out_of_processed_results_for_every_client() {
    let a = raw_server(|_| vec![h1_response("200 OK", "Content-Type: text/html\r\n", b"<html>BODY-MARKER-TEXT</html>")], false).await;
    let dir = tempfile::tempdir().unwrap();
    let matrix: Matrix = serde_json::from_value(serde_json::json!({
        "name": "t", "delay_ms": 0,
        "clients": [{"name": "cfprobe", "kind": "cfprobe"}, {"name": "curl", "kind": "curl"}],
        "cases": [{"id": "c1", "category": "x", "description": "d", "url": format!("http://{a}/")}]
    }))
    .unwrap();
    let path = dir.path().join("m.json");
    let opts = RunOptions { matrix_path: &path, out: dir.path(), base_config: Config::default(), only: None, save_bodies: true, seed: Some(1) };
    let results = runner::run(&matrix, &opts).await.unwrap();
    assert_eq!(results.len(), 2);
    let processed = std::fs::read_to_string(dir.path().join("results.json")).unwrap();
    assert!(!processed.contains("BODY-MARKER-TEXT"), "a body reached results.json");
    for client in ["cfprobe", "curl"] {
        let raw = std::fs::read_to_string(dir.path().join("raw").join(client).join("c1.json")).unwrap();
        assert!(raw.contains("BODY-MARKER-TEXT"), "{client}: raw record keeps the body");
    }
}

fn matrix_for(url: String) -> Matrix {
    serde_json::from_value(serde_json::json!({
        "name": "t", "delay_ms": 0,
        "clients": [{"name": "cfprobe", "kind": "cfprobe"}, {"name": "curl", "kind": "curl"}],
        "cases": [{"id": "c1", "category": "x", "description": "d", "url": url}]
    }))
    .unwrap()
}

/// Proxy-first campaigns: the preflight checks the proxy before any case, both clients (cfprobe and
/// curl) go through it, and the route is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn campaigns_run_through_the_proxy_for_every_client() {
    let (dest, hits) = scripted_server(|_| h1_response("200 OK", "", b"ok")).await;
    let (p, log, _) = test_proxy(TestProxyKind::Http, None, dest).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.json");
    let base = proxied(Config::default(), "camp", format!("http://{p}"));
    let opts = RunOptions { matrix_path: &path, out: dir.path(), base_config: base, only: None, save_bodies: false, seed: Some(1) };
    let results = runner::run(&matrix_for(format!("http://site.invalid:{}/", dest.port())), &opts).await.unwrap();
    assert!(results.iter().all(|r| r.status == Some(200)), "{:?}", results.iter().map(|r| (&r.client, r.status, &r.details)).collect::<Vec<_>>());
    let run: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.path().join("run.json")).unwrap()).unwrap();
    assert_eq!(run["route"]["id"], "camp");
    assert_eq!(run["proxy_preflight"]["ok"], true);
    // preflight + cfprobe + curl: three tunnels, and the destination saw exactly the two requests.
    assert_eq!(log.tunnels.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    // `.invalid` cannot resolve locally: curl reached it only because the proxy resolved it.
    assert!(log.targets.lock().unwrap().iter().all(|t| t == &format!("site.invalid:{}", dest.port())));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_proxy_stops_the_campaign_before_any_request() {
    let (dest, hits) = scripted_server(|_| h1_response("200 OK", "", b"ok")).await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.json");
    let opts = RunOptions { matrix_path: &path, out: dir.path(), base_config: proxied(Config::default(), "dead", format!("http://{closed}")), only: None, save_bodies: false, seed: Some(1) };
    let err = runner::run(&matrix_for(format!("http://127.0.0.1:{}/", dest.port())), &opts).await.unwrap_err();
    assert!(err.to_string().contains("proxy \"dead\""), "{err}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing went direct");
}
