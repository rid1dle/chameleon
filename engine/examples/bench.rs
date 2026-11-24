//! Performance harness (loopback only).
//!
//!   bench serve                      start the mock server with one 2 KiB 200 response, print its
//!                                    ports and CA as JSON, run until killed
//!   bench load <client> <url> <n> <concurrency> [--ca pem] [--resolve host:port:addr] [--h1]
//!                                    n requests, `client` = cfprobe | reqwest; prints JSON with
//!                                    latency percentiles, throughput, CPU time, peak and sampled RSS
//!
//! The server runs in its own process so the client's CPU and memory are measured alone.

use std::sync::Arc;
use std::time::{Duration, Instant};

use cfprobe::random::mock::MockServer;
use cfprobe::random::scenario::{Body, Fault, Scenario, Transport};
use cfprobe::{CFProbe, Config, Target};
use tokio::sync::Semaphore;

fn proc_status(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with(key)).and_then(|l| l.split_whitespace().nth(1)?.parse().ok()))
        .unwrap_or(0)
}

/// (user, system) CPU milliseconds of this process.
fn cpu_ms() -> (u64, u64) {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after = s.rsplit_once(')').map(|x| x.1).unwrap_or("");
    let f: Vec<u64> = after.split_whitespace().filter_map(|x| x.parse().ok()).collect();
    // fields after ")" start at state (non-numeric, skipped); utime and stime are 14th/15th overall.
    let tick = 10; // CLK_TCK 100 on Linux
    (f.get(10).copied().unwrap_or(0) * tick, f.get(11).copied().unwrap_or(0) * tick)
}

fn scenario() -> Scenario {
    Scenario {
        index: 0,
        transport: Transport::PlainH1,
        status: 200,
        cloudflare: false,
        body: Body::Text,
        filler: 2048,
        encoding: None,
        chunked: false,
        set_cookies: vec![],
        extra_headers: vec![],
        retry_after: None,
        redirects: 0,
        redirect_loop: false,
        fault: Fault::None,
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => {
            let m = MockServer::start(Arc::new(vec![scenario()])).await.unwrap();
            println!(
                "{}",
                serde_json::json!({"plain": m.plain.to_string(), "tls_h1": m.tls_h1.to_string(), "tls_h2": m.tls_h2.to_string(), "ca": m.ca_file.path()})
            );
            // Keep the CA file: copy it where the caller can read it after this process prints.
            tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
        }
        Some("load") => load(&args[1..]).await,
        _ => eprintln!("usage: bench serve | bench load <cfprobe|reqwest> <url> <n> <concurrency> [--ca pem] [--resolve h:p:a] [--h1]"),
    }
}

async fn load(a: &[String]) {
    let (client, url, n, conc) = (a[0].as_str(), a[1].clone(), a[2].parse::<usize>().unwrap(), a[3].parse::<usize>().unwrap());
    let mut ca = None;
    let mut resolve = None;
    let mut h1 = false;
    // Leak checks: keep no per-request data, so RSS growth is the client's alone.
    let mut no_latency = false;
    // CPU profile (SIGPROF sampling, no kernel perf access needed): self and total samples per
    // function, written as text.
    let mut profile: Option<String> = None;
    let mut i = 4;
    while i < a.len() {
        match a[i].as_str() {
            "--ca" => {
                ca = Some(a[i + 1].clone());
                i += 2;
            }
            "--resolve" => {
                resolve = Some(a[i + 1].clone());
                i += 2;
            }
            "--h1" => {
                h1 = true;
                i += 1;
            }
            "--no-latency" => {
                no_latency = true;
                i += 1;
            }
            "--profile" => {
                profile = Some(a[i + 1].clone());
                i += 2;
            }
            x => panic!("unknown {x}"),
        }
    }
    // A loopback benchmark: it never sends anything off this machine, so it has no route to choose.
    let host = url::Url::parse(&url).ok().and_then(|u| u.host().map(|h| h.to_string()));
    let loopback = host.as_deref().is_some_and(|h| h == "localhost" || h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()));
    if !loopback {
        eprintln!("bench load measures loopback servers only; {url} is not one");
        std::process::exit(2);
    }
    let rss_start = proc_status("VmRSS:");
    let guard = profile.as_ref().map(|_| pprof::ProfilerGuardBuilder::default().frequency(1000).build().unwrap());
    let started = Instant::now();
    let send: Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync> = match client {
        "cfprobe" => {
            let mut c = Config::default();
            if let Some(p) = &ca {
                c.tls.ca_file = Some(p.into());
            }
            if let Some(r) = &resolve {
                let (hp, addr) = r.rsplit_once(':').unwrap();
                let port: u16 = hp.rsplit_once(':').unwrap().1.parse().unwrap();
                c.resolve.insert(hp.to_string(), std::net::SocketAddr::new(addr.parse().unwrap(), port));
            }
            if h1 {
                c.tls.alpn = vec!["http/1.1".into()];
            }
            let e = Arc::new(CFProbe::new(c).unwrap());
            let t = Target::get(&url).unwrap();
            Arc::new(move || {
                let (e, t) = (e.clone(), t.clone());
                Box::pin(async move { e.inspect(t).await.is_ok_and(|x| x.response.status == 200) })
            })
        }
        "reqwest" => {
            let mut b = reqwest::Client::builder();
            if ca.is_some() {
                // The mock's throwaway certificate is a self-signed CA used as end entity, which
                // rustls refuses; see examples/reqwest_get.rs.
                b = b.danger_accept_invalid_certs(true);
            }
            if let Some(r) = &resolve {
                let (hp, addr) = r.rsplit_once(':').unwrap();
                let (host, port) = hp.rsplit_once(':').unwrap();
                b = b.resolve(host, std::net::SocketAddr::new(addr.parse().unwrap(), port.parse().unwrap()));
            }
            if h1 {
                b = b.http1_only();
            }
            let c = b.build().unwrap();
            let url = url.clone();
            Arc::new(move || {
                let (c, u) = (c.clone(), url.clone());
                Box::pin(async move {
                    match c.get(&u).send().await {
                        Ok(r) => r.status() == 200 && r.bytes().await.is_ok(),
                        Err(_) => false,
                    }
                })
            })
        }
        x => panic!("client {x}"),
    };
    let sem = Arc::new(Semaphore::new(conc));
    let samples = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut lat = Vec::with_capacity(n);
    let mut set = tokio::task::JoinSet::new();
    for k in 0..n {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let (send, samples) = (send.clone(), samples.clone());
        set.spawn(async move {
            let t = Instant::now();
            let ok = send().await;
            drop(permit);
            if k % (n / 10).max(1) == 0 {
                samples.lock().unwrap().push((k, proc_status("VmRSS:")));
            }
            (t.elapsed().as_secs_f64() * 1000.0, ok)
        });
        while set.len() > conc * 2 {
            let (ms, ok) = set.join_next().await.unwrap().unwrap();
            if !no_latency || !ok || lat.is_empty() {
                lat.push((ms, ok));
            }
        }
    }
    while let Some(r) = set.join_next().await {
        let (ms, ok) = r.unwrap();
        if !no_latency || !ok || lat.is_empty() {
            lat.push((ms, ok));
        }
    }
    let wall = started.elapsed().as_secs_f64();
    if let (Some(g), Some(path)) = (guard, &profile) {
        write_profile(&g.report().build().unwrap(), path);
    }
    let failed = lat.iter().filter(|x| !x.1).count();
    if failed > 0 {
        // Latencies of failed requests are not performance numbers: refuse to report them.
        eprintln!("{failed} of {n} requests failed: no measurement reported");
        std::process::exit(1);
    }
    let mut ms: Vec<f64> = lat.iter().map(|x| x.0).collect();
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| ms[((ms.len() as f64 * p) as usize).min(ms.len() - 1)];
    let (u, s) = cpu_ms();
    let mut rss = samples.lock().unwrap().clone();
    rss.sort();
    println!(
        "{}",
        serde_json::json!({
            "client": client, "url": url, "requests": n, "concurrency": conc, "http1_only": h1, "failed": failed,
            "wall_s": (wall * 1000.0).round() / 1000.0, "requests_per_s": (n as f64 / wall).round(),
            "latency_ms": {"p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99), "max": ms[ms.len() - 1]},
            "cpu_ms": {"user": u, "system": s, "per_request_us": ((u + s) as f64 * 1000.0 / n as f64).round()},
            "rss_kb": {"start": rss_start, "peak_hwm": proc_status("VmHWM:"), "end": proc_status("VmRSS:"), "samples": rss},
        })
    );
}

/// Self samples (the function on top of the stack) and total samples (anywhere in the stack), top 60
/// of each, from a pprof report.
fn write_profile(report: &pprof::Report, path: &str) {
    use std::collections::HashMap;
    let (mut selfc, mut total): (HashMap<String, usize>, HashMap<String, usize>) = (HashMap::new(), HashMap::new());
    let mut all = 0usize;
    for (frames, &count) in &report.data {
        let count = count.max(0) as usize;
        all += count;
        let names: Vec<String> = frames.frames.iter().flat_map(|f| f.iter().map(|s| s.name())).collect();
        if let Some(top) = names.first() {
            *selfc.entry(top.clone()).or_default() += count;
        }
        let mut seen = std::collections::HashSet::new();
        for n in names {
            if seen.insert(n.clone()) {
                *total.entry(n).or_default() += count;
            }
        }
    }
    let fmt = |m: HashMap<String, usize>| {
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
        v.into_iter().take(400).map(|(n, c)| format!("{:6.2}%  {}", 100.0 * c as f64 / all.max(1) as f64, n)).collect::<Vec<_>>().join("\n")
    };
    std::fs::write(path, format!("samples {all}\n\n== self\n{}\n\n== total\n{}\n", fmt(selfc), fmt(total))).unwrap();
}
