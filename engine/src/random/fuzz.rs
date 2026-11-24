//! `cfprobe fuzz`: run seeded random scenarios against the loopback mock server and check each one.
//!
//! Checks per scenario: the verdict is the one the scenario was built to produce; a decodable body
//! arrives byte for byte; every `Set-Cookie` and every repeated header is recorded (none silently
//! dropped); injected latency shows in the timings; no task panics. Each scenario runs in its own
//! `Session` on one shared engine, so concurrent runs also exercise the shared connection pool.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use tokio::sync::Semaphore;

use super::mock::MockServer;
use super::scenario::{self, Fault, Scenario, Transport};
use crate::cloudflare::Verdict;
use crate::core::{Config, Target};
use crate::networking::CFProbe;
use crate::resilience::{FetchOutcome, Policy, RetryPolicy, Session};

#[derive(Debug, Clone)]
pub struct FuzzOptions {
    pub seed: Option<u64>,
    pub count: u64,
    pub only: Option<u64>,
    pub concurrency: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResult {
    pub index: u64,
    pub scenario: Scenario,
    pub expected: scenario::Expected,
    pub verdict: Option<Verdict>,
    pub outcome: Option<FetchOutcome>,
    pub attempts: usize,
    pub elapsed_ms: u64,
    pub checks: Vec<Check>,
    pub pass: bool,
    pub reproduce: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzReport {
    pub seed: u64,
    pub seed_given: bool,
    pub count: u64,
    pub concurrency: usize,
    pub client_request_timeout_ms: u64,
    pub started: String,
    pub elapsed_ms: u64,
    pub passed: usize,
    pub failed: usize,
    /// Scenario kinds run, for coverage: e.g. `fault:close_mid_body` -> 9.
    pub coverage: BTreeMap<String, usize>,
    pub results: Vec<ScenarioResult>,
}

const REQUEST_TIMEOUT_MS: u64 = 1_500;

pub async fn run(opts: &FuzzOptions) -> crate::core::Result<FuzzReport> {
    let seed = super::seed_or_new(opts.seed);
    let started = Instant::now();
    let indexes: Vec<u64> = match opts.only {
        Some(i) => vec![i],
        None => (0..opts.count).collect(),
    };
    let scenarios: Vec<Scenario> = indexes.iter().map(|&i| scenario::generate(&mut super::stream(seed, i), i)).collect();
    let scenarios = Arc::new(scenarios);
    let mock = MockServer::start(scenarios.clone()).await.map_err(|e| crate::core::Error::Config(format!("mock server: {e}")))?;
    let refused = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| crate::core::Error::Config(e.to_string()))?;
        l.local_addr().map_err(|e| crate::core::Error::Config(e.to_string()))?
    }; // dropped: nothing listens there now

    let mut base = Config { request_timeout_ms: REQUEST_TIMEOUT_MS, connect_timeout_ms: 1_000, ..Config::default() };
    for a in [mock.tls_h1, mock.tls_h2] {
        base.resolve.insert(format!("localhost:{}", a.port()), a);
    }
    let mut trusted = base.clone();
    trusted.tls.ca_file = Some(mock.ca_file.path().to_path_buf());
    let trusted = Arc::new(CFProbe::new(trusted)?);
    let untrusted = Arc::new(CFProbe::new(base)?);

    let sem = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for s in scenarios.iter().cloned() {
        let (sem, trusted, untrusted) = (sem.clone(), trusted.clone(), untrusted.clone());
        let url = match (s.fault, s.transport) {
            (Fault::DnsFailure, _) => format!("http://s{}.cfprobe-fuzz.invalid/s/{}/0", s.index, s.index),
            (Fault::Refused, _) => format!("http://{refused}/s/{}/0", s.index),
            (_, Transport::PlainH1) => format!("http://{}/s/{}/0", mock.plain, s.index),
            (_, Transport::TlsH1) => format!("https://localhost:{}/s/{}/0", mock.tls_h1.port(), s.index),
            (_, Transport::TlsH2) => format!("https://localhost:{}/s/{}/0", mock.tls_h2.port(), s.index),
        };
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let engine = if s.fault == Fault::UntrustedCertificate { untrusted } else { trusted };
            let index = s.index;
            // Each scenario in its own task: a panic is caught by the JoinSet and reported, not lost.
            let inner = tokio::spawn(run_one(engine, s.clone(), url, seed));
            match inner.await {
                Ok(r) => r,
                Err(e) => failed_task(&s, seed, if e.is_panic() { "panicked" } else { "task failed" }),
            }
            .with_index(index)
        });
    }
    let mut results = Vec::new();
    while let Some(r) = set.join_next().await {
        results.push(r.map_err(|e| crate::core::Error::Config(format!("fuzz task: {e}")))?);
    }
    results.sort_by_key(|r: &ScenarioResult| r.index);
    let mut coverage = BTreeMap::new();
    for r in &results {
        let f = serde_json::to_value(r.scenario.fault).unwrap()["kind"].as_str().unwrap_or("?").to_string();
        let b = serde_json::to_value(&r.scenario.body).unwrap()["kind"].as_str().unwrap_or("?").to_string();
        *coverage.entry(format!("fault:{f}")).or_insert(0) += 1;
        *coverage.entry(format!("body:{b}")).or_insert(0) += 1;
        *coverage.entry(format!("transport:{}", serde_json::to_value(r.scenario.transport).unwrap().as_str().unwrap_or("?"))).or_insert(0) += 1;
        if let Some(e) = r.scenario.encoding {
            *coverage.entry(format!("encoding:{}", serde_json::to_value(e).unwrap().as_str().unwrap_or("?"))).or_insert(0) += 1;
        }
        if r.scenario.redirects > 0 {
            *coverage.entry(format!("redirects:{}", if r.scenario.redirect_loop { "loop" } else { "chain" })).or_insert(0) += 1;
        }
    }
    let passed = results.iter().filter(|r| r.pass).count();
    Ok(FuzzReport {
        seed,
        seed_given: opts.seed.is_some(),
        count: indexes.len() as u64,
        concurrency: opts.concurrency.max(1),
        client_request_timeout_ms: REQUEST_TIMEOUT_MS,
        started: crate::runner::now_rfc3339(),
        elapsed_ms: started.elapsed().as_millis() as u64,
        passed,
        failed: results.len() - passed,
        coverage,
        results,
    })
}

trait WithIndex {
    fn with_index(self, i: u64) -> Self;
}

impl WithIndex for ScenarioResult {
    fn with_index(mut self, i: u64) -> Self {
        self.index = i;
        self
    }
}

fn reproduce(seed: u64, index: u64) -> String {
    format!("cfprobe fuzz --seed {seed} --only {index}")
}

fn failed_task(s: &Scenario, seed: u64, why: &str) -> ScenarioResult {
    ScenarioResult {
        index: s.index,
        scenario: s.clone(),
        expected: s.expected(s.redirects > 0),
        verdict: None,
        outcome: None,
        attempts: 0,
        elapsed_ms: 0,
        checks: vec![Check { name: "no_panic", ok: false, detail: why.into() }],
        pass: false,
        reproduce: reproduce(seed, s.index),
    }
}

async fn run_one(engine: Arc<CFProbe>, s: Scenario, url: String, seed: u64) -> ScenarioResult {
    let following = s.redirects > 0;
    let policy = Policy {
        max_redirects: if following { 5 } else { 0 },
        cookies: true,
        retry: RetryPolicy { max_attempts: 2, base_delay_ms: 10, max_delay_ms: 50, jitter: 0.5, honor_retry_after: true, max_retry_after_ms: 1_500 },
        circuit: None,
    };
    let session = Session::new(engine, policy, super::stream(seed, s.index ^ (1 << 63))).expect("valid fuzz policy");
    let t0 = Instant::now();
    let fetch = session.fetch(Target::get(&url).expect("fuzz URLs are valid")).await;
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    let expected = s.expected(following);
    let verdict = fetch.analysis.as_ref().map(|a| a.verdict);
    let mut checks = Vec::new();

    if expected.redirect_loop {
        let ok = matches!(fetch.outcome, FetchOutcome::RedirectLoop { .. });
        checks.push(Check { name: "redirect_loop_detected", ok, detail: format!("{:?}", fetch.outcome) });
    } else {
        checks.push(Check { name: "verdict", ok: verdict == Some(expected.verdict), detail: format!("expected {:?}, got {verdict:?}", expected.verdict) });
    }

    if let Some(ex) = fetch.last_exchange().filter(|_| !expected.redirect_loop) {
        if expected.body_must_match && ex.response.status != 204 {
            let want = s.plain_body();
            let ok = ex.response.body.as_ref() == want.as_slice();
            checks.push(Check { name: "body_intact", ok, detail: format!("got {} bytes, want {}", ex.response.body.len(), want.len()) });
        }
        let got = ex.response.set_cookies.len();
        checks.push(Check { name: "set_cookies_all_recorded", ok: got == s.set_cookies.len(), detail: format!("{got} recorded of {} sent", s.set_cookies.len()) });
        let mut want: BTreeMap<&str, usize> = BTreeMap::new();
        for (k, _) in &s.extra_headers {
            *want.entry(k.as_str()).or_default() += 1;
        }
        for (name, n) in want {
            let got = ex.response.headers.iter().filter(|h| h.name == name).count();
            checks.push(Check { name: "repeated_headers_all_recorded", ok: got == n, detail: format!("{name}: {got} of {n}") });
        }
        if let Fault::Latency { ms } = s.fault {
            checks.push(Check { name: "latency_visible", ok: ex.timings.ttfb_ms + 1.0 >= ms as f64, detail: format!("ttfb {:.0} ms, injected {ms} ms", ex.timings.ttfb_ms) });
        }
        let json = serde_json::to_string(ex).unwrap_or_default();
        checks.push(Check { name: "no_cookie_value_in_record", ok: !json.contains("quoted value"), detail: String::new() });
    }
    if s.fault == Fault::Timeout {
        let bounded = elapsed_ms < 2 * (REQUEST_TIMEOUT_MS + 200) + 200;
        checks.push(Check { name: "timeout_bounded", ok: bounded, detail: format!("{elapsed_ms} ms for 2 attempts of {REQUEST_TIMEOUT_MS} ms") });
    }
    let pass = checks.iter().all(|c| c.ok);
    ScenarioResult {
        index: s.index,
        expected,
        verdict,
        outcome: Some(fetch.outcome.clone()),
        attempts: fetch.attempts(),
        elapsed_ms,
        checks,
        pass,
        reproduce: reproduce(seed, s.index),
        scenario: s,
    }
}

pub fn markdown(r: &FuzzReport) -> String {
    let mut out = format!(
        "# cfprobe fuzz\n\nSeed **{}** ({}), {} scenarios, concurrency {}, client request timeout {} ms, run {} in {} ms.\n\n**{} passed, {} failed.**\n\n",
        r.seed,
        if r.seed_given { "given" } else { "generated" },
        r.count,
        r.concurrency,
        r.client_request_timeout_ms,
        r.started,
        r.elapsed_ms,
        r.passed,
        r.failed
    );
    out.push_str("## Coverage\n\n| kind | scenarios |\n|---|---|\n");
    for (k, v) in &r.coverage {
        out.push_str(&format!("| {k} | {v} |\n"));
    }
    let failed: Vec<_> = r.results.iter().filter(|x| !x.pass).collect();
    if !failed.is_empty() {
        out.push_str("\n## Failures\n\n| scenario | transport | status | body | fault | failed checks | reproduce |\n|---|---|---|---|---|---|---|\n");
        for f in failed {
            let bad: Vec<String> = f.checks.iter().filter(|c| !c.ok).map(|c| format!("{}: {}", c.name, c.detail)).collect();
            out.push_str(&format!(
                "| {} | {:?} | {} | {} | {} | {} | `{}` |\n",
                f.index,
                f.scenario.transport,
                f.scenario.status,
                serde_json::to_value(&f.scenario.body).unwrap()["kind"].as_str().unwrap_or("?"),
                serde_json::to_value(f.scenario.fault).unwrap()["kind"].as_str().unwrap_or("?"),
                bad.join("; ").replace('|', "\\|"),
                f.reproduce
            ));
        }
    }
    out
}
