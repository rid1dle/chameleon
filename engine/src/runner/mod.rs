//! Test matrix runner: many configured cases, each run by one or more clients, each result saved
//! with its evidence, classification and how to reproduce it.
//!
//! A matrix is JSON:
//! ```json
//! { "name": "P2 zone",
//!   "delay_ms": 1000,
//!   "clients": [ {"name": "cfprobe", "kind": "cfprobe", "config": {}},
//!                {"name": "curl", "kind": "curl"} ],
//!   "cases": [ {"id": "zone-managed", "category": "challenge", "description": "Managed Challenge rule on /c/",
//!               "url": "https://lab.riddlelab.dev/c/echo", "headers": [["accept", "text/html"]],
//!               "expect": {"verdict": "CONFIRMED_CHALLENGE_RESPONSE", "status": 403}} ] }
//! ```
//! `expect` is optional: a case without one is an observation (`observed`), never a pass. Expected
//! values are only written for infrastructure whose configuration is known (the zone lab, local
//! servers); third-party cases are observations.
//!
//! Output, under `--out`: `raw/<client>/<case>.json` (the full record, body included only with
//! `save_bodies`), `results.json` and `results.md` (one row per case and client).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cloudflare::{self, Analysis, Verdict};
use crate::core::{Config, Error, Result, Target};
use crate::http::{HeaderEntry, header_list};
use crate::networking::CFProbe;
use crate::random::{Schedule, jitter_rng, seed_or_new};
use crate::resilience::{Decision, Fetch, FetchOutcome, Policy, Session};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matrix {
    pub name: String,
    /// Pause between requests, so third-party sites see ordinary pacing. With `max_delay_ms` it is
    /// the lower bound of a uniformly random pause (bounded jitter).
    #[serde(default = "default_delay")]
    pub delay_ms: u64,
    #[serde(default)]
    pub max_delay_ms: Option<u64>,
    /// Run cases in a random order drawn from the seed (the same order for every client).
    #[serde(default)]
    pub shuffle: bool,
    /// Seed for order, pauses and retry jitter. `--seed` overrides it; when neither is given one is
    /// generated. Always recorded in the results.
    #[serde(default)]
    pub seed: Option<u64>,
    /// Fields laid over `Policy::runner_default()` (redirects 5, cookies on, 3 attempts, breaker on).
    #[serde(default)]
    pub policy: Option<serde_json::Value>,
    #[serde(default = "default_clients")]
    pub clients: Vec<ClientSpec>,
    pub cases: Vec<Case>,
}

fn default_delay() -> u64 {
    1000
}

fn default_clients() -> Vec<ClientSpec> {
    vec![ClientSpec { name: "cfprobe".into(), kind: ClientKind::Cfprobe, config: None }]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSpec {
    pub name: String,
    pub kind: ClientKind,
    /// cfprobe only: a `Config`, merged over the run's base config field by field.
    #[serde(default)]
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    Cfprobe,
    /// The `curl` on PATH, same URL and headers, `--compressed`, no redirects followed.
    Curl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub category: String,
    pub description: String,
    pub url: String,
    #[serde(default = "get")]
    pub method: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Requests in sequence on one engine; the last one is classified (all are recorded).
    #[serde(default = "one")]
    pub repeat: u32,
    #[serde(default)]
    pub expect: Option<Expect>,
    /// Run only by these clients (names). Default: every client.
    #[serde(default)]
    pub clients: Option<Vec<String>>,
    /// Fields laid over the matrix policy for this case, e.g. `{"retry": {"max_attempts": 1}}`.
    #[serde(default)]
    pub policy: Option<serde_json::Value>,
}

fn get() -> String {
    "GET".into()
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub verdict: Option<Verdict>,
    pub status: Option<u16>,
    /// How the fetch must end: `completed`, `redirect_loop`, `too_many_redirects`, `circuit_open`.
    #[serde(default)]
    pub fetch_outcome: Option<String>,
    /// Text the final (decoded) body must contain.
    #[serde(default)]
    pub body_contains: Option<String>,
    /// Statuses of every attempt in order, e.g. `[429, 200]` for a rate limit waited out.
    #[serde(default)]
    pub attempt_statuses: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Fail,
    /// No expectation was configured: the result is an observation.
    Observed,
    /// The request did not complete.
    Error,
}

/// One case run by one client.
#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub case_id: String,
    pub category: String,
    pub description: String,
    pub client: String,
    pub timestamp: String,
    pub request: RequestConfig,
    pub status: Option<u16>,
    pub http_version: Option<String>,
    /// Headers that matter for classification and transport, redacted.
    pub relevant_headers: Vec<HeaderEntry>,
    pub tls: Option<serde_json::Value>,
    pub response_meta: Option<serde_json::Value>,
    pub analysis: Option<Analysis>,
    pub expect: Option<Expect>,
    pub seed: u64,
    /// The resilience policy in force for this case.
    pub policy: Policy,
    /// How the last fetch ended (completed, redirect loop, circuit open, ...).
    pub fetch_outcome: Option<FetchOutcome>,
    /// Every attempt of every hop of the last fetch, in order.
    pub attempts: Vec<AttemptSummary>,
    pub outcome: Outcome,
    /// Why the outcome is `fail` (each mismatch) or `error`.
    pub details: Vec<String>,
    pub reproduce: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttemptSummary {
    /// Which fetch of a repeated case (0-based).
    pub fetch: usize,
    pub hop: usize,
    pub url: String,
    pub attempt: u32,
    pub status: Option<u16>,
    pub verdict: Verdict,
    pub waited_ms: u64,
    pub elapsed_ms: u64,
    pub decision: Decision,
}

fn summarize(n: usize, f: &Fetch) -> Vec<AttemptSummary> {
    f.hops
        .iter()
        .enumerate()
        .flat_map(|(i, h)| {
            h.attempts.iter().map(move |a| AttemptSummary {
                fetch: n,
                hop: i,
                url: h.url.clone(),
                attempt: a.number,
                status: a.exchange.as_ref().map(|x| x.response.status),
                verdict: a.analysis.verdict,
                waited_ms: a.waited_ms,
                elapsed_ms: a.elapsed_ms,
                decision: a.decision.clone(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestConfig {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub repeat: u32,
    /// cfprobe: the config in force; curl: the command line.
    pub client_config: serde_json::Value,
}

const RELEVANT: [&str; 12] = [
    "server", "cf-ray", "cf-mitigated", "cf-cache-status", "content-type", "content-encoding", "location",
    "retry-after", "set-cookie", "alt-svc", "critical-ch", "accept-ch",
];

pub struct RunOptions<'a> {
    pub matrix_path: &'a Path,
    pub out: &'a Path,
    pub base_config: Config,
    pub only: Option<String>,
    pub save_bodies: bool,
    /// Overrides the matrix seed.
    pub seed: Option<u64>,
}

pub async fn run(matrix: &Matrix, opts: &RunOptions<'_>) -> Result<Vec<CaseResult>> {
    let io = |e: std::io::Error| Error::Config(format!("{}: {e}", opts.out.display()));
    let seed = seed_or_new(opts.seed.or(matrix.seed));
    let base_policy: Policy = merge_json(&Policy::runner_default(), matrix.policy.as_ref(), "matrix policy")?;
    base_policy.validate()?;
    let route = opts.base_config.proxy.route()?;
    let preflight = preflight(&route, matrix, opts).await?;
    std::fs::create_dir_all(opts.out).map_err(io)?;
    std::fs::write(
        opts.out.join("run.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "matrix": matrix.name, "seed": seed, "started": now_rfc3339(), "route": route.record(), "route_description": route.describe(),
            "proxy_preflight": preflight,
        }))
        .unwrap(),
    )
    .map_err(io)?;
    let mut results = Vec::new();
    let mut first = true;
    for client in &matrix.clients {
        let session = match client.kind {
            ClientKind::Cfprobe => {
                let engine = CFProbe::new(merge_json(&opts.base_config, client.config.as_ref(), "client config")?)?;
                Some(Session::new(std::sync::Arc::new(engine), base_policy.clone(), jitter_rng(seed))?)
            }
            ClientKind::Curl => None,
        };
        let curl_jar = tempdir_path(&format!("jar-{}", client.name));
        let raw_dir = opts.out.join("raw").join(&client.name);
        std::fs::create_dir_all(&raw_dir).map_err(io)?;
        let cases: Vec<&Case> = matrix
            .cases
            .iter()
            .filter(|c| opts.only.as_deref().is_none_or(|o| o == c.id) && c.clients.as_ref().is_none_or(|names| names.contains(&client.name)))
            .collect();
        let schedule = Schedule::new(seed, cases.len(), matrix.shuffle, matrix.delay_ms, matrix.max_delay_ms.unwrap_or(matrix.delay_ms));
        for (position, &i) in schedule.order.iter().enumerate() {
            let case = cases[i];
            if !first {
                // Within a client the schedule's jittered pause; between clients the minimum.
                let pause = if position == 0 { Duration::from_millis(matrix.delay_ms) } else { schedule.delay(position) };
                tokio::time::sleep(pause).await;
            }
            first = false;
            let policy: Policy = merge_json(&base_policy, case.policy.as_ref(), &format!("case {} policy", case.id))?;
            policy.validate()?;
            let (result, raw) = match &session {
                Some(s) => run_cfprobe(s, &policy, client, case, opts, seed).await,
                None => run_curl(client, case, opts, &policy, &curl_jar, seed, &route).await,
            };
            let result = scrub_location(result);
            let raw_path = raw_dir.join(format!("{}.json", case.id));
            let record = serde_json::json!({ "result": result, "raw": raw });
            std::fs::write(&raw_path, serde_json::to_vec_pretty(&record).unwrap()).map_err(io)?;
            eprintln!("{} [{}] {:?} {}", case.id, client.name, result.outcome, result.analysis.as_ref().map(|a| verdict_name(a.verdict)).unwrap_or_default());
            results.push(result);
        }
        let _ = std::fs::remove_file(&curl_jar);
    }
    std::fs::write(opts.out.join("results.json"), serde_json::to_vec_pretty(&results).unwrap()).map_err(io)?;
    std::fs::write(opts.out.join("results.md"), markdown(matrix, &results, opts)).map_err(io)?;
    Ok(results)
}

/// Before any case runs through a proxy: open one tunnel to the first case's origin, which checks
/// the proxy, its credentials and that it reaches the destination. A failure stops the campaign
/// (nothing runs, nothing goes direct). With no proxy there is nothing to check.
async fn preflight(route: &crate::proxy::Route, matrix: &Matrix, opts: &RunOptions<'_>) -> Result<serde_json::Value> {
    let crate::proxy::Route::Proxy(p) = route else {
        return Ok(serde_json::json!({ "skipped": "no proxy defined: direct connections" }));
    };
    let Some(first) = matrix.cases.iter().find(|c| opts.only.as_deref().is_none_or(|o| o == c.id)) else {
        return Ok(serde_json::json!({ "skipped": "no cases" }));
    };
    let url = url::Url::parse(&first.url).map_err(|e| Error::Target(e.to_string()))?;
    let host = url.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']').to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let t = crate::proxy::open_tunnel(p, &host, port, Duration::from_millis(opts.base_config.connect_timeout_ms)).await?;
    drop(t.io);
    Ok(serde_json::json!({
        "proxy": p.id, "scheme": p.scheme, "destination": format!("{host}:{port}"),
        "connect_ms": t.connect_ms, "negotiate_ms": t.negotiate_ms, "ok": true,
    }))
}

/// `base` with `over`'s fields laid on top, one level deep for objects.
fn merge_json<T: Serialize + serde::de::DeserializeOwned>(base: &T, over: Option<&serde_json::Value>, what: &str) -> Result<T> {
    let mut v = serde_json::to_value(base).map_err(|e| Error::Config(e.to_string()))?;
    if let Some(serde_json::Value::Object(o)) = over {
        for (k, val) in o {
            match (v.get_mut(k), val) {
                (Some(serde_json::Value::Object(dst)), serde_json::Value::Object(src)) => {
                    for (k2, v2) in src {
                        dst.insert(k2.clone(), v2.clone());
                    }
                }
                _ => {
                    v[k] = val.clone();
                }
            }
        }
    }
    serde_json::from_value(v).map_err(|e| Error::Config(format!("{what}: {e}")))
}

fn target(case: &Case) -> Result<Target> {
    let mut t = Target::get(&case.url)?;
    t.method = case.method.clone();
    for (k, v) in &case.headers {
        t = t.header(k, v);
    }
    Ok(t)
}

fn verdict_name(v: Verdict) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

/// Pass/fail against the expectation. A request that got no response is still judged by its
/// verdict (an expected CONNECTION_FAILURE passes); without an expectation it is an error.
/// What a run produced beyond status and verdict, for the optional expectations.
#[derive(Default)]
struct Observed<'a> {
    fetch_outcome: Option<&'a FetchOutcome>,
    body: Option<&'a [u8]>,
    attempt_statuses: Vec<Option<u16>>,
    /// False for clients whose attempts and fetch outcome are not visible (curl).
    attempts_known: bool,
}

#[cfg(test)]
fn judge(case: &Case, status: Option<u16>, analysis: Option<&Analysis>, error: Option<&str>) -> (Outcome, Vec<String>) {
    judge_full(case, status, analysis, error, &Observed::default())
}

fn judge_full(case: &Case, status: Option<u16>, analysis: Option<&Analysis>, error: Option<&str>, seen: &Observed) -> (Outcome, Vec<String>) {
    let Some(exp) = &case.expect else {
        return match error {
            Some(e) => (Outcome::Error, vec![e.to_string()]),
            None => (Outcome::Observed, Vec::new()),
        };
    };
    let mut misses = Vec::new();
    let mut notes = Vec::new();
    if let Some(s) = exp.status {
        if status != Some(s) {
            misses.push(format!("status: expected {s}, got {status:?}"));
        }
    }
    if let Some(v) = exp.verdict {
        let got = analysis.map(|a| a.verdict);
        if got != Some(v) {
            misses.push(format!("verdict: expected {}, got {}", verdict_name(v), got.map(verdict_name).unwrap_or("none".into())));
        }
    }
    if !seen.attempts_known && (exp.fetch_outcome.is_some() || exp.attempt_statuses.is_some()) {
        notes.push("attempts and fetch outcome are not visible for this client: not checked".to_string());
    }
    if let Some(want) = exp.fetch_outcome.as_ref().filter(|_| seen.attempts_known) {
        let got = seen.fetch_outcome.and_then(|o| serde_json::to_value(o).ok()).and_then(|v| v["outcome"].as_str().map(str::to_string));
        if got.as_deref() != Some(want.as_str()) {
            misses.push(format!("fetch outcome: expected {want}, got {}", got.unwrap_or("none".into())));
        }
    }
    if let Some(want) = &exp.body_contains {
        if !seen.body.is_some_and(|b| String::from_utf8_lossy(b).contains(want.as_str())) {
            misses.push(format!("body does not contain {want:?}"));
        }
    }
    if let Some(want) = exp.attempt_statuses.as_ref().filter(|_| seen.attempts_known) {
        let got: Vec<Option<u16>> = seen.attempt_statuses.clone();
        if got != want.iter().map(|s| Some(*s)).collect::<Vec<_>>() {
            misses.push(format!("attempt statuses: expected {want:?}, got {got:?}"));
        }
    }
    if let (Some(e), false) = (error, misses.is_empty()) {
        misses.push(e.to_string());
    }
    let outcome = if misses.is_empty() { Outcome::Pass } else { Outcome::Fail };
    misses.extend(notes);
    (outcome, misses)
}

fn reproduce(case: &Case, client: &ClientSpec, opts: &RunOptions, seed: u64) -> String {
    format!("cfprobe run {} --out <dir> --seed {seed} --only {}   # client {:?}", opts.matrix_path.display(), case.id, client.name)
}

async fn run_cfprobe(session: &Session, policy: &Policy, client: &ClientSpec, case: &Case, opts: &RunOptions<'_>, seed: u64) -> (CaseResult, serde_json::Value) {
    let request = RequestConfig {
        method: case.method.clone(),
        url: crate::http::redact_url(&case.url),
        headers: case.headers.clone(),
        repeat: case.repeat,
        client_config: serde_json::to_value(session.engine().config()).unwrap_or_default(),
    };
    let mut fetches: Vec<Fetch> = Vec::new();
    let mut error = None;
    match target(case) {
        Err(err) => error = Some(err.to_string()),
        Ok(t) => {
            for _ in 0..case.repeat.max(1) {
                fetches.push(session.fetch_with(t.clone(), policy, std::future::pending::<()>()).await);
            }
        }
    }
    let last_fetch = fetches.last();
    let last = last_fetch.and_then(Fetch::last_exchange);
    let analysis = last_fetch.and_then(|f| f.analysis.clone());
    if error.is_none() {
        if let Some(f) = last_fetch {
            match (&f.outcome, last_fetch.and_then(|f| f.hops.last()).and_then(|h| h.attempts.last()).and_then(|a| a.error.clone())) {
                (FetchOutcome::Completed, Some(e)) => error = Some(e),
                (FetchOutcome::Completed, None) => {}
                (other, _) => error = Some(format!("fetch ended: {}", serde_json::to_string(other).unwrap_or_default())),
            }
        }
    }
    // Every attempt of every fetch, so a repeated case shows the waits in its earlier fetches too.
    let attempts: Vec<AttemptSummary> = fetches.iter().enumerate().flat_map(|(n, f)| summarize(n, f)).collect();
    // A redirect loop or circuit stop is judged by its own expectation, not reported as an error.
    if let (Some(e), Some(exp)) = (&error, &case.expect) {
        if exp.fetch_outcome.is_some() && e.starts_with("fetch ended:") {
            error = None;
        }
    }
    let seen = Observed {
        fetch_outcome: last_fetch.map(|f| &f.outcome),
        body: last.map(|x| x.response.body.as_ref()),
        attempt_statuses: attempts.iter().map(|a| a.status).collect(),
        attempts_known: true,
    };
    let (outcome, details) = judge_full(case, last.map(|x| x.response.status), analysis.as_ref(), error.as_deref(), &seen);
    let result = CaseResult {
        case_id: case.id.clone(),
        category: case.category.clone(),
        description: case.description.clone(),
        client: client.name.clone(),
        timestamp: now_rfc3339(),
        request,
        status: last.map(|x| x.response.status),
        http_version: last.map(|x| x.response.http_version.clone()),
        relevant_headers: last.map(|x| x.response.headers.iter().filter(|h| RELEVANT.contains(&h.name.as_str())).cloned().collect()).unwrap_or_default(),
        tls: last.and_then(|x| x.tls.as_ref()).map(|t| {
            serde_json::json!({ "version": t.version, "cipher": t.cipher, "alpn": t.alpn, "session_reused": t.session_reused, "peer_chain": t.peer_chain })
        }),
        response_meta: last.map(|x| {
            serde_json::json!({
                "body_len": x.response.body_len, "body_decoding": x.response.body_decoding,
                "informational": x.response.informational, "set_cookies": x.response.set_cookies,
                "connection": x.connection, "timings": x.timings,
            })
        }),
        analysis,
        expect: case.expect.clone(),
        seed,
        policy: policy.clone(),
        fetch_outcome: last_fetch.map(|f| f.outcome.clone()),
        attempts,
        outcome,
        details,
        reproduce: reproduce(case, client, opts, seed),
    };
    let raw: Vec<serde_json::Value> = fetches
        .iter()
        .map(|f| {
            let mut v = serde_json::to_value(f).unwrap_or_default();
            if opts.save_bodies {
                if let (Some(x), Some(hops)) = (f.last_exchange(), v["hops"].as_array_mut()) {
                    if let Some(last_attempt) = hops.last_mut().and_then(|h| h["attempts"].as_array_mut()).and_then(|a| a.last_mut()) {
                        last_attempt["exchange"]["response"]["body"] = String::from_utf8_lossy(&x.response.body).into_owned().into();
                    }
                }
            }
            v
        })
        .collect();
    (result, serde_json::json!({ "fetches": raw }))
}

async fn run_curl(client: &ClientSpec, case: &Case, opts: &RunOptions<'_>, policy: &Policy, jar: &Path, seed: u64, route: &crate::proxy::Route) -> (CaseResult, serde_json::Value) {
    let dir = tempdir_path(&case.id);
    let (head, body) = (dir.join("head"), dir.join("body"));
    // The same address pins as the cfprobe clients, so both reach the same edge. Through a proxy,
    // --connect-to makes curl ask the proxy for the pinned address, as cfprobe does; --resolve would
    // be ignored there (the proxy resolves).
    let pin_flag = if matches!(route, crate::proxy::Route::Proxy(_)) { "--connect-to" } else { "--resolve" };
    let mut args: Vec<String> = opts
        .base_config
        .resolve
        .iter()
        .flat_map(|(hp, addr)| {
            let ip = if addr.is_ipv6() { format!("[{}]", addr.ip()) } else { addr.ip().to_string() };
            let v = if pin_flag == "--connect-to" { format!("{hp}:{ip}:{}", addr.port()) } else { format!("{hp}:{ip}") };
            [pin_flag.to_string(), v]
        })
        .collect();
    // The route, the same as cfprobe's: the proxy through the environment (its credentials never
    // reach the command line or the record), or explicitly none, so curl cannot pick up an ambient
    // proxy variable cfprobe would not use.
    match route {
        crate::proxy::Route::Proxy(p) => {
            // cfprobe always tunnels (CONNECT); without this curl would forward plain-HTTP requests
            // in absolute form instead, a different route.
            if p.scheme != crate::proxy::ProxyScheme::Socks5 {
                args.push("--proxytunnel".into());
            }
            if let Some(ca) = &p.ca_file {
                args.extend(["--proxy-cacert".into(), ca.display().to_string()]);
            }
        }
        crate::proxy::Route::Direct => args.extend(["--noproxy".into(), "*".into()]),
    }
    args.extend::<Vec<String>>(vec!["-sS".into(), "--compressed".into(), "-X".into(), case.method.clone(), "-D".into(), head.display().to_string(), "-o".into(), body.display().to_string(), "-w".into(), "%{json}".into()]);
    // The same policy, in curl's terms, so the comparison is like for like.
    if policy.max_redirects > 0 {
        args.extend(["-L".into(), "--max-redirs".into(), policy.max_redirects.to_string()]);
    }
    if policy.cookies {
        args.extend(["-b".into(), jar.display().to_string(), "-c".into(), jar.display().to_string()]);
    }
    if policy.retry.max_attempts > 1 {
        args.extend(["--retry".into(), (policy.retry.max_attempts - 1).to_string(), "--retry-max-time".into(), (policy.retry.max_retry_after_ms / 1000).to_string()]);
    }
    for (k, v) in &case.headers {
        args.push("-H".into());
        args.push(format!("{k}: {v}"));
    }
    args.push(case.url.clone());
    let shown: Vec<String> = args.iter().map(|a| if a == &case.url { crate::http::redact_url(a) } else { a.clone() }).collect();
    let request = RequestConfig {
        method: case.method.clone(),
        url: crate::http::redact_url(&case.url),
        headers: case.headers.clone(),
        repeat: 1,
        client_config: serde_json::json!({ "command": format!("curl {}", shown.join(" ")), "route": route.record() }),
    };
    let _ = std::fs::create_dir_all(&dir);
    let mut cmd = tokio::process::Command::new("curl");
    cmd.args(&args);
    for var in ["ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"] {
        cmd.env_remove(var);
    }
    if let crate::proxy::Route::Proxy(p) = route {
        cmd.env("ALL_PROXY", p.url_with_credentials()).env("NO_PROXY", "");
    }
    let out = cmd.output().await;
    let (mut status, mut http_version, mut headers, mut error, mut meta) = (None, None, Vec::new(), None, None);
    let mut analysis = None;
    let mut body_bytes: Option<Vec<u8>> = None;
    match out {
        Err(e) => error = Some(format!("could not run curl: {e}")),
        Ok(o) => {
            let w: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_default();
            if !o.status.success() {
                error = Some(format!("curl exit {}: {}", o.status, String::from_utf8_lossy(&o.stderr).trim()));
            }
            let code = w["response_code"].as_u64().map(|c| c as u16).filter(|c| *c != 0);
            status = code;
            http_version = w["http_version"].as_str().map(|v| format!("HTTP/{v}"));
            // Only the final header block (after any 1xx).
            let raw_head = std::fs::read_to_string(&head).unwrap_or_default();
            let last_block = raw_head.split("\r\n\r\n").filter(|b| !b.trim().is_empty()).last().unwrap_or("");
            let mut map = http::HeaderMap::new();
            for line in last_block.lines().skip(1) {
                if let Some((k, v)) = line.split_once(':') {
                    if let (Ok(k), Ok(v)) = (http::HeaderName::from_bytes(k.trim().as_bytes()), http::HeaderValue::from_str(v.trim())) {
                        map.append(k, v);
                    }
                }
            }
            headers = header_list(&map);
            let bytes = std::fs::read(&body).unwrap_or_default();
            if let Some(s) = status {
                analysis = Some(cloudflare::analyze(s, &headers, Some(&bytes)));
            }
            meta = Some(serde_json::json!({
                "body_len_decoded": bytes.len(), "remote_ip": "<removed>", "num_connects": w["num_connects"],
                "time_total_ms": w["time_total"].as_f64().map(|t| t * 1000.0), "ssl_verify_result": w["ssl_verify_result"],
                "scheme": w["scheme"],
            }));
            body_bytes = Some(bytes);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let seen = Observed { body: body_bytes.as_deref(), ..Observed::default() };
    let (outcome, details) = judge_full(case, status, analysis.as_ref(), error.as_deref(), &seen);
    let result = CaseResult {
        case_id: case.id.clone(),
        category: case.category.clone(),
        description: case.description.clone(),
        client: client.name.clone(),
        timestamp: now_rfc3339(),
        request,
        status,
        http_version,
        relevant_headers: headers.iter().filter(|h| RELEVANT.contains(&h.name.as_str())).cloned().collect(),
        tls: None,
        response_meta: meta.clone(),
        analysis,
        expect: case.expect.clone(),
        seed,
        policy: policy.clone(),
        fetch_outcome: None,
        attempts: Vec::new(),
        outcome,
        details,
        reproduce: reproduce(case, client, opts, seed),
    };
    // The body goes to the raw record only (local, gitignored), never into the processed result.
    let mut raw = serde_json::json!({ "curl": meta, "headers": headers });
    if opts.save_bodies {
        raw["body"] = body_bytes.as_deref().map(|b| String::from_utf8_lossy(b).into_owned()).into();
    }
    (result, raw)
}

/// The data-centre code at the end of `cf-ray` (e.g. `-HYD`) says where the client is. Processed
/// results are committed, so it is removed there (raw records stay local).
fn scrub_location(mut r: CaseResult) -> CaseResult {
    let strip = |v: &str| match v.rsplit_once('-') {
        Some((id, colo)) if colo.len() == 3 && colo.chars().all(|c| c.is_ascii_uppercase()) => format!("{id}-<removed>"),
        _ => v.to_string(),
    };
    for h in r.relevant_headers.iter_mut().filter(|h| h.name == "cf-ray") {
        h.value = strip(&h.value);
    }
    if let Some(a) = r.analysis.as_mut() {
        a.cf_ray = a.cf_ray.as_deref().map(strip);
    }
    if let Some(m) = r.response_meta.as_mut() {
        if let Some(c) = m.get_mut("connection") {
            c["remote_addr"] = "<removed>".into();
        }
    }
    r
}

/// A temp path unique to this call: two runs in one process (parallel tests, a library caller) with
/// the same case id must not share or delete each other's files (D26).
fn tempdir_path(id: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("cfprobe-run-{}-{n}-{id}", std::process::id()))
}

/// UTC, seconds precision, without a date crate.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil_from_days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn markdown(matrix: &Matrix, results: &[CaseResult], opts: &RunOptions) -> String {
    let count = |o: Outcome| results.iter().filter(|r| r.outcome == o).count();
    let mut out = format!(
        "# {}\n\nMatrix `{}`, run {}, seed **{}**{}. {} results: {} pass, {} fail, {} observed (no expectation), {} error.\n\n\
         | case | category | client | status | verdict | confidence | issued by | indicators | attempts | outcome | details |\n|---|---|---|---|---|---|---|---|---|---|---|\n",
        matrix.name,
        opts.matrix_path.display(),
        results.first().map(|r| r.timestamp.as_str()).unwrap_or("-"),
        results.first().map(|r| r.seed.to_string()).unwrap_or("-".into()),
        if matrix.shuffle { ", shuffled order" } else { "" },
        results.len(),
        count(Outcome::Pass),
        count(Outcome::Fail),
        count(Outcome::Observed),
        count(Outcome::Error),
    );
    let name = |v: serde_json::Value| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
    for r in results {
        let a = r.analysis.as_ref();
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | **{}** | {} |\n",
            r.case_id,
            r.category,
            r.client,
            r.status.map(|s| s.to_string()).unwrap_or("-".into()),
            a.map(|a| verdict_name(a.verdict)).unwrap_or("-".into()),
            a.map(|a| name(serde_json::to_value(a.confidence).unwrap())).unwrap_or("-".into()),
            a.map(|a| name(serde_json::to_value(a.issued_by).unwrap())).unwrap_or("-".into()),
            a.map(|a| a.indicators.iter().map(|i| name(serde_json::to_value(i).unwrap())).collect::<Vec<_>>().join(", ")).filter(|s| !s.is_empty()).unwrap_or("none".into()),
            if r.attempts.is_empty() { "-".to_string() } else { r.attempts.iter().map(|x| x.status.map(|s| s.to_string()).unwrap_or("err".into())).collect::<Vec<_>>().join(" > ") },
            name(serde_json::to_value(r.outcome).unwrap()),
            r.details.join("; ").replace('|', "\\|"),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_is_rfc3339_utc() {
        let t = now_rfc3339();
        assert_eq!(t.len(), 20, "{t}");
        assert!(t.starts_with("20") && t.ends_with('Z'));
    }

    #[test]
    fn client_config_overrides_one_level_deep() {
        let c: Config = merge_json(&Config::default(), Some(&serde_json::json!({"tls": {"alpn": ["http/1.1"]}, "h1": {"title_case_headers": true}})), "t").unwrap();
        assert_eq!(c.tls.alpn, ["http/1.1"]);
        assert!(c.tls.verify, "other tls fields kept");
        assert!(c.h1.title_case_headers);
    }

    #[test]
    fn no_expectation_is_observed_never_pass() {
        let case: Case = serde_json::from_value(serde_json::json!({"id": "x", "category": "c", "description": "d", "url": "https://a.test/"})).unwrap();
        assert_eq!(judge(&case, Some(200), None, None).0, Outcome::Observed);
        let case: Case = serde_json::from_value(serde_json::json!({"id": "x", "category": "c", "description": "d", "url": "https://a.test/", "expect": {"status": 403, "verdict": "CONFIRMED_CHALLENGE_RESPONSE"}})).unwrap();
        let (o, why) = judge(&case, Some(200), None, None);
        assert_eq!(o, Outcome::Fail);
        assert_eq!(why.len(), 2, "{why:?}");
    }
}
