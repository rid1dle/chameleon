//! Fault handling around the engine: retries with backoff, `Retry-After`, a per-host circuit breaker,
//! redirect following with loop detection, a cookie jar, and cancellation.
//!
//! `CFProbe::inspect` stays one request = one exchange (pure measurement). A `Session` wraps it for
//! runs that need continuity, and records every attempt and hop, so nothing it does is hidden.
//!
//! Rules it never breaks:
//! - A permanent answer (access denied, challenge, normal page, redirect) is never retried.
//! - A non-idempotent request (POST, PATCH) is never retried.
//! - Attempts and redirect hops are bounded; a redirect back to a URL already visited stops the
//!   fetch as a loop.
//! - TLS verification is never relaxed: a certificate failure is final.
//! - A `Retry-After` longer than the policy's cap ends the fetch instead of waiting it out.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use rand::Rng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::cloudflare::{self, Analysis, Verdict};
use crate::core::{Error, Target};
use crate::networking::{CFProbe, Exchange};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Follow at most this many redirects. 0: do not follow.
    pub max_redirects: u8,
    /// Keep cookies from responses and send them on later requests of this session.
    pub cookies: bool,
    pub retry: RetryPolicy,
    /// `None`: no circuit breaker.
    pub circuit: Option<CircuitPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetryPolicy {
    /// Attempts per hop, the first included. 1: never retry.
    pub max_attempts: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    /// 0 to 1. The backoff delay is reduced by a random share of up to this much, so it never
    /// exceeds `max_delay_ms`.
    pub jitter: f64,
    pub honor_retry_after: bool,
    /// A longer `Retry-After` ends the fetch rather than waiting.
    pub max_retry_after_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CircuitPolicy {
    /// Consecutive failed attempts to one host that open the circuit.
    pub failures_to_open: u32,
    /// How long an open circuit refuses requests before letting one through.
    pub open_ms: u64,
}

impl Default for Policy {
    /// Off: one attempt, no redirects, no cookies, no breaker. What `inspect` does.
    fn default() -> Self {
        Self { max_redirects: 0, cookies: false, retry: RetryPolicy::default(), circuit: None }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 1, base_delay_ms: 500, max_delay_ms: 8_000, jitter: 0.5, honor_retry_after: true, max_retry_after_ms: 60_000 }
    }
}

impl Default for CircuitPolicy {
    fn default() -> Self {
        Self { failures_to_open: 3, open_ms: 30_000 }
    }
}

impl Policy {
    /// What the matrix runner uses unless a case says otherwise.
    pub fn runner_default() -> Self {
        Self {
            max_redirects: 5,
            cookies: true,
            retry: RetryPolicy { max_attempts: 3, ..RetryPolicy::default() },
            circuit: Some(CircuitPolicy::default()),
        }
    }

    pub fn validate(&self) -> crate::core::Result<()> {
        let r = &self.retry;
        let bad = |m: &str| Err(Error::Config(format!("policy: {m}")));
        if r.max_attempts == 0 || r.max_attempts > 10 {
            return bad("retry.max_attempts must be 1..=10");
        }
        if !(0.0..=1.0).contains(&r.jitter) {
            return bad("retry.jitter must be within 0..=1");
        }
        if r.base_delay_ms > r.max_delay_ms {
            return bad("retry.base_delay_ms must not exceed retry.max_delay_ms");
        }
        if self.max_redirects > 20 {
            return bad("max_redirects must be at most 20");
        }
        if self.circuit.as_ref().is_some_and(|c| c.failures_to_open == 0) {
            return bad("circuit.failures_to_open must be at least 1");
        }
        Ok(())
    }
}

// ---------- decisions (pure, unit-tested) ----------

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum Decision {
    Retry { after_ms: u64, reason: String },
    Stop { reason: String },
}

fn idempotent(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "PUT" | "DELETE" | "TRACE")
}

/// Whether to try the same request again after `attempt` (1-based) gave `analysis`.
pub fn decide(policy: &RetryPolicy, method: &str, attempt: u32, analysis: &Analysis, err: Option<&Error>, rng: &mut ChaCha8Rng) -> Decision {
    let stop = |r: &str| Decision::Stop { reason: r.to_string() };
    use crate::proxy::ProxyStage;
    let transient = match analysis.verdict {
        // Proxy credentials, the proxy's certificate and a proxy speaking another protocol do not get
        // better by asking again. A retry always goes through the same proxy, never direct.
        Verdict::ConnectionFailure if matches!(err, Some(Error::Proxy { stage: ProxyStage::Auth | ProxyStage::Tls | ProxyStage::Protocol, .. })) => false,
        Verdict::ConnectionFailure => !matches!(err, Some(Error::Config(_) | Error::Target(_) | Error::Request(_))),
        // A timed-out handshake may succeed later; a refused certificate will not.
        Verdict::TlsFailure => matches!(err, Some(Error::Timeout { .. })),
        Verdict::OriginUnavailable | Verdict::RateLimited => true,
        _ => false,
    };
    if !transient {
        return stop(&format!("{} is not transient", serde_json::to_value(analysis.verdict).unwrap().as_str().unwrap_or("?")));
    }
    if !idempotent(method) {
        return stop(&format!("{method} is not idempotent"));
    }
    if attempt >= policy.max_attempts {
        return stop(&format!("attempt {attempt} of {} used", policy.max_attempts));
    }
    let exp = policy.base_delay_ms.saturating_mul(1u64 << (attempt - 1).min(20)).min(policy.max_delay_ms);
    let cut = (exp as f64 * policy.jitter * rng.random::<f64>()) as u64;
    let backoff = exp - cut;
    if policy.honor_retry_after {
        if let Some(ra) = analysis.retry_after.as_deref().and_then(parse_retry_after_ms) {
            if ra > policy.max_retry_after_ms {
                return stop(&format!("Retry-After {ra} ms exceeds the cap of {} ms", policy.max_retry_after_ms));
            }
            // Never sooner than the backoff: Cloudflare counts Retry-After down in whole seconds and
            // sends 0 while still limiting (zone run, 2026-11-24), which would otherwise mean
            // retrying at once, again and again.
            return if ra >= backoff {
                Decision::Retry { after_ms: ra, reason: format!("Retry-After {ra} ms") }
            } else {
                Decision::Retry { after_ms: backoff, reason: format!("Retry-After {ra} ms raised to the backoff of {backoff} ms") }
            };
        }
    }
    Decision::Retry { after_ms: backoff, reason: format!("backoff {exp} ms less jitter {cut} ms") }
}

/// `Retry-After` as delta-seconds or an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), in ms from now.
pub fn parse_retry_after_ms(v: &str) -> Option<u64> {
    let v = v.trim();
    if let Ok(s) = v.parse::<u64>() {
        return Some(s.saturating_mul(1000));
    }
    let parts: Vec<&str> = v.split_ascii_whitespace().collect();
    if parts.len() != 6 || parts[5] != "GMT" {
        return None;
    }
    let day: i64 = parts[1].parse().ok()?;
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|m| *m == parts[2])? as i64 + 1;
    let year: i64 = parts[3].parse().ok()?;
    let hms: Vec<i64> = parts[4].split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    if hms.len() != 3 {
        return None;
    }
    // days_from_civil (Howard Hinnant)
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let at = days * 86_400 + hms[0] * 3600 + hms[1] * 60 + hms[2];
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(((at - now).max(0) as u64) * 1000)
}

/// The next request after a redirect, or why there is none.
fn redirect_target(current: &Target, ex: &Exchange) -> Option<std::result::Result<Target, String>> {
    let status = ex.response.status;
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    // The raw Location: the record's copy has challenge tokens redacted, which would change the URL.
    let loc = ex.response.raw_location.as_deref()?;
    let next = match current.url.join(loc) {
        Ok(u) => u,
        Err(e) => return Some(Err(format!("location {:?} is not a URL: {e}", crate::http::redact_url(loc)))),
    };
    if !matches!(next.scheme(), "http" | "https") {
        return Some(Err(format!("location scheme {:?} is not followed", next.scheme())));
    }
    let mut t = current.clone();
    let cross_origin = next.origin() != current.url.origin();
    t.url = next;
    // 303 always, and 301/302 for POST, become GET without a body (as browsers do).
    if status == 303 || (matches!(status, 301 | 302) && current.method == "POST") {
        t.method = "GET".into();
        t.body = None;
        t.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type") && !k.eq_ignore_ascii_case("content-length"));
    }
    // Credentials given for one origin do not travel to another.
    if cross_origin {
        t.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("authorization") && !k.eq_ignore_ascii_case("cookie"));
    }
    Some(Ok(t))
}

// ---------- session ----------

/// One attempt at one URL.
#[derive(Debug, Clone, Serialize)]
pub struct Attempt {
    pub number: u32,
    /// Time waited before this attempt (backoff or Retry-After).
    pub waited_ms: u64,
    /// How long the attempt itself took, connection setup included.
    pub elapsed_ms: u64,
    /// Cookie names this session added to the request (values are never recorded).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub jar_cookies_sent: Vec<String>,
    pub exchange: Option<Exchange>,
    pub error: Option<String>,
    pub analysis: Analysis,
    pub decision: Decision,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hop {
    pub method: String,
    pub url: String,
    pub attempts: Vec<Attempt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum FetchOutcome {
    /// The last hop got a final answer (any status), or retries ran out.
    Completed,
    RedirectLoop { url: String },
    TooManyRedirects { limit: u8 },
    BadRedirect { reason: String },
    /// The host's circuit is open: the request was not sent.
    CircuitOpen { host: String, retry_in_ms: u64 },
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct Fetch {
    pub hops: Vec<Hop>,
    pub outcome: FetchOutcome,
    /// The analysis of the last attempt, or the reason no request was made.
    pub analysis: Option<Analysis>,
}

impl Fetch {
    pub fn last_exchange(&self) -> Option<&Exchange> {
        self.hops.last()?.attempts.last()?.exchange.as_ref()
    }

    pub fn attempts(&self) -> usize {
        self.hops.iter().map(|h| h.attempts.len()).sum()
    }
}

#[derive(Debug, Default)]
struct Circuit {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

/// An engine plus a policy, a cookie jar, circuits and a seeded RNG for jitter.
pub struct Session {
    engine: Arc<CFProbe>,
    policy: Policy,
    jar: Mutex<cookie_store::CookieStore>,
    circuits: Mutex<HashMap<String, Circuit>>,
    rng: Mutex<ChaCha8Rng>,
}

fn counts_as_failure(v: Verdict) -> bool {
    matches!(v, Verdict::ConnectionFailure | Verdict::TlsFailure | Verdict::OriginUnavailable | Verdict::RateLimited)
}

impl Session {
    pub fn new(engine: Arc<CFProbe>, policy: Policy, rng: ChaCha8Rng) -> crate::core::Result<Self> {
        policy.validate()?;
        Ok(Self {
            engine,
            policy,
            jar: Mutex::new(cookie_store::CookieStore::new()),
            circuits: Mutex::new(HashMap::new()),
            rng: Mutex::new(rng),
        })
    }

    pub fn engine(&self) -> &CFProbe {
        &self.engine
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Names of the cookies the jar holds for `url` (values are not exposed).
    pub fn cookie_names_for(&self, url: &Url) -> Vec<String> {
        self.jar.lock().unwrap().get_request_values(url).map(|(n, _)| n.to_string()).collect()
    }

    pub async fn fetch(&self, target: Target) -> Fetch {
        self.fetch_until(target, std::future::pending::<()>()).await
    }

    /// `fetch` that stops as soon as `cancel` completes, keeping what was recorded so far. The
    /// engine stays usable: a cancelled request's connection is dropped, not pooled.
    pub async fn fetch_until(&self, target: Target, cancel: impl Future<Output = ()>) -> Fetch {
        let policy = self.policy.clone();
        self.fetch_with(target, &policy, cancel).await
    }

    /// `fetch_until` with another policy for this fetch, sharing this session's cookie jar and
    /// circuits (a matrix case can turn retries or redirects off without losing session state).
    pub async fn fetch_with(&self, target: Target, policy: &Policy, cancel: impl Future<Output = ()>) -> Fetch {
        tokio::pin!(cancel);
        let mut fetch = Fetch { hops: Vec::new(), outcome: FetchOutcome::Completed, analysis: None };
        let mut visited: HashSet<(String, String)> = HashSet::new();
        let mut current = target;
        loop {
            visited.insert((current.method.clone(), current.url.to_string()));
            let host = format!("{}:{}", current.url.host_str().unwrap_or(""), current.url.port_or_known_default().unwrap_or(0));
            let mut hop = Hop { method: current.method.clone(), url: crate::http::redact_url(current.url.as_str()), attempts: Vec::new() };
            let mut waited_ms = 0;
            let mut attempt = 0;
            let last_ex = loop {
                if let Some(ms) = self.circuit_open_for(&host, policy) {
                    fetch.outcome = FetchOutcome::CircuitOpen { host: host.clone(), retry_in_ms: ms };
                    fetch.hops.push(hop);
                    return fetch;
                }
                attempt += 1;
                let (request, jar_names) = self.with_jar_cookies(&current, policy);
                let attempt_started = Instant::now();
                let result = tokio::select! {
                    r = self.engine.inspect(request) => r,
                    _ = &mut cancel => {
                        fetch.outcome = FetchOutcome::Cancelled;
                        fetch.hops.push(hop);
                        return fetch;
                    }
                };
                let (exchange, error, analysis) = match result {
                    Ok(ex) => {
                        self.store_cookies(&current.url, &ex, policy);
                        let a = cloudflare::analyze_exchange(&ex);
                        (Some(ex), None, a)
                    }
                    Err(e) => {
                        let a = cloudflare::analyze_error(&e);
                        (None, Some(e), a)
                    }
                };
                let verdict = analysis.verdict;
                let decision = {
                    let mut rng = self.rng.lock().unwrap();
                    decide(&policy.retry, &current.method, attempt, &analysis, error.as_ref(), &mut rng)
                };
                fetch.analysis = Some(analysis.clone());
                hop.attempts.push(Attempt {
                    number: attempt,
                    waited_ms,
                    elapsed_ms: attempt_started.elapsed().as_millis() as u64,
                    jar_cookies_sent: jar_names,
                    exchange: exchange.clone(),
                    error: error.as_ref().map(|e| e.to_string()),
                    analysis,
                    decision: decision.clone(),
                });
                match decision {
                    Decision::Retry { after_ms, .. } => {
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(after_ms)) => {}
                            _ = &mut cancel => {
                                fetch.outcome = FetchOutcome::Cancelled;
                                fetch.hops.push(hop);
                                return fetch;
                            }
                        }
                        waited_ms = after_ms;
                    }
                    Decision::Stop { .. } => {
                        // One request counts once, however many attempts it took: retries are
                        // already bounded, the breaker guards against a run of failing requests.
                        self.record_circuit(&host, verdict, policy);
                        break exchange;
                    }
                }
            };
            fetch.hops.push(hop);

            let Some(ex) = last_ex else { return fetch };
            if policy.max_redirects == 0 {
                return fetch;
            }
            match redirect_target(&current, &ex) {
                None => return fetch,
                Some(Err(reason)) => {
                    fetch.outcome = FetchOutcome::BadRedirect { reason };
                    return fetch;
                }
                Some(Ok(next)) => {
                    if visited.contains(&(next.method.clone(), next.url.to_string())) {
                        fetch.outcome = FetchOutcome::RedirectLoop { url: crate::http::redact_url(next.url.as_str()) };
                        return fetch;
                    }
                    if fetch.hops.len() > policy.max_redirects as usize {
                        fetch.outcome = FetchOutcome::TooManyRedirects { limit: policy.max_redirects };
                        return fetch;
                    }
                    current = next;
                }
            }
        }
    }

    /// The request with the jar's cookies for its URL appended to any cookie header it carries.
    fn with_jar_cookies(&self, t: &Target, policy: &Policy) -> (Target, Vec<String>) {
        if !policy.cookies {
            return (t.clone(), Vec::new());
        }
        let jar = self.jar.lock().unwrap();
        let pairs: Vec<(String, String)> = jar.get_request_values(&t.url).map(|(n, v)| (n.to_string(), v.to_string())).collect();
        drop(jar);
        if pairs.is_empty() {
            return (t.clone(), Vec::new());
        }
        let names = pairs.iter().map(|(n, _)| n.clone()).collect();
        let joined = pairs.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join("; ");
        let mut t = t.clone();
        match t.headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case("cookie")) {
            Some(h) => h.1 = format!("{}; {joined}", h.1),
            None => t.headers.push(("cookie".into(), joined)),
        }
        (t, names)
    }

    fn store_cookies(&self, url: &Url, ex: &Exchange, policy: &Policy) {
        if !policy.cookies {
            return;
        }
        let mut jar = self.jar.lock().unwrap();
        for raw in &ex.response.raw_set_cookies {
            // Malformed cookies are ignored, as browsers do; the record still lists what was sent.
            let _ = jar.parse(raw, url);
        }
    }

    fn circuit_open_for(&self, host: &str, policy: &Policy) -> Option<u64> {
        let p = policy.circuit.as_ref()?;
        let mut circuits = self.circuits.lock().unwrap();
        let c = circuits.entry(host.to_string()).or_default();
        let until = c.open_until?;
        let now = Instant::now();
        if now < until {
            return Some((until - now).as_millis() as u64);
        }
        // Half-open: let this one through; one more failure reopens at once.
        c.open_until = None;
        c.consecutive_failures = p.failures_to_open.saturating_sub(1);
        None
    }

    fn record_circuit(&self, host: &str, v: Verdict, policy: &Policy) {
        let Some(p) = policy.circuit.as_ref() else { return };
        let mut circuits = self.circuits.lock().unwrap();
        let c = circuits.entry(host.to_string()).or_default();
        if counts_as_failure(v) {
            c.consecutive_failures += 1;
            if c.consecutive_failures >= p.failures_to_open {
                c.open_until = Some(Instant::now() + Duration::from_millis(p.open_ms));
            }
        } else {
            c.consecutive_failures = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn a(v: Verdict, retry_after: Option<&str>) -> Analysis {
        let mut x = cloudflare::analyze(200, &[], Some(b""));
        x.verdict = v;
        x.retry_after = retry_after.map(str::to_string);
        x
    }

    fn rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(7)
    }

    #[test]
    fn permanent_answers_are_never_retried() {
        let p = RetryPolicy { max_attempts: 5, ..Default::default() };
        for v in [Verdict::AccessDenied, Verdict::ConfirmedChallengeResponse, Verdict::ChallengeIndicator, Verdict::NormalPage, Verdict::Redirect, Verdict::Unknown] {
            assert!(matches!(decide(&p, "GET", 1, &a(v, None), None, &mut rng()), Decision::Stop { .. }), "{v:?}");
        }
        let cert = Error::TlsHandshake("certificate verify failed".into());
        assert!(matches!(decide(&p, "GET", 1, &a(Verdict::TlsFailure, None), Some(&cert), &mut rng()), Decision::Stop { .. }));
    }

    #[test]
    fn transient_answers_back_off_exponentially_within_bounds() {
        let p = RetryPolicy { max_attempts: 6, base_delay_ms: 100, max_delay_ms: 1000, jitter: 0.5, ..Default::default() };
        let mut r = rng();
        let mut prev_cap = 0;
        for attempt in 1..6 {
            let cap = (100u64 << (attempt - 1)).min(1000);
            match decide(&p, "GET", attempt, &a(Verdict::OriginUnavailable, None), None, &mut r) {
                Decision::Retry { after_ms, .. } => assert!(after_ms <= cap && after_ms >= cap / 2, "attempt {attempt}: {after_ms} vs cap {cap}"),
                other => panic!("{other:?}"),
            }
            assert!(cap >= prev_cap);
            prev_cap = cap;
        }
        assert!(matches!(decide(&p, "GET", 6, &a(Verdict::OriginUnavailable, None), None, &mut r), Decision::Stop { .. }), "attempts are bounded");
        assert!(matches!(decide(&p, "POST", 1, &a(Verdict::OriginUnavailable, None), None, &mut r), Decision::Stop { .. }), "POST is not retried");
    }

    #[test]
    fn retry_after_is_honoured_and_capped() {
        let p = RetryPolicy { max_attempts: 3, max_retry_after_ms: 20_000, ..Default::default() };
        assert_eq!(decide(&p, "GET", 1, &a(Verdict::RateLimited, Some("10")), None, &mut rng()), Decision::Retry { after_ms: 10_000, reason: "Retry-After 10000 ms".into() });
        assert!(matches!(decide(&p, "GET", 1, &a(Verdict::RateLimited, Some("120")), None, &mut rng()), Decision::Stop { reason } if reason.contains("exceeds the cap")));
        assert_eq!(parse_retry_after_ms("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0), "a past date means now");
        assert!(parse_retry_after_ms("Fri, 01 Jan 2100 00:00:00 GMT").unwrap() > 1_000_000);
        // D23: Retry-After 0 while still limited must not mean "retry at once".
        let p = RetryPolicy { max_attempts: 3, base_delay_ms: 500, jitter: 0.0, ..Default::default() };
        assert!(matches!(decide(&p, "GET", 1, &a(Verdict::RateLimited, Some("0")), None, &mut rng()), Decision::Retry { after_ms: 500, .. }));
        assert!(matches!(decide(&p, "GET", 2, &a(Verdict::RateLimited, Some("0")), None, &mut rng()), Decision::Retry { after_ms: 1000, .. }));
        assert_eq!(parse_retry_after_ms("soon"), None);
    }

    #[test]
    fn same_seed_same_jitter() {
        let p = RetryPolicy { max_attempts: 5, ..Default::default() };
        let run = |seed| {
            let mut r = ChaCha8Rng::seed_from_u64(seed);
            (1..5).map(|n| decide(&p, "GET", n, &a(Verdict::ConnectionFailure, None), None, &mut r)).collect::<Vec<_>>()
        };
        assert_eq!(run(42), run(42));
        assert_ne!(run(42), run(43));
    }

    #[test]
    fn policy_bounds_are_checked() {
        let mut p = Policy::runner_default();
        assert!(p.validate().is_ok());
        p.retry.max_attempts = 0;
        assert!(p.validate().is_err());
        p.retry.max_attempts = 3;
        p.retry.jitter = 1.5;
        assert!(p.validate().is_err());
    }
}
