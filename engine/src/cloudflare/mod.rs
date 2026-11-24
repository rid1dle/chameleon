//! What happened to a request, read from the response alone, with the evidence for it.
//!
//! Every verdict carries a confidence, who issued the response (Cloudflare's edge or the origin),
//! the markers that decided it, and caveats. No single string decides a verdict on its own: a
//! Cloudflare script on a page is an *indicator*, not a challenge.
//!
//! Markers, each seen in a real response (experiments/test-results/E4 from the zone lab,
//! experiments/test-results/P2 from public sites):
//!
//! | Marker | Seen in | Means |
//! |---|---|---|
//! | header `cf-mitigated: challenge` | E4 managed, js, interactive | Cloudflare answered with a challenge (the documented signal) |
//! | body `window._cf_chl_opt`, `/cdn-cgi/challenge-platform/h/*/orchestrate/`, title `Just a moment...` | E4 challenge pages | the interstitial page itself |
//! | body `/cdn-cgi/challenge-platform/scripts/jsd/main.js` | P2 asurascans, discord, bookmyshow homepages (200) | JavaScript Detections, injected into normal pages. **Not a challenge** |
//! | body `challenges.cloudflare.com/turnstile/`, `class="cf-turnstile"` | zone Turnstile page | an embedded Turnstile widget. **Not a blocking challenge** |
//! | body `data-translate="block_headline"` | E4 block | WAF block page (no error number, no `cf-mitigated`) |
//! | body `error code: NNNN` (plain text, 3 or 4 digits) | E4 1015, 1003; P2 nowsecure.nl 522 | numbered Cloudflare error |
//!
//! Absence of `cf-mitigated` never proves no challenge was applied: a held `cf_clearance`, or
//! JavaScript Detections scoring the page for later requests, leave no mark on this response.

use serde::{Deserialize, Serialize};

use crate::http::{HeaderEntry, redact_url};
use crate::networking::Exchange;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// The origin's own content. Its status is the origin's (a 404 is still a normal page).
    NormalPage,
    /// A 3xx that does not lead into a challenge.
    Redirect,
    /// Challenge-page structure without the confirming header, or a redirect into the challenge
    /// platform. Something challenge-like happened; this response alone cannot confirm it.
    ChallengeIndicator,
    /// `cf-mitigated: challenge`: Cloudflare answered with a challenge instead of the origin.
    ConfirmedChallengeResponse,
    RateLimited,
    /// A block: WAF block page, a 10xx access error, or the origin's own 401/403.
    AccessDenied,
    /// Cloudflare could not reach or get an answer from the origin (52x, 530, 1016, 1033), or the
    /// origin said it is unavailable (502/503/504).
    OriginUnavailable,
    /// The TLS handshake failed or timed out: no HTTP exchange happened.
    TlsFailure,
    /// DNS, TCP, or the HTTP exchange itself failed (refused, reset, timed out, malformed): no
    /// complete response to classify.
    ConnectionFailure,
    /// Not enough to decide. `evidence` says what was seen.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Who produced this response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuedBy {
    /// Cloudflare's edge answered instead of the origin.
    CloudflareEdge,
    /// The origin answered (through Cloudflare or not).
    Origin,
    Unknown,
}

/// The challenge type the page states in `_cf_chl_opt.cType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    Managed,
    /// The JS Challenge action.
    NonInteractive,
    /// The legacy Interactive Challenge action.
    Interactive,
}

impl ChallengeKind {
    fn from_ctype(v: &str) -> Option<Self> {
        match v {
            "managed" => Some(Self::Managed),
            "non-interactive" => Some(Self::NonInteractive),
            "interactive" => Some(Self::Interactive),
            _ => None,
        }
    }
}

/// A structural marker found in the response. Mentions in page text (e.g. the word "Turnstile" in a
/// product menu) are not markers: each one is a script URL, an attribute or a page-defining value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Indicator {
    /// `/cdn-cgi/challenge-platform/scripts/jsd/main.js`: JavaScript Detections on a normal page.
    JsDetectionsScript,
    /// `/cdn-cgi/challenge-platform/h/<x>/orchestrate/`: the script that runs a challenge page.
    ChallengeOrchestrateScript,
    /// `window._cf_chl_opt`: the challenge page's options object.
    ChallengeOptions,
    /// `<title>Just a moment...</title>`, the English challenge page title. Supporting only.
    ChallengeTitle,
    /// `challenges.cloudflare.com/turnstile/` script.
    TurnstileScript,
    /// An element with class `cf-turnstile`.
    TurnstileWidget,
    /// `cf-error-details` or `cf-wrapper`: Cloudflare's HTML error or block page layout.
    CloudflareErrorPage,
    /// The WAF block page (`data-translate="block_headline"`).
    BlockPage,
    /// `Location` points into the challenge platform or carries `__cf_chl_` parameters.
    ChallengeRedirect,
    /// `Set-Cookie: __cf_bm`: set by Cloudflare's bot products (Bot Fight Mode, Super Bot Fight
    /// Mode, Bot Management) to smooth their scoring. [documented] Cloudflare cookies reference.
    BotManagementCookie,
    /// `Set-Cookie: _cfuvid`: Cloudflare rate limiting's visitor id. [documented]
    RateLimitVisitorCookie,
    /// `Set-Cookie: cf_clearance`: a challenge was passed and clearance issued. [documented]
    ClearanceCookie,
}

/// Cloudflare cookie names that are indicators (names only; values are never read).
const COOKIE_INDICATORS: [(&str, Indicator); 3] = [
    ("__cf_bm", Indicator::BotManagementCookie),
    ("_cfuvid", Indicator::RateLimitVisitorCookie),
    ("cf_clearance", Indicator::ClearanceCookie),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Analysis {
    pub verdict: Verdict,
    pub confidence: Confidence,
    pub issued_by: IssuedBy,
    /// A `cf-ray` header or `server: cloudflare` was present.
    pub cloudflare_present: bool,
    /// Only for challenges; `None` when the page does not state a type this engine knows.
    pub challenge_kind: Option<ChallengeKind>,
    /// The Cloudflare error number from the body, when there is one.
    pub error_code: Option<u16>,
    pub cf_ray: Option<String>,
    pub retry_after: Option<String>,
    /// `Location`, with challenge tokens and credentials redacted.
    pub location: Option<String>,
    pub title: Option<String>,
    pub indicators: Vec<Indicator>,
    /// The facts that decided the verdict, in the order they were checked.
    pub evidence: Vec<String>,
    /// What this response cannot tell.
    pub caveats: Vec<String>,
}

const MITIGATED: &str = "cf-mitigated";
const CTYPE: &str = "cType: '";
const PLAIN_ERROR: &str = "error code: ";
const HTML_ERROR: &str = "<span class=\"cf-error-code\">";
/// The HTML 5xx error page: `<span class="code-label">Error code 522</span>` (P2 zone capture).
const HTML_CODE_LABEL: &str = "<span class=\"code-label\">Error code ";
/// The HTML 1xxx error page: `<span data-translate="error">Error</span> <span>1002</span>` (P2 zone
/// captures of 1002 and 1016). Cloudflare sends the HTML pages only to requests that offer a
/// content encoding; others get `error code: N` as plain text.
const HTML_1XXX: &str = "<span data-translate=\"error\">Error</span>";
const RATE_LIMITED_CODE: u16 = 1015;
/// Cloudflare 10xx errors that deny access. [documented] developers.cloudflare.com/support/troubleshooting/cloudflare-errors/
const ACCESS_DENIED_CODES: [u16; 10] = [1003, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1020];
/// Origin unreachable, timed out, invalid response, the origin/tunnel could not be resolved, the
/// origin's DNS record is unusable (1000-range configuration errors), or the Worker serving the
/// hostname failed (1101 exception, 1102 resource limits). Observed on the zone: 522 (unanswering
/// origin), 530 + 1016 (CNAME to a missing name), 1002 (record pointing at a reserved address),
/// 1101. The rest are [documented] (developers.cloudflare.com/support/troubleshooting/cloudflare-errors/).
const ORIGIN_CODES: [u16; 20] = [
    520, 521, 522, 523, 524, 525, 526, 527, 530, 1000, 1001, 1002, 1004, 1014, 1016, 1018, 1019, 1033, 1101, 1102,
];
/// Of `ORIGIN_CODES`, those that are also HTTP status codes Cloudflare answers with.
const ORIGIN_STATUSES: [u16; 9] = [520, 521, 522, 523, 524, 525, 526, 527, 530];

fn header<'a>(headers: &'a [HeaderEntry], name: &str) -> Option<&'a str> {
    headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_str())
}

/// The quoted value after `cType: '`, if any.
fn ctype(body: &str) -> Option<&str> {
    let start = body.find(CTYPE)? + CTYPE.len();
    let len = body[start..].find('\'')?;
    Some(&body[start..start + len])
}

/// A Cloudflare error number: `error code: NNN[N]` as the whole plain-text body, or the
/// `cf-error-code` span of an HTML error page. Three or four digits.
fn error_code(body: &str) -> Option<u16> {
    let plain = body.trim().strip_prefix(PLAIN_ERROR).filter(|rest| rest.len() <= 4);
    let html = || {
        [HTML_ERROR, HTML_CODE_LABEL].iter().find_map(|m| body.find(m).map(|i| &body[i + m.len()..])).or_else(|| {
            let i = body.find(HTML_1XXX)? + HTML_1XXX.len();
            body[i..].trim_start().strip_prefix("<span>")
        })
    };
    let digits = plain.or_else(html)?;
    let n: String = digits.chars().take_while(char::is_ascii_digit).collect();
    matches!(n.len(), 3 | 4).then(|| n.parse().ok()).flatten()
}

/// Text of the first `<title>`, trimmed, at most 200 characters.
fn title(body: &str) -> Option<String> {
    let lower = body.get(..body.len().min(64 * 1024))?.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let start = open + lower[open..].find('>')? + 1;
    let end = start + lower[start..].find("</title")?;
    let t: String = body[start..end].trim().chars().take(200).collect();
    (!t.is_empty()).then_some(t)
}

fn find_indicators(body: &str, location: Option<&str>) -> Vec<Indicator> {
    let mut out = Vec::new();
    let mut add = |cond: bool, i: Indicator| {
        if cond {
            out.push(i)
        }
    };
    add(body.contains("/cdn-cgi/challenge-platform/scripts/jsd/main.js"), Indicator::JsDetectionsScript);
    add(
        body.match_indices("/cdn-cgi/challenge-platform/h/").any(|(i, _)| body[i..].get(..60).is_some_and(|s| s.contains("/orchestrate/"))),
        Indicator::ChallengeOrchestrateScript,
    );
    add(body.contains("_cf_chl_opt"), Indicator::ChallengeOptions);
    add(title(body).is_some_and(|t| t == "Just a moment..."), Indicator::ChallengeTitle);
    add(body.contains("challenges.cloudflare.com/turnstile/"), Indicator::TurnstileScript);
    add(has_class(body, "cf-turnstile"), Indicator::TurnstileWidget);
    add(body.contains("cf-error-details") || body.contains("id=\"cf-wrapper\""), Indicator::CloudflareErrorPage);
    add(body.contains("data-translate=\"block_headline\""), Indicator::BlockPage);
    add(
        location.is_some_and(|l| l.contains("/cdn-cgi/challenge-platform/") || l.contains("__cf_chl_")),
        Indicator::ChallengeRedirect,
    );
    out
}

/// `class="... name ..."` with `name` as a whole class token.
fn has_class(body: &str, name: &str) -> bool {
    body.match_indices("class=").any(|(i, _)| {
        let rest = &body[i + 6..];
        let Some(q) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else { return false };
        rest[1..].split(q).next().is_some_and(|v| v.split_ascii_whitespace().any(|c| c == name))
    })
}

/// Classify one response. `body` is the decoded body; `None` when it could not be inspected (e.g. an
/// encoding this engine does not decode). An empty body (HEAD, 204) is `Some(b"")`.
pub fn analyze(status: u16, headers: &[HeaderEntry], body: Option<&[u8]>) -> Analysis {
    let text = body.map(String::from_utf8_lossy).unwrap_or_default();
    let cf_ray = header(headers, "cf-ray").map(str::to_string);
    let server_cf = header(headers, "server").is_some_and(|s| s.eq_ignore_ascii_case("cloudflare"));
    let location = header(headers, "location").map(redact_url);
    let indicators = find_indicators(&text, location.as_deref());
    let has = |i: Indicator| indicators.contains(&i);

    let mut a = Analysis {
        verdict: Verdict::Unknown,
        confidence: Confidence::Low,
        issued_by: IssuedBy::Unknown,
        cloudflare_present: cf_ray.is_some() || server_cf,
        challenge_kind: None,
        error_code: None,
        cf_ray: cf_ray.clone(),
        retry_after: header(headers, "retry-after").map(str::to_string),
        location,
        title: title(&text),
        indicators: indicators.clone(),
        evidence: Vec::new(),
        caveats: Vec::new(),
    };
    let set = |a: &mut Analysis, v: Verdict, c: Confidence, by: IssuedBy| {
        a.verdict = v;
        a.confidence = c;
        a.issued_by = by;
    };

    a.evidence.push(match (&cf_ray, server_cf) {
        (Some(_), _) => "cf-ray present".into(),
        (None, true) => "server: cloudflare".into(),
        (None, false) => "no cf-ray header and server is not cloudflare".into(),
    });
    if body.is_none() {
        a.caveats.push("body not inspected (encoding not decoded); only status and headers were used".into());
    }

    // 1. The documented challenge signal.
    if let Some(m) = header(headers, MITIGATED) {
        a.evidence.push(format!("{MITIGATED}: {m}"));
        if !m.eq_ignore_ascii_case("challenge") {
            a.evidence.push(format!("{MITIGATED} value {m:?} is not one this engine knows"));
            set(&mut a, Verdict::Unknown, Confidence::Medium, IssuedBy::CloudflareEdge);
            return a;
        }
        let page = has(Indicator::ChallengeOptions) || has(Indicator::ChallengeOrchestrateScript);
        set(
            &mut a,
            Verdict::ConfirmedChallengeResponse,
            if page { Confidence::High } else { Confidence::Medium },
            IssuedBy::CloudflareEdge,
        );
        if page {
            a.evidence.push("body is the challenge page (_cf_chl_opt or orchestrate script)".into());
        } else {
            a.caveats.push("header only: the body does not show the challenge page (empty, cut short or changed)".into());
        }
        match ctype(&text) {
            Some(t) => {
                a.challenge_kind = ChallengeKind::from_ctype(t);
                a.evidence.push(format!("body cType '{t}'"));
                if a.challenge_kind.is_none() {
                    a.evidence.push(format!("cType '{t}' is not one this engine knows"));
                }
            }
            None => a.evidence.push("body has no cType".into()),
        }
        return a;
    }

    // 2. Numbered Cloudflare errors. Only trusted when the response came through Cloudflare.
    if a.cloudflare_present {
        if let Some(code) = error_code(&text) {
            a.error_code = Some(code);
            a.evidence.push(format!("body error code {code}"));
            let v = if code == RATE_LIMITED_CODE {
                Verdict::RateLimited
            } else if ACCESS_DENIED_CODES.contains(&code) {
                Verdict::AccessDenied
            } else if ORIGIN_CODES.contains(&code) {
                Verdict::OriginUnavailable
            } else {
                a.evidence.push(format!("error {code} is not one this engine maps"));
                Verdict::Unknown
            };
            let c = if v == Verdict::Unknown { Confidence::Medium } else { Confidence::High };
            set(&mut a, v, c, IssuedBy::CloudflareEdge);
            return a;
        }
        if has(Indicator::BlockPage) {
            a.evidence.push("body is the WAF block page (block_headline)".into());
            set(&mut a, Verdict::AccessDenied, Confidence::High, IssuedBy::CloudflareEdge);
            return a;
        }
    }

    // 3. Challenge-page structure without the header: something stripped it, or it is a copy.
    let structure = [Indicator::ChallengeOptions, Indicator::ChallengeOrchestrateScript, Indicator::ChallengeTitle]
        .iter()
        .filter(|i| has(**i))
        .count();
    if structure >= 2 {
        a.evidence.push(format!("{structure} of 3 challenge-page markers, but no {MITIGATED} header"));
        let c = if matches!(status, 403 | 429 | 503) { Confidence::Medium } else { Confidence::Low };
        set(&mut a, Verdict::ChallengeIndicator, c, IssuedBy::Unknown);
        a.caveats.push(format!("{MITIGATED} absent: a proxy may have removed it, or the page quotes a challenge page"));
        return a;
    }

    // 4. Redirects.
    if (300..400).contains(&status) {
        match &a.location {
            Some(l) => a.evidence.push(format!("status {status}, location {l}")),
            None => a.evidence.push(format!("status {status} without a location header")),
        }
        if has(Indicator::ChallengeRedirect) {
            a.evidence.push("location points into the challenge platform".into());
            set(&mut a, Verdict::ChallengeIndicator, Confidence::Medium, IssuedBy::Unknown);
        } else if a.location.is_some() {
            set(&mut a, Verdict::Redirect, Confidence::High, IssuedBy::Origin);
        } else {
            set(&mut a, Verdict::Unknown, Confidence::Low, IssuedBy::Unknown);
        }
        return a;
    }

    // 5. Cloudflare's own error page layout or status codes, without a known number.
    if a.cloudflare_present {
        let edge_status = ORIGIN_STATUSES.contains(&status);
        if edge_status || (status >= 500 && has(Indicator::CloudflareErrorPage)) {
            a.evidence.push(format!("status {status}{}", if edge_status { " is a Cloudflare origin error" } else { " with a Cloudflare error page" }));
            set(&mut a, Verdict::OriginUnavailable, Confidence::Medium, IssuedBy::CloudflareEdge);
            a.caveats.push("no error number in the body to confirm which origin failure".into());
            return a;
        }
        if status >= 400 && has(Indicator::CloudflareErrorPage) {
            a.evidence.push(format!("status {status} with a Cloudflare page, but no challenge, block or error-code marker"));
            set(&mut a, Verdict::Unknown, Confidence::Medium, IssuedBy::CloudflareEdge);
            return a;
        }
    }

    // 6. The origin answered.
    a.evidence.push(format!("no challenge, block or error marker: status {status} is the origin's"));
    let (v, c) = match status {
        200..=299 => (Verdict::NormalPage, Confidence::High),
        401 | 403 | 407 => (Verdict::AccessDenied, Confidence::Medium),
        429 => (Verdict::RateLimited, Confidence::Medium),
        502..=504 => (Verdict::OriginUnavailable, Confidence::Low),
        400..=599 => (Verdict::NormalPage, Confidence::Medium),
        _ => (Verdict::Unknown, Confidence::Low),
    };
    set(&mut a, v, c, IssuedBy::Origin);
    if a.cloudflare_present {
        a.caveats.push(format!("{MITIGATED} absent does not prove no challenge applied: a held cf_clearance or a later JavaScript Detections result leave no mark here"));
    }
    if has(Indicator::JsDetectionsScript) {
        a.evidence.push("JavaScript Detections script present: it scores this visit for later requests, it does not block this one".into());
    }
    if has(Indicator::TurnstileScript) || has(Indicator::TurnstileWidget) {
        a.evidence.push("embedded Turnstile: a widget inside the origin's page, not a blocking challenge".into());
    }
    if body.is_none() && v == Verdict::NormalPage {
        a.confidence = Confidence::Low;
    }
    a
}

/// The verdict for a request that produced no response. Nothing here is Cloudflare's doing as far as
/// this client can tell: `cloudflare_present` is false and `issued_by` unknown.
pub fn analyze_error(err: &crate::core::Error) -> Analysis {
    use crate::core::{Error, Stage};
    let (verdict, stage) = match err {
        Error::TlsHandshake(_) | Error::TlsSetup(_) => (Verdict::TlsFailure, "tls"),
        Error::Timeout { stage: Stage::Tls, .. } => (Verdict::TlsFailure, "tls"),
        Error::Dns { .. } | Error::Timeout { stage: Stage::Dns, .. } => (Verdict::ConnectionFailure, "dns"),
        Error::Connect { .. } | Error::Timeout { stage: Stage::Connect, .. } => (Verdict::ConnectionFailure, "connect"),
        // A response that arrived but cannot be parsed (malformed, not HTTP, head over the client's
        // limit) is not a connection failure, and sending again gets the same answer.
        Error::Http(e) if e.is_parse() || e.is_parse_too_large() || e.is_parse_status() => (Verdict::Unknown, "response parsing"),
        Error::Http(_) | Error::Timeout { stage: Stage::Response, .. } => (Verdict::ConnectionFailure, "response"),
        Error::Body(_) | Error::Timeout { stage: Stage::Body, .. } => (Verdict::ConnectionFailure, "body"),
        Error::BodyTooLarge { .. } => (Verdict::Unknown, "body"),
        // The destination was never reached: a proxy's TLS failing is not the destination's TLS.
        Error::Proxy { .. } => (Verdict::ConnectionFailure, "proxy"),
        Error::Config(_) | Error::Target(_) | Error::Request(_) | Error::Receiver(_) => (Verdict::Unknown, "not sent"),
    };
    Analysis {
        verdict,
        confidence: if verdict == Verdict::Unknown { Confidence::Low } else { Confidence::High },
        issued_by: IssuedBy::Unknown,
        cloudflare_present: false,
        challenge_kind: None,
        error_code: None,
        cf_ray: None,
        retry_after: None,
        location: None,
        title: None,
        indicators: Vec::new(),
        evidence: vec![format!("no response: failed at {stage}: {err}")],
        caveats: vec!["a failure before any response cannot be attributed to Cloudflare or the origin".into()],
    }
}

/// `analyze` on an exchange's response, using the decoded body when there is one, plus indicators
/// from the names of the cookies it sets (the header list carries cookie values redacted, names too).
pub fn analyze_exchange(ex: &Exchange) -> Analysis {
    let mut a = analyze(ex.response.status, &ex.response.headers, ex.response.inspectable_body());
    for (name, ind) in COOKIE_INDICATORS {
        if ex.response.set_cookies.iter().any(|c| c.name == name) && !a.indicators.contains(&ind) {
            a.indicators.push(ind);
            a.evidence.push(format!("sets cookie {name}"));
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<HeaderEntry> {
        pairs.iter().map(|(n, v)| HeaderEntry { name: n.to_string(), value: v.to_string() }).collect()
    }

    #[test]
    fn error_code_accepts_three_and_four_digits_only() {
        assert_eq!(error_code("error code: 1015\n"), Some(1015));
        assert_eq!(error_code("error code: 522"), Some(522));
        assert_eq!(error_code("<span class=\"cf-error-code\">1003</span>"), Some(1003));
        assert_eq!(error_code("<span class=\"code-label\">Error code 522</span>"), Some(522));
        assert_eq!(error_code("<span data-translate=\"error\">Error</span>\n   <span>1016</span>"), Some(1016));
        assert_eq!(error_code("error code: 10155"), None);
        assert_eq!(error_code("error code: 52"), None);
        assert_eq!(error_code("the error code: 1015 was mentioned"), None);
        assert_eq!(error_code(""), None);
    }

    #[test]
    fn title_is_read_case_insensitively() {
        assert_eq!(title("<html><TITLE> Just a moment... </TITLE>").as_deref(), Some("Just a moment..."));
        assert_eq!(title("<title></title>"), None);
        assert_eq!(title("no title"), None);
    }

    #[test]
    fn class_match_is_whole_token() {
        assert!(has_class(r#"<div class="a cf-turnstile b">"#, "cf-turnstile"));
        assert!(has_class("<div class='cf-turnstile'>", "cf-turnstile"));
        assert!(!has_class(r#"<div class="cf-turnstile-wrapper">"#, "cf-turnstile"));
        assert!(!has_class("we use cf-turnstile", "cf-turnstile"));
    }

    #[test]
    fn unknown_challenge_type_is_kept_as_unknown_not_guessed() {
        let a = analyze(403, &h(&[("cf-ray", "x"), ("cf-mitigated", "challenge")]), Some(b"window._cf_chl_opt={cType: 'turnstile-v9'}"));
        assert_eq!((a.verdict, a.confidence), (Verdict::ConfirmedChallengeResponse, Confidence::High));
        assert_eq!(a.challenge_kind, None);
        assert!(a.evidence.iter().any(|e| e.contains("not one this engine knows")));
    }

    #[test]
    fn challenge_header_without_page_is_medium() {
        let a = analyze(403, &h(&[("cf-ray", "x"), ("cf-mitigated", "challenge")]), Some(b""));
        assert_eq!((a.verdict, a.confidence), (Verdict::ConfirmedChallengeResponse, Confidence::Medium));
    }

    #[test]
    fn cloudflare_page_without_a_known_marker_is_unknown() {
        let a = analyze(418, &h(&[("server", "cloudflare")]), Some(b"<div id=\"cf-wrapper\">something new</div>"));
        assert_eq!(a.verdict, Verdict::Unknown);
    }

    #[test]
    fn unknown_mitigation_value_is_unknown() {
        let a = analyze(403, &h(&[("cf-ray", "x"), ("cf-mitigated", "something-else")]), Some(b""));
        assert_eq!(a.verdict, Verdict::Unknown);
    }

    #[test]
    fn origin_404_through_cloudflare_is_a_normal_page() {
        let a = analyze(404, &h(&[("cf-ray", "x"), ("server", "cloudflare")]), Some(b"{\"error\":\"not found\"}"));
        assert_eq!((a.verdict, a.issued_by), (Verdict::NormalPage, IssuedBy::Origin));
    }

    #[test]
    fn plain_403_without_cloudflare_is_the_origins_denial() {
        let a = analyze(403, &h(&[("server", "nginx")]), Some(b"<h1>403 Forbidden</h1>"));
        assert_eq!((a.verdict, a.issued_by, a.cloudflare_present), (Verdict::AccessDenied, IssuedBy::Origin, false));
    }

    #[test]
    fn error_code_text_without_cloudflare_is_not_trusted() {
        let a = analyze(429, &h(&[("server", "nginx")]), Some(b"error code: 1015"));
        assert_eq!((a.verdict, a.issued_by, a.error_code), (Verdict::RateLimited, IssuedBy::Origin, None));
    }

    #[test]
    fn redirect_into_the_challenge_platform_is_an_indicator() {
        let a = analyze(302, &h(&[("cf-ray", "x"), ("location", "/x?__cf_chl_rt_tk=abcdefabcdefabcdef")]), Some(b""));
        assert_eq!(a.verdict, Verdict::ChallengeIndicator);
        assert!(!a.location.as_deref().unwrap().contains("abcdef"), "{:?}", a.location);
    }

    #[test]
    fn challenge_structure_without_header_is_an_indicator_not_confirmed() {
        let body = b"<title>Just a moment...</title><script>window._cf_chl_opt={}</script>";
        let a = analyze(403, &h(&[("server", "nginx")]), Some(body));
        assert_eq!((a.verdict, a.confidence), (Verdict::ChallengeIndicator, Confidence::Medium));
        let a = analyze(200, &h(&[]), Some(body));
        assert_eq!((a.verdict, a.confidence), (Verdict::ChallengeIndicator, Confidence::Low));
    }

    #[test]
    fn a_title_alone_is_not_a_challenge() {
        let a = analyze(200, &h(&[("cf-ray", "x")]), Some(b"<title>Just a moment...</title><p>loading</p>"));
        assert_eq!(a.verdict, Verdict::NormalPage);
        assert!(a.indicators.contains(&Indicator::ChallengeTitle));
    }

    #[test]
    fn bare_52x_status_without_body_is_origin_unavailable_medium() {
        let a = analyze(522, &h(&[("cf-ray", "x")]), Some(b""));
        assert_eq!((a.verdict, a.confidence, a.issued_by), (Verdict::OriginUnavailable, Confidence::Medium, IssuedBy::CloudflareEdge));
    }

    #[test]
    fn errors_get_failure_verdicts_by_stage() {
        use crate::core::{Error, Stage};
        let t = |e: Error| analyze_error(&e).verdict;
        assert_eq!(t(Error::TlsHandshake("x".into())), Verdict::TlsFailure);
        assert_eq!(t(Error::Timeout { stage: Stage::Tls, after_ms: 1 }), Verdict::TlsFailure);
        assert_eq!(t(Error::Timeout { stage: Stage::Body, after_ms: 1 }), Verdict::ConnectionFailure);
        assert_eq!(t(Error::Body("cut".into())), Verdict::ConnectionFailure);
        assert_eq!(t(Error::Target("bad".into())), Verdict::Unknown);
    }

    #[test]
    fn undecoded_body_lowers_confidence_and_says_why() {
        let a = analyze(200, &h(&[("cf-ray", "x")]), None);
        assert_eq!((a.verdict, a.confidence), (Verdict::NormalPage, Confidence::Low));
        assert!(a.caveats.iter().any(|c| c.contains("not inspected")));
    }
}
