//! Randomized response scenarios and what each one should be classified as.
//!
//! The expected verdict comes from what a scenario was generated to be (a challenge page, a block
//! page, an origin 403, a dropped connection), not from running the classifier. Decoys are mixed into
//! ordinary pages on purpose: words like "Turnstile", "Just a moment" and the challenge-platform path
//! in page text, and the JavaScript Detections script, must not turn a normal page into a challenge.

use rand::Rng;
use rand::seq::IndexedRandom;
use rand_chacha::ChaCha8Rng;
use serde::Serialize;

use crate::cloudflare::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    PlainH1,
    TlsH1,
    TlsH2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Body {
    Html { title: String, js_detections: bool, turnstile_widget: bool, decoys: bool },
    Json { valid: bool },
    Text,
    Empty,
    /// The interstitial; sent with `cf-mitigated: challenge`.
    Challenge { ctype: String },
    BlockPage,
    /// `error code: N` as the whole body.
    ErrorCode { code: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Gzip,
    Deflate,
    Br,
    Zstd,
    /// Says gzip, is not.
    CorruptGzip,
    /// An encoding the engine does not decode.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Fault {
    None,
    /// Pause before the response head.
    Latency { ms: u64 },
    /// Body sent in small chunks with pauses.
    SlowDrip { chunk: usize, pause_ms: u64 },
    /// Connection closed after reading the request, before any response.
    CloseBeforeHead,
    /// Connection closed after half the body (HTTP/1.1 with Content-Length).
    CloseMidBody,
    /// Head later than the client's request timeout.
    Timeout,
    /// The host name does not resolve (`.invalid`, RFC 6761).
    DnsFailure,
    /// Nothing listens on the port.
    Refused,
    /// The server's certificate is not trusted by the client.
    UntrustedCertificate,
}

#[derive(Debug, Clone, Serialize)]
pub struct Scenario {
    pub index: u64,
    pub transport: Transport,
    pub status: u16,
    pub cloudflare: bool,
    pub body: Body,
    /// Filler bytes added to text-like bodies.
    pub filler: usize,
    pub encoding: Option<Encoding>,
    /// HTTP/1.1 only: chunked instead of Content-Length.
    pub chunked: bool,
    /// Raw `Set-Cookie` values; some malformed on purpose.
    pub set_cookies: Vec<String>,
    /// Extra headers, repeats included.
    pub extra_headers: Vec<(String, String)>,
    pub retry_after: Option<String>,
    /// Redirect hops before the final response; `redirect_loop` makes the last hop point back.
    pub redirects: u8,
    pub redirect_loop: bool,
    pub fault: Fault,
}

/// What the run should observe.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Expected {
    pub verdict: Verdict,
    /// `Some` when the scenario must end as a redirect loop (only checked when following).
    pub redirect_loop: bool,
    /// The decoded body must equal what was generated.
    pub body_must_match: bool,
}

const WORDS: [&str; 12] = ["lorem", "manga", "ticket", "chapter", "cinema", "update", "series", "release", "review", "search", "genre", "latest"];
const DECOYS: [&str; 5] = [
    "Protected by Turnstile, our CAPTCHA replacement.",
    "Just a moment while we load your feed.",
    "See /cdn-cgi/challenge-platform/ in the docs for details.",
    "challenge-platform and cf_clearance explained",
    "class names like cf-turnstile-wrapper are styling only",
];

pub fn generate(rng: &mut ChaCha8Rng, index: u64) -> Scenario {
    let transport = *[Transport::PlainH1, Transport::TlsH1, Transport::TlsH2].choose(rng).unwrap();
    let cloudflare = rng.random_bool(0.6);
    let fault = match rng.random_range(0..100) {
        0..60 => Fault::None,
        60..70 => Fault::Latency { ms: rng.random_range(10..300) },
        70..76 => Fault::SlowDrip { chunk: rng.random_range(64..2048), pause_ms: rng.random_range(5..30) },
        76..81 => Fault::CloseBeforeHead,
        81..86 => Fault::CloseMidBody,
        86..90 => Fault::Timeout,
        90..93 => Fault::DnsFailure,
        93..96 => Fault::Refused,
        _ => Fault::UntrustedCertificate,
    };
    // Faults that need HTTP/1.1 framing control use the raw server.
    let transport = match fault {
        Fault::CloseBeforeHead | Fault::CloseMidBody | Fault::SlowDrip { .. } if transport == Transport::TlsH2 => Transport::TlsH1,
        Fault::UntrustedCertificate if transport == Transport::PlainH1 => Transport::TlsH1,
        _ => transport,
    };

    let (status, body, cloudflare) = match rng.random_range(0..100) {
        0..30 => (200, html(rng), cloudflare),
        30..38 => (200, Body::Json { valid: rng.random_bool(0.7) }, cloudflare),
        38..42 => (*[200, 204].choose(rng).unwrap(), Body::Empty, cloudflare),
        42..48 => (*[301, 302, 307, 308].choose(rng).unwrap(), Body::Empty, cloudflare),
        48..58 => (*[403, 503].choose(rng).unwrap(), Body::Challenge { ctype: ["managed", "non-interactive", "interactive", "future-type"].choose(rng).unwrap().to_string() }, true),
        58..63 => (403, Body::BlockPage, true),
        63..70 => {
            let code = *[1015u16, 1020, 1003, 1010, 520, 521, 522, 524, 1101, 1234].choose(rng).unwrap();
            let status = match code {
                1015 => 429,
                520..=530 => code,
                1101 => 500,
                _ => 403,
            };
            (status, Body::ErrorCode { code }, true)
        }
        70..80 => (*[401, 403, 404, 429].choose(rng).unwrap(), if rng.random_bool(0.5) { html(rng) } else { Body::Text }, cloudflare),
        80..90 => (*[500, 502, 503, 504].choose(rng).unwrap(), Body::Text, cloudflare),
        _ => (*[200, 201, 206, 418, 451].choose(rng).unwrap(), Body::Text, cloudflare),
    };

    let encoding = if matches!(body, Body::Empty) || !rng.random_bool(0.4) {
        None
    } else {
        Some(*[Encoding::Gzip, Encoding::Deflate, Encoding::Br, Encoding::Zstd, Encoding::CorruptGzip, Encoding::Unknown].choose(rng).unwrap())
    };
    let set_cookies = (0..rng.random_range(0..4)).map(|_| cookie(rng)).collect();
    let extra_headers = (0..rng.random_range(0..5))
        .map(|_| {
            let name = *["x-dup", "x-trace", "vary", "link", "x-empty"].choose(rng).unwrap();
            let value = if name == "x-empty" { String::new() } else { format!("v{}", rng.random_range(0..100)) };
            (name.to_string(), value)
        })
        .collect();
    let retry_after = matches!(status, 429 | 503).then(|| ["1", "0", "3600", "Wed, 21 Oct 2015 07:28:00 GMT", "soon"].choose(rng).unwrap().to_string()).filter(|_| rng.random_bool(0.6));
    let redirects = if matches!(fault, Fault::None) && rng.random_bool(0.15) { rng.random_range(1..4) } else { 0 };
    let redirect_loop = redirects > 0 && rng.random_bool(0.3);
    // A chain ends on a non-redirect, so following it has one defined end.
    let status = if redirects > 0 && (300..400).contains(&status) { 200 } else { status };
    // A 204 has no body (RFC 9110 15.3.5), so there is nothing to cut: make it a 200.
    let status = if fault == Fault::CloseMidBody && status == 204 { 200 } else { status };

    let mut filler = if rng.random_bool(0.1) { rng.random_range(100_000..600_000) } else { rng.random_range(0..4000) };
    // A slow drip must finish well inside the client's request timeout (1.5 s in fuzz runs), or the
    // scenario is a timeout, not a slow response: at most 600 ms of pauses.
    if let Fault::SlowDrip { chunk, pause_ms } = fault {
        filler = filler.min(chunk * (600 / pause_ms as usize).saturating_sub(1));
    }
    Scenario {
        index,
        transport,
        status,
        cloudflare,
        filler,
        body,
        encoding,
        chunked: rng.random_bool(0.3),
        set_cookies,
        extra_headers,
        retry_after,
        redirects,
        redirect_loop,
        fault,
    }
}

fn html(rng: &mut ChaCha8Rng) -> Body {
    Body::Html {
        title: format!("{} {}", WORDS.choose(rng).unwrap(), WORDS.choose(rng).unwrap()),
        js_detections: rng.random_bool(0.4),
        turnstile_widget: rng.random_bool(0.2),
        decoys: rng.random_bool(0.5),
    }
}

fn cookie(rng: &mut ChaCha8Rng) -> String {
    match rng.random_range(0..10) {
        0 => ";;;".into(),
        1 => "=novalue".into(),
        2 => "nameonly".into(),
        3 => format!("old{}=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT", rng.random_range(0..9)),
        4 => format!("q{}=\"quoted value\"; Path=/", rng.random_range(0..9)),
        5 => format!("dom{}=1; Domain=other.invalid", rng.random_range(0..9)),
        _ => format!("c{}={}; Path=/; HttpOnly; SameSite=Lax", rng.random_range(0..99), rng.random_range(0..1_000_000)),
    }
}

impl Scenario {
    pub fn expected(&self, following_redirects: bool) -> Expected {
        let failure = |v| Expected { verdict: v, redirect_loop: false, body_must_match: false };
        match self.fault {
            Fault::CloseBeforeHead | Fault::CloseMidBody | Fault::Timeout | Fault::DnsFailure | Fault::Refused => return failure(Verdict::ConnectionFailure),
            Fault::UntrustedCertificate => return failure(Verdict::TlsFailure),
            _ => {}
        }
        if self.redirects > 0 && following_redirects && self.redirect_loop {
            return Expected { verdict: Verdict::Redirect, redirect_loop: true, body_must_match: false };
        }
        if self.redirects > 0 && !following_redirects {
            return Expected { verdict: Verdict::Redirect, redirect_loop: false, body_must_match: false };
        }
        let decodable = !matches!(self.encoding, Some(Encoding::CorruptGzip | Encoding::Unknown));
        let verdict = match (&self.body, self.status) {
            (Body::Challenge { .. }, _) => Verdict::ConfirmedChallengeResponse,
            (Body::BlockPage, _) if decodable => Verdict::AccessDenied,
            (Body::ErrorCode { code }, _) if decodable => match code {
                1015 => Verdict::RateLimited,
                1003 | 1010 | 1020 => Verdict::AccessDenied,
                520..=530 | 1101 => Verdict::OriginUnavailable,
                _ => Verdict::Unknown,
            },
            // Without a readable body, Cloudflare's own statuses still tell an origin failure.
            (_, 520..=527 | 530) if self.cloudflare => Verdict::OriginUnavailable,
            (_, 200..=299) => Verdict::NormalPage,
            (_, 300..=399) => Verdict::Redirect,
            (_, 401 | 403 | 407) => Verdict::AccessDenied,
            (_, 429) => Verdict::RateLimited,
            (_, 502..=504) => Verdict::OriginUnavailable,
            (_, 400..=599) => Verdict::NormalPage,
            _ => Verdict::Unknown,
        };
        Expected { verdict, redirect_loop: false, body_must_match: decodable && !matches!(self.body, Body::Empty) }
    }

    /// The final response body before encoding. Deterministic from the scenario.
    pub fn plain_body(&self) -> Vec<u8> {
        let filler: String = {
            let mut s = String::with_capacity(self.filler);
            let mut i = self.index as usize;
            while s.len() < self.filler {
                s.push_str(WORDS[i % WORDS.len()]);
                s.push(' ');
                i = i.wrapping_mul(31).wrapping_add(7);
            }
            s
        };
        match &self.body {
            Body::Html { title, js_detections, turnstile_widget, decoys } => {
                let mut b = format!("<!doctype html><html><head><title>{title}</title>");
                if *js_detections {
                    b.push_str("<script>(function(){var u='/cdn-cgi/challenge-platform/scripts/jsd/main.js?ray=abc';var a=document.createElement('script');a.src=u;})();</script>");
                }
                if *turnstile_widget {
                    b.push_str("<script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\" async defer></script>");
                }
                b.push_str("</head><body>");
                if *decoys {
                    for d in DECOYS {
                        b.push_str(&format!("<p>{d}</p>"));
                    }
                }
                if *turnstile_widget {
                    b.push_str("<form><div class=\"cf-turnstile\" data-sitekey=\"1x00000000000000000000AA\"></div></form>");
                }
                b.push_str(&format!("<main>{filler}</main></body></html>"));
                b.into_bytes()
            }
            Body::Json { valid: true } => format!("{{\"items\":[1,2,3],\"note\":\"{}\"}}", filler.trim()).into_bytes(),
            Body::Json { valid: false } => format!("{{\"items\":[1,2,\"note\":\"{}", filler.trim()).into_bytes(),
            Body::Text => filler.into_bytes(),
            Body::Empty => Vec::new(),
            Body::Challenge { ctype } => format!(
                "<!DOCTYPE html><html lang=\"en-US\"><head><title>Just a moment...</title></head><body><noscript>Enable JavaScript and cookies to continue</noscript>\
                 <script>(function(){{window._cf_chl_opt = {{cvId: '3', cType: '{ctype}', cRay: 'abc'}};var a = document.createElement('script');a.src = '/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=abc';}}());</script></body></html>"
            )
            .into_bytes(),
            Body::BlockPage => "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head><body><div id=\"cf-wrapper\"><div id=\"cf-error-details\"><h1 data-translate=\"block_headline\">Sorry, you have been blocked</h1></div></div></body></html>".as_bytes().to_vec(),
            Body::ErrorCode { code } => format!("error code: {code}").into_bytes(),
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self.body {
            Body::Html { .. } | Body::Challenge { .. } | Body::BlockPage => "text/html; charset=utf-8",
            Body::Json { .. } => "application/json",
            _ => "text/plain; charset=utf-8",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::stream;

    #[test]
    fn same_seed_and_index_give_the_same_scenario() {
        let a = generate(&mut stream(77, 5), 5);
        let b = generate(&mut stream(77, 5), 5);
        assert_eq!(serde_json::to_string(&a).unwrap(), serde_json::to_string(&b).unwrap());
        assert_eq!(a.plain_body(), b.plain_body());
    }

    #[test]
    fn generated_values_stay_within_their_bounds() {
        for i in 0..2000 {
            let s = generate(&mut stream(3, i), i);
            assert!((100..=599).contains(&s.status), "{s:?}");
            assert!(s.redirects <= 3 && (s.redirects > 0 || !s.redirect_loop));
            assert!(s.filler < 600_000);
            if let Fault::Latency { ms } = s.fault {
                assert!(ms < 300);
            }
            if matches!(s.body, Body::Challenge { .. } | Body::BlockPage | Body::ErrorCode { .. }) {
                assert!(s.cloudflare, "Cloudflare's own pages come through Cloudflare");
            }
            if matches!(s.fault, Fault::CloseMidBody | Fault::CloseBeforeHead | Fault::SlowDrip { .. }) {
                assert_ne!(s.transport, Transport::TlsH2);
            }
        }
    }

    #[test]
    fn every_kind_is_reachable() {
        let all: Vec<Scenario> = (0..3000).map(|i| generate(&mut stream(11, i), i)).collect();
        for f in ["none", "latency", "slow_drip", "close_before_head", "close_mid_body", "timeout", "dns_failure", "refused", "untrusted_certificate"] {
            assert!(all.iter().any(|s| serde_json::to_value(s.fault).unwrap()["kind"] == f), "{f}");
        }
        assert!(all.iter().any(|s| s.redirect_loop));
        assert!(all.iter().any(|s| s.encoding == Some(Encoding::CorruptGzip)));
    }
}
