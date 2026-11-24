//! Regression fixtures from public sites (experiments/test-results/P2/fixtures, excerpts made by
//! scripts/phase2/excerpt_fixture.py from one ordinary GET each, 2026-11-24). The first detector used
//! for Phase 2 called three of these normal pages challenges because they contain
//! `/cdn-cgi/challenge-platform/` (JavaScript Detections) and one because it mentions "Turnstile".

use std::path::PathBuf;

use cfprobe::cloudflare::{Analysis, Confidence, Indicator, IssuedBy, Verdict, analyze};
use cfprobe::http::HeaderEntry;
use serde_json::Value;

fn fixture(name: &str) -> (u16, Analysis) {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../experiments/test-results/P2/fixtures").join(format!("{name}.json"));
    let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    let r = &v["response"];
    let status = r["status"].as_u64().unwrap() as u16;
    let headers: Vec<HeaderEntry> = serde_json::from_value(r["headers"].clone()).unwrap();
    (status, analyze(status, &headers, Some(r["body"].as_str().unwrap().as_bytes())))
}

/// Former false positives: JavaScript Detections on a normal page is an indicator, not a challenge.
#[test]
fn js_detections_pages_are_normal_pages_with_the_indicator() {
    for site in ["asurascans.com", "discord.com", "in.bookmyshow.com"] {
        let (status, a) = fixture(site);
        assert_eq!((status, a.verdict, a.confidence, a.issued_by), (200, Verdict::NormalPage, Confidence::High, IssuedBy::Origin), "{site}: {a:#?}");
        assert_eq!(a.indicators, [Indicator::JsDetectionsScript], "{site}");
        assert!(a.caveats.iter().any(|c| c.contains("does not prove")), "{site}: absence of cf-mitigated must be caveated");
    }
}

/// Former false positive: the word "Turnstile" in a product menu is not a Turnstile widget.
#[test]
fn turnstile_mentions_are_not_indicators() {
    let (status, a) = fixture("www.cloudflare.com");
    assert_eq!((status, a.verdict), (200, Verdict::NormalPage));
    assert!(a.indicators.is_empty(), "{:?}", a.indicators);
}

#[test]
fn plain_redirect_is_a_redirect() {
    let (status, a) = fixture("asuracomic.net");
    assert_eq!((status, a.verdict, a.location.as_deref()), (301, Verdict::Redirect, Some("https://asurascans.com/")));
}

/// Former false negative: `error code: 522` has three digits; the Phase 7 detector wanted four and
/// called this origin failure "reached".
#[test]
fn error_522_is_origin_unavailable() {
    let (status, a) = fixture("nowsecure.nl");
    assert_eq!((status, a.verdict, a.error_code, a.issued_by, a.confidence), (522, Verdict::OriginUnavailable, Some(522), IssuedBy::CloudflareEdge, Confidence::High));
}

/// nowsecure.nl once back up (2026-11-24 15:28Z): a normal 200 page with an embedded Turnstile
/// widget (`class="cf-turnstile"`, test sitekey 3x...FF) and the api.js script. Embedded Turnstile is
/// an integration inside the origin's page, not a blocking challenge.
#[test]
fn embedded_turnstile_widget_is_a_normal_page_with_indicators() {
    let (status, a) = fixture("nowsecure.nl-turnstile");
    assert_eq!((status, a.verdict, a.issued_by), (200, Verdict::NormalPage, IssuedBy::Origin));
    for i in [Indicator::TurnstileScript, Indicator::TurnstileWidget, Indicator::JsDetectionsScript] {
        assert!(a.indicators.contains(&i), "{i:?} missing: {:?}", a.indicators);
    }
    assert!(a.evidence.iter().any(|e| e.contains("not a blocking challenge")));
}

/// Real 522s from the zone lab (2026-11-24 15:32Z, about 2 minutes after the Worker's Custom Domain
/// was created). The HTML page states its number as `<span class="code-label">Error code 522</span>`;
/// before, only a `cf-error-code` span was read, so the number was missed and confidence was medium.
#[test]
fn zone_522_html_and_plain_text_both_give_the_number() {
    for name in ["zone-522-html", "zone-522-plain"] {
        let (status, a) = fixture(name);
        assert_eq!((status, a.verdict, a.error_code, a.confidence, a.issued_by), (522, Verdict::OriginUnavailable, Some(522), Confidence::High, IssuedBy::CloudflareEdge), "{name}");
    }
    let (_, a) = fixture("zone-522-html");
    assert_eq!(a.title.as_deref(), Some("riddlelab.dev | 522: Connection timed out"));
}

/// The Worker serving a hostname threw: `error code: 1101`. Before: UNKNOWN (unmapped number).
#[test]
fn worker_exception_1101_is_origin_unavailable() {
    let (status, a) = fixture("zone-1101");
    assert_eq!((status, a.verdict, a.error_code, a.issued_by), (500, Verdict::OriginUnavailable, Some(1101), IssuedBy::CloudflareEdge));
}

/// Deliberate origin failures on the zone (2026-11-24): proxied records to a TEST-NET address that
/// never answers (522 after ~19.5 s), a CNAME to a name that does not exist (530 + 1016), and a
/// reserved class E address (403 + 1002). 1002 used to be UNKNOWN (unmapped).
#[test]
fn deliberate_origin_failures_are_origin_unavailable() {
    for (name, status, code) in [("zone-522-deliberate", 522, 522), ("zone-530-1016", 530, 1016), ("zone-1002", 403, 1002)] {
        let (s, a) = fixture(name);
        assert_eq!((s, a.verdict, a.error_code, a.issued_by, a.confidence), (status, Verdict::OriginUnavailable, Some(code), IssuedBy::CloudflareEdge, Confidence::High), "{name}");
    }
}

/// D28: the HTML form of 1xxx errors (sent when the request offers compression) states its number as
/// `<span data-translate="error">Error</span> <span>1002</span>`. curl (`--compressed`) got these
/// pages on the zone and the 1002 one came out UNKNOWN, the 1016 one without its number.
#[test]
fn html_1xxx_pages_give_their_number() {
    for (name, status, code) in [("zone-1002-html", 403, 1002), ("zone-530-1016-html", 530, 1016)] {
        let (s, a) = fixture(name);
        assert_eq!((s, a.verdict, a.error_code, a.confidence), (status, Verdict::OriginUnavailable, Some(code), Confidence::High), "{name}");
    }
}
