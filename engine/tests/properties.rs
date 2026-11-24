//! Property-based tests (proptest): invariants that must hold for any input, not just the fixtures.

use cfprobe::cloudflare::{Indicator, Verdict, analyze};
use cfprobe::http::{DecodeError, HeaderEntry, decode_body, parse_set_cookie, redact_url};
use cfprobe::random::Schedule;
use cfprobe::resilience::parse_retry_after_ms;
use cfprobe::{Config, Target};
use proptest::prelude::*;

fn header() -> impl Strategy<Value = HeaderEntry> {
    let names = prop::sample::select(vec!["server", "cf-ray", "cf-mitigated", "location", "retry-after", "content-type", "x-other"]);
    (names, ".{0,40}").prop_map(|(n, v)| HeaderEntry { name: n.to_string(), value: v })
}

/// Text that carries no structural marker: page copy may mention anything else.
fn plain_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 .,:/-]{0,200}".prop_filter("no structural markers", |s| {
        !s.contains("_cf_chl_opt") && !s.contains("/orchestrate/") && !s.contains("error code") && !s.contains("challenge-platform")
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn classifier_never_panics(status in 0u16..1000, headers in prop::collection::vec(header(), 0..8), body in prop::option::of(prop::collection::vec(any::<u8>(), 0..2000))) {
        let a = analyze(status, &headers, body.as_deref());
        prop_assert!(!a.evidence.is_empty());
    }

    #[test]
    fn a_confirmed_challenge_always_has_the_header(status in 100u16..600, headers in prop::collection::vec(header(), 0..8), body in ".{0,500}") {
        let a = analyze(status, &headers, Some(body.as_bytes()));
        if a.verdict == Verdict::ConfirmedChallengeResponse {
            prop_assert!(headers.iter().any(|h| h.name == "cf-mitigated" && h.value.eq_ignore_ascii_case("challenge")));
        }
        if !a.cloudflare_present {
            prop_assert_eq!(a.error_code, None, "error numbers are only trusted through Cloudflare");
        }
    }

    /// The original false positive, generalised: a 200 page with JavaScript Detections, any title,
    /// any Turnstile mention and any copy is a normal page.
    #[test]
    fn js_detections_and_mentions_never_make_a_challenge(before in plain_text(), after in plain_text(), title in "[a-zA-Z .]{0,30}", mention_turnstile in any::<bool>()) {
        let mut body = format!("<html><head><title>{title}</title><script>var u='/cdn-cgi/challenge-platform/scripts/jsd/main.js?ray=1';</script></head><body>{before}");
        if mention_turnstile {
            body.push_str("<p>Turnstile is a CAPTCHA replacement. Just a moment.</p>");
        }
        body.push_str(&after);
        let h = vec![HeaderEntry { name: "cf-ray".into(), value: "x".into() }, HeaderEntry { name: "server".into(), value: "cloudflare".into() }];
        let a = analyze(200, &h, Some(body.as_bytes()));
        prop_assert_eq!(a.verdict, Verdict::NormalPage);
        prop_assert!(a.indicators.contains(&Indicator::JsDetectionsScript));
    }

    #[test]
    fn redaction_removes_tokens_and_credentials_and_is_idempotent(path in "[a-z/]{0,20}", token in "[A-Za-z0-9_.-]{8,40}", other in "[a-z]{1,8}", user in "[a-z]{1,8}") {
        let url = format!("https://{user}:pw{token}@h.test/{path}?a={other}&__cf_chl_tk={token}&__cf_chl_rt_tk={token}#f");
        let r = redact_url(&url);
        prop_assert!(!r.contains(&token), "{}", r);
        let creds = format!("{user}:pw");
        prop_assert!(!r.contains(&creds), "{}", r);
        prop_assert_eq!(redact_url(&r), r.clone());
        let clean = format!("https://h.test/{path}?a={other}");
        prop_assert_eq!(redact_url(&clean), clean);
    }

    #[test]
    fn decoding_never_panics_and_never_exceeds_the_cap(enc in prop::sample::select(vec!["gzip", "deflate", "br", "zstd", "identity", "gzip, br", "x-unknown", ""]), raw in prop::collection::vec(any::<u8>(), 0..4000), limit in 1usize..10_000) {
        match decode_body(enc, &raw, limit) {
            Ok(out) => prop_assert!(out.len() <= limit || enc.trim().is_empty() || enc == "identity"),
            Err(DecodeError::TooLarge(l)) => prop_assert_eq!(l, limit),
            Err(_) => {}
        }
    }

    #[test]
    fn every_encoding_round_trips_any_bytes(data in prop::collection::vec(any::<u8>(), 0..5000)) {
        use std::io::Write;
        let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        g.write_all(&data).unwrap();
        prop_assert_eq!(decode_body("gzip", &g.finish().unwrap(), 1 << 20).unwrap(), data.clone());
        prop_assert_eq!(decode_body("zstd", &zstd::encode_all(&data[..], 1).unwrap(), 1 << 20).unwrap(), data.clone());
        let mut b = Vec::new();
        brotli::BrotliCompress(&mut &data[..], &mut b, &brotli::enc::BrotliEncoderParams { quality: 2, ..Default::default() }).unwrap();
        prop_assert_eq!(decode_body("br", &b, 1 << 20).unwrap(), data);
    }

    #[test]
    fn set_cookie_parsing_never_panics_or_overstates(raw in ".{0,300}") {
        let c = parse_set_cookie(&raw);
        prop_assert!(c.value_len <= raw.len());
        prop_assert!(!c.name.contains(';'));
    }

    #[test]
    fn retry_after_parsing_never_panics(raw in ".{0,60}", secs in 0u64..100_000) {
        let _ = parse_retry_after_ms(&raw);
        prop_assert_eq!(parse_retry_after_ms(&secs.to_string()), Some(secs * 1000));
    }

    #[test]
    fn schedules_are_permutations_with_bounded_delays(seed in any::<u64>(), n in 0usize..60, a in 0u64..5000, b in 0u64..5000, shuffle in any::<bool>()) {
        let s = Schedule::new(seed, n, shuffle, a, b);
        let mut o = s.order.clone();
        o.sort();
        prop_assert_eq!(o, (0..n).collect::<Vec<_>>());
        let (lo, hi) = (a.min(b), a.max(b));
        prop_assert!(s.delays_ms.iter().skip(1).all(|d| (lo..=hi).contains(d)));
        prop_assert_eq!(s, Schedule::new(seed, n, shuffle, a, b));
    }

    #[test]
    fn targets_and_configs_never_panic(url in ".{0,80}", json in ".{0,120}") {
        let _ = Target::get(&url);
        if let Ok(c) = Config::from_json(&json) {
            let _ = cfprobe::CFProbe::new(c);
        }
    }
}
