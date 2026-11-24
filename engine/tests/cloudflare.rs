//! The response classifier against one real, scrubbed response per Cloudflare action, captured from
//! the zone lab by scripts/zone/e4_capture.sh (read live from experiments/test-results/E4).

use std::path::PathBuf;

use cfprobe::cloudflare::{Analysis, ChallengeKind, Confidence, Indicator, IssuedBy, Verdict, analyze};
use cfprobe::http::HeaderEntry;
use serde_json::Value;

fn capture(name: &str) -> (u16, Analysis) {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../experiments/test-results/E4").join(format!("{name}.json"));
    let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    let r = &v["response"];
    let status = r["status"].as_u64().unwrap() as u16;
    let headers: Vec<HeaderEntry> = serde_json::from_value(r["headers"].clone()).unwrap();
    let body = r["body"].as_str().unwrap();
    (status, analyze(status, &headers, Some(body.as_bytes())))
}

#[test]
fn reached() {
    let (status, a) = capture("reached");
    assert_eq!((status, a.verdict, a.confidence, a.issued_by), (200, Verdict::NormalPage, Confidence::High, IssuedBy::Origin));
    assert!(a.cf_ray.is_some());
}

#[test]
fn each_challenge_action_is_told_apart_by_its_page() {
    for (name, kind) in [
        ("managed", ChallengeKind::Managed),
        ("js-challenge", ChallengeKind::NonInteractive),
        ("interactive", ChallengeKind::Interactive),
    ] {
        let (status, a) = capture(name);
        assert_eq!((status, a.verdict, a.challenge_kind), (403, Verdict::ConfirmedChallengeResponse, Some(kind)), "{name}");
        assert_eq!((a.confidence, a.issued_by), (Confidence::High, IssuedBy::CloudflareEdge), "{name}");
        for i in [Indicator::ChallengeOptions, Indicator::ChallengeOrchestrateScript, Indicator::ChallengeTitle] {
            assert!(a.indicators.contains(&i), "{name}: {i:?} missing from {:?}", a.indicators);
        }
        assert_eq!(a.error_code, None, "{name}");
    }
}

#[test]
fn waf_block_has_no_error_number() {
    let (status, a) = capture("block");
    assert_eq!((status, a.verdict, a.error_code, a.confidence), (403, Verdict::AccessDenied, None, Confidence::High));
    assert!(a.indicators.contains(&Indicator::BlockPage));
}

#[test]
fn rate_limit_is_1015_with_retry_after() {
    let (status, a) = capture("rate-limited");
    assert_eq!((status, a.verdict, a.error_code, a.issued_by), (429, Verdict::RateLimited, Some(1015), IssuedBy::CloudflareEdge));
    assert_eq!(a.retry_after.as_deref(), Some("10"));
}

#[test]
fn direct_ip_access_is_error_1003() {
    let (status, a) = capture("error-1003");
    assert_eq!((status, a.verdict, a.error_code), (403, Verdict::AccessDenied, Some(1003)));
}

#[test]
fn same_status_different_verdicts() {
    // Five of the seven captures are 403: status alone cannot tell them apart.
    let verdicts: Vec<_> = ["managed", "js-challenge", "interactive", "block", "error-1003"]
        .iter()
        .map(|n| capture(n))
        .inspect(|(s, _)| assert_eq!(*s, 403))
        .map(|(_, a)| (a.verdict, a.challenge_kind, a.error_code))
        .collect();
    for (i, a) in verdicts.iter().enumerate() {
        assert!(verdicts[i + 1..].iter().all(|b| b != a), "two captures got the same verdict: {a:?}");
    }
}
