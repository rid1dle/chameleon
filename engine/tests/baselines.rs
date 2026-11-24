//! Fingerprint parsing and comparison, checked against the real lab captures in
//! experiments/test-results (read live; nothing is copied into the engine).

use std::path::PathBuf;

use cfprobe::fingerprint::{self, FieldStatus, Receiver};

fn results(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../experiments/test-results").join(rel)
}

fn load(rel: &str) -> fingerprint::Observation {
    fingerprint::parse_receiver_body(&std::fs::read(results(rel)).unwrap()).unwrap()
}

fn status(c: &fingerprint::Comparison, field: &str) -> FieldStatus {
    c.fields.iter().find(|f| f.field == field).unwrap().status
}

#[test]
fn trackme_record_matches_the_l1_summary_table() {
    // Values from experiments/test-results/L1/summary-table.md.
    let o = load("L1/chromium-headful.json");
    assert_eq!(o.receiver, Receiver::TrackMe);
    let f = &o.fingerprint;
    assert_eq!(f.tls.ja4.as_deref(), Some("t13d1517h2_8daaf6152771_cb7bf5808d99"));
    assert_eq!(f.http.akamai.as_deref(), Some("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"));
    assert_eq!(f.http.pseudo_order.as_deref(), Some("m,a,s,p"));
    assert_eq!(f.tls.version.as_deref(), Some("TLSv1.3"));
    assert_eq!(f.http.h2_window_update, Some(15663105));
    assert_eq!(f.http.h2_settings.as_ref().unwrap()[0], ("HEADER_TABLE_SIZE".to_string(), 65536));
    let order = f.http.header_order.as_ref().unwrap().join(",");
    assert_eq!(order, "sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,priority");
    // GREASE normalised, real values kept.
    let ciphers = f.tls.ciphers.as_ref().unwrap();
    assert_eq!(ciphers[0], "GREASE");
    assert!(ciphers.iter().all(|c| !c.contains("0x0A0A")));
    assert!(f.tls.sigalgs.as_ref().unwrap().contains(&"GREASE".to_string()));
    assert_eq!(f.tls.alpn.as_ref().unwrap().join(","), "h2,http/1.1");
    assert!(o.derived.iter().any(|d| d.name == "grease_in_ciphers" && d.value));
}

#[test]
fn same_browser_build_matches_on_wire_fields() {
    // FlareSolverr's Chrome and headful Chromium are the same binary (L1 finding).
    let a = load("L1/chromium-headful.json");
    let b = load("L1/flaresolverr-chrome.json");
    let c = fingerprint::compare("a", &a.fingerprint, "b", &b.fingerprint);
    for field in ["tls.ja4", "tls.extensions_sorted", "tls.ciphers", "http.akamai", "http.header_order", "http.user_agent"] {
        assert_eq!(status(&c, field), FieldStatus::Same, "{field}");
    }
}

#[test]
fn chrome_vs_firefox_and_impersonation_differences_are_reported() {
    let chrome = load("L1/chromium-headful.json");
    let firefox = load("L1/ci-firefox155.json");
    let c = fingerprint::compare("chrome", &chrome.fingerprint, "firefox", &firefox.fingerprint);
    for field in ["tls.ja4", "http.akamai", "http.pseudo_order", "http.header_order"] {
        assert_eq!(status(&c, field), FieldStatus::Differs, "{field}");
    }
    // curl-impersonate chrome152: same JA4 and HTTP/2 as real Chrome, but a different header list (L1).
    let ci = load("L1/ci-chrome152.json");
    let c = fingerprint::compare("chrome", &chrome.fingerprint, "ci", &ci.fingerprint);
    assert_eq!(status(&c, "tls.ja4"), FieldStatus::Same);
    assert_eq!(status(&c, "http.akamai"), FieldStatus::Same);
    assert_eq!(status(&c, "http.header_order"), FieldStatus::Differs);
}

#[test]
fn worker_record_reads_tls_and_http_fields_only() {
    let o = load("E1/run1/a2-okhttp-fsua-cookie.json");
    assert_eq!(o.receiver, Receiver::ZoneWorker);
    let f = &o.fingerprint;
    assert_eq!(f.tls.version.as_deref(), Some("TLSv1.3"));
    assert_eq!(f.tls.client_hello_len, Some(1575));
    assert_eq!(f.tls.ja4, None, "Free plan: no Bot Management fields");
    assert_eq!(f.http.protocol.as_deref(), Some("h2"));
    assert_eq!(f.http.pseudo_order.as_deref(), Some("m,p,a,s"));
    let json = serde_json::to_string(&o).unwrap();
    // The record holds these fields (values scrubbed to "<removed>"); the parser must not carry any of them.
    let raw = std::fs::read_to_string(results("E1/run1/a2-okhttp-fsua-cookie.json")).unwrap();
    for key in ["asn", "asOrganization", "colo", "country", "cf-ipcountry", "<removed>"] {
        assert!(raw.contains(key), "fixture lost {key}, test would prove nothing");
        assert!(!json.contains(key), "location field leaked: {key}");
    }
}

#[test]
fn cross_receiver_comparison_marks_uncaptured_fields_not_comparable() {
    // OkHttp seen by TrackMe (L1) and by the zone Worker (E1 a2): pseudo order agrees (E2-2).
    let lab = load("L1/okhttp-suwayomi.json");
    let zone = load("E1/run1/a2-okhttp-fsua-cookie.json");
    let c = fingerprint::compare("lab", &lab.fingerprint, "zone", &zone.fingerprint);
    assert_eq!(status(&c, "http.pseudo_order"), FieldStatus::Same);
    assert_eq!(status(&c, "tls.ja4"), FieldStatus::OnlyLeft);
    assert_eq!(status(&c, "tls.client_hello_len"), FieldStatus::OnlyRight);
    assert_eq!(c.same + c.differs + c.order_only + c.not_comparable, c.fields.len());
}

#[test]
fn baseline_directory_loads_records_and_lists_the_rest() {
    let (found, skipped) = fingerprint::load_baselines(&results("L1")).unwrap();
    let names: Vec<_> = found.iter().map(|b| b.name.as_str()).collect();
    for n in ["chromium-headful", "ci-chrome152", "ci-firefox155", "curl-host", "flaresolverr-chrome", "okhttp-suwayomi"] {
        assert!(names.contains(&n), "{n} missing from {names:?}");
    }
    assert!(skipped.is_empty(), "{skipped:?}");
}

#[test]
fn chromium_124_and_152_differ_in_tls_but_not_http2() {
    // L1-10: version dependence, both captured headless=new the same way.
    let old = load("L1/chromium124-headless.json");
    let new = load("L1/chromium152-headless.json");
    let c = fingerprint::compare("124", &old.fingerprint, "152", &new.fingerprint);
    for field in ["tls.ja4", "tls.groups", "tls.sigalgs", "tls.extensions_sorted"] {
        assert_eq!(status(&c, field), FieldStatus::Differs, "{field}");
    }
    for field in ["http.akamai", "http.pseudo_order", "http.header_order", "tls.ciphers", "tls.alpn"] {
        assert_eq!(status(&c, field), FieldStatus::Same, "{field}");
    }
    assert!(old.fingerprint.tls.groups.as_ref().unwrap().iter().any(|g| g.starts_with("X25519Kyber768")));
    assert!(new.fingerprint.tls.groups.as_ref().unwrap().iter().any(|g| g.starts_with("X25519MLKEM768")));
    // GREASE in signature_algorithms is new in 152: absent in 124 (and in curl-impersonate chrome152, L1-8).
    let sig_grease = |o: &fingerprint::Observation| o.fingerprint.tls.sigalgs.as_ref().unwrap().contains(&"GREASE".to_string());
    assert!(!sig_grease(&old) && sig_grease(&new) && !sig_grease(&load("L1/ci-chrome152.json")));
}

#[test]
fn okhttp_first_stream_is_3() {
    // L1-4
    assert_eq!(load("L1/okhttp-suwayomi.json").fingerprint.http.h2_first_stream, Some(3));
    assert_eq!(load("L1/chromium-headful.json").fingerprint.http.h2_first_stream, Some(1));
}

#[test]
fn baseline_markdown_matches_the_python_table_except_escaped_pipes() {
    let (found, _) = fingerprint::load_baselines(&results("L1")).unwrap();
    let md = cfprobe::reporting::baseline_table(&found);
    assert!(md.contains("| `okhttp-suwayomi` | `h2` | `t13d1114h2_5e2a75874763_89e9e4bb3419` | `4:16777216\\|16711681\\|0\\|m,p,a,s` | `3` |"), "{md}");
    assert!(md.contains("- **curl-host**: `user-agent,accept`  \n  UA: `curl/8.22.0`"));
}

/// D8. Before: the same Chromium binary diffed as "1 differ" on tls.ja3_hash, because JA3 keeps
/// extension order and Chrome reorders extensions per connection. The JA3 strings hold the same
/// values, so that difference is now reported as order-only and not counted as a difference.
#[test]
fn d8_ja3_order_difference_is_not_a_client_difference() {
    let a = load("L1/chromium-headful.json");
    let b = load("L1/flaresolverr-chrome.json");
    let c = fingerprint::compare("a", &a.fingerprint, "b", &b.fingerprint);
    assert_eq!(status(&c, "tls.ja3_hash"), FieldStatus::OrderOnly);
    assert_eq!((c.differs, c.order_only), (0, 1));
    // A real JA3 difference (another browser) stays a difference.
    let f = load("L1/ci-firefox155.json");
    let c = fingerprint::compare("chrome", &a.fingerprint, "firefox", &f.fingerprint);
    assert_eq!(status(&c, "tls.ja3_hash"), FieldStatus::Differs);
}
