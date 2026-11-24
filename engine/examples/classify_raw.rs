//! Classify saved `cfprobe inspect --show-body` JSON files. Usage: cargo run --example classify_raw -- <file>...
use cfprobe::cloudflare::analyze;
use cfprobe::http::HeaderEntry;

fn main() {
    for p in std::env::args().skip(1) {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let r = &v["response"];
        let status = r["status"].as_u64().unwrap() as u16;
        let headers: Vec<HeaderEntry> = serde_json::from_value(r["headers"].clone()).unwrap();
        let a = analyze(status, &headers, Some(r["body"].as_str().unwrap_or_default().as_bytes()));
        println!("{p}\t{status}\t{}", serde_json::to_string(&serde_json::json!({"verdict": a.verdict, "confidence": a.confidence, "issued_by": a.issued_by, "indicators": a.indicators, "error_code": a.error_code})).unwrap());
    }
}
