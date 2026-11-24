"""Summarise TrackMe /api/all captures (experiments/test-results/L1/*.json) into one comparison table.

Usage: python3 -I summarize_l1.py <dir-with-json> > summary.md
Extracts only what TrackMe recorded; a field TrackMe did not capture prints as "not captured", never blank.
"""
import json
import sys
from pathlib import Path

NOT_CAPTURED = "not captured"


def headers_frame(capture):
    for frame in (capture.get("http2") or {}).get("sent_frames", []):
        if frame.get("frame_type") == "HEADERS":
            return frame
    return None


def row(name, capture):
    tls = capture.get("tls", {})
    h2 = capture.get("http2") or {}
    frame = headers_frame(capture)
    if frame:
        names = [h.split(":")[0] if not h.startswith(":") else ":" + h.split(":")[1] for h in frame["headers"]]
        regular = [n for n in names if not n.startswith(":")]
        stream = frame.get("stream_id")
    else:
        regular, stream = [], NOT_CAPTURED
    return {
        "client": name,
        "http": capture.get("http_version", NOT_CAPTURED),
        "ja4": tls.get("ja4", NOT_CAPTURED),
        "ja3_hash": tls.get("ja3_hash", NOT_CAPTURED),
        "akamai_h2": h2.get("akamai_fingerprint", NOT_CAPTURED),
        "first_stream": stream,
        "header_order": ",".join(regular) or NOT_CAPTURED,
        "user_agent": capture.get("user_agent", NOT_CAPTURED),
    }


def main(folder):
    rows = [row(p.stem, json.loads(p.read_text())) for p in sorted(Path(folder).glob("*.json"))]
    cols = ["client", "http", "ja4", "akamai_h2", "first_stream"]
    print("| " + " | ".join(cols) + " |")
    print("|" + "---|" * len(cols))
    for r in rows:
        print("| " + " | ".join(f"`{r[c]}`" for c in cols) + " |")
    print("\n## Header order (pseudo-headers excluded) and User-Agent\n")
    for r in rows:
        print(f"- **{r['client']}**: `{r['header_order']}`  \n  UA: `{r['user_agent']}`")


if __name__ == "__main__":
    main(sys.argv[1])
