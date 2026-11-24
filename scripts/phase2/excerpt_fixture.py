"""Turn a full `cfprobe inspect --show-body` capture of a third-party page into a committable fixture.

Third-party HTML is not committed (this repo is public). The fixture keeps what the classifier reads:
status, headers, the <title>, and a window of 300 characters around every structural marker the
classifier knows, plus around plain mentions it must ignore ("turnstile", "challenge-platform").
Tokens (runs of 30+ token characters), IPv4 addresses and the cf-ray data-centre suffix are removed.

Usage: python3 -I scripts/phase2/excerpt_fixture.py <raw.json> <fixture.json>
"""
import json
import re
import sys

MARKERS = [
    "/cdn-cgi/challenge-platform/", "_cf_chl_opt", "cType:", "challenges.cloudflare.com/turnstile/",
    "cf-turnstile", "cf-error-details", "cf-wrapper", "block_headline", "cf-error-code", "code-label", "error code:",
    "turnstile", "Just a moment",
]
WINDOW = 300
TOKEN = re.compile(r"[A-Za-z0-9_.~%+=-]{30,}")
IPV4 = re.compile(r"\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b")


def scrub(s):
    return IPV4.sub("<removed>", TOKEN.sub("<removed>", s))


def excerpt(body):
    spans = []
    m = re.search(r"<title[^>]*>.*?</title>", body, re.I | re.S)
    if m:
        spans.append((m.start(), m.end()))
    for marker in MARKERS:
        for m in re.finditer(re.escape(marker), body, re.I):
            spans.append((max(0, m.start() - WINDOW), min(len(body), m.end() + WINDOW)))
    spans.sort()
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else:
            merged.append((a, b))
    return "\n<!-- excerpt gap -->\n".join(body[a:b] for a, b in merged) if merged else body[:2000]


def main(src, dst):
    raw = json.load(open(src))
    r = raw["response"]
    headers = []
    for h in r["headers"]:
        v = h["value"]
        v = re.sub(r"-[A-Z]{3}$", "-<removed>", v) if h["name"] == "cf-ray" else scrub(v)
        headers.append({"name": h["name"], "value": v})
    fixture = {
        "source": {"url": raw["request"]["url"], "captured_by": "cfprobe inspect --show-body", "raw_file": src},
        "note": "Excerpt of a third-party page: title and windows around classifier markers only.",
        "response": {
            "status": r["status"],
            "http_version": r["http_version"],
            "headers": headers,
            "body_len_full": r["body_len"],
            "body": scrub(excerpt(r.get("body", ""))),
        },
    }
    json.dump(fixture, open(dst, "w"), indent=2, ensure_ascii=False)
    print(f"{dst}: status {r['status']}, body {r['body_len']} -> {len(fixture['response']['body'])} chars")


if __name__ == "__main__":
    main(*sys.argv[1:3])
