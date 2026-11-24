# Phase 2 summary: cfprobe ("Chameleon-RS") testing, debugging and hardening (2026-11-24)

The engine the briefs call Chameleon-RS is `engine/` (`cfprobe`). Phase 2 tested it on loopback servers, on a Cloudflare zone owned by the researcher (`lab.riddlelab.dev`, Free plan), and with one ordinary request per public URL on six sites. **27 defects were found; 26 are fixed with a regression test, 1 is documented.** Proxy routing (a later requirement) is in `PROXY_ROUTING.md`: every connection through a defined proxy with no direct fallback, and announced direct mode when none is defined.

## The answers the brief asked for

### What works (with evidence)

| Area | Evidence |
|---|---|
| Classification of Cloudflare responses | 10 verdicts with confidence, issuer, indicators, evidence, caveats. Every real response correct: 7 E4 captures, 10 P2 fixtures, 96 zone results (0 failed), 38 public observations, 10,000 fuzzed responses |
| The reported false positives | Reproduced (JavaScript Detections script on 3 normal pages; "Turnstile" in a menu), fixed, regression-tested, generalised in a property test |
| Transport | TLS 1.2 and 1.3, ALPN, HTTP/1.1 and HTTP/2 with multiplexing, connection reuse, keep-alive recovery, IPv6 literals, every address tried, gzip/deflate/br/zstd decoding (live from Cloudflare), per-stage timeouts, body caps |
| Resilience | Bounded retries with seeded jitter, Retry-After (floor and cap), circuit breaker, redirect following with loop detection, cookie jar, cancellation; never retries denials or challenges, never relaxes TLS |
| Reproducibility | Seeded fuzzing (`--seed`, `--only`), seeded run order and pauses, same seed gives the same sequence |
| Stability and performance | No panics under fuzzing; flat memory over 1M requests; sequential latency equal to reqwest; HTTP/2 throughput 8% above reqwest at concurrency 32 |
| Secret handling | Cookie values, URL credentials and challenge tokens never reach records; committed results scrubbed and checked (`scripts/phase2/scrub.py --check`) |

### What failed, and why (all fixed unless marked)

| Defect | Why it happened |
|---|---|
| Normal pages called challenges (D17) | A string rule matched the challenge-platform directory, which also serves JavaScript Detections |
| `error code: 522` read as "reached" (D15); HTML 522 number missed (D16) | 4-digit-only parser; a span name never checked against a real page |
| Dead pooled connections failed requests, 49/100 (D1) | No retry on a reused connection closed by the server |
| A config value crashed the process (D2) | `h2` asserts; config was not validated |
| First DNS address only (D3), IPv6 literals broken (D5), `--resolve` silently fell back to DNS (D6) | Simplified dialing |
| URL passwords in reports and on the wire (D4), challenge tokens in reports (D11), double redaction misreporting lengths (D20), curl bodies in committed results (D25) | Redaction covered only cookies and authorization; one path skipped it |
| Compressed bodies never decoded (D7) | No Content-Encoding handling |
| Comparison noise (D8), duplicate headers lost (D9), no multiplexing (D12), header case (D13), 1xx and header limits (D14), h2 headers misreported (D19) | Engine defaults and record-keeping |
| Runner and resilience defects found on the zone: curl unpinned (D18), breaker counted retries (D21), unparseable responses retried (D22), `Retry-After: 0` meant hammering (D23) | Assumptions that only real Cloudflare behaviour exposed |
| Cloudflare cookies ignored (D24) | Classifier saw only the redacted header list |
| **Open:** header wire order (D10) | hyper exposes only a header map |
| **Open:** HTTP/1.1 throughput 14 to 19% below reqwest at concurrency 32 (P1) | Not profiled |

### Which capabilities are missing

JavaScript execution, challenge solving (by design), TLS session resumption, HTTP/3, proxy chaining/PAC/NTLM, browser-equivalent fingerprints (by design: HTTP/2 is hyper's, identical to reqwest; TLS is BoringSSL's default; 13 of 17 comparable fields differ from Chromium 152). Full list: `KNOWN_ISSUES.md`.

### Which observations are reliable

| Reliable | Less reliable |
|---|---|
| Status, headers, TLS version/cipher/ALPN, certificate chain, timings of each attempt | Response header **order** (grouped, D10) |
| Classification when `cf-mitigated`, a block page or an error number is present (high confidence) | Classification from status alone (medium/low, stated) |
| Fingerprints measured at a receiver | Worker TLS hashes for GREASE clients (vary per connection) |
| "Absent `cf-mitigated`" as a fact about this response | "Absent `cf-mitigated`" as proof of no mitigation (never claimed) |

### What Cloudflare was measured doing

Retry-After counts down to 0 while still limiting and a request at the end of the wait can restart the window; clearance is bound to the User-Agent but not to TLS, HTTP/2 or HTTP version on this Free zone; an origin that dies mid-body is delivered as a complete response; brief 522s appeared right after a Custom Domain was created (inferred propagation); with all four offered, the edge compresses with zstd.

### What improvements are necessary

1. Profile HTTP/1.1 under concurrency (P1).
2. Deliberate 52x scenarios once the zone token has DNS:Edit.
3. A Google Chrome and a Firefox capture for comparisons; IPv6 egress for network-level IPv6 tests.
4. Pool limits and idle timeout for long runs over many origins.
5. TLS session resumption if resumed-handshake fingerprints matter.
6. Verify egress with a proxy on another host (`proxy-check --expect-egress-ip`): the local proxy proves routing, not a different egress.

## Acceptance criteria (brief Part J 18)

| Criterion | State |
|---|---|
| Original false positive fixed and regression-tested | Yes |
| Meaningful coverage of major modules | 133 tests across every module; fuzzing; property tests |
| Real-world observations collected | 19 URLs, 6 sites, 2 runs |
| Controlled Cloudflare scenarios evaluated | 34 cases, 3 clients, lifecycle; deliberate 52x open (token) |
| TLS and HTTP independently validated | At TrackMe and the zone Worker (receiver-side), and against curl, reqwest, Chromium |
| Randomized testing reproducible | Yes |
| Fault handling verified | Yes (`FAULT_TOLERANCE.md`) |
| No uncontrolled retry loops | Bounded and tested |
| Major defects fixed or documented | 24 fixed, D10 and P1 documented |
| Performance and reliability results | `PERFORMANCE.md` |
| Reports separate evidence from inference | Each report marks inferences and open items |

## Where things are

`docs/phase2/README.md` maps every report and data folder.
