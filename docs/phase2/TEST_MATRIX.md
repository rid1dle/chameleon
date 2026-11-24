# Test matrix (Phase 2, 2026-11-24)

What was tested, where, and with what result. Environments: **Local** (loopback servers in `cargo test`, the fuzz mock, TrackMe), **Zone** (`lab.riddlelab.dev`, owned), **Public** (third-party, one GET per URL per run).

Status: **pass** (expectation met), **observed** (no expectation; recorded), **open** (not done, with the reason), **n/a** (out of scope for that environment by rule).

## Resource types (brief Part A 5, Part B 6)

| Resource type | Local | Zone | Public |
|---|---|---|---|
| Landing page | pass (fixtures, fuzz html) | pass `echo`, `echo-html` | observed: 5 homepages |
| Documentation | n/a | n/a | observed: Discord docs (301 > 200), Turnstile docs |
| Static asset | pass (fuzz) | pass `static` | observed: AsuraScans CSS and CDN image, BookMyShow CDN image |
| Search / listing | n/a | n/a | observed: AsuraScans `/browse?genres=action`, BookMyShow `/explore/action-movies` |
| JSON | pass (fuzz valid and broken JSON) | pass `json` | observed: Cloudflare `/client/v4/ips`, Discord discovery (401), AsuraScans API root (404) |
| Redirect | pass (chains, loops, too many, cross-origin) | pass `redirect`, `redirect-no-follow`, `redirect-loop` | observed: 4 redirects, all followed within the site |
| Authentication required | pass (origin 401/403 classification) | pass `auth-required`, `origin-forbidden` | observed: Cloudflare API without a token (403 JSON), Discord API (401) |
| Rate limited | pass (fuzz 429 and 1015) | pass `rate-limit`, `rate-limit-backoff`, `origin-429` | n/a |
| Challenge (managed, JS, interactive) | pass (fuzz, fixtures) | pass `managed`, `js-challenge`, `interactive`, `managed-browser-headers`, `managed-head` | none observed |
| WAF block, 10xx denial | pass (fuzz, fixtures) | pass `waf-block`, `direct-ip` | none observed |
| Turnstile embedded | pass (fuzz, fixture) | pass `turnstile-embed`, `turnstile-verify-no-token` | observed: nowsecure.nl |
| Origin failure | pass (fuzz 50x, 52x, 1101) | pass `origin-502`, `origin-503`, `worker-throws`; 522 by chance; **open**: deliberate 52x (token lacks DNS:Edit) | observed: nowsecure.nl 522 (first pass) |
| Cookies and session continuity | pass (jar tests) | pass `cookies`, `cookie-continuity`; lifecycle L0 to L4 | observed: cookie names and attributes |
| Recovery after failures | pass (D1, resilience, fuzz) | pass `breaker-*`, retries in `origin-502`, `worker-throws`, `rate-limit-backoff` | n/a (no failures happened) |
| JavaScript execution requirement | n/a | observed: every challenge stops cfprobe; solved only by a browser (lifecycle) | n/a |

## Transport and protocol (brief Part F)

| Area | Status | Where |
|---|---|---|
| Invalid URLs, credentials in URLs | pass | `d4_...`, property `targets_and_configs_never_panic` |
| Malformed response, not HTTP | pass | `malformed_cut_and_slow_responses...`, `unparseable_responses...` |
| Connection closed before head / mid-body | pass | adversarial, fuzz |
| Slow responses, timeouts per stage | pass | `tls_stage_times_out`, fuzz `slow_drip`, `timeout`; zone `slow-2s` |
| DNS failure | pass | fuzz `dns_failure` |
| TLS failure, untrusted certificate | pass | `untrusted_certificate_is_rejected`, fuzz |
| Redirect loops | pass | resilience, zone |
| Large headers (64 KiB value, 150 headers) | pass / limit documented | adversarial D14, zone `many-headers` |
| Large bodies, compression bomb | pass | `body_over_limit...`, D7 cap |
| Unexpected content encodings | pass | D7, fuzz `corrupt_gzip`, `unknown` |
| Duplicate and empty headers | pass | D9, fuzz `repeated_headers_all_recorded` |
| Invalid cookies | pass | fuzz cookie variants, property test |
| Unexpected status codes | pass | fuzz (418, 451, 206, 52x) |
| Connection reuse, keep-alive, server-closed keep-alive | pass | `local_tls.rs`, D1, D12 |
| HTTP/1.1 and HTTP/2 | pass | every suite runs both |
| IPv6 | pass on loopback; **open** on the network (no IPv6 egress) | D5 |
| Certificate parsing, ALPN reporting, TLS negotiation | pass | `TLS_COMPATIBILITY.md` |
| Fingerprint extraction | pass | `baselines.rs`, D8, `FINGERPRINT_ACCURACY.md` |

## Randomization (brief Part D, F)

| Area | Status | Where |
|---|---|---|
| Seed reproducibility | pass | `randomized.rs`, `random` unit tests |
| Value bounds, scenario validity | pass | `generated_values_stay_within_their_bounds`, `every_kind_is_reachable` |
| Concurrent isolation | pass | fuzz at concurrency 32 (10,000 scenarios) |
| Cancellation | pass | `cancellation_returns_promptly...` |
| Long-running stability | pass | 1M-request runs, flat memory |

## Client comparison (brief Part B 7)

| Client | TLS | HTTP/2 | Headers | Cookies | Redirects | Reuse |
|---|---|---|---|---|---|---|
| Chromium 152 (headless; TrackMe) | measured | measured | measured | n/a | n/a | n/a |
| curl 8.22.0 | measured (TrackMe) | measured | measured | zone `cookie-continuity` | zone redirects | n/a |
| reqwest 0.13 (rustls) | measured (TrackMe) | measured | measured | not compared | not compared | benchmark |
| Google Chrome, Firefox | **open**: not installed on this host | | | | | |

## Performance (brief Part F)

| Area | Status | Where |
|---|---|---|
| Startup | measured | `PERFORMANCE.md` |
| Latency, throughput, CPU per request | measured vs reqwest and curl | `PERFORMANCE.md` |
| Memory, long-running | measured: flat over 1M requests | `PERFORMANCE.md` |
| Connection pool under concurrency | measured: 1 HTTP/2 connection for 20 concurrent requests; HTTP/1.1 connections reused | D12 |
