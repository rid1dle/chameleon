# Regression results (Phase 2, 2026-11-24)

Run everything: `cd engine && CARGO_BUILD_JOBS=4 cargo test` (offline, loopback only, about 15 s after a build). Last run: **133 passed, 0 failed**. `cargo clippy --all-targets`: no warnings.

| File | Tests | What it covers |
|---|---|---|
| `src/cloudflare/mod.rs` (unit) | 16 | Classifier edge cases, failure verdicts by stage |
| `src/resilience/mod.rs` (unit) | 5 | Retry decisions: permanent vs transient, backoff bounds, Retry-After cap and floor, seeded jitter, policy bounds |
| `src/random/mod.rs`, `scenario.rs` (unit) | 6 | Seeds, schedules, scenario bounds and reachability |
| `src/http/mod.rs` (unit) | 5 | Redaction (idempotent), every body encoding, decode cap |
| `src/runner/mod.rs` (unit) | 3 | Timestamp, config merge, "no expectation is never a pass" |
| `src/main.rs`, `src/fingerprint`, `src/reporting` (unit) | 3 | `--resolve` parsing, GREASE, table escaping |
| `tests/adversarial.rs` | 18 | One or more per transport defect, malformed and cut responses |
| `tests/resilience.rs` | 12 | Redirect chains and loops, cookie jar, retries, Retry-After, circuit breaker, cancellation, failure verdicts |
| `tests/randomized.rs` | 4 | Fixed-seed fuzz run (150 scenarios), reproducibility, single-scenario rerun |
| `tests/properties.rs` | 10 | proptest invariants, 2000 cases each |
| `tests/real_world.rs` | 7 | P2 fixtures: former false positives and negatives |
| `tests/cloudflare.rs` | 6 | E4 zone captures, one per Cloudflare action |
| `tests/baselines.rs` | 10 | L1 receiver records |
| `tests/local_tls.rs` | 11 | TLS, ALPN, reuse, header order, timeouts, limits |
| `tests/runner.rs` | 3 | The matrix runner end to end with both client kinds; proxy campaigns and preflight |
| `tests/proxy.rs` | 11 | Proxy routing: every request through the proxy, no local DNS, no direct fallback on any failure, auth, HTTPS proxy, source audit |
| `src/proxy/mod.rs` (unit) | 3 | Route selection, credentials never printed, URL credential decoding |

## Defects found and fixed

"Before" is what a probe or run showed on the unfixed code. "Found by" says which kind of testing caught it.

| ID | Defect | Root cause | Fix | Before | Found by | Guarded by |
|---|---|---|---|---|---|---|
| D1 | A reused connection the server had closed failed the request | One send, error returned; `is_closed()` races a server close | Idempotent requests failing on a **reused** connection before any response go once more on a new connection; `connection.retried_after` says why | 49/100 failed `connection error` | Adversarial probe | `d1_dead_pooled_connection_is_retried_once_and_reported`, `d1_non_idempotent_request_is_not_retried` |
| D2 | `{"h2":{"max_frame_size":1}}` crashed the process | `h2` asserts on out-of-range SETTINGS; config never checked them | `Config::validate` enforces RFC 9113 ranges | panic at `h2-0.4.20/src/frame/settings.rs:91` | Adversarial probe | `d2_out_of_range_h2_settings_are_refused_not_panics`, property `targets_and_configs_never_panic` |
| D3 | Only the first resolved address was tried | `addrs.next()` | Every address in order; failures in `connection.skipped_addresses` | `localhost` -> `[::1]` refused, no fallback | Adversarial probe | `d3_every_resolved_address_is_tried` |
| D4 | A URL password reached the report and HTTP/2 `:authority` | HTTP/2 URI was `url.as_str()` | URLs with credentials refused; reports redact URLs | server saw `user:hunter2@localhost` | Adversarial probe | `d4_urls_with_credentials_are_refused` |
| D5 | IPv6 literal URLs failed | Brackets passed to DNS and SNI | Bare address in the pool key; IP hosts skip DNS | `dns lookup for [::1] failed` | Adversarial probe | `d5_ipv6_literals_work_over_http_and_tls` |
| D6 | A `--resolve` key in other case silently used real DNS | Exact string match | Case-insensitive; IPv6 `[addr]`; bad keys refused; `address_source` reported | connected via real DNS | Adversarial probe | `d6_...`, `resolve_takes_ipv4_and_bracketed_ipv6` |
| D7 | Compressed bodies never decoded | No `Content-Encoding` handling | gzip, deflate (zlib and raw), br, zstd, stacked, capped; unknown kept and marked | `fingerprint`: `body is not JSON` | Adversarial probe | `d7_...`, encoding unit and property tests; live: gzip, br, zstd from the edge |
| D8 | The same Chromium binary diffed as "1 differ" | JA3 keeps extension order; Chrome permutes | Order-only JA3 differences counted separately | `16 same, 1 differ` | Code reading + diff | `d8_ja3_order_difference_is_not_a_client_difference` |
| D9 | Repeated request headers collapsed to the last | Same-name replacement | Only defaults are replaced; repeats all sent | `x-dup: b` only | Adversarial probe | `d9_repeated_headers_are_all_sent` |
| D11 | Challenge tokens in URLs printed | Only cookie/authorization redacted | `__cf_chl_*` values and credentials redacted in URLs, `location`, `content-location`, `referer` | `__cf_chl_rt_tk=SECRET` | Adversarial probe | `d11_challenge_tokens_in_urls_are_redacted` |
| D12 | No HTTP/2 multiplexing; pool kept one connection | Pool removed connections while in use | HTTP/2 shared and multiplexed; HTTP/1.1 idle list; serialized dials per origin | 20 requests -> 20 TCP connections | Adversarial probe | `d12_...` (1 connection, streams 1..20) |
| D13 | HTTP/1.1 header names always lowercase | hyper default | `h1.title_case_headers` | `user-agent:` | Wire capture | `d13_title_case_header_names_are_selectable` |
| D14 | 103 Early Hints dropped; >100 headers failed | No 1xx callback; hyper default limit | `on_informational` (HTTP/1.1); `h1.max_response_headers` | 103 absent; `Parse(TooLarge)` | Adversarial probe | `d14_...`; zone `many-headers` |
| D15 | Cloudflare's 3-digit `error code: 522` read as reached | 4 digits only | 3 or 4 digits | nowsecure.nl 522 -> reached | Real-world capture | `error_522_is_origin_unavailable` |
| D16 | HTML 5xx page number missed | Detector read a `cf-error-code` span no real page has; the page uses `code-label` | Both read | zone HTML 522: no number, medium | Zone capture | `zone_522_html_and_plain_text_both_give_the_number` |
| D17 | Normal pages called challenges (the brief's report) | String rule on `/cdn-cgi/challenge-platform/` and "Turnstile" | Structural, evidence-based classifier | 3 normal pages labelled challenges | Real-world capture | `real_world.rs` (4 tests), property `js_detections_and_mentions_never_make_a_challenge` |
| D18 | Runner's curl ignored `--resolve` | Command built without the pins | curl gets every pin | `Could not resolve host` | Zone run | zone rerun: curl completed every case |
| D19 | HTTP/2 connection headers recorded as sent | hyper drops them silently | `request.not_sent` | `connection` listed as sent | Adversarial probe | `h2_connection_headers_are_reported_as_not_sent` |
| D20 | URL redaction not idempotent: a second pass reported the placeholder's length | Placeholder not recognised | Placeholders left alone | classifier `location` showed `<redacted 19 bytes>` for a 12-byte token | **Property test** | property `redaction_..._is_idempotent`, `d11_...` asserts 12 bytes |
| D21 | One retried request opened the circuit breaker for the whole host | Each attempt counted as a failure | One request counts once after its retries | zone: one rate-limited case with retries refused ~20 later cases for 30 s | **Zone run** | `one_retried_request_counts_once_toward_the_circuit` |
| D22 | Unparseable responses (head over limit, not HTTP) classified CONNECTION_FAILURE and retried | Every `hyper::Error` mapped to connection failure | Parse errors are UNKNOWN with "response parsing" evidence, not retried | zone `many-headers` (HTTP/1.1): CONNECTION_FAILURE | Zone run | `unparseable_responses_are_unknown_and_not_retried` |
| D23 | `Retry-After: 0` meant "retry at once", repeatedly | Retry-After used as the delay with no floor | Delay is the larger of Retry-After and the backoff | zone: 429, 429, 429 within 12 ms | **Zone run** (Cloudflare counts Retry-After down to 0 while still limiting) | `retry_after_is_honoured_and_capped` (0 -> 500 ms, 1000 ms) |
| D25 | With `--save-bodies`, curl's response body went into the processed (committed) `results.json`, including a challenge page with a live `__cf_chl_f_tk` token | `run_curl` put the body in the metadata shared by the processed result and the raw record | Body only in the raw record; existing results stripped of the field | zone `results.json` held 12 challenge-page fragments | **Scrub check** (`scripts/phase2/scrub.py`) | `bodies_stay_out_of_processed_results_for_every_client` |
| D26 | Two runner runs in one process with the same case id shared and deleted each other's curl temp files | Temp path built from process id and case id only | Per-call counter in the path | `bodies_stay_out...` failed when run beside another runner test | Parallel tests | `runner.rs` (3 tests, run 3 times) |
| D27 | Proxy URL credentials printed by `{:?}` on the config | Derived `Debug` on `ProxySpec` | Hand-written `Debug` that redacts the URL | `url: "http://x:pw-in-url@h:3128"` | Unit test written with the feature | `credentials_never_print` |
| D24 | Cloudflare's own cookies ignored | Classifier read only the redacted header list | `__cf_bm`, `_cfuvid`, `cf_clearance` names become indicators | seen on cloudflare.com, BookMyShow, Discord, never reported | Real-world run | `cloudflare_cookie_names_are_indicators_and_values_stay_out` |

## Not fixed, documented

| ID | Issue | Why | Where |
|---|---|---|---|
| D10 | Response headers grouped by name, not wire order | hyper's client exposes only a `HeaderMap`; wire order is behind its `ffi` feature | `KNOWN_ISSUES.md`, field doc |
| P1 | HTTP/1.1 throughput 14 to 19% below reqwest at concurrency 32 | Not profiled; likely the per-request measurement record and the async pool lock | `PERFORMANCE.md` |

## Defects in the test harness itself (found and fixed, not engine defects)

| Issue | Effect | Fix |
|---|---|---|
| Cancellation test used `std::thread::sleep` in a single-threaded test runtime | Test blocked its own timer | Async sleep in the test server |
| Fuzz generator allowed slow drips longer than the client timeout | 3 scenarios "failed" with a correct body timeout | Drip bounded to 600 ms |
| Fuzz generator allowed "close mid-body" on a 204 | 1 scenario expected a failure that cannot happen (204 has no body) | 204 becomes 200 for that fault |
| Mock server compressed bodies (brotli quality 11) on the async workers | Fault-free scenarios timed out under concurrency 16 | `spawn_blocking`, quality 4; 4 failing seeds then passed 400/400 |
| Mock server without `TCP_NODELAY`, head and body in two writes | Every response 41 ms (cfprobe and reqwest alike) | `set_nodelay`, one write |
| Benchmark printed latencies when every request failed | 0.03 ms "latency" from a dead server | Harness refuses to report when any request fails |
| Benchmark stored every latency | Looked like a 7 MB leak over 300k requests | `--no-latency` mode: flat RSS over 1M requests |
| Zone `dead-origin` scenario | Worker fetch to `192.0.2.1:81` got an answer, not a failure | Replaced by an explicit origin 502 |

## Tests changed, and why

No expectation was loosened to make code pass.

| Test | Change | Reason |
|---|---|---|
| `tests/cloudflare.rs` | Old class names -> the brief's classes, with confidence and indicator checks added | Class set chosen by the user |
| `direct_ip_access_is_error_1003` | `CloudflareError` -> `ACCESS_DENIED` with code 1003 | 1003 is a denial; the number still distinguishes it |
| `same_status_different_verdicts` | Compares (verdict, kind, error number) | Block and 1003 share ACCESS_DENIED, differ by number |
| `tests/local_tls.rs` h2 test | `NotCloudflare` -> NORMAL_PAGE with `cloudflare_present: false` | Presence is a separate field |
| Zone `rate-limit-backoff` | `[429, 200]` -> "ends in 200" | Measured: Cloudflare restarted its window after a full Retry-After wait (`429, 429, 200`); the stricter expectation described a behaviour Cloudflare does not have |
| Zone matrix | Circuit breaker off except in `breaker-*` cases | The matrix fails on purpose; a host breaker correctly opens on it |
