# Known issues and limitations (Phase 2, 2026-11-24)

What cfprobe (the engine the brief calls Chameleon-RS) does not do, does only partly, or does with a known defect. Each line says how it was established: **probe** (a run that showed it), **source** (read in code), **design** (a stated choice).

## Open defects

| ID | Issue | Impact | Evidence |
|---|---|---|---|
| D10 | Response headers recorded grouped by name, not in wire order (`a, b, a` -> `a, a, b`) | Server header order cannot be studied from records | Probe; hyper's client exposes only a `HeaderMap` (wire order is behind its `ffi` feature) |
| P1 | HTTP/1.1 throughput 14 to 19% below reqwest at concurrency 32 | Bulk HTTP/1.1 runs are slower; sequential and HTTP/2 are not | `PERFORMANCE.md`; not profiled |

## Unsupported capabilities

| Capability | State | Evidence |
|---|---|---|
| JavaScript execution | **None.** Challenge pages, JavaScript Detections and Turnstile widgets are read as text | Design; zone: every challenge ends at the challenge |
| Challenge solving, clearance acquisition | **None, by design.** A challenge is classified, never completed | Design; the lifecycle run needed FlareSolverr |
| Browser profiles, identity rotation | None, by design | Design |
| Cookies in `cfprobe inspect` | Not kept (one request = one exchange). A `Session` (used by `cfprobe run`) has a jar | Probe: next request `cookieNames: []`; zone `cookie-continuity` with the jar |
| Redirects in `cfprobe inspect` | Not followed. A `Session` follows up to `max_redirects` with loop detection | Zone `redirect-no-follow`, `redirect`, `redirect-loop` |
| TLS session resumption | None: every connection is a full handshake | Source; `session_reused: false` everywhere |
| HTTP/3 / QUIC, client certificates, 0-RTT | None | Source |
| Proxies | Supported since this phase: HTTP, HTTPS, SOCKS5 with Basic / user-password auth (`PROXY_ROUTING.md`). Not supported: chaining, PAC, per-destination rules, NTLM/Kerberos | Tests `proxy.rs` |
| Request bodies from the CLI | None (the library `Target` has a body) | Source |
| Public suffix list in the jar | Not loaded: a site could set a cookie for a whole TLD | `cookie_store` source |

## Partial or fixed by a dependency

| Area | Limitation | Evidence |
|---|---|---|
| HTTP/2 pseudo-header order | `m,s,a,p`, fixed by `h2` (Chrome: `m,a,s,p`) | TrackMe |
| HTTP/2 SETTINGS order and defaults | hyper's; identical to reqwest's | TrackMe (`FINGERPRINT_ACCURACY.md`) |
| TLS 1.3 cipher suites | Not configurable in BoringSSL | Source |
| Default ClientHello | No GREASE, no permutation unless configured; matches no browser | TrackMe |
| HTTP/1.1 header case | Lowercase unless `h1.title_case_headers` | Test D13 |
| 1xx responses | Recorded on HTTP/1.1 only | hyper source |
| HTTP/1.1 response header count | 100 unless `h1.max_response_headers`; over it the response is UNKNOWN | Zone `many-headers` |
| Dialing | Addresses tried in order, not in parallel (no Happy Eyeballs); a blackholed first address costs the connect timeout | Source |
| Dials per origin | Serialized (so concurrent first requests can share one HTTP/2 handshake); concurrent first HTTP/1.1 requests wait for each other's handshake | Design |
| Connection pool | No size limit, no idle timeout; one entry per origin | Source |
| Decompression | Runs on the async worker; bounded by `max_body_bytes` (8 MiB) | Source |
| Encodings | gzip, deflate, br, zstd; others kept and marked `not_decoded` | Tests D7 |

## Resilience limits

| Area | Limitation |
|---|---|
| Circuit breaker | Per host, not per path: one failing path shields the whole host. Deliberate for third parties |
| Non-idempotent requests | Never retried, even on a dead pooled connection (10 of 20 POSTs failed against a server that closes idle connections) |
| Retry-After | Above `max_retry_after_ms` (60 s default) the fetch ends instead of waiting |
| curl comparison client | Its attempts and redirect hops are not visible to the runner, only its final answer |

## Classification limits

| Gap | Effect |
|---|---|
| `cf-mitigated` stripped by a proxy in front of Cloudflare | A real challenge page drops to CHALLENGE_INDICATOR |
| Localized challenge title | `challenge_title` misses; the other two markers still match |
| New challenge template | Header still confirms; type may be unknown (recorded, not guessed) |
| JavaScript Detections outcome | Never visible in the response it is on |
| Unmapped 1xxx numbers | UNKNOWN with the number |
| A body Cloudflare closed early | Looks complete to every client (zone `cut-body`) |

## Measurement limits

| What | Limit |
|---|---|
| Own ClientHello and HTTP/2 frames | Measured only at a receiver (TrackMe, zone Worker) |
| Zone Worker on Free | No JA3/JA4, bot score or detection IDs; header names arrive sorted |
| Worker TLS hashes | `tlsClientCiphersSha1` / `ExtensionsSha1` vary per connection for GREASE clients; order-only changes cannot be told apart there |
| Real Chrome | Only Chromium (152, 124); no Google Chrome, Windows or Firefox capture on this host |

## Environment limits

| Limit | Effect |
|---|---|
| Free plan zone | No Bot Management actions or scores |
| Zone token without DNS:Edit | Deliberate 52x not set up; only chance 522s captured |
| One egress IPv4, no IPv6 | Clearance-to-IP binding at replay untested; IPv6 tested on loopback only |
| Third-party sites | One ordinary GET per URL per run, robots.txt first; no repeats, concurrency, logins or challenge paths |
| Timing statistics on real networks | One sample per case; loopback benchmarks only for latency distributions |
