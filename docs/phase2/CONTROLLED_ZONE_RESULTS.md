# Controlled zone results (Phase 2, 2026-11-24)

Zone `riddlelab.dev`, **Free plan**, owned by the researcher. Worker `cflab-echo` on the Custom Domain `lab.riddlelab.dev`. Brought up with `scripts/zone/up.sh` and taken down with `scripts/zone/down.sh` (final check: 0 rules, 0 domains, 0 scripts, record gone). All challenge, clearance, replay, rate-limit and resilience experiments ran here and nowhere else.

| What | Where |
|---|---|
| WAF rules | `scripts/zone/lib.sh`: Managed Challenge `/c/`, Block `/b/`, JS Challenge `/j/`, Interactive Challenge `/i/`; rate limit `/r/echo`, 2 per 10 s |
| Phase 2 scenarios | `lab/zone-worker/worker.js` `/p2/...`: Turnstile page (Cloudflare's public test sitekeys) and its siteverify endpoint, 401, origin 403, JSON, static CSS, redirects and a loop, origin 503/429/502, Worker exception (1101), cookies, 120 headers, slow response, cut body |
| Matrix | `experiments/test-results/P2/matrices/zone.template.json` (34 cases, seed 20261124) |
| Run | `scripts/phase2/run_zone.sh <out>` (pins the host to the edge address from the zone's own nameserver) |
| Results | `experiments/test-results/P2/zone/results.json`, `results.md` (raw records local only) |
| Lifecycle | `scripts/phase2/lifecycle.sh`, `experiments/test-results/P2/lifecycle/` |

## Final run: 96 results, 0 failed

Three clients: `cfprobe` (HTTP/2), `cfprobe-h1-titlecase` (HTTP/1.1, Title-Case headers), `curl` 8.22.0 with the same policy translated to flags. Runner defaults: redirects followed (5), cookie jar, 3 attempts with backoff and Retry-After; circuit breaker only in the `breaker-*` cases.

cfprobe (HTTP/2) column; the HTTP/1.1 client gave the same answers except where noted:

| Case | Status | Verdict | Confidence | Issued by | Attempts | Note |
|---|---|---|---|---|---|---|
| echo | 200 | NORMAL_PAGE | high | origin | 200 | |
| echo-html | 200 | NORMAL_PAGE | high | origin | 200 | No JavaScript Detections injected (Free plan, Bot Fight Mode off) |
| echo-compressed | 200 | NORMAL_PAGE | high | origin | 200 | Edge sent zstd; decoded |
| managed | 403 | CONFIRMED_CHALLENGE_RESPONSE (managed) | high | edge | 403 | |
| managed-browser-headers | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | edge | 403 | Chrome 152 headers change nothing |
| managed-head | 403 | CONFIRMED_CHALLENGE_RESPONSE | **medium** | edge | 403 | HEAD: header without page |
| js-challenge | 403 | CONFIRMED_CHALLENGE_RESPONSE (non_interactive) | high | edge | 403 | |
| interactive | 403 | CONFIRMED_CHALLENGE_RESPONSE (interactive) | high | edge | 403 | |
| waf-block | 403 | ACCESS_DENIED | high | edge | 403 | Block page |
| rate-limit | 429 | RATE_LIMITED (1015) | high | edge | 200 > 200 > 429 | Retries off for this case |
| rate-limit-backoff | 200 | NORMAL_PAGE | high | origin | see below | Retry-After honoured |
| direct-ip | 403 | ACCESS_DENIED (1003) | high | edge | 403 | |
| turnstile-embed | 200 | NORMAL_PAGE | high | origin | 200 | Indicators: Turnstile script and widget |
| turnstile-verify-no-token | 403 | ACCESS_DENIED | medium | origin | 403 | Origin's siteverify refused an empty token |
| auth-required | 401 | ACCESS_DENIED | medium | origin | 401 | |
| origin-forbidden | 403 | ACCESS_DENIED | medium | **origin** | 403 | Not attributed to Cloudflare |
| json, static | 200 | NORMAL_PAGE | high | origin | 200 | |
| redirect | 200 | NORMAL_PAGE | high | origin | 302 > 200 | Followed |
| redirect-no-follow | 302 | REDIRECT | high | origin | 302 | |
| redirect-loop | 302 | REDIRECT, `redirect_loop` | high | origin | 302 | Loop detected without a second request |
| origin-503 | 503 | ORIGIN_UNAVAILABLE | low | origin | 503 | Retry-After 120 above the 60 s cap: not retried |
| origin-429 | 429 | RATE_LIMITED | medium | origin | 429 | Retry-After 30 above this case's 10 s cap |
| origin-502 | 502 | ORIGIN_UNAVAILABLE | low | origin | 502 > 502 > 502 | Waits 289, 517 ms |
| worker-throws | 500 | ORIGIN_UNAVAILABLE (1101) | high | edge | 500 > 500 > 500 | Waits 357, 985 ms |
| cookies, cookie-continuity | 200 | NORMAL_PAGE | high | origin | 200 | Next request carried `lab_session` (all three clients) |
| many-headers | 200 | NORMAL_PAGE | high | origin | 200 | HTTP/1.1 client: UNKNOWN, "message head is too large" (hyper's 100-header limit) |
| slow-2s | 200 | NORMAL_PAGE | high | origin | 200 | |
| cut-body | 200 | NORMAL_PAGE | high | origin | 200 | See "Cut bodies" |
| breaker-1..3 | 503 | ORIGIN_UNAVAILABLE | low | origin | 503 each | |
| breaker-open | none | none | | | none | `circuit_open`: refused locally, not sent |

curl agreed with cfprobe on status and verdict in 27 of the 28 cases all three ran (`many-headers` is the exception, as above).

## Rate limiter behaviour (measured)

| Client | Attempts on the rate-limited request |
|---|---|
| cfprobe | 429 (Retry-After 9) -> wait 9000 ms -> 429 (Retry-After **0**) -> wait 517 ms -> 200 |
| cfprobe | 429 (Retry-After 10) -> wait 10000 ms -> 429 (Retry-After 10) -> wait 10000 ms -> 200 |
| cfprobe HTTP/1.1 | 429 (Retry-After 10) -> wait 10000 ms -> 429 (Retry-After 0) -> wait 714 ms -> 200 |

Observed: Cloudflare counts Retry-After down in whole seconds, sends 0 while still limiting, and a request at the end of the wait can restart the window. In an earlier run, honouring the 0 literally produced three requests within 12 ms (D23, fixed).

## Challenge lifecycle (managed challenge, clearance, replay)

FlareSolverr 3.5.2 (Chromium) solved `/c/echo` once (`"Challenge solved!"`, `cf_clearance` issued; the solve file is kept outside the repo). cfprobe then replayed:

| Arm | Request | Result |
|---|---|---|
| L0 | No cookie, solver's User-Agent | 403 CONFIRMED_CHALLENGE_RESPONSE (high) |
| L1 | `cf_clearance` + solver's User-Agent, cfprobe TLS and HTTP/2 | **200 NORMAL_PAGE** |
| L2 | `cf_clearance` + cfprobe's own User-Agent | **403** CONFIRMED_CHALLENGE_RESPONSE |
| L3 | `cf_clearance` + solver's User-Agent over HTTP/1.1 | 200 NORMAL_PAGE |
| L4 | No cookie again | 403 |

This reproduces E1 with a third client stack: on this Free zone the clearance is bound to the User-Agent, not to the TLS or HTTP/2 fingerprint or HTTP version. The cookie value appears in records only as `<redacted 445 bytes>`.

## JavaScript execution requirements

cfprobe executes no JavaScript. Every challenge page (managed, JS, interactive) and the Turnstile widget therefore end with cfprobe at the challenge: it classifies them correctly and stops. Completing them took a browser (FlareSolverr) in the lifecycle run. The Turnstile page uses Cloudflare's public test sitekeys; completing its widget was not attempted (no browser run for it), and submitting the form without a token was refused by the origin's siteverify (403).

## Cut bodies

The Worker sent 1000 bytes and then errored its stream. Cloudflare closed the response as complete: cfprobe (both protocols) and curl all received 200 with 1000 bytes and no error. An origin that dies mid-body behind Cloudflare is **not detectable by any client** from the response alone.

## Real 522s, by chance

About two minutes after the Custom Domain was created, four requests (HTTP/1.1 client and curl, 15:32:00 to 15:32:48Z) got `522`, plain text to cfprobe (`error code: 522`) and an HTML page to curl. A rerun minutes later had none. The likely cause is the Custom Domain not yet reaching every edge server (**[inference]**, not confirmed by Cloudflare). The classifier labelled all four ORIGIN_UNAVAILABLE; the HTML page led to D16. Both are fixtures now (`zone-522-html`, `zone-522-plain`).

## Not done in the zone

| Scenario | Why |
|---|---|
| Deliberate 52x (dead origin) | Needs DNS:Edit on the zone token (refused: `Authentication error`, last checked during this phase); only the chance 522s above |
| Turnstile widget completion and real (non-test) sitekey behaviour | Needs a browser run and a real widget |
| Bot score, JA4 at the edge, Super Bot Fight Mode | Free plan |
| Clearance bound to IP at replay | One egress IP |
| Multiple runs per case for timing statistics | One run per case; timings are single samples |
