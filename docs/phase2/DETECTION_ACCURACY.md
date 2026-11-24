# Detection accuracy (Phase 2, 2026-11-24)

The classifier is `engine/src/cloudflare/mod.rs`. It reads one response (status, headers, decoded body, names of cookies set) and returns one of the brief's ten verdicts, a confidence, who issued the response, the structural indicators it found, the evidence that decided the verdict, and caveats. A request that got no response is classified too: TLS_FAILURE, CONNECTION_FAILURE (with the stage), or UNKNOWN when the response could not be parsed.

## 1. The reported false positives, reproduced

The brief reported that a detector called three normal pages challenges. No session in this repo produced that table (session -51, which wrote the Phase 7 detector, confirmed it never matched `/cdn-cgi/challenge-platform/`). So the pages were fetched again, once each, and the strings were counted.

| Page (GET /, 2026-11-24) | Status | `cf-mitigated` | `/cdn-cgi/challenge-platform/` | "turnstile" | `_cf_chl_opt` | `Just a moment` |
|---|---|---|---|---|---|---|
| asurascans.com | 200 | absent | 1 | 0 | 0 | 0 |
| in.bookmyshow.com | 200 | absent | 1 | 0 | 0 | 0 |
| discord.com | 200 | absent | 1 | 0 | 0 | 0 |
| www.cloudflare.com | 200 | absent | 0 | 6 | 0 | 0 |
| asuracomic.net | 301 | absent | 0 | 0 | 0 | 0 |
| nowsecure.nl | 522 | absent | 0 | 0 | 0 | 0 |
| zone `/c/echo` (real Managed Challenge, E4) | 403 | `challenge` | 1 | 0 | 7 | 1 |

**Root cause.** The three matches are one script, identical on all three sites:

```
var u='/cdn-cgi/challenge-platform/scripts/jsd/main.js?ray=a5f9594f3a9e2e97', a=document.createElement('script'); ...
```

This is Cloudflare **JavaScript Detections**, inserted into HTML pages on zones with bot detection on. It runs in the background and scores the visit for later requests; it does not block the page it is on. A real challenge page loads a different script from the same directory (`/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1`), defines `window._cf_chl_opt`, and comes with `cf-mitigated: challenge`. A rule that matches the directory name matches both. The cloudflare.com matches are product names in its navigation menu (`"title":"Turnstile","description":"A CAPTCHA Replacement Solution"`).

**A second defect found while reproducing.** The Phase 7 detector (before this phase) called nowsecure.nl's `error code: 522` "reached": it accepted only four-digit error numbers, and 522 has three. An origin failure was reported as the origin answering.

## 2. How the classifier decides now

No single string decides a verdict. Markers are structural: a script URL, a class attribute, a page-defining object, a header.

| Step | Checks | Verdict | Confidence |
|---|---|---|---|
| 1 | `cf-mitigated: challenge` + challenge page in body (`_cf_chl_opt` or orchestrate script) | CONFIRMED_CHALLENGE_RESPONSE | high |
| 1 | `cf-mitigated: challenge`, no page in body (HEAD, empty, cut) | CONFIRMED_CHALLENGE_RESPONSE | medium |
| 1 | `cf-mitigated` with another value | UNKNOWN | medium |
| 2 | Through Cloudflare, body error number 1015 | RATE_LIMITED | high |
| 2 | Through Cloudflare, 1003, 1005-1012, 1020 | ACCESS_DENIED | high |
| 2 | Through Cloudflare, 520-527, 530, 1016, 1033, 1101, 1102 (plain text, `cf-error-code` span or the HTML page's `code-label` span) | ORIGIN_UNAVAILABLE | high |
| 2 | Through Cloudflare, WAF block page (`block_headline`) | ACCESS_DENIED | high |
| 3 | 2 of 3 challenge-page markers, no `cf-mitigated` | CHALLENGE_INDICATOR | medium on 403/429/503, low otherwise |
| 4 | 3xx into the challenge platform (`/cdn-cgi/challenge-platform/`, `__cf_chl_`) | CHALLENGE_INDICATOR | medium |
| 4 | Other 3xx with `Location` | REDIRECT | high |
| 5 | Through Cloudflare, status 52x/530 or a Cloudflare error page on 5xx, no number | ORIGIN_UNAVAILABLE | medium |
| 6 | Origin answered: 2xx | NORMAL_PAGE | high (low if the body could not be decoded) |
| 6 | Origin 401/403/407 | ACCESS_DENIED, issued by origin | medium |
| 6 | Origin 429 | RATE_LIMITED, issued by origin | medium |
| 6 | Origin 502-504 | ORIGIN_UNAVAILABLE, issued by origin | low |
| 6 | Other origin 4xx/5xx | NORMAL_PAGE (the origin's own answer) | medium |
| no response | Handshake failed or timed out | TLS_FAILURE | high |
| no response | DNS, TCP, response or body failed or timed out | CONNECTION_FAILURE, evidence names the stage | high |
| no response | Response arrived but cannot be parsed (not HTTP, head over the limit) | UNKNOWN, "response parsing" | low |

Error numbers in a body are trusted only when the response came through Cloudflare (`cf-ray` or `server: cloudflare`): an origin that prints `error code: 1015` is not Cloudflare's rate limit.

Every NORMAL_PAGE through Cloudflare carries the caveat that **an absent `cf-mitigated` does not prove no challenge was applied**: a held `cf_clearance`, or JavaScript Detections scoring the visit for later, leave no mark on the response.

Indicators the classifier reports without letting them decide alone:

| Indicator | Marker | Seen on |
|---|---|---|
| `js_detections_script` | `/cdn-cgi/challenge-platform/scripts/jsd/main.js` | asurascans, bookmyshow, discord, nowsecure.nl (all 200) |
| `challenge_orchestrate_script` | `/cdn-cgi/challenge-platform/h/<x>/orchestrate/` | E4 challenge pages |
| `challenge_options` | `_cf_chl_opt` | E4 challenge pages |
| `challenge_title` | `<title>Just a moment...</title>` (English only) | E4 challenge pages |
| `turnstile_script` | `challenges.cloudflare.com/turnstile/` | nowsecure.nl, zone `/p2/turnstile` |
| `turnstile_widget` | class token `cf-turnstile` | nowsecure.nl, zone `/p2/turnstile` |
| `cloudflare_error_page` | `cf-error-details` or `id="cf-wrapper"` | E4 block, zone HTML 522 |
| `block_page` | `data-translate="block_headline"` | E4 block |
| `challenge_redirect` | `Location` into the challenge platform | synthetic only (unit and adversarial tests) |
| `bot_management_cookie` | `Set-Cookie: __cf_bm` | cloudflare.com, its docs and API, BookMyShow (D24) |
| `rate_limit_visitor_cookie` | `Set-Cookie: _cfuvid` | BookMyShow, Discord API (D24) |
| `clearance_cookie` | `Set-Cookie: cf_clearance` | synthetic (adversarial test); issued in the lifecycle run by the solver's browser |

## 3. Results on every real response

Each row is a real response, not a synthetic one. "Before" is the Phase 7 detector as handed over; "brief's detector" is the string rule the brief describes, applied to the same bytes.

| Response | Expected | Brief's detector | Phase 7 detector | Now |
|---|---|---|---|---|
| asurascans.com 200 | normal | **challenge (FP)** | reached | NORMAL_PAGE, high, indicator js_detections_script |
| in.bookmyshow.com 200 | normal | **challenge (FP)** | reached | NORMAL_PAGE, high, js_detections_script |
| discord.com 200 | normal | **challenge (FP)** | reached | NORMAL_PAGE, high, js_detections_script |
| www.cloudflare.com 200 | normal | challenge per brief (Turnstile text) | reached | NORMAL_PAGE, high, no indicator |
| asuracomic.net 301 | redirect | redirect | reached | REDIRECT, high |
| nowsecure.nl 522 plain text | origin failure | origin unreachable | **reached (FN)** | ORIGIN_UNAVAILABLE, high, code 522 |
| nowsecure.nl 200 with Turnstile widget | normal, embedded Turnstile | not run | reached | NORMAL_PAGE, high, turnstile_script + turnstile_widget |
| zone 522 HTML page | origin failure | not run | not run | ORIGIN_UNAVAILABLE, high, code 522 (read from `code-label`) |
| zone 522 plain text | origin failure | not run | not run | ORIGIN_UNAVAILABLE, high, code 522 |
| zone 1101 (Worker threw) | origin failure | not run | **unclassified** | ORIGIN_UNAVAILABLE, high, code 1101 |
| E4 managed / js / interactive | confirmed challenge + type | not run | challenge + type | CONFIRMED_CHALLENGE_RESPONSE, high, type managed / non_interactive / interactive |
| E4 block | block | not run | blocked | ACCESS_DENIED, high, block_page |
| E4 1015 | rate limit | not run | rate limited | RATE_LIMITED, high |
| E4 1003 | access denied | not run | cloudflare error | ACCESS_DENIED, high |
| E4 reached (Worker JSON) | normal | not run | reached | NORMAL_PAGE, high |

The zone matrix (`CONTROLLED_ZONE_RESULTS.md`) adds 34 cases run by up to three clients: **96 results, 0 failed** on the final run (cfprobe HTTP/2, cfprobe HTTP/1.1, curl). The fuzz campaign (`RANDOMIZED_TESTING.md`) adds 10,000 generated responses, decoys included, with 0 misclassified.

Negative cases that must not be called Cloudflare blocks, all correct:

| Response | Verdict | Issued by |
|---|---|---|
| Origin 403 HTML, through Cloudflare (zone `/p2/forbidden`) | ACCESS_DENIED, medium | origin |
| Origin 401 with `WWW-Authenticate` (zone `/p2/auth`) | ACCESS_DENIED, medium | origin |
| Origin 429 (zone `/p2/ratelimit-origin`) | RATE_LIMITED, medium | origin |
| Discord API 401 JSON, Cloudflare API 403 JSON | ACCESS_DENIED, medium | origin |
| nginx 403, no Cloudflare (local) | ACCESS_DENIED, medium | origin, `cloudflare_present: false` |
| `error code: 1015` from a non-Cloudflare server (unit) | RATE_LIMITED from status 429, no error number | origin |

## 4. What the classifier cannot tell

| Gap | Effect | Why it stays |
|---|---|---|
| A proxy or CDN in front of Cloudflare strips `cf-mitigated` | A real challenge page drops to CHALLENGE_INDICATOR (medium) | That is the honest answer: the confirming header is gone |
| The challenge page title is localized | `challenge_title` misses; `_cf_chl_opt` and the orchestrate script still match | Only the English title was observed |
| Cloudflare changes the challenge template (`cTplV:5` today) | Header still confirms the challenge; the type may come back unknown | Recorded as "cType not one this engine knows", never guessed |
| A JavaScript Detections result | Not visible in any response; it affects later requests | Needs a later request, or Bot Management fields on an Enterprise zone |
| 1xxx numbers not in the table | UNKNOWN with the number | Only numbers seen or documented are mapped |
| 103 Early Hints over HTTP/2 | Not reported | hyper does not surface 1xx on HTTP/2 |
| A body the edge cut short | Classified on the part that arrived | Cloudflare closes it as complete (zone `cut-body`): no client can tell |

## 5. Regression coverage

| File | Tests | Source |
|---|---|---|
| `engine/src/cloudflare/mod.rs` (unit) | 16 | Synthetic edge cases: title alone, header alone, untrusted error text, class token matching, failure verdicts by stage |
| `engine/tests/cloudflare.rs` | 6 | E4 zone captures |
| `engine/tests/real_world.rs` | 7 | P2 fixtures: the 4 former false positives, the 522 false negative, embedded Turnstile, zone 522 HTML/plain, zone 1101 |
| `engine/tests/adversarial.rs` | 4 that touch the classifier | Gzipped block page, Location token redaction, origin 403 without Cloudflare, cookie indicators |
| `engine/tests/properties.rs` | 3 | Never panics; a confirmed challenge always has the header; JavaScript Detections plus any title, Turnstile mention and page copy is never a challenge (2000 cases each) |
| `engine/tests/resilience.rs` | 2 | Failure verdicts for refused, untrusted and unparseable responses |

Fixtures from third-party sites are excerpts (title plus 300 characters around each marker, tokens and IPv4 addresses removed), made by `scripts/phase2/excerpt_fixture.py`. Each excerpt was checked to classify the same as the full page: 6 of 6 identical (`cargo run --example classify_raw`).
