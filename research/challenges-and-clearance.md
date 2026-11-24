# Challenges and clearance

The challenge types, how a client knows it was challenged, and what `cf_clearance` is. The binding question is experiment E1. Docs read 2026-11-24.

Tags as in `README.md`. **[documented]** links the page. **[verified]** is read in `vendor/` or `projects/`. **[recall]** is prior knowledge with no source found. **[to measure]** names the run that settles it.

## Answer first

| # | Point | Tag |
|---|---|---|
| 1 | **Lifetime is Challenge Passage: default 30 minutes**, recommended 15 to 45. Validation adds "a few extra minutes" for clock skew, and **an extra hour for XmlHTTP requests**. | **[documented]** [passage] |
| 2 | **The docs claim a binding but never name its inputs.** "The cookie is securely tied to the specific visitor and device it was issued to, preventing reuse across machines." No page says IP, User-Agent, JA3/JA4, TLS or HTTP/2. | **[documented]** [clearance] |
| 3 | **The docs also concede reuse.** The rate limiting guide warns that actors "may attempt to reuse or share a single valid clearance identity across multiple requests or devices" and answers with a per-Clearance-UUID rate limit, not with a binding. | **[documented]** [rl-bp] |
| 4 | **IP binding is documented only for the solve step.** A Managed Challenge solved from a different IP than the one it was issued to is invalid. Nothing says the cookie is checked against IP when replayed later. | **[documented]** [howworks] |
| 5 | **There is a clean validity oracle:** `http.request.clearance.uuid` is non-empty only when the request carries a valid clearance cookie. Log it per arm. | **[documented]** [f-uuid] |

## Challenge types

| Type | Issued by | What runs | Interaction | Clearance level set | Tag |
|---|---|---|---|---|---|
| **Non-Interactive** (JS challenge, action `jschallenge`) | WAF, rate limiting, IP access rules | Injected JS on an interstitial page, usually under 5 s. Fail gives another interstitial | None | Non-Interactive (low) | **[documented]** [pages], [clearance] |
| **Managed** (action `managedChallenge`) | WAF, BFM/SBFM, Under Attack Mode | Cloudflare picks the challenge from browser signals. Most humans pass with no click | Checkbox only if signals are weak | Managed (medium) | **[documented]** [pages], [howworks] |
| **Interactive** (action `challenge`) | WAF | Visitor must interact | Always | Interactive (high) | **[documented]** [pages], [clearance] |
| **Turnstile** | Embedded widget, modes Managed, Non-Interactive, Invisible | Same challenge platform as Challenge Pages | Managed mode only, checkbox | None by default; optional pre-clearance cookie at `interactive`, `managed` or `jschallenge` | **[documented]** [turnstile], [clearance] |
| **JavaScript Detections** | Bot Management | Invisible script on every HTML page view, not AJAX. Result stored in `cf_clearance`. Lifespan 15 min, reinjected before expiry | None | Not a clearance level; sets `js_detection.passed` | **[documented]** [jsd] |
| **Precursor** | Bot Management, modes Off, Monitor, Armed | Continuous client-side session verification, optional interstitial. Supersedes JSD; Armed mode disables JSD | Interstitial optional | Can grant challenge clearance; in Armed mode can reduce or void it | **[documented]** [precursor] |

Action names: `jschallenge` for Non-Interactive matches the pre-clearance value of the same name **[documented]** [clearance]. `challenge` for Interactive is **[recall]**: Logpush lists the value but no page maps it.

Logpush records which path a visitor took: `managedChallengeNonInteractiveSolved` vs `managedChallengeInteractiveSolved`. **[documented]** [logpush]. For E2 this shows whether FlareSolverr's Tab and Space click (`flaresolverr.md` F3) was needed.

What the challenge does inside the browser is described only at a high level: non-interactive sub-challenges "include, but are not limited to, proof-of-work, proof-of-space, probing for web APIs, and various challenges for detecting browser-quirks and human behavior." **[documented]** [blog-captcha] (2022)

### Unsupported clients, per Cloudflare

| Case | Tag |
|---|---|
| Solve request from a different IP than the challenge was issued to: invalid, may loop | **[documented]** [howworks] |
| A domain serving a challenge page that was requested for another domain | **[documented]** [howworks] |
| Challenge Pages in cross-origin iframes | **[documented]** [howworks] |
| Extensions that modify `User-Agent`, `Canvas` or `WebGL` | **[documented]** [howworks] |
| `curl`, `wget` and other tools without JS | **[documented]** [browsers] |
| Selenium, Puppeteer, Playwright, Cypress: "not supported for solving production challenges" | **[documented]** [browsers] |
| WebViews whose User-Agent changes during the session: Turnstile "treats this as a potential security risk and rejects the challenge" | **[documented]** [mobile] |

FlareSolverr sits in the Selenium row. That is a support statement, not a detection claim.

## Detecting a challenge response

| Signal | Value | Tag |
|---|---|---|
| `cf-mitigated` response header | `challenge` is the only valid value; set on every Challenge Page type | **[documented]** [detect] |
| `Content-Type` of a challenge | Always `text/html`, whatever was requested | **[documented]** [detect] |
| HTTP status | Not stated on any challenge page read. 403 is common | **[recall]**, **[to measure]** E1 |
| CORS preflight | `OPTIONS` carries no cookies, so `cf_clearance` is not sent and cannot bypass | **[documented]** [trouble] |

Suwayomi keys on status 403/503 plus `Server: cloudflare` instead of `cf-mitigated` (`suwayomi-tachidesk.md` S1). FlareSolverr keys on page title and selectors and always reports status 200 (`flaresolverr.md` F1, F5). **[verified]**

## `cf_clearance`: what the docs say

| Property | Documented value | Tag |
|---|---|---|
| Purpose | "Proof of challenge passed. It is used to no longer issue a challenge if present. It is required to reach an origin server." | **[documented]** [cookies] |
| Contents | Two clearances: challenge clearance and Precursor clearance | **[documented]** [clearance] |
| Contents | The challenge passed, its type, and when it was completed | **[documented]** [blog-preclear] (2023) |
| Contents | The JavaScript Detections outcome | **[documented]** [jsd], [cookies] |
| Encoding | Encrypted value that Cloudflare refreshes (JSD, Precursor) while a stable Clearance UUID stays the same | **[documented]** [clearance], [f-uuid] |
| Size | At most 4096 bytes | **[documented]** [clearance] |
| Lifetime | Challenge Passage, default 30 min, set per zone in Security Settings | **[documented]** [passage] |
| Tolerance | Clock skew: a few minutes. XmlHTTP requests: one extra hour | **[documented]** [passage] |
| Early loss | Precursor in Armed mode can reduce or invalidate clearance before expiry. Monitor mode does not | **[documented]** [clearance], [precursor] |
| Levels | Interactive bypasses all three; Managed bypasses Managed and Non-Interactive; Non-Interactive bypasses only itself. A higher solve replaces a lower one | **[documented]** [clearance] |
| Attributes | `SameSite=None; Secure; Partitioned`. Over HTTP it falls back to `SameSite=Lax` and `Partitioned` has no effect | **[documented]** [samesite], [cookies] |
| Partitioning | CHIPS: a clearance won in one top-level site is not reused under another | **[documented]** [samesite] |
| Zone scope (pre-clearance) | Accepted only on domains that match the widget hostnames, are zones in the account, and have challenges enabled | **[documented]** [preclear-host] |
| Turnstile tokens (not the cookie) | 300 s, single use, `timeout-or-duplicate` on replay; reuse detection is eventually consistent (SLO: 99% rejected after 5 s) | **[documented]** [siteverify] |
| Rate limiting | Challenge Passage does not apply to rate limiting rules | **[documented]** [passage] |
| Binding | "Securely tied to the specific visitor and device it was issued to, preventing reuse across machines" | **[documented]** [clearance] |
| Binding | "A clearance cookie can't be shared between users" | **[documented]** [blog-preclear] (2023) |
| Reuse | Acknowledged as an abuse pattern; mitigated by rate limiting on `http.request.clearance.uuid` | **[documented]** [rl-bp] |

## Binding: documented vs not documented

This is the E1 matrix. Each row is a candidate input to the binding check.

| Candidate binding at replay | Documented? | What the docs actually say | E1 arm that tests it |
|---|---|---|---|
| Client IP | **No** | IP must match only between challenge issue and solve | Replay from a second IP, same client, same UA |
| User-Agent | **No** | UA must stay stable while solving (Turnstile, WebView). Nothing about replay | Replay with FlareSolverr's UA vs a changed UA, same client and IP |
| TLS fingerprint (JA3/JA4) | **No** | Not mentioned in any clearance or challenge page | OkHttp (JA4 differs) vs curl-impersonate (JA4 matches) |
| HTTP/2 fingerprint | **No** | Not mentioned | Needs an arm that changes HTTP/2 only (see design notes) |
| "Device" | Yes, undefined | "Specific visitor and device" with no definition | Inferred from the rows above |
| Zone or hostname | Partly | Pre-clearance is per configured hostname; CHIPS partitions by top-level site | Hold constant: mint and replay on the same hostname |
| Clearance level | Yes | Level must cover the rule's challenge type | Hold constant: one Managed Challenge rule |
| Time | Yes | Challenge Passage plus skew, plus 1 h for XmlHTTP | Hold constant: replay within 5 min of mint |
| Bot score of the replaying client | **No** | Passage says a valid cookie means "no challenges will be shown"; nothing says a low score at replay overrides it | Record `score` on each replay |
| JSD outcome carried by the cookie | Implied | JSD result is stored in the cookie and populates `js_detection.passed` | Record `jsDetection.passed` on each replay |

## Not documented

Stated plainly, because these gaps are what E1 measures.

1. **The inputs of the "visitor and device" binding.** No page lists IP, User-Agent, Accept-Language, JA3/JA4, ClientHello hash, HTTP/2 settings, or any other attribute.
2. **Whether a binding mismatch re-challenges, silently ignores the cookie, or only lowers the score.** The docs describe no failure mode for a mismatched cookie.
3. **How a mismatch is logged.** Whether it shows as `managedChallenge` again, as `managedChallengeBypassed` with a low score, or as an empty clearance UUID.
4. **Whether IP binding (if any) is exact, per subnet, per ASN, or tolerant of IPv4 to IPv6 changes.**
5. **How Cloudflare decides a request is "XmlHTTP"** for the extra hour. Possibly the `X-Requested-With` header. **[recall]**
6. **Whether the bot score is re-checked against a valid cookie.** A rule like `score lt 30` with Managed Challenge: does a valid cookie on a score-1 request skip it?
7. **The cookie's internal format.** Only "encrypted" is stated. No published structure, so binding cannot be read from the cookie itself.
8. **The challenge page HTTP status code.**
9. **How the 2023 claim "can't be shared between users" squares with the rate limiting guide's acknowledgement of reuse across devices.** One describes intent, the other a residual risk; neither gives the mechanism.

## How to observe the outcome on the zone

| Oracle | What it shows | Where | Tag |
|---|---|---|---|
| `cf-mitigated: challenge` on the response | Replay was challenged | Client side | **[documented]** [detect] |
| `SecurityActions` contains `managedChallengeBypassed` | The cookie let the request past the Managed Challenge rule | Logpush | **[documented]** [logpush] |
| `SecurityActions` contains `managedChallenge` | Challenge served again | Logpush | **[documented]** [logpush] |
| `http.request.clearance.uuid` non-empty | Cloudflare considered the cookie valid | Rules engine; copy to a header or log via a custom rule | Field **[documented]** [f-uuid]. Usable in Transform or custom rules **[to measure]** E1 |
| `jsDetection.passed`, `score`, `ja4`, `detectionIds` | What the replaying client looked like | Worker echo, Logpush | **[documented]**, see `bot-management-signals.md` |
| `Cookies` custom field with `cf_clearance` | Which cookie value arrived | Logpush, needs a Custom Fields rule naming the cookie | **[documented]** [custom] |

## E1 design notes from the docs

1. **One rule, one level.** Use a single Managed Challenge custom rule on a test path that always matches, so the cookie is the only way through. Mixed levels confound results because higher clearance covers lower rules. **[documented]** [clearance]
2. **Precursor Off** for E1, or record its mode. Armed mode can void clearance mid-run. **[documented]** [precursor]
3. **Replay well inside 30 minutes**, and do not send `X-Requested-With` unless testing the XmlHTTP extension as its own arm. **[documented]** [passage]; header trigger **[recall]**
4. **Fresh TLS handshake per replay.** Session resumption leaves JA3/JA4 empty, which would hide the very variable being tested. **[documented]** [ja]
5. **Same hostname, HTTPS only.** Over HTTP the cookie drops to `SameSite=Lax`. **[documented]** [samesite]
6. **Separate TLS from HTTP/2.** OkHttp differs from Chrome at TLS, HTTP/2 and header layers at once, so an OkHttp rejection does not say which layer is bound. Add curl-impersonate arms that change one layer: forced HTTP/1.1, or modified `CURLOPT_HTTP2_SETTINGS`. Option exists **[verified]** `projects/curl-impersonate.md`
7. **Pin the protocol at mint time.** If FlareSolverr's Chromium solves over HTTP/3, the minting JA4 starts with `q`, not `t`. Record `httpProtocol` and `ja4` on the mint request, or disable HTTP/3 on the zone for the run. JA4 `q` prefix **[documented]** [ja4spec]. Chromium using h3 there **[to measure]** E1
8. **With and without `__cf_bm`.** It smooths score per session, so sending FlareSolverr's `__cf_bm` alongside `cf_clearance` is a separate arm. **[documented]** [score]
9. **Same address family.** Mint and replay both over IPv4, or both over IPv6, unless that is the variable.

[clearance]: https://developers.cloudflare.com/cloudflare-challenges/concepts/clearance/
[passage]: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/challenge-passage/
[pages]: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/
[detect]: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
[howworks]: https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/
[turnstile]: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/turnstile/
[jsd]: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/
[precursor]: https://developers.cloudflare.com/cloudflare-challenges/precursor/
[browsers]: https://developers.cloudflare.com/cloudflare-challenges/reference/supported-browsers/
[trouble]: https://developers.cloudflare.com/cloudflare-challenges/troubleshooting/
[mobile]: https://developers.cloudflare.com/turnstile/get-started/mobile-implementation/
[siteverify]: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
[preclear-host]: https://developers.cloudflare.com/turnstile/additional-configuration/hostname-management/pre-clearance/
[cookies]: https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/
[samesite]: https://developers.cloudflare.com/waf/troubleshooting/samesite-cookie-interaction/
[rl-bp]: https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/
[f-uuid]: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.clearance.uuid/
[logpush]: https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/http_requests/
[custom]: https://developers.cloudflare.com/logs/logpush/logpush-job/custom-fields/
[score]: https://developers.cloudflare.com/bots/concepts/bot-score/
[ja]: https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
[ja4spec]: https://github.com/FoxIO-LLC/ja4/blob/dccfdd6e4e8948f7acb5d634db78c6e5794faa97/technical_details/JA4.md
[blog-preclear]: https://blog.cloudflare.com/integrating-turnstile-with-the-cloudflare-waf-to-challenge-fetch-requests/
[blog-captcha]: https://blog.cloudflare.com/end-cloudflare-captcha/
