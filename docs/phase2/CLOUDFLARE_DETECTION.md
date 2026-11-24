# Cloudflare detection (Phase 2, 2026-11-24)

What tells a client that Cloudflare is present and what it did, as observed in real responses. The classifier's rules and accuracy are in `DETECTION_ACCURACY.md`; this file is the evidence behind them.

## Is Cloudflare in front?

| Signal | Reliability | Seen |
|---|---|---|
| `cf-ray` header | Present on every Cloudflare response observed (zone, 6 sites) | Every case except BookMyShow's image CDN |
| `server: cloudflare` | Present on the same set; absent on CloudFront/ImageKit | Same |
| `cf-cache-status` | On proxied origin responses; absent on the 301 redirects observed | HIT on AsuraScans and Discord pages, DYNAMIC on BookMyShow |

Absence matters too: `assets-in.bmscdn.com` (BookMyShow images) answered with `x-server: ImageKit.io` and `via: ... (CloudFront)` and no Cloudflare header. **One site, two providers.** Other vendors' markers (Akamai, Imperva, DataDome, HUMAN, AWS WAF, Kasada, reCAPTCHA, hCaptcha) were searched for on all six sites and not found.

## What Cloudflare did

| Action | Status | Decisive marker | Supporting markers | Source |
|---|---|---|---|---|
| Managed / JS / Interactive Challenge | 403 | `cf-mitigated: challenge` | `window._cf_chl_opt` with `cType` `managed` / `non-interactive` / `interactive`; `/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1`; title `Just a moment...` | E4, zone |
| WAF Block | 403 | Block page `data-translate="block_headline"` | `cf-wrapper`, `cf-error-details`, title `Attention Required! \| Cloudflare`; **no** `cf-mitigated`, no number | E4, zone |
| Rate limit | 429 | Body `error code: 1015` | `retry-after`, counting down | E4, zone |
| Direct IP access | 403 | Body `error code: 1003` | | E4, zone |
| Origin unreachable | 522 | Body `error code: 522` or HTML `<span class="code-label">Error code 522</span>` | Title `<host> \| 522: Connection timed out` | nowsecure.nl, zone (chance) |
| Worker exception | 500 | Body `error code: 1101` | | zone |

Plain-text vs HTML error pages: with `accept: */*` (cfprobe's default) the zone's 522 came as 16 bytes of text; curl got the HTML page. E4 saw 1015 and 1003 as text even with a browser `accept` header. So both forms occur and both are read.

## What Cloudflare did not block, but left traces of

| Trace | Meaning | Seen on |
|---|---|---|
| `/cdn-cgi/challenge-platform/scripts/jsd/main.js` in the page | **JavaScript Detections**: scores this visit in the background for later requests | AsuraScans (home, browse), BookMyShow (home, explore), Discord, nowsecure.nl |
| `Set-Cookie: __cf_bm` | Cookie of Cloudflare's bot products | cloudflare.com (home, apex), developers.cloudflare.com, api.cloudflare.com (ips, user), BookMyShow home |
| `Set-Cookie: _cfuvid` | Rate limiting's visitor id | BookMyShow home, Discord API |
| `Set-Cookie: __cflb` | Load balancer affinity | api.cloudflare.com |
| `challenges.cloudflare.com/turnstile/v0/api.js` + `class="cf-turnstile"` | An embedded Turnstile widget, not a block | nowsecure.nl (test sitekey `3x...FF`), zone `/p2/turnstile` |

These are indicators. None is evidence that this request was challenged or blocked, and their absence is not evidence that it was not: a held `cf_clearance` or a later JavaScript Detections result leave no mark on the response.

## Lifecycle observed on the zone

`managed` -> browser solves -> `cf_clearance` -> replay accepted when the User-Agent matches, refused when it does not, regardless of TLS stack or HTTP version (`CONTROLLED_ZONE_RESULTS.md`).

## Limits

- Free plan: no bot score, JA4 or detection IDs visible on the zone; no Super Bot Fight Mode actions to capture.
- Third-party sites were observed with one plain request per URL; their configuration (plan, rules, Bot Fight Mode) is not observable and is not claimed.
- Earlier the same day, a separate session recorded BookMyShow answering every page with a challenge to an honest client; both P2 runs got 200. Why is unknown.
