# Real-world observations (Phase 2, 2026-11-24)

Passive observation only. Each URL got **one ordinary GET** with cfprobe's defaults (`user-agent: cfprobe/0.1.0`, `accept: */*`, no cookies, no JavaScript), 2 s apart, after robots.txt was read. No URL was repeated within a run, none was requested concurrently, and no challenge, login or booking path was requested. A failed or challenged request is recorded, never worked around.

- Matrix: `experiments/test-results/P2/matrices/real-world.json`
- Processed results: `experiments/test-results/P2/real-world/results.json`, `results.md`
- Raw records with bodies: `experiments/test-results/P2/real-world/raw/` (**local only**, gitignored: third-party pages are not republished; client location removed from processed output)
- Committed fixtures: `experiments/test-results/P2/fixtures/` (excerpts, see `DETECTION_ACCURACY.md`)
- Reproduce: `engine/target/debug/cfprobe run experiments/test-results/P2/matrices/real-world.json --out <dir> --save-bodies [--seed 7530801478306363241]`

## robots.txt (read first, 2026-11-24)

| Host | `User-agent: *` | Used for |
|---|---|---|
| asurascans.com | `Allow: /`; disallows `/login /register /settings /bookmarks /history /notifications /api/` | home, `/browse`, a stylesheet |
| asuracomic.net | `Allow: /` (AI crawlers disallowed by name) | home |
| in.bookmyshow.com | Own `*` group: disallows test, payment, booking-detail and some legacy paths; `/` and `/explore/` allowed | home, `/explore/action-movies` |
| discord.com | Disallows `/api/` except `/api/v*/discovery` and a few others; `/channels`, `/oauth2` disallowed | home, docs, `/api/v9/discovery/categories` |
| www.cloudflare.com, developers.cloudflare.com | `Allow: /` | home, Turnstile docs |
| api.cloudflare.com, api.asurascans.com, cdn hosts | no robots.txt (404 or not served) | one request each to a public root or asset |
| nowsecure.nl | robots.txt timed out (site down at the time) | home only |

## Raw observations (run 2026-11-24 15:27:58Z to 15:28:37Z)

Values as received. `cf-ray` "yes" means the header was present. Body is bytes on the wire (no compression was asked for).

| Case | Category | Status | HTTP | `server` | `cf-ray` | `cf-cache-status` | Content type | Body bytes | Set-Cookie | Location |
|---|---|---|---|---|---|---|---|---|---|---|
| asura-home | landing | 200 | 2 | cloudflare | yes | HIT | text/html | 779937 | 0 | |
| asura-browse | search | 200 | 2 | cloudflare | yes | HIT | text/html | 230281 | 0 | |
| asura-css | static | 200 | 2 | cloudflare | yes | HIT | text/css | 200735 | 0 | |
| asura-cdn-image | static | 200 | 2 | cloudflare | yes | HIT | image/webp | 21302 | 0 | |
| asura-api-root | json | 404 | 2 | cloudflare | yes | HIT | text/plain | 19 | 0 | |
| asuracomic-home | redirect | 301 | 2 | cloudflare | yes | | text/html | 167 | 0 | https://asurascans.com/ |
| bms-home | landing | 200 | 2 | cloudflare | yes | DYNAMIC | text/html | 141697 | 3 | |
| bms-explore | search | 200 | 2 | cloudflare | yes | DYNAMIC | text/html | 181338 | 3 | |
| bms-cdn-image | static | 200 | 2 | (none; `x-server: ImageKit.io`, `via: ... (CloudFront)`) | no | | image/png | 35274 | 0 | |
| discord-home | landing | 200 | 2 | cloudflare | yes | HIT | text/html | 160949 | 2 | |
| discord-docs | docs | 301 | 2 | cloudflare | yes | | text/plain | 0 | 0 | https://docs.discord.com/developers/intro |
| discord-json | json | 401 | 2 | cloudflare | yes | BYPASS | application/json | 43 | 3 | |
| discord-http | redirect | 301 | 1.1 | cloudflare | yes | | text/html | 167 | 0 | https://discord.com/ |
| cf-home | landing | 200 | 2 | cloudflare | yes | HIT | text/html | 1334658 | 5 | |
| cf-docs-turnstile | docs | 200 | 2 | cloudflare | yes | MISS | text/html | 123402 | 1 | |
| cf-apex | redirect | 301 | 2 | cloudflare | yes | | text/html | 167 | 1 | https://www.cloudflare.com/ |
| cf-api-ips | json | 200 | 2 | cloudflare | yes | | application/json | 505 | 1 | |
| cf-api-user | auth | 403 | 2 | cloudflare | yes | DYNAMIC | application/json | 162 | 2 | |
| nowsecure-home | landing | 200 | 2 | cloudflare | yes | DYNAMIC | text/html | 179642 | 0 | |

Earlier the same day (homepage pass, 14:5xZ): nowsecure.nl answered **522** (`error code: 522`, 16 bytes); the other five homepages gave the same status as above.

Body markers found (structural only, `DETECTION_ACCURACY.md`):

| Case | Markers |
|---|---|
| asura-home, asura-browse, bms-home, bms-explore, discord-home | `/cdn-cgi/challenge-platform/scripts/jsd/main.js` (JavaScript Detections) |
| nowsecure-home | JavaScript Detections; `challenges.cloudflare.com/turnstile/v0/api.js`; `<div class="cf-turnstile" data-sitekey="3x00000000000000000000FF">` (Cloudflare's public **test** sitekey that forces an interactive widget) |
| cf-home, cf-docs-turnstile | none (the word "Turnstile" appears as text and links only) |
| all others | none |

Other security vendors: response headers and bodies were searched for Akamai (`_abck`, `bm_sz`, `ak_bmsc`), Imperva (`incap_ses`, `x-iinfo`), DataDome, PerimeterX/HUMAN (`_px`), AWS WAF (`aws-waf-token`), Kasada (`x-kpsdk`), reCAPTCHA and hCaptcha. **None found** on any page. This only shows they are absent from these responses, not from the sites.

## Raw observations, run 2 (2026-11-24 16:35:51Z, seed 7530801478306363241, shuffled, 2 to 4 s apart)

Same 19 URLs, one GET each, through the runner's session: redirects followed within the site, a cookie jar per run, retries only on transient failures (none happened), circuit breaker on. Target registry: `experiments/test-results/P2/targets.json`.

Times in ms; DNS, TCP and TLS are "-" when the connection was reused from an earlier case to the same host.

| Case | Attempts | DNS | TCP | TLS | TTFB | TLS / ALPN | Issuer | Cloudflare cookies set | Title |
|---|---|---|---|---|---|---|---|---|---|
| bms-cdn-image | 200 | 2.6 | 1.9 | 5.5 | 29.3 | 1.3 / h2 | Amazon | | |
| discord-home | 200 | 1.1 | 1.6 | 6.1 | 28.2 | 1.3 / h2 | Google Trust Services | | Discord - Group Chat That's All Fun &amp; Games |
| cf-api-user | 403 | 1.1 | 1.9 | 7.4 | 378.4 | 1.3 / h2 | Google Trust Services | `__cflb`, `__cf_bm` | |
| asura-api-root | 404 | 1.8 | 9.7 | 13.2 | 204.1 | 1.3 / h2 | Google Trust Services | | |
| nowsecure-home | 200 | 1.1 | 1.7 | 8.9 | 627.8 | 1.3 / h2 | Google Trust Services | | nowsecure.nl |
| asura-css | 200 | 1.4 | 2.0 | 8.0 | 19.6 | 1.3 / h2 | Google Trust Services | | |
| cf-home | 200 | 1.1 | 2.0 | 6.7 | 261.7 | 1.3 / h2 | Google Trust Services | `__cf_bm` | Cloudflare: Build for the agent era |
| cf-docs-turnstile | 200 | 1.6 | 2.3 | 7.6 | 48.1 | 1.3 / h2 | Google Trust Services | `__cf_bm` | Overview · Cloudflare Turnstile docs |
| discord-docs | 301 > 200 | 8.5 | 1.7 | 8.0 | 342.1 | 1.3 / h2 | Google Trust Services | | Discord Developer Platform - Documentation |
| asuracomic-home | 301 > 200 | - | - | - | 12.7 | 1.3 / h2 | Google Trust Services | | Asura Scans - Read Manga, Manhwa &amp; Manhua Online |
| bms-home | 200 | 1.2 | 2.0 | 6.2 | 105.3 | 1.3 / h2 | Entrust | `__cf_bm`, `_cfuvid` | Movie Tickets, Plays, Sports, Events &amp; Cinemas nearby - BookMyShow |
| asura-browse | 200 | - | - | - | 530.1 | 1.3 / h2 | Google Trust Services | | Browse \| Asura Scans |
| asura-cdn-image | 200 | 1.1 | 1.8 | 6.3 | 19.1 | 1.3 / h2 | Google Trust Services | | |
| cf-apex | 301 > 200 | - | - | - | 11.7 | 1.3 / h2 | Google Trust Services | `__cf_bm` | Cloudflare: Build for the agent era |
| discord-http | 301 > 200 | - | - | - | 26.2 | 1.3 / h2 | Google Trust Services | | Discord - Group Chat That's All Fun &amp; Games |
| discord-json | 401 | - | - | - | 310.1 | 1.3 / h2 | Google Trust Services | `_cfuvid` | |
| cf-api-ips | 200 | - | - | - | 34.5 | 1.3 / h2 | Google Trust Services | `__cf_bm` | |
| bms-explore | 200 | - | - | - | 113.9 | 1.3 / h2 | Entrust | | Latest Action Movies 2026 \| List of New ... |
| asura-home | 200 | - | - | - | 11.0 | 1.3 / h2 | Google Trust Services | | Asura Scans - Read Manga, Manhwa &amp; Manhua Online |

Every redirect resolved within the same site (`asuracomic.net` -> `asurascans.com`, `discord.com/developers/docs` -> `docs.discord.com`, `cloudflare.com` -> `www.cloudflare.com`, `http://discord.com` -> `https://discord.com`). No case was retried, rate limited, challenged or denied by Cloudflare.

## Interpretation

| Classification | Cases |
|---|---|
| NORMAL_PAGE (high) | 13: every 200 |
| NORMAL_PAGE (medium) | asura-api-root (the origin's own 404) |
| REDIRECT (high) | asuracomic-home, discord-docs, discord-http, cf-apex |
| ACCESS_DENIED (medium, issued by origin) | discord-json (401 JSON), cf-api-user (403 JSON: missing auth headers) |
| Indicators without a block | JavaScript Detections (AsuraScans, BookMyShow, Discord, nowsecure.nl); `__cf_bm` (cloudflare.com, BookMyShow); `_cfuvid` (BookMyShow, Discord); embedded Turnstile (nowsecure.nl) |
| CHALLENGE_INDICATOR / CONFIRMED_CHALLENGE_RESPONSE | **none** |

What the evidence supports, with how sure it is:

| Site | Cloudflare in front? | Protection seen by a plain client | Uncertainty |
|---|---|---|---|
| asurascans.com | Yes (all 5 endpoints, `cf-ray`) | JavaScript Detections on HTML pages; no challenge on home, browse, static or API host | Bot Fight Mode or a paid bot product is likely (JS Detections are injected), but the plan and rules are not observable. Cached HIT pages may never reach rules that apply at the origin |
| asuracomic.net | Yes | 301 to asurascans.com | None beyond the redirect |
| in.bookmyshow.com | Yes for pages; **no** for the image CDN (ImageKit.io on AWS CloudFront) | JavaScript Detections on pages; no challenge on home or `/explore/` | An earlier, separate session (2026-11-24 about 00:44Z) recorded every BookMyShow page answering with a Cloudflare challenge to an honest client; today one GET each got 200. Why it changed is **unknown** (time, rules, request headers or IP reputation could each explain it); one sample cannot settle it |
| discord.com | Yes | JavaScript Detections on the homepage; API answers its own 401 | None |
| www.cloudflare.com | Yes | Nothing visible to this client | Text mentions of Turnstile are product copy |
| nowsecure.nl | Yes | Was down (522), then up with JS Detections and a Turnstile widget using a **test** sitekey | A bot-detection test page; the test sitekey means its widget does not use a real Turnstile configuration |

Different endpoints of one site behaved differently in two ways: BookMyShow's static images bypass Cloudflare entirely, and cached responses (`cf-cache-status: HIT`) were served from Cloudflare's cache on AsuraScans and Discord.

**Not supported by this evidence:** any claim about what a browser, a repeated client or another IP would get; that absence of `cf-mitigated` means no protection; or which Cloudflare plan or rules a site runs.
