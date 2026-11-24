# FlareSolverr

Pinned: `FlareSolverr/FlareSolverr` @ `cc2224b` (2026-10-24), version 3.5.2 (`package.json`). Paths are relative to the repo root. Tags as in `suwayomi-tachidesk.md`.

## What it is

A proxy server in Python. A client POSTs `{cmd, url, session, cookies, proxy, ...}` to `/v1`. FlareSolverr opens the URL in a real Chrome, waits out or clicks through the challenge, and returns the browser's cookies, its User-Agent and, optionally, the page HTML. **[verified]** `src/flaresolverr_service.py:98-228`

Stack: `bottle` + `waitress` for HTTP, `selenium` 4.51, a **vendored and modified** copy of `undetected_chromedriver` (`src/undetected_chromedriver/`), and `xvfbwrapper` on Linux and macOS. **[verified]** `requirements.txt`

## Browser launch

| Item | Behaviour | Evidence |
|---|---|---|
| Driver patch | Finds the `{window.cdc...;}` block that chromedriver injects into pages and overwrites it in the binary with `console.log("undetected chromedriver 1337!")`, padded to the same length. Removes the classic `cdc_` page artefact. | **[verified]** `src/undetected_chromedriver/patcher.py:416-441` |
| Headless | Default `HEADLESS=true`. On Linux this starts Xvfb **and** passes `headless=True` to the driver, which adds `--headless=new` for Chrome 108 and later. The comment in `utils.py` says it launches "in head-full mode with the window hidden", but the code does not do that. | **[verified]** `src/utils.py:27-28`, `:209-219`, `src/undetected_chromedriver/__init__.py:399-410`. Runtime: **[verified]** `--headless=new` in the Chrome command line, with Xvfb running unused (L1-7) |
| Headless cover-up (dormant by default, see F2) | On the first `get()` where `navigator.webdriver` is true, it injects: a `Proxy` around `navigator` that hides `webdriver`; a UA override with `Headless` removed; `navigator.maxTouchPoints = 1`; `navigator.connection.rtt = 100`; a hand-built `window.chrome` object (copied from browserless). | **[verified]** `src/undetected_chromedriver/__init__.py:496-560` |
| UA | Read from `navigator.userAgent` once, `HEADLESS` stripped, cached globally, then forced with `--user-agent` on later launches | **[verified]** `src/utils.py:192-195`, `:353-373` |
| Flags | `--no-sandbox`, `--window-size=1920,1080`, `--disable-dev-shm-usage`, `--no-zygote`, `--ignore-certificate-errors`, one `--disable-features` list (mostly Chrome AI features) | **[verified]** `src/utils.py:140-207` |
| Proxy auth | Uses a generated Chrome extension when `username`/`password` are given. The README says proxy auth is "not supported". | **[verified]** `src/utils.py:59-125`, `:197-201`. Docs: `README.md:229` |

## Challenge loop: `_evil_logic`

`src/flaresolverr_service.py:342-496` **[verified]**

1. Optionally block images, CSS and fonts through CDP `Network.setBlockedURLs` (`:348-367`).
2. Navigate. If cookies were sent, set them and navigate again (`:372-391`).
3. **Access denied:** title starts with `Access denied` or `Attention Required! | Cloudflare`, or `.cf-error-*` selectors match. Raises "Probably your IP is banned" (`:403-414`, lists `:26-37`).
4. **Challenge present:** title equals `Just a moment...` or `DDoS-Guard`, or one of 10 selectors matches (`#cf-challenge-running`, `#challenge-spinner`, `#turnstile-wrapper`, `#trk_jschal_js` ...) (`:416-429`, lists `:38-51`).
5. Wait up to `BROWSER_TIMEOUT` for the title to change and the selectors to disappear. On each timeout, call `click_verify` and loop with **no attempt cap**; only the outer `maxTimeout` ends it (`:433-458`).
6. Wait for the old `<html>` to go stale, which marks the redirect (`:461-467`).
7. Return `driver.get_cookies()`, the UA, and the HTML unless `returnOnlyCookies` (`:474-494`).

### `click_verify` (`:261-292`)

- Pause about 5 s, press **Tab** `num_tabs` times with 0.1-0.2 s gaps, pause about 1 s, press **Space**. This focuses and toggles the Turnstile checkbox by keyboard, so no mouse coordinates are needed inside the cross-origin iframe.
- Then look for `input[type=button][value="Verify you are human"]` and click it at a fixed (5, 7) offset.

### Turnstile token mode (`:294-340`)

With `tabs_till_verify` set, it reads `input[name=cf-turnstile-response]` until a fresh token appears and returns it as `turnstile_token`. That is a standalone Turnstile solve, not just page clearance.

## Findings

| # | Finding | Tag and evidence |
|---|---|---|
| F1 | **Detection relies on page text.** Fixed titles and CSS selectors. Several selectors belong to retired challenge pages (`#trk_jschal_js` is the old IUAM). A changed title or DOM gives "Challenge not detected" plus the challenge HTML. | **[verified]** `:38-51`. Retired: **[unverified]**, based on public history, not checked against today's page |
| F2 | **The browser is new-headless Chrome**, not a hidden headful browser (see table). The JS cover-up patches in the source **do not run by default**: they are guarded by `navigator.webdriver` being true, and it is already false because the driver launches Chrome itself, without `--enable-automation`. The JS tells that remain are configuration: `navigator.languages = ["C.UTF-8"]`, a 1920x1080 window on an 800x600 screen, no focus, and a SwiftShader GPU. | **[verified]** at runtime: `ps` in the container (L1-7) and the L2 probe (`experiments/test-results/L2/summary.md`). Source: `src/undetected_chromedriver/__init__.py:276-283`, `:504`. Which of these Cloudflare's challenge script reads: **[unverified]** |
| F9 | **Default Docker deployments send `accept-language: C.UTF-8,C.UTF;q=0.9`.** `LANG` goes straight to `--accept-lang`, and the image inherits `LANG=C.UTF-8` from its Python base image. | **[verified]** `src/utils.py:189-191`, `docker inspect`, L1-2 |
| F3 | **Input is synthetic keyboard events through CDP.** Fixed tab count, uniform jitter of 0.02-0.5 s, no pointer movement before the Space key. A behavioural model sees focus jump by tab order, with no mouse activity at all. | **[verified]** `:261-275` |
| F4 | **Unbounded retry.** The solve loop has no attempt cap, only the request timeout, so one stuck page clicks every `BROWSER_TIMEOUT` seconds until `maxTimeout`. | **[verified]** `:433-458` |
| F5 | **Response metadata is fake.** `status` is always `200` and `headers` is always `{}`, both marked "todo, selenium does not provide this". Clients cannot tell a 403 page from a success. | **[verified]** `:475`, `:479` |
| F6 | **The output is portable.** The full cookie jar plus the exact UA string, designed for replay by a different HTTP client. Suwayomi is one such consumer. | **[verified]** `:476`, `:492`; Suwayomi `CloudflareInterceptor.kt:371-420`. Other consumers: **[unverified]**, the README does not name any |
| F7 | **Sessions keep one browser warm.** `sessions.create` keeps the browser, so later requests reuse its cookies and fingerprint. A per-request proxy is ignored inside a session. | **[verified]** `src/sessions.py:28-50` (one driver per session, kept until destroy). Proxy ignored: **[documented]** `README.md:229` |
| F8 | **Effectiveness is not claimed.** The README is a usage document. Whether 3.5.2 clears a current managed challenge on an Enterprise zone with default settings is open. | **[to measure]**, experiment E2 |

## What this means for detection

- **During the solve**, the client is a real Chromium, and L1 shows its TLS and HTTP/2 fingerprints are identical to headful Chromium. Detection has to come from the default-config tells (F2, F9), behaviour (F3) and reputation (datacenter IP, many solves per IP).
- **After the solve**, the value moves to another stack (F6). The defensive question for the zone is the same as Suwayomi S3: is `cf_clearance` checked against the fingerprint of the client presenting it?
