# Suwayomi-Server (formerly Tachidesk)

Pinned: `Suwayomi/Suwayomi-Server` @ `4081b05` (2026-11-22). Paths are relative to the repo root.

Tags: **[verified]** read in source at the pin. **[documented]** stated in project or Cloudflare docs, not read in code. **[unverified]** claim with no source in hand. **[to measure]** settled only by a lab or zone run, see `experiments/`.

## What it is

A self-hosted manga server on the JVM (Kotlin). It runs Tachiyomi/Mihon extensions, which are Android APKs, through an Android compatibility layer (`AndroidCompat/`). Every extension makes its HTTP calls through one shared OkHttp client that the server provides. **[verified]** `server/src/main/kotlin/eu/kanade/tachiyomi/network/NetworkHelper.kt:69-125`

That shared client is why Cloudflare matters here: one server instance fetches from many third-party sites, and each extension is code the server operator did not write.

## Network stack

| Layer | What it is | Evidence |
|---|---|---|
| HTTP client | OkHttp 5.5.1, version locked by extension ABI | **[verified]** `gradle/libs.versions.toml:6` |
| TLS | JVM default JSSE. BouncyCastle is *appended* as a provider (`addProvider`, not `insertProviderAt`), so it does not take over TLS | **[verified]** `server/src/main/kotlin/suwayomi/tachidesk/server/ServerSetup.kt:471`. Which JSSE ClientHello this produces: **[to measure]** |
| Encodings | brotli and zstd interceptors on the classpath | **[verified]** `gradle/libs.versions.toml:49-50` |
| Cookies | One persistent cookie store, also installed as the JVM-wide `CookieHandler` | **[verified]** `NetworkHelper.kt:42-48` |
| Default User-Agent | `Mozilla/5.0 (Linux; Android 10; K) ... Chrome/149.0.0.0 Mobile Safari/537.36` | **[verified]** `NetworkHelper.kt:51-55` |
| Interceptor order | UncaughtException, then UserAgent, then Cloudflare (application interceptors); HTTP logging as a network interceptor | **[verified]** `NetworkHelper.kt:83-104` |
| Real browser | JCEF (Chromium 144) via KCEF, as an `android.webkit.WebView` stand-in for extensions | **[verified]** `gradle/libs.versions.toml:20`, `AndroidCompat/src/main/java/xyz/nulldev/androidcompat/webkit/KcefWebViewProvider.kt` |

**Defensive note.** The default request claims to be Chrome 149 on Android, but it carries a JVM TLS and HTTP/2 fingerprint. A UA-to-JA4 consistency check catches it on the first request, before any challenge. **[to measure]**: the actual JA4 and HTTP/2 SETTINGS of this client.

## Cloudflare handling: `CloudflareInterceptor`

File: `server/src/main/kotlin/eu/kanade/tachiyomi/network/interceptor/CloudflareInterceptor.kt`. The `CFClearance` half is a port of `vvanglro/cf-clearance` (Apache 2.0), per the header at line 207-210. **[verified]**

### Flow

```
extension request
  -> OkHttp (JVM TLS, UA "Chrome 149 Android")
  -> response 403/503 AND Server: cloudflare?          (:52, :200-201)
       no  -> return response
       yes -> FlareSolverr disabled?  -> IOException    (:56-58)
              another call for this host in flight? -> wait, reuse its UA + stored cookies (:81-105)
              POST {flareSolverrUrl}/v1  cmd=request.get|post   (:320-369)
              solution has cf_clearance?
                 no  -> throw / optional fallback to FlareSolverr's HTML   (:151-185, :376-378)
                 yes -> store FlareSolverr's cookies in OkHttp's jar,
                        set GLOBAL UA to FlareSolverr's UA,
                        replay original request from OkHttp            (:371-420)
```

### Findings

| # | Finding | Tag and evidence |
|---|---|---|
| S1 | **The challenge is detected by status 403/503 plus `Server: cloudflare`.** Cloudflare sets that `Server` header on every proxied response, so an origin's own 403 also sends Suwayomi to FlareSolverr. Cloudflare's documented signal for a challenge is `cf-mitigated: challenge`, which Suwayomi does not read. | **[verified]** `:52`, `:200-201`. Header: **[documented]** [Cloudflare: Detect a Challenge Page response](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response) |
| S2 | **The solver is external, not built in.** FlareSolverr is the only path. It is off by default, and the URL defaults to `http://localhost:8191`. | **[verified]** `ServerConfig.kt:524-537`, `CloudflareInterceptor.kt:56-58` |
| S3 | **The clearance handoff crosses stacks.** The challenge is solved in FlareSolverr's Chrome, then `cf_clearance` and Chrome's UA are replayed from OkHttp's JVM TLS stack. Whether the zone accepts the cookie depends on what Cloudflare binds it to. | **[verified]** `:371-420`. Acceptance: **[to measure]**, experiment E1 |
| S4 | **The UA switch is global.** `setUserAgent` replaces the server-wide UA, and a change unregisters every source so headers get rebuilt. One challenged site changes the UA that all extensions send to all sites. | **[verified]** `CloudflareInterceptor.kt:380`, `NetworkHelper.kt:60-67` |
| S5 | **A stale `cf_clearance` is not forwarded to FlareSolverr.** Other cookies for the URL are passed in. Added in commit `3064f51d` (2026-05-10). | **[verified]** `:342-348` |
| S6 | **All FlareSolverr calls run one at a time.** A global `Mutex` serializes them across hosts, and an in-flight map dedupes calls per host. | **[verified]** `:228`, `:328`, `:81-105`. Dedupe: commit `344ef0dc` (2026-07-25) |
| S7 | **Proxy parity.** When Suwayomi has a SOCKS proxy, it sends the proxy to FlareSolverr and drops the session (FlareSolverr ignores per-request proxies inside sessions). Without this, the cookie would be minted on one IP and used from another. | **[verified]** `:283-284`, `:325`, `:333`. Commit `2ce9e849` (2026-10-08) |
| S8 | **Status is not trusted.** Commit `57f23403` stopped requiring 2xx for a bypass to count. That matches FlareSolverr always reporting `status: 200` (see FlareSolverr F5). The fallback still checks `200..299`, which is then always true. | **[verified]** `:160-162`, FlareSolverr `src/flaresolverr_service.py:475` |
| S9 | **POST bodies go through FlareSolverr** as `postData`, read as UTF-8. Binary bodies would be mangled. | **[verified]** `:351-361`. Mangling: **[unverified]**, not exercised |
| S10 | **Session defaults.** Session name `suwayomi`, TTL 15 min, timeout 60 s. | **[verified]** `ServerConfig.kt:539-562` |

### History (dates from `git log --follow`)

| Date | Change | Commit |
|---|---|---|
| 2022-12-09 | In-process Playwright Chromium used to clear challenges | `ab4d925a` |
| 2023-02-12 | Playwright disabled for v0.6.7 | `a027d6df` |
| 2024-01-12 | Playwright removed | `28e4ac8d` |
| 2024-01-23 | FlareSolverr integration | `d658e075` |
| 2024-07-28 | Option to use FlareSolverr's HTML as the response | `9e006166` |
| 2025-06-12 / 2025-07-01 | WebView via Playwright, then KCEF browser WebView (for extensions, not the interceptor) | `a2fadbe5`, `a79dc580` |
| 2026-02-18 | POST support | `2249d237` |
| 2026-10-08 | SOCKS proxy applied to WebView and bypass | `2ce9e849` |

The project tried an embedded browser solver and moved the browser out of process. The likely reasons are image size, maintenance and detection, but the commit messages do not say. **[unverified]**

## Second path: extensions with their own WebView

The KCEF WebView gives extensions a real Chromium. An extension can load a challenged page in it, which is how Tachiyomi extensions clear challenges on Android. Whether any current extension does this on Suwayomi was not checked: extensions live in other repos. **[unverified]**

## What this means for detection

1. **First request:** UA says Chrome on Android, TLS says JVM. Cheap and deterministic to catch. **[to measure]** what the bot score says about it today.
2. **Solve:** done by FlareSolverr's Chrome. See `flaresolverr.md`.
3. **Replay:** a valid `cf_clearance`, a desktop Chrome UA, and a JVM fingerprint, from the same IP if the proxy is configured. This is the key question for the zone: does a clearance minted under JA4 *A* get honoured under JA4 *B*? Experiment E1.
4. **Fan-out:** after one solve, every extension sends the new UA, including to sites that never challenged. For the hosts that are on Cloudflare, that gives a population signal: one IP, one desktop Chrome UA, many unrelated zones, all with a JVM fingerprint.
