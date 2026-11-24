# L1 results: wire fingerprints (2026-11-24)

Server: TrackMe @ `9d2e865` on the private Docker network `cflab`, hostname `fp.lab.test`, HTTP/2 over TLS 1.3, QUIC off. One request per client, fresh connection each time. Raw captures sit next to this file. Full table in `summary-table.md`, produced by `engine/target/debug/cfprobe baselines experiments/test-results/L1` (originally by `scripts/fingerprint-analysis/summarize_l1.py`; the Rust output is identical apart from escaping `|` inside table cells).

## Clients

| Capture | What ran |
|---|---|
| `curl-host` | Host curl 8.22.0 (OpenSSL) |
| `okhttp-suwayomi` | `lab/okhttp-client`: OkHttp 5.5.1 on Zulu JDK 25.0.5.1, Suwayomi's default UA |
| `ci-chrome152`, `ci-firefox155` | lexiforest curl-impersonate release v2.3.2 (sha256 `bc9bd252...c3f495`), `--impersonate <target>` in `debian:stable-slim` |
| `flaresolverr-chrome` | `flaresolverr/flaresolverr:v3.5.2`, default env, `request.get` through a session |
| `chromium-headful` | Same image's Chromium 152 under Xvfb, launched directly: no driver, no patches, no UA override (`scripts/fingerprint-analysis/baseline_chromium.py`) |
| `chromium152-headless`, `chromium124-headless` | Added 2026-11-24 for version dependence. Plain `--headless=new --ignore-certificate-errors --dump-dom`, no driver: Chromium 152 from the FlareSolverr image, Chromium 124.0.6367.78 from `zenika/alpine-chrome:124` |

## Results

| Client | JA4 | Akamai HTTP/2 | 1st stream | Headers sent |
|---|---|---|---|---|
| chromium-headful (baseline) | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | 1 | 13, Chrome order |
| flaresolverr-chrome | **same as baseline** | **same** | 1 | 13, same order |
| ci-chrome152 | **same as baseline** | **same** | 1 | 14, same order plus `cache-control` |
| ci-firefox155 | `t13d1517h2_8daaf6152771_3cbfd9057e0d` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | 1 | 9, Firefox order |
| okhttp-suwayomi | `t13d1114h2_5e2a75874763_89e9e4bb3419` | `4:16777216\|16711681\|0\|m,p,a,s` | **3** | 2 |
| curl-host | `t13d3013h2_1d37bd780c83_8537cf56674e` | `3:100;4:65536;2:0\|1048510465\|0\|m,s,a,p` | 1 | 2 |

## Findings

| # | Finding | Evidence |
|---|---|---|
| L1-1 | **FlareSolverr's Chrome cannot be told from headful Chromium on the wire.** JA4, the full HTTP/2 fingerprint, header set and header order all match. Headless `new` no longer leaks into `sec-ch-ua` either. Wire signals alone will not catch it; detection has to come from JS (L2), behaviour, or the header below. | Table rows 1-2 |
| L1-2 | **FlareSolverr in Docker sends `accept-language: C.UTF-8,C.UTF;q=0.9`.** No real browser sends that. It comes from `--accept-lang=$LANG` (`src/utils.py:189-191`), and the image inherits `LANG=C.UTF-8` from its Python base image; FlareSolverr's Dockerfile never sets it. Every default deployment carries it until an operator sets `LANG`. The value appears on the solve request, **not** on Suwayomi's replay, which copies only the cookie and UA. | Capture + `docker inspect` + source |
| L1-3 | **curl-impersonate `chrome152` matches Chromium 152 at JA4 and HTTP/2 exactly.** (Corrected by L1-8: the ClientHello is not identical.) In headers it differs only in context: `sec-ch-ua-platform: "Windows"` on a Linux host, a Google Chrome brand list, and `cache-control: max-age=0`. A headful Chromium baseline does not send `cache-control` on a first navigation. Whether real Google Chrome 152 on Windows does is **[to measure]**. | Table, header diff |
| L1-4 | **OkHttp (Suwayomi) fails every layer against its own UA.** It claims Chrome 149 Android but presents JDK 25's ClientHello (11 ciphers, 14 extensions), one SETTINGS entry, pseudo-header order `m,p,a,s`, no `accept`, no client hints, no `sec-fetch-*`, and opens its first request on **stream 3**, where every other client uses 1 (why: **[recall]**, OkHttp reserves stream 1 for HTTP/1.1 Upgrade; not checked in source). Any one of these is enough. | Table |
| L1-5 | **The Suwayomi replay pairs a Chrome-minted `cf_clearance` with the L1-4 fingerprint.** For E1 the two arms to compare are: OkHttp (every layer mismatched) and curl-impersonate `chrome152` with the FlareSolverr UA (every wire layer matched). | Rows 1, 3, 5 |
| L1-6 | **The fork's Firefox and Chrome profiles offer the same cipher set** (15 ciphers), ordered differently. JA4 sorts ciphers, so `ja4_b` collides. Whether real Firefox 155 offers this set is **[to measure]** against a real Firefox capture. | `ja4_r` of both captures |
| L1-7 | Runtime check of source findings: FlareSolverr runs `--headless=new` with an unused Xvfb running (F2 confirmed), and its API returned `status: 200, headers: {}` (F5 confirmed). | `ps` in the container, `flaresolverr-api-response.raw` |
| L1-8 | **curl-impersonate `chrome152` omits Chrome's GREASE value in `signature_algorithms`.** Both real Chromium 152 captures put a random GREASE value first (`0x7a7a` headful, `0x1a1a` FlareSolverr); the fork sends none. JA4 drops GREASE, so JA4 matches; peetprint keeps GREASE positions and separates them: `fc97c1cd...` for both real captures, `1528e8ef...` for the fork. Found by `cfprobe diff` (added 2026-11-24). | `tls.extensions[signature_algorithms]` and `peetprint` in the three captures |
| L1-9 | **cfprobe's own default fingerprint** (boring 5.6.0 + hyper/h2, no profile): JA4 `t13d1711h2_5b57614c22b0_8af51f2a06eb`, HTTP/2 `2:0;4:2097152;5:16384;6:16384\|5177345\|0\|m,s,a,p`, headers `user-agent,accept`. It matches no other client here. A second capture taken later the same day matched the first on all 16 comparable fields, so BoringSSL's default ClientHello is stable between connections (no extension permutation, no GREASE). | `cfprobe-default.json`; engine `cfprobe fingerprint` run |
| L1-10 | **Chromium 124 to 152 changes the TLS layer but not HTTP/2.** Akamai HTTP/2 fingerprint, pseudo-header order, header order, cipher list and ALPN are identical. What changed: key-exchange group `X25519Kyber768 (25497)` became `X25519MLKEM768 (4588)`; ALPS moved from `application_settings_old (17513)` to `application_settings (17613)`; 152 adds extension 51764 (unnamed by TrackMe), 3 new signature algorithms `0x904`-`0x906`, and a GREASE value at the head of `signature_algorithms`. So JA4 moves `t13d1516h2_..._02713d6af862` to `t13d1517h2_..._cb7bf5808d99`. The sigalg GREASE is new since 124, which puts L1-8 in context: curl-impersonate's `chrome152` profile lacks a 152 feature. Headless vs headful 152 differ only in the `HeadlessChrome` UA token (JA3 aside, which permutes). | `cfprobe diff chromium124-headless.json chromium152-headless.json`; test `chromium_124_and_152_differ_in_tls_but_not_http2` |

## Limits

- One run per client. JA4 and the HTTP/2 fingerprint are deterministic per build, so repeat runs only matter for JA3 (which permutes).
- Version dependence (L1-10) rests on one capture per version, two versions, both Chromium builds, both headless.
- The baseline is **Chromium** (Debian build), not Google Chrome. Brand list and field trials differ. A real Google Chrome capture is still missing.
- TCP fingerprint was not compared: every client shares this host's kernel.
- curl-impersonate was run with `--impersonate`, without the wrapper's `--compressed`. That flag controls decoding only; the `accept-encoding` header comes from the profile.
