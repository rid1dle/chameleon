# curl-impersonate

Two repos, and the difference between them matters:

| Repo | Pin | Last commit | Status |
|---|---|---|---|
| `lwthiker/curl-impersonate` (original) | `822dbef` | 2024-03-03 | Dormant. Newest targets: `curl_chrome116`, `curl_ff117` **[verified]** `chrome/`, `firefox/` |
| `lexiforest/curl-impersonate` (fork) | `ec2a231` | 2026-11-24 | Active. Ships the `curl_cffi` Python binding (pushed 2026-11-23) **[verified]** git log, GitHub API |

The rest of this document describes the fork unless stated otherwise. Tags as in `suwayomi-tachidesk.md`.

## What it is

A patched curl that reproduces one browser's TLS ClientHello, HTTP/2 connection preface and frames, HTTP/3 and QUIC parameters, and header set and order. It is a passive-fingerprint tool: **it runs no JavaScript**, so it cannot complete a JS or managed challenge by itself. It only looks like a browser on the wire. **[verified]** No JS engine in the build; the only non-patch source is `src/webcrypto.cc`.

## How it works

| Part | Mechanism | Evidence |
|---|---|---|
| TLS library | BoringSSL for **every** target, Firefox and Safari included. The original built Firefox targets on NSS, Firefox's own library. The fork imitates NSS's ClientHello from BoringSSL. | **[verified]** fork `CMakeLists.txt` (no NSS); original `README.md:21`, `:174` |
| Patches | `boringssl.patch`, `curl.patch`, `nghttp3.patch`, `ngtcp2.patch`, `brotli.patch` | **[verified]** `patches/` |
| New curl options | 41 `CURLOPT_*` added, including `TLS_EXTENSION_ORDER`, `TLS_GREASE`, `SSL_PERMUTE_EXTENSIONS`, `TLS_KEY_SHARES_LIMIT`, `SSL_ENABLE_ALPS`, `TLS_USE_NEW_ALPS_CODEPOINT`, `SSL_CERT_COMPRESSION`, `HTTP2_SETTINGS`, `HTTP2_WINDOW_UPDATE`, `HTTP2_PSEUDO_HEADERS_ORDER`, `HTTP2_NO_PRIORITY`, `HTTPHEADER_ORDER`, `HTTP3_SETTINGS`, `QUIC_TRANSPORT_PARAMETERS`, `IMPERSONATE` | **[verified]** `grep '^+ *CURLOPT(' patches/curl.patch` |
| Targets | 48 compiled-in profiles (`.target = ` in `curl.patch`), 47 wrapper scripts in `bin/`. `browsers.json` lists only 12 of them and is out of date. | **[verified]** |
| Wrappers | Each wrapper is one line: `curl-impersonate --compressed --impersonate "<target>"` | **[verified]** `bin/curl_chrome152` |

### One profile in full: `chrome152` (`patches/curl.patch:4767`)

| Layer | Value |
|---|---|
| Key shares | `X25519MLKEM768:X25519:P-256:P-384`, limited to 2 key shares (post-quantum hybrid first, as current Chrome does) |
| Signature algs | ML-DSA 44/65/87 first, then the usual ECDSA/RSA-PSS/PKCS1 set |
| Extensions | GREASE on, **permuted per connection**, ALPS with the new codepoint, cert compression brotli, SCT, session tickets, **ECH on**, Trust Anchor IDs list |
| HTTP/2 | SETTINGS `1:65536;2:0;4:6291456;6:262144`, WINDOW_UPDATE 15663105, pseudo-header order `m,a,s,p`, priority weight 256 exclusive |
| HTTP/3 | SETTINGS `1:65536;6:262144;7:100;51:1;GREASE`, fixed TLS extension order, full QUIC transport parameter list |
| Headers | Full Chrome 152 **Windows** navigation set: `sec-ch-ua*`, `sec-fetch-*`, `priority: u=0, i`, in Chrome's order |

Whether these values match a real Chrome 152 capture is **[to measure]**, lab L1. Do not assume they do because the file says so.

## Findings

| # | Finding | Tag |
|---|---|---|
| C1 | **JA3 is useless against it.** Extension permutation makes JA3 change on every connection, as it does for real Chrome since version 110 (**[unverified]**, from memory of the 2023 Chrome change, recheck). JA4 sorts extensions, so it stays stable and matches Chrome. | Permutation **[verified]** `.tls_permute_extensions = true`. JA4 equality **[to measure]** L1 |
| C2 | **The fingerprint is right; the context can be wrong.** It claims Windows (`sec-ch-ua-platform: "Windows"`) on whatever host it runs on, usually a Linux server on a datacenter ASN. Nothing on the wire contradicts this, but IP reputation and the TCP/IP stack (TTL, window size, MSS) still say Linux. | Headers **[verified]**. TCP signal **[to measure]** L1 with p0f |
| C3 | **No JS means no challenge.** It passes only where a zone scores passive signals and does not serve a challenge. Its usual role in a pipeline is the replay client after a browser has solved the challenge, the same slot OkHttp fills for Suwayomi, but with a matching fingerprint. | **[verified]** by design |
| C4 | **Profiles go stale.** Each target is frozen at one browser version. Real Chrome updates about every 4 weeks, so the claimed version falls behind or stays consistent only if someone maintains it. A fingerprint matching only an old Chrome is itself a signal. | Freeze **[verified]**. Detection value **[unverified]** |
| C5 | **The best replay client for the S3 question.** Pairing FlareSolverr's cookie with curl-impersonate gives a replay with *matching* JA4, while OkHttp gives a *mismatched* one. Running both separates "the cookie is bound to the fingerprint" from "the cookie is bound only to UA and IP". | Experiment E1 design |
