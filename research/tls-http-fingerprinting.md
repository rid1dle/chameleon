# TLS and HTTP fingerprinting

How passive fingerprints are built, what Cloudflare says it uses, and where curl-impersonate, OkHttp on the JVM, and FlareSolverr's Chromium land. Input to L1 and to the E1 arm design. Docs read 2026-11-24.

Tags as in `README.md`. **[documented]** links the page or spec. **[verified]** is read in `vendor/` at the pinned commit (TrackMe at `9d2e865`, 2026-08-26, not yet in the README pin table). **[recall]** is prior knowledge with no source found. **[to measure]** names the run that settles it.

## Answer first

| # | Point | Tag |
|---|---|---|
| 1 | **Cloudflare documents JA3 and JA4 only.** It exposes both, plus JA4 Signals, to Enterprise Bot Management. | **[documented]** [cf-ja] |
| 2 | **Cloudflare does not document using HTTP/2 SETTINGS, WINDOW_UPDATE, pseudo-header order or TCP traits.** No field exposes them. Only `httpProtocol` and `requestPriority` reach a Worker. | **[documented]** [wreq] by absence |
| 3 | **Header order is documented as a heuristic:** a detection ID can flag headers "in a different order than what its claimed browser would use." | **[documented]** [detids] |
| 4 | **JA3 broke because Chromium shuffles TLS extensions per connection (early 2023).** JA4 sorts them, so one Chrome build gives one JA4. | **[documented]** [blog-ja4], [ja4spec] |
| 5 | **curl-impersonate `chrome152` copies TLS, HTTP/2 and header order; OkHttp on the JVM differs at all three; FlareSolverr's Chromium is genuine on the wire.** So E1's OkHttp arm changes three layers at once. | Profile **[verified]**; OkHttp values **[recall]**, **[to measure]** L1 |

## JA3 vs JA4

| | JA3 | JA4 (TLS client) | Tag |
|---|---|---|---|
| Input | `SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat`, decimal, in wire order | ClientHello: protocol, version, SNI, counts, ALPN, sorted ciphers, sorted extensions plus signature algorithms | **[documented]** [ja3], [ja4spec] |
| Output | MD5 of the string | `a_b_c`, human-readable prefix plus two 12-char SHA-256 truncations | **[documented]** [ja3], [ja4spec] |
| GREASE | Ignored | Ignored everywhere | **[documented]** [ja3], [ja4spec] |
| Extension order | **Part of the hash** | **Sorted, order ignored** | **[documented]** [ja4spec] |
| Effect of Chrome's shuffling | New JA3 on nearly every connection | Stable | **[documented]** [blog-ja4] |
| QUIC | Not designed for it | `q` prefix | **[documented]** [blog-ja4], [ja4spec] |
| License | BSD 3-Clause | JA4 is BSD 3-Clause; JA4+ (JA4H, JA4T, JA4S, ...) is FoxIO License 1.1 | **[documented]** [ja4readme] |

Why permutation broke JA3: Chromium began shuffling extension order in early 2023 so servers would not ossify on a fixed order. JA3 hashes that order, so it varies per connection. **[documented]** [blog-ja4]. The Chrome version that shipped it (110) is **[recall]**; `projects/curl-impersonate.md` C1 carries the same caveat.

Consequence for detection: a **stable JA3 with a Chrome UA** is itself a tell, since real modern Chrome never repeats JA3. A client that does not permute (JVM, plain curl) gives one JA3 per build. **[recall]**, **[to measure]** L1

## JA4 parts

Example from the spec: `t13d1516h2_8daaf6152771_e5627efa2ab1`. **[documented]** [ja4spec]

| Part | Example | Rule | What it catches |
|---|---|---|---|
| Protocol | `t` | `t` TCP, `q` QUIC, `d` DTLS | h3 vs h2 changes the whole JA4 |
| Version | `13` | Highest in `supported_versions`, else ClientHello version; handshake version ignored | TLS 1.2-only stacks |
| SNI | `d` | `d` if SNI present, `i` if not | Clients hitting an IP |
| Cipher count | `15` | Two digits, GREASE excluded, SCSV counted | Cipher list size |
| Extension count | `16` | Two digits, GREASE excluded, SNI and ALPN included | Extension set size, including ECH |
| ALPN | `h2` | First and last alphanumeric char of the **first** ALPN value; `00` if none | A client offering `http/1.1` first gives `h1` |
| `b` | `8daaf6152771` | SHA-256 of cipher hex codes **sorted**, first 12 chars | Cipher set |
| `c` | `e5627efa2ab1` | SHA-256 of extension codes **sorted** (minus SNI, ALPN) `_` signature algorithms **in wire order** | Extension set, and signature algorithm order |

Two consequences:

- **Signature algorithm order still counts.** Sorting applies to extensions, not to `signature_algorithms`. A stack that copies Chrome's extension set but not its signature algorithm order gets a different `c`. **[documented]** [ja4spec]
- **Cloudflare exposes only the hashed JA4.** Raw `JA4_r` and wire-order `JA4_ro` are not in any field. To see what differs, L1 must log raw. **[documented]** [wreq], [logpush] by absence; TrackMe outputs `ja4_r` **[verified]** `pkg/types/structs.go:20`

## HTTP/2 fingerprint (Akamai format)

Format: `S[;]|WU|P[,]#|PS[,]`. **[verified]** TrackMe `pkg/http/fingerprint_h2.go:11-17`, which cites the Akamai Black Hat EU 2017 paper [akamai]. The paper text could not be extracted here, so its own wording is **[recall]**.

| Component | Content | Spec basis |
|---|---|---|
| `S` | First SETTINGS frame, `id:value` in sent order, `;` separated | IDs 1 to 6 **[documented]** [rfc9113] §6.5.2. 8 is `ENABLE_CONNECT_PROTOCOL` (RFC 8441) **[recall]**. 9 is `NO_RFC7540_PRIORITIES` **[documented]** [rfc9218] |
| `WU` | Increment of the first connection WINDOW_UPDATE, `00` if none | **[verified]** `fingerprint_h2.go:58-67` |
| `P` | PRIORITY frames `stream:exclusive:dependsOn:weight`, `0` if none | PRIORITY frame and the RFC 7540 scheme are deprecated **[documented]** [rfc9113] §5.3.2 |
| `PS` | Pseudo-header order from the first HEADERS frame (`m`,`a`,`s`,`p`) | Order among pseudo-headers is free; they must only precede regular fields **[documented]** [rfc9113] §8.3 |

Why it fingerprints: the spec fixes neither SETTINGS choice, nor window sizes, nor pseudo-header order, so each stack picks its own. HTTP/2 also forces lowercase field names **[documented]** [rfc9113] §8.2, so header **case** is a signal only over HTTP/1.1. Header **order** is a signal on both.

### Known values

| Client | Akamai string | Tag |
|---|---|---|
| Chrome 133 macOS | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | **[verified]** `lexiforest_curl-impersonate/tests/signatures/chrome_133.0.6943.55.yaml:147` |
| curl-impersonate `chrome152` | SETTINGS `1:65536;2:0;4:6291456;6:262144`, WU `15663105`, pseudo `masp`, stream weight 256 exclusive on HEADERS | **[verified]** `patches/curl.patch:4791-4793`, `:4801-4802` |
| Firefox 144 | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | **[verified]** `tests/signatures/firefox_144.0.0_linux.yaml:153` |
| Safari 18 macOS | `2:0;3:100;4:2097152;8:1;9:1\|10420225\|0\|m,s,a,p` | **[verified]** `tests/signatures/safari_18.0_macOS.yaml:143` |
| OkHttp 5 (Suwayomi) | Large INITIAL_WINDOW_SIZE (16 MiB), large WINDOW_UPDATE, pseudo `m,p,a,s` | **[recall]**, **[to measure]** L1 |
| Plain curl (nghttp2) | Differs from all browsers; exact values not in hand | **[recall]**, **[to measure]** L1 |

The vendor signature files are curl-impersonate's test expectations. Whether they match today's real browsers is **[to measure]** L1, the same caveat as `projects/curl-impersonate.md`.

## Header order

| Point | Tag |
|---|---|
| Cloudflare documents a detection ID class for header order inconsistent with the claimed browser | **[documented]** [detids] |
| Chrome 152 Windows navigation order in the `chrome152` profile: `sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cache-control, cookie` | **[verified]** `patches/curl.patch:4781` |
| A Worker cannot observe order. Fetch `Headers` iterate via "sort and combine" | **[documented]** [fetch]; workerd behaviour **[to measure]** E3 |
| Logpush `RequestHeaders` is an object of named headers only | **[documented]** [logpush] |
| JA4H (FoxIO License) fingerprints HTTP request headers; header count excludes `Cookie` and `Referer`. Cloudflare does not expose it | Count rule **[documented]** [ja4h]. Rest of the algorithm **[recall]** |

So on the zone, header order is visible **only** as `detectionIds`. L1 has to measure order directly.

## What Cloudflare exposes, by layer

| Layer | Exposed | Where | Plan | Tag |
|---|---|---|---|---|
| TLS | `ja3Hash`, `ja4`, `ja4Signals` | Workers, rules, Logpush | Ent BM | **[documented]** [cf-ja] |
| TLS | `tlsClientCiphersSha1`, `tlsClientExtensionsSha1`, `tlsClientExtensionsSha1Le`, `tlsClientHelloLength`, `tlsVersion`, `tlsCipher` | Workers | All plans | **[documented]** [wreq] |
| TLS | `ClientTLSKeyExchangeGroup` (for example `X25519MLKEM768`) | Logpush | All | **[documented]** [logpush] |
| HTTP/2 | `httpProtocol`, `requestPriority` | Workers | All | **[documented]** [wreq] |
| HTTP/2 | SETTINGS, WINDOW_UPDATE, pseudo-header order | Nowhere | n/a | Not documented |
| Headers | Order: only through detection IDs. Values: Custom Fields | Logpush | Ent BM for IDs | **[documented]** [detids], [custom] |
| TCP | `clientTcpRtt`, `ClientTCPRTTMs` | Workers, Logpush | All | **[documented]** [wreq], [logpush] |
| TCP | TTL, window, MSS, options (JA4T) | Nowhere | n/a | Not documented |

`ClientTLSKeyExchangeGroup` is a cheap discriminator: current Chrome and `chrome152` lead with `X25519MLKEM768` (**[verified]** `projects/curl-impersonate.md`), while a JVM negotiates a classical group unless its JDK supports hybrid ML-KEM. JDK support level **[recall]**, **[to measure]** E3.

## The three clients

| Layer | curl-impersonate `chrome152` | OkHttp 5.5.1 on JVM (Suwayomi replay) | FlareSolverr 3.5.2 Chromium (solver) |
|---|---|---|---|
| TLS library | BoringSSL **[verified]** `projects/curl-impersonate.md` | JVM JSSE; BouncyCastle appended, not primary **[verified]** `projects/suwayomi-tachidesk.md` | Chromium's BoringSSL, Debian `chromium` package **[verified]** `FlareSolverr/Dockerfile:32`; BoringSSL **[recall]** |
| Extension permutation | On **[verified]** `curl.patch:4784` | Off **[recall]** | On **[recall]** |
| GREASE | On **[verified]** `projects/curl-impersonate.md` | None **[recall]** | On **[recall]** |
| Key share | `X25519MLKEM768` first **[verified]** | Classical groups **[recall]** | Matches Chrome of the same build **[recall]** |
| ECH | On **[verified]** `curl.patch:4780` | None **[recall]** | Chromium default **[recall]** |
| JA4 vs real Chrome | Same, if profile is current **[to measure]** L1 | Different at `c` at least **[recall]** | Same as Chromium of that version **[to measure]** L1 |
| HTTP/2 Akamai | Chrome's (table above) **[verified]** | OkHttp's **[recall]** | Chrome's **[recall]** |
| HTTP/3 | Supported, Chrome settings **[verified]** `projects/curl-impersonate.md` | No | May upgrade via Alt-Svc **[recall]** |
| Header order and set | Chrome 152 Windows, `sec-ch-ua*`, `sec-fetch-*`, `priority` **[verified]** `curl.patch:4781` | OkHttp order; UA "Chrome 149 Android" with no `sec-ch-ua` or `sec-fetch-*` **[recall]** | Chromium's own; UA forced by `--user-agent` **[verified]** `projects/flaresolverr.md` |
| UA vs other claims | Says Windows; runs on Linux | Says Android Chrome; TLS says JVM | `--user-agent` may not rewrite `sec-ch-ua` brands; new-headless brand leak **[recall]**, **[to measure]** L1, L2 |
| TCP stack | Host OS, usually Linux **[verified]** C2 | Host OS | Container host OS |
| JavaScript | None | None | Full |

Reading the table for E1:

- **curl-impersonate vs FlareSolverr** differ only in context (and in HTTP/3 if Chromium used it). A rejection here points at IP, UA or something outside the wire fingerprint.
- **OkHttp vs FlareSolverr** differ in TLS, HTTP/2, header set and order. A rejection says "something on the wire", not which layer.
- To split layers, add curl-impersonate arms that change one thing: `--http1.1` (removes HTTP/2, keeps TLS), or custom `CURLOPT_HTTP2_SETTINGS` (keeps TLS, changes HTTP/2), or a different `--impersonate` target (changes TLS and HTTP/2 together). Options exist **[verified]** `projects/curl-impersonate.md`.

## L1 instrument notes

| Need | State | Tag |
|---|---|---|
| JA3, JA4, `ja4_r`, Akamai string, PeetPrint | TrackMe computes them | **[verified]** `pkg/types/structs.go:16-23`, `pkg/http/fingerprint_h2.go:104-113` |
| TCP options and order | **TrackMe stubs them** (`parseTCPOptions` returns `""`). Use p0f or a pcap for TTL, window, MSS, options | **[verified]** `pkg/tcp/tcp.go:108-114` |
| Header order | Record raw frames, not a parsed map | Design |
| Cross-check with Cloudflare | Run each L1 client against the zone echo too (E3) and compare `ja4` strings, to prove L1's JA4 equals Cloudflare's | **[to measure]** L1 vs E3 |
| Session resumption | Disable or use a new session per run; Cloudflare skips JA3/JA4 on resumed connections | **[documented]** [cf-ja] |

## Not documented

| Gap | Matters for |
|---|---|
| Whether HTTP/2 SETTINGS, WINDOW_UPDATE or pseudo-header order feed the bot score or any detection ID | E3: wire-perfect vs JVM scores |
| Whether TCP/IP traits (JA4T-style) feed the score | C2 in `projects/curl-impersonate.md` |
| Which ClientHello JA4 is computed on under real ECH (outer or inner) | `chrome152` has ECH on |
| How JA4 is reported for HTTP/3 requests | Chromium solving over h3 in E1 |
| Whether `tlsClientExtensionsSha1` is order-sensitive | Free permutation detector |
| Which detection IDs are header-order checks | E3 interpretation |
| Any binding of `cf_clearance` to TLS or HTTP/2 fingerprints | E1, see `challenges-and-clearance.md` |

[cf-ja]: https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
[detids]: https://developers.cloudflare.com/bots/additional-configurations/detection-ids/
[wreq]: https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties
[logpush]: https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/http_requests/
[custom]: https://developers.cloudflare.com/logs/logpush/logpush-job/custom-fields/
[blog-ja4]: https://blog.cloudflare.com/ja4-signals/
[ja4spec]: https://github.com/FoxIO-LLC/ja4/blob/dccfdd6e4e8948f7acb5d634db78c6e5794faa97/technical_details/JA4.md
[ja4h]: https://github.com/FoxIO-LLC/ja4/blob/dccfdd6e4e8948f7acb5d634db78c6e5794faa97/technical_details/JA4H.md
[ja4readme]: https://github.com/FoxIO-LLC/ja4/blob/dccfdd6e4e8948f7acb5d634db78c6e5794faa97/README.md#licensing
[ja3]: https://github.com/salesforce/ja3#readme
[rfc9113]: https://www.rfc-editor.org/rfc/rfc9113
[rfc9218]: https://www.rfc-editor.org/rfc/rfc9218
[akamai]: https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf
[fetch]: https://fetch.spec.whatwg.org/#concept-header-list-sort-and-combine
