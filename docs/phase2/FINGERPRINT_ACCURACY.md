# Fingerprint accuracy (Phase 2, 2026-11-24)

Two questions: does cfprobe **measure** fingerprints correctly, and what does cfprobe's own fingerprint **look like** next to other clients. Every value below was measured by a receiver (local TrackMe at `fp.lab.test`, or the zone Worker); none is inferred from the client's settings.

Captures: `experiments/test-results/P2/compare/*.json` (new), `experiments/test-results/L1/*.json` (earlier the same day). Compare: `cfprobe diff <a.json> <b.json> --format md`.

## 1. Measurement accuracy

| Check | Result | Evidence |
|---|---|---|
| Receiver parsing (TrackMe) matches the L1 summary table | Yes, all fields | `trackme_record_matches_the_l1_summary_table` |
| Client's own TLS view matches the receiver's | Yes: ClientHello random equal at the zone Worker (`same_handshake_as_client: true`, live, with br/zstd compression on) | Zone `fingerprint` run, P2 |
| Same client, two connections | Chromium 152 headless (L1 vs P2): 16 same, 0 differ, JA3 order-only; cfprobe with permutation (two captures): 16 same, 0 differ, JA3 order-only | `cfprobe diff` |
| Different clients | Every pair below differs on the fields it should | Section 2 |
| Engine changes in Phase 2 did not change the wire | cfprobe default L1 vs P2: **17 same, 0 differ** | `cfprobe diff L1/cfprobe-default.json P2/compare/cfprobe-p2-default.json` |
| TLS settings reach the wire | `grease` + `permute_extensions`: GREASE cipher first (`0xEAEA`, then `0x8A8A`), GREASE extensions, order different on each connection | `cfprobe-p2-grease-permute*.json` |
| HTTP/1.1 Title-Case reaches the wire | `Host:`, `User-Agent:`, `Accept-Language:` on the raw socket | `d13_title_case_header_names_are_selectable` |

**Defect fixed (D8):** JA3 keeps extension order and Chrome permutes it, so the same binary diffed as "1 differ". The comparison now checks whether the JA3 strings hold the same values once the extension list is sorted, and reports `order_only` instead of `differs` when they do. A real JA3 difference (Chrome vs Firefox) still counts.

**Not fixed:** the Worker's `tlsClientCiphersSha1` / `tlsClientExtensionsSha1` are hashes, so an order-only change there cannot be told from a real one (E1-4). They are compared as given.

## 2. cfprobe next to other clients (TrackMe, 2026-11-24)

| Client | HTTP | JA4 | HTTP/2 (Akamai) |
|---|---|---|---|
| cfprobe default | h2 | `t13d1711h2_5b57614c22b0_8af51f2a06eb` | `2:0;4:2097152;5:16384;6:16384\|5177345\|0\|m,s,a,p` |
| cfprobe GREASE + permute | h2 | same as default (JA4 ignores GREASE and sorts) | same |
| cfprobe HTTP/1.1 Title-Case | http/1.1 | `t13d1711h1_5b57614c22b0_8af51f2a06eb` | none |
| reqwest 0.13 (rustls) | h2 | `t13d1011h2_61a7ad8aa9b6_3a8073edd8ef` | **identical to cfprobe** |
| curl 8.22.0 (OpenSSL 3.6.5, nghttp2) | h2 | `t13d3013h2_1d37bd780c83_8537cf56674e` | `3:100;4:65536;2:0\|1048510465\|0\|m,s,a,p` |
| Chromium 152 headless | h2 | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |

Field by field against cfprobe default (20 fields; "not comparable" omitted):

| vs | Same | Differ | Order only | Same fields |
|---|---|---|---|---|
| Chromium 152 | 4 | 13 | 0 | TLS 1.3, ALPN `h2,http/1.1`, h2, first stream 1 |
| curl 8.22 | 6 | 11 | 0 | + pseudo-header order `m,s,a,p`, header order `user-agent,accept` |
| reqwest 0.13 | 8 | 8 | 0 | + **every HTTP/2 field** (SETTINGS, window update, Akamai, pseudo order); TLS differs entirely (rustls vs BoringSSL) |
| cfprobe HTTP/1.1 | 7 | 4 | 0 | every TLS field except ALPN, JA4's protocol letter and peetprint |

What this establishes:

- **cfprobe's HTTP/2 layer is hyper's default, byte for byte the same as reqwest's.** It identifies "a hyper/h2 client", not cfprobe specifically.
- cfprobe's TLS layer is BoringSSL's default, with no GREASE and no permutation unless configured. It matches no other client measured. Its offered groups include one TrackMe cannot name (`Unknown curve 65074`, 0xFE32): **[unverified]** what BoringSSL 5.6.0 sends it for.
- **cfprobe is not browser-equivalent and does not claim to be.** Against Chromium 152 it differs on 13 of 17 comparable fields: cipher list, extensions, groups, signature algorithms, HTTP/2 SETTINGS, window update, pseudo-header order (`m,s,a,p` vs Chrome's `m,a,s,p`, fixed by the h2 crate), header set and order, user agent. Matching TLS version and ALPN is not similarity in any useful sense.

## 3. Real Chrome

No Google Chrome build exists on this host. "Chrome" here is **Chromium 152** (Debian, inside the FlareSolverr image), headless and headful, and Chromium 124 (Alpine). Google Chrome adds branding (`sec-ch-ua` brand list) and may differ in field trials; that comparison remains open (README research gaps).

## 4. Fingerprint measurement variation

| Variation | Effect measured |
|---|---|
| Browser version (Chromium 124 vs 152) | TLS changes (groups, ALPS, new extension, sigalgs, GREASE in sigalgs); HTTP/2 identical (L1-10) |
| Headless vs headful (152) | Only the `HeadlessChrome` token in the user agent |
| HTTP version (cfprobe h2 vs h1) | ALPN, JA4 protocol letter, peetprint; TLS otherwise identical |
| TLS settings (cfprobe GREASE + permute) | JA3 changes per connection; JA4 and peetprint stable |
| Client library (cfprobe vs reqwest) | TLS entirely different; HTTP/2 identical |

Randomized identities were not generated: the brief excludes them, and this engine has no profile or rotation feature.
