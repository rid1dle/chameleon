# HTTP compatibility (Phase 2, 2026-11-24)

Stack: hyper 1.13 client connections (HTTP/1.1 and HTTP/2 via the `h2` crate), chosen by ALPN. cfprobe owns the connection pool.

## HTTP/1.1 and HTTP/2

| Area | Behaviour | Evidence |
|---|---|---|
| Protocol choice | h2 when ALPN agrees, else HTTP/1.1; plain `http://` is HTTP/1.1 | `local_tls.rs`; zone `discord-http`-style redirects |
| Request header order | Host (HTTP/1.1 only), config defaults, then the target's headers; a target header replaces a default in place; repeats all sent (D9) | `headers_arrive_in_configured_order`, `d9_...` |
| Header case | HTTP/1.1 lowercase by default, Title-Case with `h1.title_case_headers` (D13); HTTP/2 lowercase by protocol | `d13_...` |
| HTTP/2 pseudo-header order | `m,s,a,p`, fixed by `h2` | TrackMe captures |
| HTTP/2 connection-specific headers | Dropped (hyper) and listed in `request.not_sent` (D19) | `h2_connection_headers_are_reported_as_not_sent` |
| HTTP/2 `:authority` | `host[:port]` from the URL; credentials refused before sending (D4) | `d4_...`, `d5_...` |
| Connection reuse | HTTP/2: one shared, multiplexed connection per origin (20 concurrent requests, 1 TCP connection, D12); HTTP/1.1: idle list, all connections reused | `d12_...`, `h2_connection_is_reused...` |
| Keep-alive closed by the server | Idempotent requests resent once on a new connection (D1) | `d1_...` (100/100) |
| `reuse_connections: false` | One connection per request | `no_reuse_when_disabled` |
| 1xx responses | HTTP/1.1: recorded in `response.informational` (D14); HTTP/2: not surfaced by hyper | `d14_...` |
| Response header count | HTTP/1.1 limit 100 unless `h1.max_response_headers`; over it the response is UNKNOWN ("response parsing"), not retried (D22); HTTP/2 no count limit | Zone `many-headers` (120 headers): h2 and curl 200, HTTP/1.1 refused |
| Large single header | 64 KiB header accepted | adversarial probe (Phase 2 start) |
| Response header order in the record | HTTP/1.1: exact wire order and case in `wire_header_order` (D10). HTTP/2: `headers` only, where a repeated name is grouped at its first position | `d10_...`; real cloudflare.com over HTTP/1.1 |
| Unexpected status codes | Any status recorded and classified; 418 and 451 included in fuzzing | fuzz |
| Body size limit | Wire and decoded body capped at `max_body_bytes` (8 MiB); over is an error, never a truncation | `body_over_limit...`, D7 cap test |
| Connection cut mid-body | `Error::Body`, CONNECTION_FAILURE, when the length is known; a chunked body cut by the origin through Cloudflare arrives as complete for every client (zone `cut-body`) | adversarial; zone |
| Not HTTP at all | UNKNOWN ("response parsing"), not retried | `unparseable_responses_are_unknown_and_not_retried` |

## Compression

| Encoding | Decoded | Evidence |
|---|---|---|
| gzip, deflate (zlib and raw), br, zstd, stacked (`gzip, br`) | Yes, capped at `max_body_bytes` | unit and property round trips; **live from Cloudflare: gzip (1284 -> 2836 bytes), br (1307 -> 2834), zstd (1346 -> 2800); offering all four, Cloudflare chose zstd** |
| Unknown or corrupt | Kept as received, `body_decoding: not_decoded` with the reason; the classifier uses status and headers only and lowers confidence | `d7_...`, fuzz `corrupt_gzip` and `unknown` |
| A small body expanding past the cap (compression bomb) | `BodyTooLarge` | `decoding_is_capped...` (10 MB of zeros in under 4 KB of zstd) |

cfprobe sends no `accept-encoding` by default (it measures what a request without one gets). Browsers send `gzip, deflate, br, zstd`.

## Cookies

| Area | Behaviour | Evidence |
|---|---|---|
| Parsing | Name, value length (value never stored in records), attributes in order, lowercased names | `set_cookie_keeps_attributes...`; property test (never panics, never overstates) |
| Malformed `Set-Cookie` | Recorded, never dropped from the record; ignored by the jar | fuzz `set_cookies_all_recorded` |
| Jar (session, opt-in; on in the runner) | RFC 6265 matching via `cookie_store` 0.22: path, expiry, domain; cookies of one request sent on later ones | `cookie_jar_keeps_respects_path_and_expiry...`; zone `cookie-continuity` (cfprobe both protocols and curl: `lab_session` arrived) |
| `inspect` | No jar: cookies are not persisted (probe: `cookieNames: []` on the next request) | Phase 2 cookie probe |
| Cross-origin redirect | A caller's `cookie` and `authorization` are dropped | `credentials_do_not_follow...` |
| Public suffix list | Not loaded, so a site could set a cookie for a whole TLD; acceptable for a research tool, listed in `KNOWN_ISSUES.md` | `cookie_store` source |

## Redirects

| Area | Behaviour | Evidence |
|---|---|---|
| `inspect` | Not followed: 3xx returned as REDIRECT, `Location` reported redacted | zone `redirect-no-follow`; real-world run 1 |
| Session / runner | Followed up to `max_redirects` (runner 5): 301/302/303/307/308; 303 and POST on 301/302 become GET; relative `Location` resolved | `redirect_chain_is_followed_and_recorded`; zone `redirect` (302 -> 200); real-world run 2 (asuracomic.net, discord docs, cloudflare.com apex, discord over http: all `301 > 200`) |
| Loops | Detected at the first repeat of a (method, URL) before re-requesting | zone `redirect-loop` (cfprobe: 1 request); curl with `-L --max-redirs 5` ended on a 302 (how many hops it made and its exit code are not recorded by the runner) |
| Too many | `too_many_redirects` after the limit | `redirect_loops_and_long_chains_stop` |
| Non-HTTP schemes | Not followed (`bad_redirect`) | source |

## Comparison with curl on the zone (same cases, same policy translated to curl flags)

| Case | cfprobe (h2 and h1) | curl |
|---|---|---|
| 27 of the 28 cases all three clients ran | Same status and verdict | Same status and verdict |
| `redirect-loop` | Stopped at the first repeat | Ended on a 302 under `--max-redirs 5` (hop count not recorded) |
| `many-headers` (120) | h2 fine; HTTP/1.1 refused (hyper limit 100) | Fine |
| `cut-body` | 200 with the 1000 bytes sent | Same |
| Retries | Visible per attempt | Not visible (curl's own `--retry`) |
