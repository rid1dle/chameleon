# E1 results: is `cf_clearance` bound to the solving client? (2026-11-24)

Zone `riddlelab.dev`, **Free plan** (no Bot Management: `request.cf.botManagement` is null). Echo Worker `cflab-echo` on the Custom Domain `lab.riddlelab.dev`. One WAF custom rule, Managed Challenge on `http.host eq "lab.riddlelab.dev" and starts_with(http.request.uri.path, "/c/")`. The cookie was minted by FlareSolverr 3.5.2 at default settings (E2) and replayed against `/c/echo` by `scripts/zone/e1_replay.sh`. Every arm left from the same host IPv4 that solved. Captures in `run1/`, location and client IP removed.

## Results

Two full runs (12:59:54 and 13:00:14 UTC), same outcome in both. Table is the second run.

| Arm | Client | UA | Cookie | Status | `cf-mitigated` | Pseudo-header order seen by Worker |
|---|---|---|---|---|---|---|
| a0 | curl-impersonate `chrome152` | FlareSolverr's | none | 403 | challenge | (challenged) |
| a1 | curl-impersonate `chrome152` | FlareSolverr's | yes | **200** | none | `m,a,s,p` |
| a2 | OkHttp 5.5.1 / JDK 25 (Suwayomi) | FlareSolverr's | yes | **200** | none | `m,p,a,s` |
| a3 | host curl 8.22.0 | FlareSolverr's | yes | **200** | none | `m,s,a,p` |
| a4 | curl-impersonate `chrome152` | Chrome 152 **Windows** (only the platform part differs) | yes | **403** | challenge | (challenged) |
| a5 | as a1, after a4 | FlareSolverr's | yes | **200** | none | `m,a,s,p` |

## Cloudflare's own record

GraphQL `firewallEventsAdaptive` (`scripts/zone/fw_events.sh`, saved to `firewall-events.tsv`, no client IP) agrees with every arm. Runs at 12:59:54 and 13:00:14 each log, in order: `managed_challenge` (a0), `managed_challenge_bypassed` x3 (a1 to a3), `managed_challenge` with the Windows UA (a4), `managed_challenge_bypassed` (a5). The earlier broken run at 12:58:51 logged two bypasses (a2, a3 were valid in it). So "200" above is Cloudflare accepting the cookie (`bypassed`), not the rule failing to match.

## Findings

| # | Finding | Evidence |
|---|---|---|
| E1-1 | **On a Free zone the cookie is not bound to the TLS or HTTP/2 fingerprint.** OkHttp (every wire layer mismatched, L1-4) and plain curl pass with a cookie minted by Chrome. | a2, a3; ClientHello length 1575 and 1568 vs 1962 for the solver |
| E1-2 | **It is bound to the User-Agent.** Changing only `X11; Linux x86_64` to `Windows NT 10.0; Win64; x64` re-challenges. This is why Suwayomi's replay works: it copies the UA with the cookie. | a4 vs a1 |
| E1-3 | A failed replay does not revoke the cookie. | a5 after a4 |
| E1-4 | `tlsClientCiphersSha1` is not a stable fingerprint for Chrome-like clients: it changes per connection (a1 `OhMy…`, a5 `4EdD…`), consistent with GREASE values being hashed. OkHttp and curl, which send no GREASE, are stable across runs. | a1 vs a5, both runs |

## Limits

- **Free plan only.** An Enterprise Bot Management zone may check more on replay. This says nothing about that case.
- **IP binding not tested.** This host has no IPv6 and no second egress, so the second-IP arm did not run. Docs say IP is checked at solve time **[documented]**, replay time unknown.
- One cookie, one solve. Cookie lifetime (zone Challenge Passage setting) was not varied.
- `http.request.clearance.uuid` could not be used: the API refused it in a Transform Rule on this plan (`20087 ... use of field http.request.clearance.uuid is not allowed`). Acceptance is shown by `managed_challenge_bypassed` events instead.
- Logpush is not available for this zone: with Logpush enabled on the account, creating an `http_requests` or `firewall_events` job returns `1004 ... missing zone subscription`. GraphQL firewall events replace it, without bot fields.
