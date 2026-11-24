# Proxy routing (2026-11-24)

## The rule

| Situation | Behaviour |
|---|---|
| **A proxy is defined** (`--proxy URL`, `CFPROBE_PROXY`, or `proxy` in the config file) | Every connection goes through it. The destination name is sent to the proxy, never resolved locally. Any proxy failure (unreachable, timeout, TLS, authentication, refused tunnel, wrong protocol) is reported as `Error::Proxy` with its stage. **There is no direct path in this mode, so nothing can fall back to one.** |
| **No proxy is defined** | Connections are direct, exactly as before proxies existed, and every run says so: `cfprobe: no proxy defined: running in no-proxy mode (direct connections)`; each connection records `"route": {"kind": "direct"}` |
| **A proxy is defined but invalid** (unknown scheme, unset `env:` variable, ambiguous selection) | A configuration error. It never turns into direct mode |

The brief asked for fail-closed when no proxy is configured; the user decided instead that no proxy means no-proxy mode, announced (2026-11-24).

## Where it is enforced

| Piece | How |
|---|---|
| `engine/src/proxy/mod.rs` | Proxy config, validation, `Route` (`Direct` or `Proxy`), tunnels: HTTP `CONNECT`, HTTPS (TLS to the proxy, then `CONNECT`), SOCKS5 (RFC 1928, user/password RFC 1929) |
| `CFProbe::new` | Decides the route once from the config. Every dial uses it |
| `networking::dial` | The only function that opens connections. Proxy route: `open_tunnel` only. Direct route: DNS and TCP as before |
| `resilience::Session` | Retries, redirect hops and every attempt go through the same engine, so the same route. Proxy auth, TLS and protocol failures are never retried; connect and tunnel failures are retried through the **same** proxy |
| `runner` | Before a campaign through a proxy: a **preflight** tunnel to the first case's origin; failure stops the campaign before any request. `run.json` records the route and preflight. The curl comparison client gets the same proxy through its environment (`ALL_PROXY`, `NO_PROXY=`), `--proxytunnel` (so it tunnels like cfprobe instead of forwarding plain HTTP), `--connect-to` for pins; with no proxy, `--noproxy '*'` so it cannot pick up an ambient proxy cfprobe would not use |
| `cfprobe proxy-check URL [--expect-egress-ip IP]` | Validates the config, connects through the proxy, makes one GET, reports route, timings and the client address the destination saw (`/cdn-cgi/trace` `ip=` or the zone Worker's `cf-connecting-ip`) |
| `scripts/zone/lib.sh` (`rcurl`, `pin`) | Every management call (Cloudflare API, DoH, readiness checks) on the same rule |
| `scripts/zone/authdns.py` | Through a proxy: DoH over HTTPS in a tunnel, and **DNS over TCP to the zone's nameserver inside the tunnel** (UDP cannot go through a proxy) |
| `scripts/phase2/solve.sh` | Passes the proxy to FlareSolverr's `request.get`, so its browser goes through it too |
| `scripts/zone/e1_replay.sh` | E1's clients (OkHttp and curl-impersonate in Docker) are not routed, so the script **refuses to run** when a proxy is defined |
| `engine/examples/reqwest_get.rs` | Same rule (`--proxy`, `CFPROBE_PROXY`, else direct and announced); ambient proxy variables ignored |
| `engine/examples/bench.rs` | Loopback benchmark: refuses any non-loopback URL |

**Audit, enforced by a test:** `only_the_central_dialer_opens_connections` scans `engine/src` for `TcpStream::connect`, `lookup_host`, `UdpSocket`, `Command::new`, `reqwest` and `std::net::TcpStream`, and fails on any occurrence outside the allowed places (the dialer, the proxy module, the runner's curl). Shown to fail on a planted `lookup_host` in a canary file.

Not routed, by nature: the fuzz mock server and benchmark server (loopback listeners), local TrackMe captures (loopback lab), FlareSolverr's own API at `localhost:8191`. The fuzz DNS-failure scenario asks the system resolver for an `.invalid` name.

## DNS behaviour by protocol

| Proxy | Destination name | Local DNS for the destination |
|---|---|---|
| `http://`, `https://` | Sent in `CONNECT host:port`, resolved by the proxy | None |
| `socks5://`, `socks5h://` | Sent as a SOCKS5 domain address (type 3), resolved by the proxy. **`socks5://` is treated as `socks5h://`**, unlike curl's convention, so no destination name leaks to the local resolver | None |
| Any, with a `--resolve` pin | The pinned address is sent to the proxy instead (`address_source: resolve_override`) | None (the user chose the address) |
| Direct (no proxy) | System resolver, every address tried in order | Yes |

The proxy's **own** host name is resolved locally when it is a name: that query is about the proxy, not the destination.

## Proxy TLS vs destination TLS

With an `https://` proxy there are two TLS sessions: one to the proxy (verified against system roots plus the proxy's optional `ca_file`; ALPN `http/1.1`), and, inside the tunnel, the destination's (cfprobe's configured ClientHello, recorded in `tls`). A proxy certificate failure is `Error::Proxy { stage: tls }` and classified CONNECTION_FAILURE (the destination was never reached); TLS_FAILURE means the destination's TLS failed. Neither is ever relaxed.

## Credentials

From the URL (`http://user:pass@host:port`, percent-decoded) or the `username` / `password` fields; `url: "env:NAME"` reads the URL from the environment so it stays out of config files. Held in `Secret`, which prints `<redacted N bytes>` in `Debug` and JSON; URLs are redacted wherever they appear. curl gets them only through its environment, never its command line (which `ps` shows to every user).

## Selection

`proxy.proxies` may list several; `proxy.select` names the one to use (required when more than one). There is **no automatic rotation or failover**, and in particular none on blocks or rate limits: a failing proxy is reported, never replaced silently. Changing proxies to get past a site's restriction would be circumvention.

## Tests (`engine/tests/proxy.rs`, `runner.rs`, `src/proxy` unit)

Every test that expects a failure also checks that the destination saw **no connection**: a direct fallback would show there.

| Test | Shows |
|---|---|
| `no_proxy_means_direct_and_is_recorded_as_such` | No proxy: direct, announced, recorded |
| `http_proxy_carries_every_request_sequential_and_concurrent` | 3 sequential + 20 concurrent requests: destination accepts = proxy tunnels; TCP peer is the proxy; no local DNS |
| `destination_names_are_resolved_by_the_proxy_not_locally` | HTTP and SOCKS5: `lab.invalid` (unresolvable locally) succeeds; the proxy received the name |
| `a_dead_proxy_is_an_error_and_nothing_goes_direct` | Connect failure; the directly reachable destination got 0 connections |
| `a_proxy_refusing_the_tunnel_is_an_error_and_nothing_goes_direct` | 502 from the proxy; 0 connections at the destination |
| `authentication_failures_are_reported_never_retried_and_never_printed` | HTTP and SOCKS5: missing and wrong credentials reported, 1 attempt each, password in no record; correct credentials work |
| `https_proxy_is_verified_and_its_tls_is_kept_apart_from_the_destinations` | Nested TLS works; untrusted proxy certificate is a proxy TLS error, 0 connections at the destination |
| `pinned_addresses_go_to_the_proxy_as_addresses` | Pins sent as addresses |
| `redirect_hops_and_retries_stay_on_the_proxy` | Both hops of a cross-host redirect asked the proxy, by name |
| `proxy_config_errors_never_become_direct` | 5 invalid configs: all errors |
| `only_the_central_dialer_opens_connections` | The source audit above |
| `campaigns_run_through_the_proxy_for_every_client` | Runner: preflight + cfprobe + curl = 3 tunnels; destination saw exactly the 2 requests; curl reached an `.invalid` name only via the proxy |
| `a_dead_proxy_stops_the_campaign_before_any_request` | Preflight fails, 0 requests anywhere |
| `src/proxy` unit (3) | Direct when empty; credentials never in `Debug`/JSON (caught a leak in the derived `Debug`, fixed); URL credential decoding |

## Real verification (gost, Docker, pinned `gogost/gost@sha256:27f4bda42d13f00ef76044cc0fe2fd900e7b7a4e08f3ff67a2826138f9dc877c`)

One container, three authenticated listeners on loopback: HTTP `:18080`, SOCKS5 `:18081`, HTTPS `:18443` (throwaway `localhost` certificate). Password random, kept in the scratchpad.

| Check | Result |
|---|---|
| `proxy-check https://www.cloudflare.com/cdn-cgi/trace`: none, http, socks5, socks5h, https | 200 each; proxied runs `address_source: proxy`, `dns_ms: null`; gost's log shows each listener asked for `www.cloudflare.com:443` **by name** |
| Wrong password / no password / dead proxy / untrusted HTTPS proxy certificate | `auth failed: 407: the proxy refused the credentials` / `auth failed: the proxy requires credentials and none are configured` / `connect failed: ... Connection refused` / `tls failed: ... self signed certificate`; none reached the site |
| Zone `up.sh` through the proxy | Up; the proxy carried `api.cloudflare.com` (11), `cloudflare-dns.com` (13), nameservers on port 53 (6, DNS over TCP), the edge (pinned checks) |
| Zone matrix through the proxy (`experiments/test-results/P2/zone-proxy/`) | **96 results, 0 failed** (same as direct); preflight tunnel to `lab.riddlelab.dev:443` ok; 93 results record `route: proxy`, the other 3 sent nothing (2 breaker-open, 1 unparseable response) |
| `proxy-check https://lab.riddlelab.dev/cdn-cgi/trace` | 200 through the proxy |
| Lifecycle through the proxy (`experiments/test-results/P2/lifecycle-proxy/`) | FlareSolverr solved via the proxy (its Chrome's traffic, background Google calls included, all went through it); cfprobe replay L0 to L4 identical to the direct run |
| `down.sh` through the proxy | Clean (0 rules, 0 domains, 0 scripts, record gone) |
| Proxy password in the working tree | Not found anywhere (raw records included) |

**Egress:** the local proxy shares this host's public address, so the egress the destination saw equals the direct one (checked for all four schemes). That proves routing, not a different egress. `--expect-egress-ip` verifies a proxy on another host (your proxy URL or an SSH SOCKS tunnel) once one is used.

## Limits

- No proxy chaining, no PAC files, no per-destination proxy rules, no NTLM/Kerberos proxy auth (Basic and SOCKS5 user/password only).
- HTTP/2 to the proxy itself is not used (the tunnel is HTTP/1.1 CONNECT); HTTP/2 to the destination inside the tunnel works.
- The fuzz campaign and benchmarks run on loopback without a proxy by design; their DNS-failure scenario queries the local resolver for `.invalid` names.
