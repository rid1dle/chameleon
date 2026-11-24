# Randomization subsystem (Phase 2, 2026-11-24)

`engine/src/random/`: seeded variation of **test conditions** to find defects deterministic tests miss. It never varies the client's identity or fingerprint, and nothing random is pointed at third-party sites: random scenarios run against a loopback mock server, and real-world runs only get bounded pauses and a shuffled order.

## Modules

| Module | Does |
|---|---|
| `random/mod.rs` | Seeds (`seed_or_new`), ChaCha8 streams (`stream(seed, n)`), `Schedule` (order and pauses), the jitter stream for retries |
| `random/scenario.rs` | `generate(rng, index) -> Scenario`; `Scenario::expected()`; the scenario's body |
| `random/mock.rs` | Loopback server: plain HTTP/1.1, TLS HTTP/1.1, TLS HTTP/2; serves `/s/<index>/<hop>` with the scenario's faults |
| `random/fuzz.rs` | `cfprobe fuzz`: runs scenarios through a `Session`, checks each, writes JSON and Markdown |

## Seeds and reproducibility

| Requirement | How |
|---|---|
| Optional seed | `--seed N` on `fuzz` and `run`; matrices may carry `"seed"` |
| Generated when absent | `rand::rng().random::<u64>()`, recorded as `seed_given: false` |
| Recorded | In every fuzz report, every run result row (`seed`), and every reproduce command |
| Rerun one failure | `cfprobe fuzz --seed S --only N` (scenario `N` comes from ChaCha8 stream `N`, so it is the same alone or among others); `cfprobe run <matrix> --seed S --only <case>` |
| Same seed, same sequence | Tests `same_seed_same_outcomes...`, `one_scenario_reruns_alone_identically`, `same_seed_same_schedule...` |
| Different seeds differ | `different_seeds_give_different_sequences`, schedule test |
| RNG choice | `rand_chacha::ChaCha8Rng`: output fixed by the algorithm, so sequences survive `rand` upgrades (`StdRng` does not promise that). Streams separate scenarios (`0..n`), the schedule (`u64::MAX`) and retry jitter (`u64::MAX - 1`) |

## Timing variation

| Feature | Where |
|---|---|
| Minimum and maximum delay, bounded jitter | Matrix `delay_ms` and `max_delay_ms`: each pause uniform in the range (`Schedule`) |
| Randomized order | Matrix `shuffle: true` (same order for every client of a run) |
| Variable response latency | Fault `latency` (10 to 300 ms), `slow_drip` (chunks of 64 to 2048 bytes, 5 to 30 ms apart, at most 600 ms) |
| Timeout testing | Fault `timeout`: head held back 2500 ms against a 1500 ms client budget |
| Cancellation | `Session::fetch_until`; resilience test |
| Server instructions | Retry-After honoured with a floor and a cap (`FAULT_TOLERANCE.md`) |

## Randomized scenarios

Each scenario combines (weights in `scenario.rs`):

| Dimension | Values |
|---|---|
| Transport | plain HTTP/1.1, TLS HTTP/1.1, TLS HTTP/2 |
| Status | 200, 201, 204, 206, 301, 302, 307, 308, 401, 403, 404, 418, 429, 451, 500, 502, 503, 504, 520, 521, 522, 524 |
| Body | HTML (title; JavaScript Detections script; Turnstile widget; **decoys**: "Turnstile", "Just a moment", the challenge-platform path and `cf_clearance` in page text), valid and broken JSON, text, empty, challenge page with known and unknown `cType`, WAF block page, `error code: N` (1015, 1020, 1003, 1010, 52x, 1101, 1234) |
| Size | 0 to 4 KB usually, 100 to 600 KB in 10% |
| Encoding | none, gzip, deflate, br, zstd, gzip that is not gzip, an unknown encoding |
| Framing | Content-Length or chunked (HTTP/1.1) |
| Cookies | 0 to 3: normal, quoted, expired, foreign domain, `;;;`, `=novalue`, `nameonly` |
| Headers | 0 to 4 extra, repeats and empty values included |
| Retry-After | 1, 0, 3600, an HTTP date in the past, `soon` |
| Redirects | 0 to 3 hops, 30% of chains loop back |
| Network fault | none, latency, slow drip, close before the head, close mid-body, timeout, DNS failure (`.invalid`), refused port, untrusted certificate |

Generation rules keep every scenario valid: Cloudflare pages always come with Cloudflare headers, a chain never ends on a redirect, framing faults use HTTP/1.1, a cut body is never on a 204.

## Checks per scenario

| Check | Passes when |
|---|---|
| `verdict` | The classifier's verdict equals the one the scenario was generated to be |
| `redirect_loop_detected` | A looping chain ends as `redirect_loop` |
| `body_intact` | A decodable body arrives byte for byte after decoding |
| `set_cookies_all_recorded` | Every `Set-Cookie` sent, malformed ones included, is in the record |
| `repeated_headers_all_recorded` | Every repeat of every extra header is in the record |
| `latency_visible` | Time to first byte is at least the injected latency |
| `no_cookie_value_in_record` | No cookie value text in the serialized record |
| `timeout_bounded` | Two timed-out attempts take less than 2 x (budget + 200 ms) + 200 ms |
| `no_panic` | The scenario's task did not panic |

## Isolation

Each scenario runs in its own `Session` (own jar, no breaker) on one shared engine, so concurrent scenarios share the connection pool, which is itself under test, but no session state. The mock server builds and compresses bodies on blocking threads, off the async workers the client uses (see `RANDOMIZED_TESTING.md` for why).

## What it does not do

- It does not randomize the client: no rotating user agents, TLS settings or header orders. Fingerprint variation is compared deliberately, one setting at a time (`FINGERPRINT_ACCURACY.md`).
- It does not send random traffic to any real site.
