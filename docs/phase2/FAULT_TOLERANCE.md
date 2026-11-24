# Fault tolerance and block resilience (Phase 2, 2026-11-24)

"Block resilience" here means staying stable and diagnostically useful when a request is blocked or fails. It never means getting past a block: a denial or a challenge is classified, recorded and not retried.

## Where it lives

`engine/src/resilience/mod.rs`, a `Session` around the engine. `cfprobe inspect` is untouched: one request, one exchange, no retries. The matrix runner (`cfprobe run`) uses a session with `Policy::runner_default()`: up to 5 redirects, a cookie jar, 3 attempts, and a circuit breaker (3 failed requests open it for 30 s). Matrices and cases can override any field.

| Rule | How it is enforced | Evidence |
|---|---|---|
| Permanent answers are never retried | `decide`: only CONNECTION_FAILURE, a TLS **timeout**, ORIGIN_UNAVAILABLE and RATE_LIMITED are transient | `permanent_answers_are_never_retried`; `denials_and_challenges_are_tried_once` (403 and a challenge: 1 request each) |
| No infinite loops | Attempts per hop 1..=10 (validated); redirects at most 20; a redirect to a visited URL ends the fetch | `transient_..._within_bounds`, `redirect_loops_and_long_chains_stop` (loop stopped before re-requesting), `policy_bounds_are_checked` |
| Non-idempotent requests are not resent | `decide` checks the method | `d1_non_idempotent_request_is_not_retried` |
| TLS verification is never relaxed | No code path changes `verify`; a certificate failure is final | `refused_connection_and_bad_certificate_get_failure_verdicts` (1 attempt, TLS_FAILURE) |
| Server instructions are respected | Retry-After (seconds or HTTP date) honoured, never sooner than the backoff, capped at `max_retry_after_ms` (60 s); above the cap the fetch ends | `retry_after_is_waited_and_a_long_one_ends_the_fetch`, `retry_after_is_honoured_and_capped`; zone `origin-503` (Retry-After 120: not retried), `rate-limit-backoff` |
| Credentials stay with their origin | A cross-origin redirect drops `authorization` and a caller's `cookie` | `credentials_do_not_follow_a_cross_origin_redirect` |
| Nothing disappears from the report | Every attempt of every hop is recorded with its verdict, wait, duration and decision | Runner `attempts` field; zone results |

## The brief's scenarios

| Scenario | Behaviour | Evidence |
|---|---|---|
| HTTP 403 | ACCESS_DENIED; issued by Cloudflare's edge only with a block page or a 10xx number, else by the origin; not retried | Zone `waf-block` (edge), `origin-forbidden` (origin), `direct-ip` (1003); local nginx 403 |
| HTTP 429 | RATE_LIMITED (1015 from the edge, or the origin's own); retried after Retry-After or backoff, within the cap | Zone `rate-limit`, `rate-limit-backoff`, `origin-429` |
| HTTP 500 | Origin 500: NORMAL_PAGE (the origin's answer), not retried. Cloudflare 1101 (Worker threw): ORIGIN_UNAVAILABLE, retried | Zone `worker-throws`: 3 attempts, waits 357 and 985 ms |
| HTTP 502 | ORIGIN_UNAVAILABLE (low confidence: the origin says so); retried with backoff | Zone `origin-502`: 3 attempts, waits 289 and 517 ms |
| HTTP 503 | ORIGIN_UNAVAILABLE; Retry-After honoured or, above the cap, the fetch ends | Zone `origin-503` (Retry-After 120, 1 attempt) |
| HTTP 522 | ORIGIN_UNAVAILABLE, issued by the edge, number read from plain text or the HTML page | P2 fixtures `zone-522-html`, `zone-522-plain`, nowsecure.nl |
| TLS failure | TLS_FAILURE with BoringSSL's reason and the verify result; certificate errors final, timeouts retried | `untrusted_certificate_is_rejected`, `refused_..._bad_certificate_...`; fuzz `untrusted_certificate` (all pass) |
| DNS failure | CONNECTION_FAILURE, stage `dns` | fuzz `dns_failure` (`.invalid` names): all pass |
| Connection timeout | CONNECTION_FAILURE at the stage it happened (`connect`, `tls`, `response`, `body`); bounded by the per-stage budgets | `tls_stage_times_out`; fuzz `timeout` and `refused` |
| Redirect loop | `fetch_outcome: redirect_loop`, detected at the first repeat | Zone `redirect-loop` (cfprobe: 1 request; curl with `--max-redirs 5` ended on a 302, hop count not recorded) |
| Malformed HTML | Parsed as text; markers are substring and attribute checks, nothing is built from it | properties `classifier_never_panics` (random bytes, 2000 cases) |
| Malformed JSON | Not parsed by the engine except receiver records, where it is a structured `Error::Receiver("body is not JSON: ...")` | fuzz `json` with `valid: false`: verdict by status, body intact |
| Unexpected cookies | Malformed Set-Cookie values kept in the record (name and length), ignored by the jar | fuzz cookie variants (`;;;`, `=novalue`, foreign domain, expired); `set_cookies_all_recorded` check |
| Challenge response | CONFIRMED_CHALLENGE_RESPONSE with type; never retried, never followed into the challenge | Zone `managed`, `js-challenge`, `interactive`, `managed-head` |
| Unparseable response | UNKNOWN, "response parsing", not retried (D22) | `unparseable_responses_are_unknown_and_not_retried`; zone `many-headers` over HTTP/1.1 |

## Recovery features

| Feature | Detail | Evidence |
|---|---|---|
| Retry policy | `max_attempts`, idempotent methods only, transient verdicts only | `resilience.rs` unit and integration tests |
| Exponential backoff | `base * 2^(attempt-1)`, capped at `max_delay_ms` | `transient_failures_back_off_exponentially_within_bounds` |
| Bounded jitter | Backoff reduced by a random share up to `jitter` (0..=1), so it never exceeds the cap; drawn from the run's seed | `same_seed_same_jitter`; zone waits identical across clients (289, 517 ms) |
| Retry-After | Delta-seconds and IMF-fixdate; floor at backoff (D23); cap | as above |
| Circuit breaker | Per host; counts failed **requests** (D21); opens for `open_ms`; half-open lets one through; one more failure reopens | `circuit_opens_after_failures_and_stops_sending`, `one_retried_request_counts_once_toward_the_circuit`; zone `breaker-1..3`, `breaker-open` (refused locally, not sent) |
| Connection recovery | A dead pooled connection is replaced (D1); a failed connection is dropped from the pool | `d1_...`: 100/100 succeed, 49 retried |
| Timeout management | Per stage (DNS, connect, TLS) plus one budget for response and body | `local_tls.rs`, fuzz `timeout_bounded` check |
| Graceful cancellation | `fetch_until(target, cancel)` returns at once with what was recorded; the engine stays usable | `cancellation_returns_promptly_and_the_engine_stays_usable` (under 600 ms against a 1.5 s response) |
| Error classification | TLS_FAILURE, CONNECTION_FAILURE (with stage), UNKNOWN (parse) | `errors_get_failure_verdicts_by_stage` |
| Session-state consistency | One jar and one circuit table per session, behind mutexes; each fetch's policy can differ while state is shared | `cookie_jar_...`; zone `cookie-continuity` |
| Structured diagnostics | Each attempt: status, verdict, wait, elapsed, decision and reason | Runner `attempts`; fuzz `checks` |

## What Cloudflare's rate limiter did (zone, Free plan, 2 requests per 10 s)

| Client | Attempts on the third request of a burst |
|---|---|
| cfprobe | 429 (Retry-After 9) -> wait 9000 ms -> 429 (Retry-After **0**) -> wait 517 ms (floor) -> 200 |
| cfprobe | 429 (Retry-After 10) -> wait 10000 ms -> 429 (Retry-After 10, window restarted) -> wait 10000 ms -> 200 |
| cfprobe HTTP/1.1 | 429 (Retry-After 10) -> wait 10000 -> 429 (Retry-After 0) -> wait 714 (floor) -> 200 |

Two measured behaviours: Retry-After counts down in whole seconds and reaches 0 while the limit still applies, and a request made at the end of the wait can restart the window. Before D23, the `0` led to three requests within 12 ms.

## Limits

- curl has its own retry logic (`--retry`), so its attempts are not visible to the runner; only its final answer is compared.
- The breaker is per host, not per path: one failing path protects the whole host. That is deliberate for third parties and is why the zone matrix turns it off for its deliberately failing cases.
- HTTP/2 1xx responses and HTTP/2 response header wire order are not observable (see `KNOWN_ISSUES.md`).
