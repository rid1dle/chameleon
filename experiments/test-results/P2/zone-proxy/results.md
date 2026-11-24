# P2 controlled zone (lab.riddlelab.dev, Free plan), runner defaults: redirects 5, cookie jar, 3 attempts with backoff and Retry-After; circuit breaker only in the breaker-* cases (the matrix fails on purpose)

Matrix `experiments/test-results/P2/zone-proxy/matrix.json`, run 2026-11-24T17:07:30Z, seed **20261124**. 96 results: 90 pass, 0 fail, 5 observed (no expectation), 1 error.

| case | category | client | status | verdict | confidence | issued by | indicators | attempts | outcome | details |
|---|---|---|---|---|---|---|---|---|---|---|
| `echo` | normal | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `echo-html` | normal | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `echo-compressed` | normal | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `managed` | challenge | cfprobe | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | 403 | **pass** |  |
| `managed-browser-headers` | challenge | cfprobe | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | 403 | **pass** |  |
| `managed-head` | challenge | cfprobe | 403 | CONFIRMED_CHALLENGE_RESPONSE | medium | cloudflare_edge | none | 403 | **pass** |  |
| `js-challenge` | challenge | cfprobe | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | 403 | **pass** |  |
| `interactive` | challenge | cfprobe | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | 403 | **pass** |  |
| `waf-block` | waf | cfprobe | 403 | ACCESS_DENIED | high | cloudflare_edge | cloudflare_error_page, block_page | 403 | **pass** |  |
| `rate-limit` | rate-limit | cfprobe | 429 | RATE_LIMITED | high | cloudflare_edge | none | 200 > 200 > 429 | **pass** |  |
| `rate-limit-backoff` | rate-limit | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 429 > 429 > 200 > 429 > 200 > 200 | **pass** |  |
| `direct-ip` | waf | cfprobe | 403 | ACCESS_DENIED | high | cloudflare_edge | none | 403 | **pass** |  |
| `turnstile-embed` | turnstile | cfprobe | 200 | NORMAL_PAGE | high | origin | turnstile_script, turnstile_widget | 200 | **pass** |  |
| `turnstile-verify-no-token` | turnstile | cfprobe | 403 | ACCESS_DENIED | medium | origin | none | 403 | **pass** |  |
| `auth-required` | auth | cfprobe | 401 | ACCESS_DENIED | medium | origin | none | 401 | **pass** |  |
| `origin-forbidden` | auth | cfprobe | 403 | ACCESS_DENIED | medium | origin | none | 403 | **pass** |  |
| `json` | json | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `static` | static | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `redirect` | redirect | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 302 > 200 | **pass** |  |
| `redirect-no-follow` | redirect | cfprobe | 302 | REDIRECT | high | origin | none | 302 | **pass** |  |
| `redirect-loop` | redirect | cfprobe | 302 | REDIRECT | high | origin | none | 302 | **pass** |  |
| `origin-503` | origin-failure | cfprobe | 503 | ORIGIN_UNAVAILABLE | low | origin | none | 503 | **pass** |  |
| `origin-429` | rate-limit | cfprobe | 429 | RATE_LIMITED | medium | origin | none | 429 | **pass** |  |
| `origin-502` | origin-failure | cfprobe | 502 | ORIGIN_UNAVAILABLE | low | origin | none | 502 > 502 > 502 | **pass** |  |
| `worker-throws` | origin-failure | cfprobe | 500 | ORIGIN_UNAVAILABLE | high | cloudflare_edge | none | 500 > 500 > 500 | **pass** |  |
| `cookies` | cookies | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `cookie-continuity` | cookies | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `many-headers` | http | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **observed** |  |
| `slow-2s` | http | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `cut-body` | http | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **observed** |  |
| `breaker-1` | resilience | cfprobe | 503 | ORIGIN_UNAVAILABLE | low | origin | none | 503 | **pass** |  |
| `breaker-2` | resilience | cfprobe | 503 | ORIGIN_UNAVAILABLE | low | origin | none | 503 | **pass** |  |
| `breaker-3` | resilience | cfprobe | 503 | ORIGIN_UNAVAILABLE | low | origin | none | 503 | **pass** |  |
| `breaker-open` | resilience | cfprobe | - | - | - | - | none | - | **pass** |  |
| `echo` | normal | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `echo-html` | normal | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `echo-compressed` | normal | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `managed` | challenge | cfprobe-h1-titlecase | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | 403 | **pass** |  |
| `managed-browser-headers` | challenge | cfprobe-h1-titlecase | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | 403 | **pass** |  |
| `managed-head` | challenge | cfprobe-h1-titlecase | 403 | CONFIRMED_CHALLENGE_RESPONSE | medium | cloudflare_edge | none | 403 | **pass** |  |
| `js-challenge` | challenge | cfprobe-h1-titlecase | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | 403 | **pass** |  |
| `interactive` | challenge | cfprobe-h1-titlecase | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | 403 | **pass** |  |
| `waf-block` | waf | cfprobe-h1-titlecase | 403 | ACCESS_DENIED | high | cloudflare_edge | cloudflare_error_page, block_page | 403 | **pass** |  |
| `rate-limit` | rate-limit | cfprobe-h1-titlecase | 429 | RATE_LIMITED | high | cloudflare_edge | none | 200 > 200 > 429 | **pass** |  |
| `rate-limit-backoff` | rate-limit | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 429 > 200 > 429 > 200 > 429 > 200 | **pass** |  |
| `direct-ip` | waf | cfprobe-h1-titlecase | 403 | ACCESS_DENIED | high | cloudflare_edge | none | 403 | **pass** |  |
| `turnstile-embed` | turnstile | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | turnstile_script, turnstile_widget | 200 | **pass** |  |
| `turnstile-verify-no-token` | turnstile | cfprobe-h1-titlecase | 403 | ACCESS_DENIED | medium | origin | none | 403 | **pass** |  |
| `auth-required` | auth | cfprobe-h1-titlecase | 401 | ACCESS_DENIED | medium | origin | none | 401 | **pass** |  |
| `origin-forbidden` | auth | cfprobe-h1-titlecase | 403 | ACCESS_DENIED | medium | origin | none | 403 | **pass** |  |
| `json` | json | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `static` | static | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `redirect` | redirect | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 302 > 200 | **pass** |  |
| `redirect-no-follow` | redirect | cfprobe-h1-titlecase | 302 | REDIRECT | high | origin | none | 302 | **pass** |  |
| `redirect-loop` | redirect | cfprobe-h1-titlecase | 302 | REDIRECT | high | origin | none | 302 | **pass** |  |
| `origin-503` | origin-failure | cfprobe-h1-titlecase | 503 | ORIGIN_UNAVAILABLE | low | origin | none | 503 | **pass** |  |
| `origin-429` | rate-limit | cfprobe-h1-titlecase | 429 | RATE_LIMITED | medium | origin | none | 429 | **pass** |  |
| `origin-502` | origin-failure | cfprobe-h1-titlecase | 502 | ORIGIN_UNAVAILABLE | low | origin | none | 502 > 502 > 502 | **pass** |  |
| `worker-throws` | origin-failure | cfprobe-h1-titlecase | 500 | ORIGIN_UNAVAILABLE | high | cloudflare_edge | none | 500 > 500 > 500 | **pass** |  |
| `cookies` | cookies | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `cookie-continuity` | cookies | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `many-headers` | http | cfprobe-h1-titlecase | - | UNKNOWN | low | unknown | none | err | **error** | http protocol error: message head is too large |
| `slow-2s` | http | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 200 | **pass** |  |
| `cut-body` | http | cfprobe-h1-titlecase | 200 | NORMAL_PAGE | high | origin | none | 200 | **observed** |  |
| `breaker-1` | resilience | cfprobe-h1-titlecase | 503 | ORIGIN_UNAVAILABLE | low | origin | none | 503 | **pass** |  |
| `breaker-2` | resilience | cfprobe-h1-titlecase | 503 | ORIGIN_UNAVAILABLE | low | origin | none | 503 | **pass** |  |
| `breaker-3` | resilience | cfprobe-h1-titlecase | 503 | ORIGIN_UNAVAILABLE | low | origin | none | 503 | **pass** |  |
| `breaker-open` | resilience | cfprobe-h1-titlecase | - | - | - | - | none | - | **pass** |  |
| `echo` | normal | curl | 200 | NORMAL_PAGE | high | origin | none | - | **pass** |  |
| `echo-html` | normal | curl | 200 | NORMAL_PAGE | high | origin | none | - | **pass** |  |
| `echo-compressed` | normal | curl | 200 | NORMAL_PAGE | high | origin | none | - | **pass** |  |
| `managed` | challenge | curl | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | - | **pass** |  |
| `managed-browser-headers` | challenge | curl | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | - | **pass** |  |
| `managed-head` | challenge | curl | 403 | CONFIRMED_CHALLENGE_RESPONSE | medium | cloudflare_edge | none | - | **pass** |  |
| `js-challenge` | challenge | curl | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | - | **pass** |  |
| `interactive` | challenge | curl | 403 | CONFIRMED_CHALLENGE_RESPONSE | high | cloudflare_edge | challenge_orchestrate_script, challenge_options, challenge_title | - | **pass** |  |
| `waf-block` | waf | curl | 403 | ACCESS_DENIED | high | cloudflare_edge | cloudflare_error_page, block_page | - | **pass** |  |
| `direct-ip` | waf | curl | 403 | ACCESS_DENIED | high | cloudflare_edge | none | - | **pass** |  |
| `turnstile-embed` | turnstile | curl | 200 | NORMAL_PAGE | high | origin | turnstile_script, turnstile_widget | - | **pass** |  |
| `turnstile-verify-no-token` | turnstile | curl | 403 | ACCESS_DENIED | medium | origin | none | - | **pass** |  |
| `auth-required` | auth | curl | 401 | ACCESS_DENIED | medium | origin | none | - | **pass** |  |
| `origin-forbidden` | auth | curl | 403 | ACCESS_DENIED | medium | origin | none | - | **pass** |  |
| `json` | json | curl | 200 | NORMAL_PAGE | high | origin | none | - | **pass** |  |
| `static` | static | curl | 200 | NORMAL_PAGE | high | origin | none | - | **pass** |  |
| `redirect` | redirect | curl | 200 | NORMAL_PAGE | high | origin | none | - | **pass** | attempts and fetch outcome are not visible for this client: not checked |
| `redirect-no-follow` | redirect | curl | 302 | REDIRECT | high | origin | none | - | **pass** |  |
| `redirect-loop` | redirect | curl | 302 | REDIRECT | high | origin | none | - | **pass** | attempts and fetch outcome are not visible for this client: not checked |
| `origin-503` | origin-failure | curl | 503 | ORIGIN_UNAVAILABLE | low | origin | none | - | **pass** | attempts and fetch outcome are not visible for this client: not checked |
| `origin-429` | rate-limit | curl | 429 | RATE_LIMITED | medium | origin | none | - | **pass** | attempts and fetch outcome are not visible for this client: not checked |
| `origin-502` | origin-failure | curl | 502 | ORIGIN_UNAVAILABLE | low | origin | none | - | **pass** | attempts and fetch outcome are not visible for this client: not checked |
| `worker-throws` | origin-failure | curl | 500 | ORIGIN_UNAVAILABLE | high | cloudflare_edge | cloudflare_error_page | - | **pass** | attempts and fetch outcome are not visible for this client: not checked |
| `cookies` | cookies | curl | 200 | NORMAL_PAGE | high | origin | none | - | **pass** |  |
| `cookie-continuity` | cookies | curl | 200 | NORMAL_PAGE | high | origin | none | - | **pass** |  |
| `many-headers` | http | curl | 200 | NORMAL_PAGE | high | origin | none | - | **observed** |  |
| `slow-2s` | http | curl | 200 | NORMAL_PAGE | high | origin | none | - | **pass** |  |
| `cut-body` | http | curl | 200 | NORMAL_PAGE | high | origin | none | - | **observed** |  |
