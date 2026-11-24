# E2 results: does FlareSolverr clear a Managed Challenge? (2026-11-24)

Same zone and rule as E1 (Free plan, Managed Challenge on `lab.riddlelab.dev/c/*`). `flaresolverr/flaresolverr:v3.5.2`, default env, one `request.get` to `https://lab.riddlelab.dev/c/echo`, `maxTimeout` 90000. Control: the same URL without a cookie returns `403` with `cf-mitigated: challenge` (E1 a0). Files: `flaresolverr-solve.json` (API response, cookie values replaced by their length, location removed), `flaresolverr.log`.

## Result

| Measure | Value |
|---|---|
| Outcome | `status: ok`, `Challenge solved!`, final status 200 |
| Time | 11.3 s (log: challenge detected 12:57:35, solved 12:57:45) |
| Cookie | `cf_clearance`, domain `.riddlelab.dev`, 432 chars |
| Interaction | **Interactive.** Cloudflare logged `managed_challenge_interactive_solved` at 12:57:43 (ray `a5f894bf0f602e85`), then `managed_challenge_bypassed` on the same ray. The FlareSolverr log is silent because its Tab+Space click logs only at DEBUG |
| What the Worker saw after the solve | `accept-language: C.UTF-8,C.UTF;q=0.9` (L1-2 tell present, did not block) |

## Findings

| # | Finding | Evidence |
|---|---|---|
| E2-1 | **FlareSolverr 3.5.2 clears a Free-plan Managed Challenge at default settings, but only through the interactive path.** Cloudflare did not pass it silently: the non-interactive check failed, FlareSolverr's fallback sent Tab+Space to the checkbox, and that solved it. The L1/L2 tells (`C.UTF-8` locale, window larger than screen, no focus, SwiftShader) did not stop the interactive solve. | `../E1/firewall-events.tsv` row 4; click on timeout `vendor/FlareSolverr_FlareSolverr/src/flaresolverr_service.py:454`, logged at DEBUG `:263`, `:271` |
| E2-1a | **Correction (same day):** this file first said "no interaction", inferred from an INFO log with no click line. The log level hid the click. Cloudflare's event record is the authority on the solve path. | as above |
| E2-2 | **`request.cf.requestHeaderNames` is the visitor's wire request, not the request the Worker receives.** After the solve the Worker got a GET, but the names list `content-length`, `content-type`, `origin`, `referer`: Chrome POSTed the challenge form, and Cloudflare replayed the original request as GET. For OkHttp (E1 a2) the list matches L1's pseudo-header order `m,p,a,s` exactly. | `workerSawAfterSolve.headers` vs `.cf.requestHeaderNames` |

## Limits

- One solve. The bot score FlareSolverr got is not visible on Free.
- The Free challenge may be easier than one on a zone with Bot Management, where the score feeds the decision.
