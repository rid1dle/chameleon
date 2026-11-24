# E4 results: what each Cloudflare action returns to a client (2026-11-24)

Zone `riddlelab.dev`, **Free plan**. Echo Worker `cflab-echo` on `lab.riddlelab.dev`, one rule per action (`scripts/zone/lib.sh`, created by `scripts/zone/up.sh`). Every response was fetched by `cfprobe inspect` (default headers: `user-agent: cfprobe/0.1.0`, `accept: */*`) and saved by `scripts/zone/e4_capture.sh`, scrubbed of challenge tokens, IP addresses and the cf-ray data-centre suffix. These files are the fixtures for the engine's classifier (`engine/src/cloudflare`, `engine/tests/cloudflare.rs`).

## Results

| Capture | Rule | Status | Content type | Body | What tells it apart |
|---|---|---|---|---|---|
| `reached` | none (`/echo`) | 200 | `application/json` | 2775 bytes, the Worker's echo | no marker below |
| `managed` | Managed Challenge (`/c/`) | 403 | `text/html` | 5372 bytes, "Just a moment..." | `cf-mitigated: challenge`, body `cType: 'managed'` |
| `js-challenge` | JS Challenge (`/j/`) | 403 | `text/html` | 5380 bytes, "Just a moment..." | `cf-mitigated: challenge`, body `cType: 'non-interactive'` |
| `interactive` | Interactive Challenge (`/i/`) | 403 | `text/html` | 5397 bytes, "Just a moment..." | `cf-mitigated: challenge`, body `cType: 'interactive'` |
| `block` | Block (`/b/`) | 403 | `text/html` | 4549 bytes, "Sorry, you have been blocked" | no `cf-mitigated`; body `data-translate="block_headline"`; **no error number** |
| `rate-limited` | Rate limit (`/r/echo`, 2 per 10 s) | 429 | `text/plain` | `error code: 1015` | the body; `retry-after: 10` |
| `error-1003` | none: plain HTTP to the edge address | 403 | `text/plain` | `error code: 1003` | the body |

## Findings

| # | Finding | Evidence |
|---|---|---|
| E4-1 | **Status alone cannot classify a Cloudflare response.** Five of the seven captures are 403: three challenge types, a block and error 1003. | Table |
| E4-2 | **The three challenge actions share one page and one header; only `_cf_chl_opt.cType` differs.** Same title, same `cf-mitigated: challenge`, same `cvId: '3'` and `cTplV:5`, bodies within 25 bytes of each other. | `managed.json`, `js-challenge.json`, `interactive.json` |
| E4-3 | **A WAF Block carries no `cf-mitigated` header and no error number.** It is recognised only by its HTML block page. A client that looks for `cf-mitigated` alone treats a block as an origin 403. | `block.json` |
| E4-4 | **Error 1015 and 1003 came back as 17-byte plain text, not HTML pages**, also when the request sent a Chrome 152 user agent and `accept: text/html,...` (checked live, not saved). | `rate-limited.json`, `error-1003.json` |
| E4-5 | **Browser headers did not change the classification.** With a Chrome 152 UA and an HTML `accept`, the four rule paths gave the same status and the same `cType` or block page. | Live run, 2026-11-24, not saved |
| E4-6 | The rate limit applied exactly as configured (2 per 10 s): requests 1 and 2 got 200, request 3 got 429, on one reused connection. | `cfprobe inspect --repeat 3`, live, twice |

## Limits

- One capture per action, one client. The page template (`cTplV:5`) can change without notice; the classifier then answers `unclassified` with what it saw, rather than guessing.
- No 52x origin errors: the token cannot create a DNS record pointing at a dead origin, and the Worker cannot produce one.
- Free plan: no Bot Management, so no bot-score-driven actions (Super Bot Fight Mode on paid plans) were captured.
