# P2 real-world passive observations (one GET per URL, 2-4 s jittered pacing, shuffled order, runner defaults: redirects 5, cookie jar per site, retries only on transient failures, circuit breaker)

Matrix `experiments/test-results/P2/matrices/real-world.json`, run 2026-11-24T16:35:51Z, seed **7530801478306363241**, shuffled order. 19 results: 0 pass, 0 fail, 19 observed (no expectation), 0 error.

| case | category | client | status | verdict | confidence | issued by | indicators | attempts | outcome | details |
|---|---|---|---|---|---|---|---|---|---|---|
| `bms-cdn-image` | static | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **observed** |  |
| `discord-home` | landing | cfprobe | 200 | NORMAL_PAGE | high | origin | js_detections_script | 200 | **observed** |  |
| `cf-api-user` | auth | cfprobe | 403 | ACCESS_DENIED | medium | origin | none | 403 | **observed** |  |
| `asura-api-root` | json | cfprobe | 404 | NORMAL_PAGE | medium | origin | none | 404 | **observed** |  |
| `nowsecure-home` | landing | cfprobe | 200 | NORMAL_PAGE | high | origin | js_detections_script, turnstile_script, turnstile_widget | 200 | **observed** |  |
| `asura-css` | static | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **observed** |  |
| `cf-home` | landing | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **observed** |  |
| `cf-docs-turnstile` | docs | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **observed** |  |
| `discord-docs` | docs | cfprobe | 200 | NORMAL_PAGE | high | origin | js_detections_script | 301 > 200 | **observed** |  |
| `asuracomic-home` | redirect | cfprobe | 200 | NORMAL_PAGE | high | origin | js_detections_script | 301 > 200 | **observed** |  |
| `bms-home` | landing | cfprobe | 200 | NORMAL_PAGE | high | origin | js_detections_script | 200 | **observed** |  |
| `asura-browse` | search | cfprobe | 200 | NORMAL_PAGE | high | origin | js_detections_script | 200 | **observed** |  |
| `asura-cdn-image` | static | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **observed** |  |
| `cf-apex` | redirect | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 301 > 200 | **observed** |  |
| `discord-http` | redirect | cfprobe | 200 | NORMAL_PAGE | high | origin | js_detections_script | 301 > 200 | **observed** |  |
| `discord-json` | json | cfprobe | 401 | ACCESS_DENIED | medium | origin | none | 401 | **observed** |  |
| `cf-api-ips` | json | cfprobe | 200 | NORMAL_PAGE | high | origin | none | 200 | **observed** |  |
| `bms-explore` | search | cfprobe | 200 | NORMAL_PAGE | high | origin | js_detections_script | 200 | **observed** |  |
| `asura-home` | landing | cfprobe | 200 | NORMAL_PAGE | high | origin | js_detections_script | 200 | **observed** |  |
