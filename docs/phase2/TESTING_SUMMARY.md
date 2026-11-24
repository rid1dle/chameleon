# Testing summary (Phase 2, 2026-11-24)

## How to run everything

| What | Command | Needs | Last result |
|---|---|---|---|
| Unit, integration, adversarial, property, randomized | `cd engine && CARGO_BUILD_JOBS=4 cargo test` | nothing (loopback) | **137 passed, 0 failed** |
| Lint | `cargo clippy --all-targets` | | no warnings |
| Fuzz campaign | `engine/target/debug/cfprobe fuzz --count 500 --concurrency 32 --out <dir>` | nothing | 20 seeds x 500: **10,000 passed** |
| Zone matrix | `scripts/zone/up.sh`, then `scripts/phase2/run_zone.sh <dir>`, then `scripts/zone/down.sh` | `.env` token (with DNS:Edit) | **105 results, 0 failed** (37 cases) |
| Lifecycle (challenge, clearance, replay) | `scripts/phase2/lifecycle.sh <flaresolverr-solve.json> <dir>` | zone up, FlareSolverr image | 5 arms as expected |
| Real-world observations | `cfprobe run experiments/test-results/P2/matrices/real-world.json --out <dir>` | network | 19 observed, 0 errors |
| Client comparison | TrackMe (lab/README section 5), then captures in `experiments/test-results/P2/compare/` and `cfprobe diff` | Docker images | `FINGERPRINT_ACCURACY.md` |
| Performance | `cargo build --release --example bench`; `bench serve`; `bench load ...` | nothing | `PERFORMANCE.md` |
| Proxy routing check | `CFPROBE_PROXY=<url> cfprobe proxy-check <url>`; zone matrix with `CFPROBE_PROXY` set | a proxy (lab: gost in Docker, `lab/README.md`) | all schemes ok; zone through proxy **96 results, 0 failed** (`PROXY_ROUTING.md`) |

## Per-test record

| Field (brief Part H) | Matrix runs (`cfprobe run`) | Fuzz runs (`cfprobe fuzz`) | `cargo test` |
|---|---|---|---|
| Identifier | `case_id` + `client` | `index` | test name |
| Description | `description`, `category` | the `scenario` itself | doc comment, defect id |
| Target or fixture | `request.url` (redacted) | scenario transport and path | fixture file or local server |
| Configuration | `request.client_config`, `policy` | scenario, client timeout | in the test |
| Seed | `seed` | `seed` | fixed in the test |
| Expected | `expect` | `expected` | assertions |
| Actual | `status`, `analysis`, `attempts`, `fetch_outcome` | `verdict`, `outcome`, `attempts` | |
| Pass/fail | `outcome` (pass, fail, observed, error) | `pass`, `checks` | cargo result |
| Error details | `details` | failed `checks` | panic message |
| Evidence | `relevant_headers`, `tls`, `response_meta`, `analysis.evidence`; raw record | `checks` details | |
| Timestamp | `timestamp` (UTC) | `started` | run log |
| Reproduction | `reproduce` (`cfprobe run ... --seed S --only <case>`) | `reproduce` (`cfprobe fuzz --seed S --only N`) | `cargo test <name>` |

Raw records (`raw/`, bodies included with `--save-bodies`) stay local; processed `results.json` / `results.md` are committed with the client's location removed (`cf-ray` data-centre suffix, remote address). Before committing, `python3 -I scripts/phase2/scrub.py --check` must pass: it fails on any IPv4 address, token-like string or data-centre suffix in a committable P2 file (`--fix` rewrites them).

## Counts

| Kind | Count |
|---|---|
| Rust tests | 137 (41 unit, 96 integration) |
| Property-test cases per run | 10 properties x 2000 cases |
| Fuzz scenarios run and passed | 10,000 (sweep) + 1,600 (fixed seeds) + 351 (in `cargo test`) |
| Zone matrix results | 96 (34 cases, up to 3 clients) |
| Public URLs observed | 19 on 6 sites, 2 runs |
| Defects found | 28 numbered (D1 to D28) plus P1: all fixed (D10 for HTTP/1.1; HTTP/2 header order unavailable by design) |
| Harness defects found and fixed | 8 (`REGRESSION_RESULTS.md`) |

## Confirmed vs inferred vs open

| Kind | Examples |
|---|---|
| **Confirmed** (probe or capture in hand) | Every D-numbered defect and its fix; all zone verdicts; Cloudflare's Retry-After countdown; Cloudflare hiding origin body truncation; cfprobe's HTTP/2 fingerprint equal to reqwest's; no memory growth over 1M requests |
| **Inferred** (stated as such) | The chance 522s came from Custom Domain propagation |
| **Open** | 520/521/524/525/526 (need an origin of our own), Google Chrome and Firefox comparisons, IPv6 on the network, clearance-to-IP binding |
