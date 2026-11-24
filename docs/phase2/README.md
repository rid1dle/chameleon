# Phase 2: reports and where everything lives

Start with `PHASE2_SUMMARY.md`.

## Reports

| Report | Answers |
|---|---|
| `PHASE2_SUMMARY.md` | What works, what fails and why, what is missing, what to improve |
| `TESTING_SUMMARY.md` | How to run every suite, counts, per-test record fields |
| `TEST_MATRIX.md` | What was tested in which environment, with status |
| `DETECTION_ACCURACY.md` | The false positives reproduced, classifier rules, results on every real response |
| `CLOUDFLARE_DETECTION.md` | The markers Cloudflare's responses carry, as observed |
| `FINGERPRINT_ACCURACY.md` | Fingerprint measurement accuracy; cfprobe vs Chromium, curl, reqwest |
| `TLS_COMPATIBILITY.md` | TLS behaviour and limits |
| `HTTP_COMPATIBILITY.md` | HTTP/1.1, HTTP/2, compression, cookies, redirects |
| `FAULT_TOLERANCE.md` | Block resilience: retries, Retry-After, breaker, redirects, cancellation |
| `RANDOMIZATION.md` | Design of the seeded randomization subsystem |
| `RANDOMIZED_TESTING.md` | Fuzz campaign results |
| `PERFORMANCE.md` | Startup, latency, throughput, CPU, memory, long runs |
| `REAL_WORLD_OBSERVATIONS.md` | Public sites: raw observations, then interpretation |
| `CONTROLLED_ZONE_RESULTS.md` | The owned zone: every scenario, lifecycle, rate limiter |
| `KNOWN_ISSUES.md` | Open defects and every limitation |
| `REGRESSION_RESULTS.md` | Every defect, root cause, fix and guarding test |
| `PROXY_ROUTING.md` | Proxy routing: the rule, where it is enforced, DNS per protocol, tests, real verification |

## The brief's `testing/` tree, mapped onto this repo

Rust requires tests in `engine/tests/` and `engine/src`; data stays in `experiments/test-results/` as for earlier labs, so there is one copy of each thing.

| Brief folder | Here |
|---|---|
| `unit/` | `#[cfg(test)]` modules in `engine/src/*` (41 tests) |
| `integration/` | `engine/tests/local_tls.rs`, `runner.rs`, `proxy.rs` |
| `adversarial/` | `engine/tests/adversarial.rs`, `engine/tests/properties.rs` |
| `randomized/` | `engine/src/random/`, `engine/tests/randomized.rs`, `cfprobe fuzz` |
| `tls/`, `http/` | `engine/tests/local_tls.rs`, `adversarial.rs` |
| `fingerprint/` | `engine/tests/baselines.rs`; captures `experiments/test-results/P2/compare/` |
| `cloudflare/` | `engine/tests/cloudflare.rs`, `real_world.rs` |
| `resilience/` | `engine/src/resilience/`, `engine/tests/resilience.rs` |
| `performance/` | `engine/examples/bench.rs`; results `experiments/test-results/P2/performance/` |
| `fixtures/` | `experiments/test-results/E4/` (zone), `experiments/test-results/P2/fixtures/` (public excerpts, zone 522/1101) |
| `targets/` | `experiments/test-results/P2/targets.json`; matrices `experiments/test-results/P2/matrices/` |
| `results/raw/` | `experiments/test-results/P2/**/raw/` (local only, gitignored: bodies, third-party pages) |
| `results/processed/` | `experiments/test-results/P2/{real-world,zone,fuzz,performance,lifecycle}/results.*` |
| `reports/` | `docs/phase2/` |

## Scripts

| Script | Does |
|---|---|
| `scripts/phase2/run_zone.sh` | Runs the zone matrix against the edge address from the zone's nameserver |
| `scripts/phase2/lifecycle.sh` | Replays a FlareSolverr clearance with cfprobe in five arms |
| `scripts/phase2/excerpt_fixture.py` | Third-party page -> committable excerpt fixture |
| `scripts/phase2/solve.sh` | FlareSolverr solve, through `CFPROBE_PROXY` when defined |
| `scripts/phase2/scrub.py` | `--fix` / `--check` every committable P2 file for IPv4 addresses, tokens, data-centre suffixes. **Run `--check` before every commit** |
