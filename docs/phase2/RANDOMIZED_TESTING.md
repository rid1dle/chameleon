# Randomized testing results (Phase 2, 2026-11-24)

Design: `RANDOMIZATION.md`. Command: `engine/target/debug/cfprobe fuzz [--seed N] [--count 200] [--concurrency 8] [--out dir]`.

Raw files: `experiments/test-results/P2/fuzz/raw/` (local only). Committed: `sweep-20x500-c32.tsv`, `seed-*-400-c16.md`, `example-run.md`.

## Final results

| Campaign | Seeds | Scenarios | Concurrency | Passed | Failed |
|---|---|---|---|---|---|
| Fixed seeds after fixes | 1, 2, 4, 6 | 400 each | 16 | 1600 | 0 |
| Sweep, generated seeds (recorded in the TSV) | 20 | 500 each | 32 | **10000** | **0** |
| In `cargo test` | 1 (150), 99 (60 x 2), 7 (40 + 1) | 351 | 8 | all | 0 |

Each sweep run took 3.8 to 5.3 s (debug build).

## What the randomized runs found

| # | Seed / scenario | Symptom | Cause | Engine or harness | Resolution |
|---|---|---|---|---|---|
| R1 | 1 / 158, 246, 290 | Slow-drip scenario classified CONNECTION_FAILURE | 339 KB in 1825-byte chunks with 7 ms pauses takes longer than the 1.5 s request budget: the client was right to time out | Generator | Drip bounded to 600 ms |
| R2 | 2, 4, 6 at concurrency 16 | Fault-free scenarios timed out; timeouts took 4 to 8 s instead of 3 | The mock compressed up to 600 KB with brotli quality 11 on the async workers shared with the client, stalling its timers | Harness | Compression on blocking threads at quality 4; seeds 1, 2, 4, 6 then passed 400/400 |
| R3 | 6 / 96 | "Close mid-body" on a 204 expected a failure | A 204 has no body; the client correctly ignored the declared length | Generator | 204 becomes 200 for that fault |

No randomized run found an engine defect that the adversarial and property tests had not. The property tests did find one (D20, URL redaction not idempotent), and the zone runs found three (D21, D22, D23): see `REGRESSION_RESULTS.md`.

## Coverage of one 400-scenario run (seed 1)

From `seed-1-400-c16.md`:

| Kind | Scenarios |
|---|---|
| Faults | none 227, latency 54, close before head 28, slow drip 21, untrusted certificate 20, close mid-body 16, refused 16, DNS failure 10, timeout 8 |
| Bodies | html 135, text 99, empty 45, json 42, challenge 31, error code 27, block page 21 |
| Transports | TLS HTTP/1.1 144, plain HTTP/1.1 134, TLS HTTP/2 122 |
| Encodings | br 27, zstd 27, unknown 25, corrupt gzip 23, deflate 22, gzip 18 (the rest unencoded) |
| Redirects | chains 25, loops 9 |

## Reproducibility, verified

| Check | Result |
|---|---|
| Same seed twice (60 scenarios) | Identical scenarios and verdicts (`same_seed_same_outcomes...`) |
| Generated seed, then rerun with the recorded seed | Identical scenarios |
| One scenario alone (`--only 17`) vs within its run | Identical scenario and verdict |
| Seeds 5 and 6 | Different scenario sequences and schedules |
| Retry jitter in the zone run | Identical waits across two clients with the same seed (289, 517 ms) |

## Limits

- The expected verdict is written from what a scenario was built to be, by hand, in `Scenario::expected`. A shared misunderstanding between that function and the classifier would not be caught by fuzzing; the real-world and zone captures are the independent check.
- HTTP/2 scenarios cannot cut a body or close before the head (hyper's server frames them); those faults run over HTTP/1.1.
- The mock serves one connection's requests sequentially (HTTP/1.1); server-side concurrency limits are not simulated.
