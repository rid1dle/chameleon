# Performance (Phase 2, 2026-11-24)

Host: 12 cores, 7.3 GB RAM (about 2 GB free during runs), Arch Linux, rustc 1.100.0. Release builds. Loopback only: the server is `engine/examples/bench.rs serve` in its own process (the fuzz mock with one 2 KiB 200 response), so client CPU and memory are measured alone. Each figure is one run; runs were made one at a time.

Raw: `experiments/test-results/P2/performance/load.jsonl`, `longrun.jsonl`, `curl-200-processes.txt`, `cfprobe-200-processes.txt`.

Reproduce: `cargo build --release --example bench`, then `bench serve` and `bench load <cfprobe|reqwest> <url> <n> <concurrency> [--ca pem] [--resolve h:p:a] [--h1] [--no-latency]`.

## Build and startup

| Measure | Value |
|---|---|
| Release binary | 11,963,432 bytes; 9,625,808 stripped |
| Release build (bin + bench example, BoringSSL from source) | 2 min 20 s wall, 4 jobs |
| `cfprobe --version`, 50 runs | 0.101 s total, about 2 ms each |
| One `cfprobe inspect` per process, 200 runs (TLS HTTP/2, new handshake each) | 1.480 s, **7.4 ms each** (includes loading system CA roots and printing the JSON report; run with `verify: false` against the loopback mock, like curl's `-k`) |
| One `curl -sk` per process, 200 runs, same server | 1.343 s, **6.7 ms each** |

## Latency and throughput: cfprobe vs reqwest 0.13 (rustls)

20,000 requests per row, one engine or client, connections reused. Latency in microseconds. CPU is user + system per request.

| Client | Transport | Concurrency | req/s | p50 | p95 | p99 | CPU/req | Peak RSS |
|---|---|---|---|---|---|---|---|---|
| cfprobe | TLS HTTP/2 | 1 | 8,237 | 103 | 153 | 176 | 36 us | 11.2 MB |
| reqwest | TLS HTTP/2 | 1 | 9,107 | 97 | 119 | 142 | 26 us | 11.3 MB |
| cfprobe | TLS HTTP/1.1 | 1 | 14,010 | 62 | 77 | 93 | 23 us | 11.1 MB |
| reqwest | TLS HTTP/1.1 | 1 | 12,496 | 65 | 97 | 111 | 20 us | 10.8 MB |
| cfprobe | plain HTTP/1.1 | 1 | 17,627 | 46 | 60 | 86 | 21 us | 10.8 MB |
| reqwest | plain HTTP/1.1 | 1 | 14,937 | 57 | 70 | 86 | 19 us | 10.4 MB |
| cfprobe | TLS HTTP/2 | 32 | **41,751** | 739 | 993 | 1,135 | 24 us | 13.6 MB |
| reqwest | TLS HTTP/2 | 32 | 38,786 | 753 | 1,004 | 1,152 | 23 us | 14.0 MB |
| cfprobe | TLS HTTP/1.1 | 32 | 75,310 | 388 | 514 | 695 | 19 us | 15.6 MB |
| reqwest | TLS HTTP/1.1 | 32 | **87,286** | 244 | 465 | 647 | 15 us | 15.9 MB |
| cfprobe | plain HTTP/1.1 | 32 | 88,584 | 334 | 436 | 587 | 16 us | 14.8 MB |
| reqwest | plain HTTP/1.1 | 32 | **109,756** | 222 | 438 | 631 | 14 us | 14.6 MB |

Reading:

- Sequentially, cfprobe matches reqwest: faster on HTTP/1.1, 6% slower median on HTTP/2.
- HTTP/2 at concurrency 32: cfprobe 8% ahead (one multiplexed connection, D12).
- **HTTP/1.1 at concurrency 32: cfprobe 14% (TLS) and 19% (plain) behind** in this first table. Profiled and fixed: see "P1" below; after the fix cfprobe is ahead.
- HTTP/2 sequential CPU is the highest per request (36 us): not profiled.

## P1: HTTP/1.1 under concurrency, profiled and fixed

Tools: `perf` and `valgrind` are not installed and samply needs `perf_event_paranoid` at 1 or lower (it is 2, changing it needs sudo), so the benchmark samples itself with `pprof` (SIGPROF, 1 kHz; `bench load ... --profile out.txt`, dev-dependency only).

| Finding | Evidence |
|---|---|
| Not TLS | The gap was the same over plain HTTP (88.6k vs 109.8k); syscall CPU similar (`__send` 11.6% vs reqwest's `writev` 10.6%) |
| The measurement record costs CPU, but little latency | `header_list` 3.2%, dropping `Exchange` 2.3%, TLS observation clone 1.2%, `HeaderMap` clone 1.2%; 4.5 us extra CPU on a ~460 us request is about 1% |
| **The pool lock** | An async `tokio::sync::Mutex` around the pool, taken twice per request by 32 tasks; each contended acquisition parks and wakes through the scheduler. Never held across an await, so a `std::sync::Mutex` is correct |

A/B on the same host and server, TLS HTTP/1.1, concurrency 32, 100,000 requests, 5 alternating runs each (medians):

| | Before | After | reqwest |
|---|---|---|---|
| req/s | 68,451 | **89,836** | 81,904 |
| CPU per request | 20.5 us | 15 us | 16 us |

After the fix, 3 alternating runs each: plain HTTP/1.1 concurrency 32 cfprobe 92,507 vs reqwest 82,404; TLS HTTP/2 concurrency 32 34,071 vs 32,901; TLS HTTP/2 sequential p50 115 vs 109 us. With the D10 head tap added later: TLS HTTP/1.1 concurrency 32 cfprobe 87,133 vs 85,867, 16 us CPU each.

Run-to-run variance is large on this host (unprofiled runs of the same configuration ranged 59k to 69k; profiled runs read lower, 42.5k to 55k), so only alternating, repeated runs are compared.

## Long-running stability

`--no-latency` keeps no per-request data in the harness, so RSS is the client's.

| Run | Requests | Concurrency | Failed | Wall | req/s | RSS at 100k, 200k ... 1M (KB) | Peak |
|---|---|---|---|---|---|---|---|
| cfprobe TLS HTTP/2 | 1,000,000 | 64 | 0 | 23.95 s | 41,752 | 14,516, 14,952, 14,888, 14,868, 14,972, 14,956, 15,028, 15,012, 15,048 | 15.1 MB |
| cfprobe TLS HTTP/1.1 | 1,000,000 | 64 | 0 | 14.23 s | 70,257 | 17,572, 17,476, 17,448, 17,884, 17,620, 17,540, 17,572, 17,772, 17,420 | 17.7 MB |

**No growth after warm-up across 1M requests on either protocol.** An earlier 300k run showed RSS rising from 11 to 19 MB; that was the harness storing 300k latencies (about 4.8 MB), confirmed by the flat `--no-latency` runs.

## Measurement pitfalls found while benchmarking

| Pitfall | Effect | Fix |
|---|---|---|
| Mock server without `TCP_NODELAY`, head and body written separately | 41 ms per request for cfprobe and reqwest alike (Nagle plus delayed ACK) | Server sets nodelay and writes once |
| A dead server and a harness that reported latencies regardless | 0.03 ms "latency", all requests failed | Harness exits with an error when any request fails |
| `pgrep -f` / `pkill -f` matching their own command lines | A stale server looked alive; a `pkill` killed the measuring shell | Server stopped by its saved PID |

## Not measured

- Real network latency distributions (only loopback is measured; zone timings are in the zone results but one sample per case).
- Decompression cost on large bodies (decoding runs on the async worker; up to `max_body_bytes`, 8 MiB).
- Memory with many distinct origins: the pool has no size limit or idle timeout (`KNOWN_ISSUES.md`).
