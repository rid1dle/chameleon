# cfprobe fuzz

Seed **7186966285944100919** (generated), 500 scenarios, concurrency 32, client request timeout 1500 ms, run 2026-11-24T15:57:30Z in 4126 ms.

**500 passed, 0 failed.**

## Coverage

| kind | scenarios |
|---|---|
| body:block_page | 30 |
| body:challenge | 54 |
| body:empty | 52 |
| body:error_code | 32 |
| body:html | 188 |
| body:json | 28 |
| body:text | 116 |
| encoding:br | 36 |
| encoding:corrupt_gzip | 25 |
| encoding:deflate | 28 |
| encoding:gzip | 32 |
| encoding:unknown | 28 |
| encoding:zstd | 29 |
| fault:close_before_head | 28 |
| fault:close_mid_body | 32 |
| fault:dns_failure | 13 |
| fault:latency | 55 |
| fault:none | 285 |
| fault:refused | 19 |
| fault:slow_drip | 29 |
| fault:timeout | 17 |
| fault:untrusted_certificate | 22 |
| redirects:chain | 24 |
| redirects:loop | 9 |
| transport:plain_h1 | 168 |
| transport:tls_h1 | 197 |
| transport:tls_h2 | 135 |
