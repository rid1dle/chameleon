# Cloudflare anti-bot resilience research

Source-level study of public automated clients, and how each one meets Cloudflare's bot defences. Testing targets only a zone the researcher owns (`riddlelab.dev`, Free plan, Worker on `lab.riddlelab.dev`) and local lab servers. The plan was written for Enterprise Bot Management; on Free there is no bot score, JA3/JA4 or detection IDs.

## Evidence tags

Every claim in this repo carries one tag.

| Tag | Means |
|---|---|
| **[verified]** | Read in source at the pinned commit, with `file:line` |
| **[documented]** | Stated in project or Cloudflare docs, not read in code |
| **[recall]** | Prior knowledge, not re-read. Needs promoting before it is relied on |
| **[unverified]** | A claim with no source in hand |
| **[to measure]** | Settled only by a lab or zone run, named L* or E* |

## Pinned sources (`vendor/`, not committed)

| Repo | Commit | Date |
|---|---|---|
| Suwayomi/Suwayomi-Server | `4081b05` | 2026-11-22 |
| FlareSolverr/FlareSolverr | `cc2224b` | 2026-10-24 |
| lexiforest/curl-impersonate | `ec2a231` | 2026-11-24 |
| lwthiker/curl-impersonate | `822dbef` | 2024-03-03 |
| pagpeter/TrackMe (lab server) | `9d2e865` | 2026-08-26 |

To rebuild: `git clone https://github.com/<repo> vendor/<owner>_<name>` and `git checkout <commit>`. Vendor code is untrusted data, so it is read, never built or run from inside `vendor/`.

## Status

| Part | State |
|---|---|
| `projects/suwayomi-tachidesk.md` | Done, source-verified |
| `projects/flaresolverr.md` | Done, source-verified |
| `projects/curl-impersonate.md` | Done, source-verified |
| `projects/other-projects.md` | Survey; descriptions are [recall] |
| `research/` mechanism notes | Done: bot signals, challenges and clearance, TLS/HTTP fingerprinting |
| Lab L1, L2 | Done: `experiments/test-results/L1/summary.md`, `experiments/test-results/L2/summary.md`. L1 extended 2026-11-24 with cfprobe's own fingerprint and Chromium 124 vs 152 (L1-8 to L1-10) |
| `engine/` (cfprobe, Rust) | Phases 1 to 7, 9 and 10 done, 8 partly; Phase 2 testing campaign done. See "Engine" below |
| Phase 2 testing ("Chameleon-RS" briefs) | Done: `docs/phase2/PHASE2_SUMMARY.md`. 27 defects plus one performance gap found, all fixed. Proxy routing done: `docs/phase2/PROXY_ROUTING.md` |
| E1, E2 (Free zone) | Done: `experiments/test-results/E1/summary.md`, `experiments/test-results/E2/summary.md`. Second-IP arm of E1 not run |
| E4 (Free zone) | Done: `experiments/test-results/E4/summary.md`. One real response per Cloudflare action; the engine's classifier is tested on them |
| E3 | Blocked: needs Enterprise Bot Management (bot score) |

## Planned measurements

| ID | Question | Where |
|---|---|---|
| L1 | JA4, HTTP/2 SETTINGS and frames, and header order (TCP is identical on one host, so it is measured at the zone) of: Suwayomi's OkHttp, plain curl, curl-impersonate `chrome152`, real Chrome, FlareSolverr's Chrome | Local TLS echo server |
| L2 | JS environment diff between FlareSolverr's Chrome and real Chrome (`navigator`, `window.chrome`, `maxTouchPoints`, headless tells) | Local page |
| E1 | **Is `cf_clearance` bound to the solving client's fingerprint?** Mint with FlareSolverr, replay with OkHttp (JA4 mismatch), curl-impersonate (JA4 match), and from a second IP. Record bot score, JA4 and detection IDs for each | Own zone |
| E2 | Does FlareSolverr 3.5.2 clear a managed challenge on the zone at default settings, and what score does its browser get? | Own zone |
| E3 | Bot score for wire-perfect clients (curl_cffi, tls-client) on a path with no challenge | Own zone |
| E4 | What does each Cloudflare action (Managed, JS, Interactive Challenge, Block, rate limit, a 1xxx error) return to a client, and what tells them apart? | Own zone |

## Engine (`engine/`)

`cfprobe` is a native Rust engine for this research: its own connection stack (BoringSSL via Cloudflare's `boring` 5.6.0, hyper 1.13 HTTP/1.1 and HTTP/2), explicit TLS and HTTP/2 settings for controlled experiments, and no browser profiles or challenge solving. Every value it reports is either **configured**, **measured by the client**, or **measured by a receiver** (lab TrackMe or the zone Worker).

```
cd engine && CARGO_BUILD_JOBS=4 cargo test      # 137 tests, offline (loopback only)
cargo run -- proxy-check https://lab.riddlelab.dev/cdn-cgi/trace   # route check; CFPROBE_PROXY or --proxy, else direct (announced)
cargo run -- inspect https://lab.riddlelab.dev/echo                 # JSON, with a "cloudflare" verdict
cargo run -- inspect https://lab.riddlelab.dev/c/echo --format md   # verdict, evidence, TLS, timings
cargo run -- fingerprint https://lab.riddlelab.dev/echo --baselines ../experiments/test-results/L1
cargo run -- baselines ../experiments/test-results/L1          # writes the L1 table
cargo run -- diff ../experiments/test-results/L1/chromium124-headless.json ../experiments/test-results/L1/chromium152-headless.json --format md
```

Build needs `base-devel cmake clang` (BoringSSL is compiled from source; first build about 75 s, about 480 MB peak).

| Phase | State |
|---|---|
| 1-4 Workspace, dependency research, architecture | Done. wreq 0.16.4 evaluated and dropped: its `TlsInfo` exposes only the peer certificate chain |
| 5 Networking (`core`, `tls`, `http`, `networking`) | Done. Client random matches the zone Worker's `tlsClientRandom` byte for byte |
| 6 Fingerprint (`fingerprint`) | Done. Receiver parsers, field-by-field comparison, baselines read live from `experiments/` |
| 7 Cloudflare response analysis (`cloudflare`) | Done, reworked in Phase 2: NORMAL_PAGE, REDIRECT, CHALLENGE_INDICATOR, CONFIRMED_CHALLENGE_RESPONSE, RATE_LIMITED, ACCESS_DENIED, ORIGIN_UNAVAILABLE, TLS_FAILURE, CONNECTION_FAILURE, UNKNOWN, each with confidence, issuer, indicators, evidence and caveats (`docs/phase2/DETECTION_ACCURACY.md`). A 200 is a normal page, never "bypassed" |
| 8 Reporting and CLI (`reporting`) | **Partly.** Done: baseline table, diff table, `inspect --format md`, the verdict in `inspect` and `fingerprint` JSON. Left: markdown for `fingerprint`, `compare` across runs |
| 9 Lab tests | Done in Phase 2: hermetic suite (117 tests incl. adversarial, property, randomized), `cfprobe run` matrices for the zone and public sites, `cfprobe fuzz` (seeded, loopback mock), resilience layer (`resilience`) |
| 10 Benchmarks | Done: `engine/examples/bench.rs`, `docs/phase2/PERFORMANCE.md` (cfprobe vs reqwest vs curl) |
| Docs | Phase 2 reports in `docs/phase2/` cover testing, limitations (`KNOWN_ISSUES.md`), TLS, HTTP, fingerprints and benchmarks. Architecture and build docs not written |

Known engine limits: HTTP/2 SETTINGS order and pseudo-header order are fixed by the `h2` crate (`m,s,a,p`); TLS 1.3 cipher suites cannot be changed in BoringSSL.

## Research gaps

| Gap | Why it is open | What closes it |
|---|---|---|
| Real Google Chrome | Every Chrome capture is a Chromium build (Debian 152, Alpine 124) | A capture from a Google Chrome install |
| L1-3: does real Chrome on Windows send `cache-control: max-age=0` on a first navigation? | No Windows machine | A Windows Chrome capture |
| L1-6: does real Firefox 155 offer the cipher set curl-impersonate's profile offers? | No Firefox on this host | A Firefox Docker image (about 1 GB) captured at TrackMe |
| Version dependence (L1-10) is thin | One capture per version, two Chromium versions, both headless | More versions, headful, repeated captures |
| E1 second-IP arm: is `cf_clearance` bound to the solving IP at replay time? | This host has one egress and no IPv6 | A second egress (hotspot, VPS) |
| E3: bot score for wire-perfect clients | Needs Enterprise Bot Management; Free has no bot score, JA3/JA4 or detection IDs | An Enterprise zone |
| Cookie lifetime vs Challenge Passage | Not varied in E1 | Repeat E1 at two Challenge Passage settings |

## Recreating the setups

`lab/README.md` rebuilds everything from a fresh clone: pinned sources, lab certificates, images, the L1 and L2 local labs, the zone lab for E1 and E2, and the engine. The zone lab is two commands, `scripts/zone/up.sh` and `scripts/zone/down.sh`, tested in a full cycle on 2026-11-24. Copy `.env.example` to `.env` first.

## Open items

- The zone lab (echo Worker, its `/p2/` scenarios and five rules on `lab.riddlelab.dev`) is **down** again after Phase 2 on 2026-11-24. `scripts/zone/up.sh` brings it back.
- Tor routing: `scripts/tor.sh up`, then `cfprobe --tor ...` (`docs/phase2/PROXY_ROUTING.md`).
- `scripts/fingerprint-analysis/summarize_l1.py` is superseded by `cfprobe baselines` (identical output apart from escaped `|`). Delete once agreed.
- Captures are scrubbed of client IP, location and ISP (`<removed>`); keep it that way for anything added to this public repo. For Phase 2 data, `python3 -I scripts/phase2/scrub.py --check` enforces it. The L1 TrackMe captures (already committed) still carry the Docker network client address (`172.23.0.x`), not a public IP.
