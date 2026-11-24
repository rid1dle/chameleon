# Other public projects: survey

Activity and stars come from the GitHub REST API on 2026-11-24 **[verified]**. The "how it works" column is **[recall]**: from prior knowledge of each project, **not re-read at source this session**. Promote a row to **[verified]** only after reading the code at a pinned commit.

Projects fall into four classes by **which layer they fake**. That class predicts where each one can be caught.

| Class | Fakes | Cannot fake | Where to catch it |
|---|---|---|---|
| A. Patched automation browsers | JS environment over a real engine | Automation side effects (CDP, Runtime.enable), input synthesis, headless rendering | JS detections, behaviour |
| B. Engine-level forks | JS environment inside the engine (C++) | Consistency between faked and real hardware, IP | Cross-signal consistency, reputation |
| C. Wire-level impersonators | TLS, HTTP/2, HTTP/3, headers | Any JS; TCP/IP stack; context | Challenges, TCP fingerprint, behaviour |
| D. Solver services | Nothing themselves; wrap A and hand off cookies | The replay client's fingerprint | Clearance and fingerprint binding (E1) |

## Projects

| Project | Class | Last push | Stars | Lang | How it works [recall] |
|---|---|---|---|---|---|
| ultrafunkamsterdam/undetected-chromedriver | A | 2025-07-05 | 12,915 | Python | Patches chromedriver's `cdc_` injection and hides `navigator.webdriver`. FlareSolverr vendors a modified copy (read: see `flaresolverr.md`) |
| ultrafunkamsterdam/nodriver | A | 2026-10-26 | 4,960 | Python | Same author's successor. Drops chromedriver and WebDriver entirely, speaks CDP directly |
| cdpdriver/zendriver | A | 2026-11-21 | 1,486 | Python | Fork of nodriver |
| Kaliiiiiiiiii-Vinyzu/patchright | A | 2026-11-13 | 5,241 | TypeScript | Patched Playwright that avoids `Runtime.enable` and other CDP leaks |
| berstend/puppeteer-extra (stealth plugin) | A | 2024-07-18 | 7,424 | JavaScript | Set of JS evasions injected at page start. Dormant |
| AtuboDad/playwright_stealth | A | 2024-07-29 | 993 | Python | Port of the puppeteer stealth evasions. Dormant |
| daijro/camoufox | B | 2026-11-22 | 13,611 | C | Firefox fork that spoofs navigator, screen, WebGL, fonts and similar in C++, below where JS can inspect it |
| lexiforest/curl_cffi | C | 2026-11-23 | 6,918 | Python | Python binding to the curl-impersonate fork (read: see `curl-impersonate.md`) |
| bogdanfinn/tls-client | C | 2026-11-18 | 1,951 | Go | Go HTTP client with browser TLS and HTTP/2 profiles, built on a uTLS fork |
| refraction-networking/utls | C | 2026-11-18 | 2,653 | Go | Go TLS library with a programmable ClientHello. Built for censorship circumvention; used by most Go impersonators |
| VeNoMouS/cloudscraper | C plus JS | 2025-06-10 | 6,826 | Python | `requests` with a custom cipher order, plus interpreters for the old IUAM v1 JS challenge. That challenge is retired, so the solver path is likely dead **[unverified]** |
| ThePhaseless/Byparr | D | 2026-11-21 | 2,123 | Python | Drop-in replacement for the FlareSolverr API, built on a different browser automation stack **[unverified]** which one |

## What the survey says

1. **The active edge has moved to classes A and B** (nodriver, zendriver, patchright, camoufox all pushed in the last month), while the stealth-plugin generation (puppeteer-extra, playwright_stealth) is dormant. JS-injection evasion is losing; avoiding CDP and patching the engine are what's being maintained.
2. **Class C is mature and saturated.** Matching JA4 and HTTP/2 is a solved problem for an attacker, so a zone whose bot score leans on wire fingerprints alone is exposed to curl_cffi and tls-client. **[to measure]** L1 then E3.
3. **Class D is plumbing.** Its weak point is the handoff, not the browser.

## Next reads, by detection value

1. **camoufox:** what it spoofs and how consistently. Class B is the hardest to catch from JS alone.
2. **patchright:** which CDP leaks it closes, since those are the class A checks still alive.
3. **Byparr:** which engine it uses, since it is FlareSolverr's replacement.
