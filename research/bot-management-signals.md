# Bot Management signals

What Cloudflare computes about a request, where each value surfaces, and which plan exposes it. Written to build the echo Worker and to read E1 to E3 results. Docs read 2026-11-24.

Tags as in `README.md`. **[documented]** links the page. **[verified]** is read in `vendor/` source. **[recall]** is prior knowledge with no source found. **[to measure]** names the run that settles it.

## Answer first

| # | Point | Tag |
|---|---|---|
| 1 | **Granular score, JA3/JA4, JA4 Signals, detection IDs, bot tags and the JSD result all need Enterprise Bot Management.** Lower plans see only score groupings in analytics. | **[documented]** [score], [plans-bm], [ja] |
| 2 | **Dump `request.cf` whole, do not pick fields.** The Workers page, the bot variables page, the JA4 page and the workerd types each list a different subset (`jsDetection`, `ja4Signals`, `corporateProxy`, `signedAgent`, `clientTrustScore`). | **[documented]** [wreq], [bmvars], [ja]; types **[documented]** [workerd] |
| 3 | **JA3/JA4 are empty on TLS session resumption.** Every probe in E1 and E3 needs a fresh full handshake or the fingerprint is missing. | **[documented]** [ja] |
| 4 | **Corrected 2026-11-24: a Worker can see header order.** `request.headers` is sorted, but `request.cf.requestHeaderNames` lists the visitor's header names in wire order, HTTP/2 pseudo-headers included, on a Free zone. It reflects the visitor's request, not the one the Worker receives (after a challenge solve it shows the form POST). Logpush `RequestHeaders` is still a key-value object. | **[verified]** by run: `experiments/test-results/E2/summary.md` E2-2, E1 arms a1 to a3 match L1 order. Not in the docs pages read |
| 5 | **The challenge outcome is in Logpush, not in the Worker.** `SecurityActions` has `managedChallenge` vs `managedChallengeBypassed` and friends. A challenged request never reaches the Worker. | Values **[documented]** [logpush]. WAF before Worker **[recall]** |

## Bot score and its sources

Score 1 to 99. 1 means "quite certain automated", 99 "quite certain human". 0 means not computed. **[documented]** [score]

| `BotScoreSrc` value (Logpush) | Engine | What the docs say it gives | Tag |
|---|---|---|---|
| `Heuristics` | Pattern match against known malicious fingerprints. Runs on every request | Score 1 for deterministic hits, sometimes 29 while overlap is assessed. Missing or empty UA gives 1 | **[documented]** [score] |
| `Machine Learning` | Adaptive Intelligence, supervised model. Inputs: headers, session characteristics, browser signals | Most scores 2 to 99. Retrains often, so scores drift | **[documented]** [score], [engines] |
| `Behavioral Analysis` | Anomaly Detection, unsupervised per-zone baseline. Being deprecated, no new customers | Score 1 for outliers | Engine **[documented]** [score]. Mapping of this label to AD **[recall]** |
| `JS Fingerprinting` | JSD and Precursor client-side signals | Range not stated | **[documented]** [precursor] |
| `Verified Bot` | Allowlist, verified mainly by reverse DNS, plus ASN and public lists | Not a score range; flag | **[documented]** [bmvars] |
| `Cloudflare Service` | Special source for Enterprise Zero Trust | n/a | **[documented]** [score] |
| `Not Computed` | BM did not run | Score 0. Not a sign of a human | **[documented]** [score] |

Notes that bite during experiments:

- **`__cf_bm` smooths the score** across one user's requests. Replays with and without `__cf_bm` are different arms. **[documented]** [score]. It expires after 30 minutes of inactivity and is per site. **[documented]** [cookies]
- **Residential proxy detection `50331651`** forces score 29 with anomaly detection as source. **[documented]** [adddet]
- **Never scored:** `/cdn-cgi/` paths (challenge platform, JSD, trace), purge, early hints. **[documented]** [skips]. Redirect Rules that fire first can also leave a request unscored. **[documented]** [score]
- **A JSD pass does not guarantee a high score**, and a JSD fail does not force a low one. **[documented]** [jsd]

## Plans: who sees what

| Plan | Product | Score visibility | Fields in rules, Workers, logs | Tag |
|---|---|---|---|---|
| Free | Bot Fight Mode | None. JSD on and cannot be disabled | None | **[documented]** [plans-free], [jsd] |
| Pro | Super Bot Fight Mode | Groupings ("Definitely automated") in a Bot Report | None | **[documented]** [plans-pro], [score] |
| Business, Enterprise without BM | Super Bot Fight Mode | Groupings in Bot Analytics (Automated 1, Likely automated 2 to 29, Likely human 30 to 99) | None | **[documented]** [plans-biz], [score] |
| **Enterprise + Bot Management** | Bot Management | Exact score | score, JA3/JA4, JA4 Signals, tags, detection IDs, `js_detection.passed`, corporate proxy, BotBase | **[documented]** [plans-bm], [ja], [detids], [jsd] |

## Detection IDs

- Static rules for "predictable bot behavior with no overlap with human traffic". One request can carry several. **[documented]** [detids]
- **Header order is a documented category:** "a detection ID can identify when a client sends headers in a different order than what its claimed browser would use." **[documented]** [detids]
- There is no public catalogue of IDs and meanings. Logpush `BotDetectionIDs` is "the primary method to discover Detection IDs". **[documented]** [detids]
- IDs named in the docs: `50331651` residential proxy [adddet]; `119853733` Cloudflare Browser Run via CDP/Puppeteer/Playwright and `128292352` its crawl endpoint [browserrun]; `3355446`, `12577893` appear only as rule examples with no meaning given [detids]. **[documented]**
- Detection tags (for example `go`) name the client family behind an ID. In Security Analytics, not Security Events. **[documented]** [detids]

## JA3, JA4, JA4 Signals

Mechanics are in `tls-http-fingerprinting.md`. What matters here:

- JA3/JA4 are Enterprise BM only. They are empty for plain HTTP, when BM is skipped, on some Worker subrequests, and after TLS session resumption. **[documented]** [ja]
- **JA4 Signals** are per-JA4 aggregates over the last hour of all Cloudflare traffic: `h2h3_ratio_1h`, `heuristic_ratio_1h`, `browser_ratio_1h`, `cache_ratio_1h`, `uas_rank_1h`, `paths_rank_1h`, `reqs_rank_1h`, `ips_rank_1h`, `reqs_quantile_1h`, `ips_quantile_1h`. May be missing; `NaN` and `Infinity` are dropped. Not usable in WAF expressions. **[documented]** [sig]
- For E3 the useful ones are `browser_ratio_1h` (how browser-like this JA4 is network-wide) and `heuristic_ratio_1h` (how often this JA4 is already caught by heuristics). A wire-perfect impersonator shares Chrome's JA4, so it inherits Chrome's signals. **[to measure]** E3

## Field table: Workers `request.cf`

Workers name, type and meaning as documented. "Ent BM" means the docs require Enterprise Bot Management for it.

### `request.cf.botManagement` and bot fields

| Field | Type | Meaning | Ent BM | Tag |
|---|---|---|---|---|
| `request.cf.botManagement` | object or null | Container. "Only set when using Cloudflare Bot Management" | Yes | **[documented]** [wreq] |
| `.botManagement.score` | number | 1 to 99; 0 = not computed | Yes | **[documented]** [bmvars], [score]; type [workerd] |
| `.botManagement.verifiedBot` | boolean | Allowlisted good bot | Yes | **[documented]** [bmvars] |
| `.botManagement.staticResource` | boolean | Path matches a static file extension | Yes | **[documented]** [bmvars]; type [workerd] |
| `.botManagement.ja3Hash` | string | JA3 MD5 | Yes | **[documented]** [bmvars], [ja] |
| `.botManagement.ja4` | string | JA4 | Yes | **[documented]** [bmvars], [ja] |
| `.botManagement.ja4Signals` | object (key to number) | The 10 JA4 Signals above. May be absent or `{}` | Yes | **[documented]** [ja], [blog-ja4] |
| `.botManagement.jsDetection.passed` | boolean | JSD outcome, read from `cf_clearance` | Yes | **[documented]** [bmvars], [jsd] |
| `.botManagement.detectionIds` | number[] | Heuristic detection IDs | Yes | **[documented]** [bmvars], [detids] |
| `.botManagement.signedAgent` | boolean | Web Bot Auth signed agent | Yes | **[documented]** [bmvars]; Ent per field ref [fref] |
| `.botManagement.corporateProxy` | boolean | Known cloud corporate proxy or SWG | Yes | Exists in Workers **[documented]** [bmvars]. Name only in [workerd] |
| `request.cf.verifiedBotCategory` | string | Verified bot category. Outside `botManagement` | Not stated | **[documented]** [bmvars] |
| `request.cf.clientTrustScore` | number | Deprecated duplicate of `score` | n/a | **[documented]** [workerd] only |
| bot tags | none | `cf.bot_management.tags` exists in rules and `BotTags` in Logpush. **No Workers name is documented** | Yes | Gap, see below |

### TLS, HTTP and network fields

The Workers page lists these under "All plans have access to". **[documented]** [wreq]

| Field | Type | Meaning | Tag |
|---|---|---|---|
| `tlsVersion` | string | For example `TLSv1.3`. `""` on plaintext | **[documented]** [wreq], [workerd] |
| `tlsCipher` | string | Negotiated cipher. The docs page describes it as "The TLS version" (doc error); workerd types give `AEAD-AES128-GCM-SHA256` as example | **[documented]** [wreq], [workerd] |
| `tlsClientHelloLength` | string | Byte length of the ClientHello | **[documented]** [wreq] |
| `tlsClientRandom` | string | 32-byte client random | **[documented]** [wreq] |
| `tlsClientCiphersSha1` | string | Base64 SHA-1 of the cipher suite list | **[documented]** [wreq] |
| `tlsClientExtensionsSha1` | string | Base64 SHA-1 of the extensions, big-endian | **[documented]** [wreq] |
| `tlsClientExtensionsSha1Le` | string | Same, little-endian | **[documented]** [wreq] |
| `tlsClientAuth` | object | mTLS client cert details, placeholders otherwise | **[documented]** [wreq] |
| `tlsExportedAuthenticator` | object, optional | ClientHello and Finished metadata | **[documented]** [workerd] only |
| `httpProtocol` | string | `HTTP/1.1`, `HTTP/2`, `HTTP/3` | **[documented]** [wreq] |
| `requestPriority` | string | Browser priority, for example `weight=192;exclusive=0;group=3;group-weight=127`; `""` if none | **[documented]** [wreq], [workerd] |
| `clientTcpRtt` | number, optional | Smoothed RTT, TCP only | **[documented]** [wreq] |
| `clientQuicRtt` | number, optional | Smoothed RTT, QUIC only | **[documented]** [wreq] |
| `edgeL4.deliveryRate` | number | Bytes per second estimate | **[documented]** [wreq] |
| `clientAcceptEncoding` | string or null | Original `Accept-Encoding` if Cloudflare replaced it | **[documented]** [wreq] |
| `asn`, `asOrganization` | number, string | Client ASN | **[documented]** [wreq] |
| `colo`, `country` | string | Edge colo, client country | **[documented]** [wreq] |

Not in `request.cf` but needed by the echo: the `Cookie` header (to log which `cf_clearance` arrived) and `CF-Connecting-IP`. Whether Cloudflare passes `cf_clearance` through to a Worker unchanged is **[to measure]** E1.

## Field table: Logpush `http_requests`

Every field below marked "Ent BM" carries the line "Available only for Bot Management customers. To enable this feature, contact your account team." **[documented]** [logpush]

| Field | Type | Meaning | Ent BM |
|---|---|---|---|
| `BotScore` | int | Bot score | Yes |
| `BotScoreSrc` | string | `Not Computed`, `Heuristics`, `Machine Learning`, `Behavioral Analysis`, `Verified Bot`, `JS Fingerprinting`, `Cloudflare Service` | Yes |
| `BotDetectionIDs` | array[int] | Heuristic detection IDs | Yes |
| `BotDetectionTags` | array[string] | Tags for those detections | Yes |
| `BotTags` | array[string] | Bot type tags | Yes |
| `JA3Hash` | string | JA3 MD5 | Yes |
| `JA4` | string | JA4 | Yes |
| `JA4Signals` | object | Per-JA4 inter-request stats | Yes |
| `JSDetectionPassed` | string | `passed`, `failed`, `missing` (three states, the Worker has a boolean) | Yes |
| `VerifiedBotCategory` | string | Verified bot category | Not stated |
| `SecurityAction` | string | Terminating action, if any | No |
| `SecurityActions` | array[string] | All actions, including `managedChallenge`, `managedChallengeNonInteractiveSolved`, `managedChallengeInteractiveSolved`, `managedChallengeBypassed`, `jschallenge`, `jschallengeSolved`, `jschallengeBypassed`, `challenge`, `challengeSolved`, `challengeBypassed`, `precursorInterstitialPage*` | No |
| `SecuritySources` | array[string] | Products that matched, including `botManagement`, `firewallCustom`, `precursor`, `bic` | No |
| `SecurityRuleID`, `SecurityRuleIDs` | string, array | Rule IDs, aligned with `SecurityActions` | No |
| `ClientIP`, `ClientASN`, `ClientIPClass` | string, int, string | Client network. `ClientIPClass` values include `badHost`, `scan`, `tor` | No |
| `ClientRequestUserAgent` | string | UA as sent | No |
| `ClientRequestProtocol` | string | HTTP version | No |
| `ClientSSLProtocol`, `ClientSSLCipher` | string | TLS version, cipher | No |
| `ClientTLSKeyExchangeGroup` | string | For example `X25519MLKEM768`; `UNK`, `NONE` | No |
| `ClientTCPRTTMs` | int | Smoothed TCP RTT | No |
| `EdgeResponseStatus` | int | Status Cloudflare returned | No |
| `RayID` | string | Join key to the Worker echo | No |
| `Cookies`, `RequestHeaders` | object | Only cookies and headers named in a Custom Fields rule; up to 100 per type; cookie names case sensitive | No; config **[documented]** [custom] |

## GraphQL Analytics

| Item | State | Tag |
|---|---|---|
| Datasets behind Security Analytics: `httpRequestsAdaptive`, `httpRequestsAdaptiveGroups` | Documented. Enterprise retention 90 days, query window 31 days | **[documented]** [secanalytics] |
| Dimension `botDetectionIds`, filter `botDetectionIds_hasany` (needs BM) | Documented in a query example | **[documented]** [aicc-gql] |
| `userAgent`, `clientRequestPath`, `clientRequestHTTPHost`, `edgeResponseStatus`, `requestSource`, `datetimeHour` | Documented in the same examples | **[documented]** [aicc-gql] |
| `botScore`, `botScoreSrcName`, `ja3Hash`, `ja4`, `botManagementDecision`, `verifiedBotCategory`, `securityAction`, `securitySource`, `clientIP`, `clientAsn` | Names not found on any docs page. Confirm by schema introspection with your own token before relying on them | **[recall]** |

Logpush is the primary record for E1 to E3. GraphQL is aggregate and sampled, so use it for sanity counts only. Sampling **[recall]**.

## Ruleset fields worth forwarding into the Worker

These exist only in the rules engine. A request-header Transform Rule can copy a field into a header the Worker then echoes. Transform Rules set header values from expressions **[documented]** [hdrmod]. Whether each field below is allowed in a Transform Rule is **[to measure]**.

| Field | Why | Tag |
|---|---|---|
| `http.request.clearance.uuid` | Stable UUID from a **valid** clearance cookie; `""` when the cookie is absent or invalid. This is a direct validity oracle for E1 | **[documented]** [f-uuid] |
| `cf.bot_management.tags` | No Workers equivalent documented | **[documented]** [fref] |
| `cf.threat_score` | IP threat score, not exposed in Workers | **[documented]** [fref] |

The Managed Transform "Add bot protection headers" sends `cf-bot-score`, `cf-verified-bot`, `cf-ja3-hash`, `cf-ja4` to the origin. Enterprise BM only. **[documented]** [mt]. Whether a Worker sees them is **[to measure]**.

## Build notes for the echo Worker

1. **Serialize all of `request.cf`**, as Cloudflare's own example does with `JSON.stringify(req.cf)`. **[documented]** [wcf]. Add `Cookie`, `CF-Connecting-IP`, `cf-ray`, and the forwarded clearance UUID.
2. **Deploy on a route or custom domain inside the BM zone,** not `workers.dev`. BM is a zone feature. **[recall]**
3. **Expect missing fields.** JA4 Signals may be `{}`; JA3/JA4 vanish on session resumption and non-TLS. **[documented]** [ja]
4. **Serve two variants: JSON and HTML.** JSD injects only into HTML page views, never AJAX, and not when the response has `Cache-Control: no-transform`. **[documented]** [jsd]. Whether JSD injects into Worker-generated HTML is **[to measure]** E1.
5. **Record Precursor mode.** In Armed mode Precursor disables JSD and can reduce or void clearance. **[documented]** [precursor]
6. **The Worker sees only requests that passed the WAF.** Challenges are read from the response (`cf-mitigated`) and from Logpush `SecurityActions`. WAF before Worker **[recall]**.
7. **Join on Ray ID** between Worker output and Logpush. **[documented]** [logpush]

## Not documented

Gaps the experiments have to fill.

| Gap | Why it matters | Settled by |
|---|---|---|
| Workers name for bot tags | Echo cannot show tags without a Transform Rule | **[to measure]** E1 (dump `request.cf`) |
| Whether `tlsClientExtensionsSha1` hashes extensions in wire order | If yes, it changes on every Chrome connection and is a free permutation detector next to JA4 | **[to measure]** L1 vs E3 |
| Which ClientHello JA4 uses with real ECH (outer or inner), and JA4 on HTTP/3 | curl-impersonate `chrome152` has ECH on; Chromium may switch to h3 | **[to measure]** E3 |
| Whether a replayed `cf_clearance` carries `jsDetection.passed = true` to the replaying client | The JSD result lives in the cookie, so a curl replay may look JS-capable | **[to measure]** E1 |
| How SETTINGS, WINDOW_UPDATE or TCP traits feed the score | Not exposed in any field | Indirect only, **[to measure]** E3 |
| Meaning of most detection IDs | Only a handful are named | Logpush `BotDetectionIDs` across L1 clients, E1 to E3 |

[bmvars]: https://developers.cloudflare.com/bots/reference/bot-management-variables/
[score]: https://developers.cloudflare.com/bots/concepts/bot-score/
[engines]: https://developers.cloudflare.com/bots/concepts/bot-detection-engines/
[ja]: https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
[sig]: https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/signals-intelligence/
[detids]: https://developers.cloudflare.com/bots/additional-configurations/detection-ids/
[adddet]: https://developers.cloudflare.com/bots/additional-configurations/detection-ids/additional-detections/
[plans-free]: https://developers.cloudflare.com/bots/plans/free/
[plans-pro]: https://developers.cloudflare.com/bots/plans/pro/
[plans-biz]: https://developers.cloudflare.com/bots/plans/biz-and-ent/
[plans-bm]: https://developers.cloudflare.com/bots/plans/bm-subscription/
[skips]: https://developers.cloudflare.com/bots/troubleshooting/bot-management-skips/
[cookies]: https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/
[jsd]: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/
[precursor]: https://developers.cloudflare.com/cloudflare-challenges/precursor/
[wreq]: https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties
[wcf]: https://developers.cloudflare.com/workers/examples/accessing-the-cloudflare-object/
[workerd]: https://github.com/cloudflare/workerd/blob/4cd61b11e71f2649c9d82f6c4d837939a2bcc229/types/defines/cf.d.ts
[logpush]: https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/http_requests/
[custom]: https://developers.cloudflare.com/logs/logpush/logpush-job/custom-fields/
[secanalytics]: https://developers.cloudflare.com/waf/analytics/security-analytics/
[aicc-gql]: https://developers.cloudflare.com/ai-crawl-control/reference/graphql-api/
[fref]: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/
[f-uuid]: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.clearance.uuid/
[hdrmod]: https://developers.cloudflare.com/rules/transform/request-header-modification/
[mt]: https://developers.cloudflare.com/rules/transform/managed-transforms/reference/
[browserrun]: https://developers.cloudflare.com/browser-run/reference/automatic-request-headers/
[blog-ja4]: https://blog.cloudflare.com/ja4-signals/
[fetch]: https://fetch.spec.whatwg.org/#concept-header-list-sort-and-combine

`[workerd]` is Cloudflare's own Workers runtime repo (type definitions at commit `4cd61b1`), not the docs site. It lags the docs: it lacks `ja4`, `jsDetection`, `signedAgent`, `ja4Signals` and the `tlsClient*` hashes.
