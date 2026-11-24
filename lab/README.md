# Lab L1: wire fingerprints, local only

Everything runs in Docker on a private network `cflab`. Nothing leaves this machine except image pulls.

## Server

TrackMe (`vendor/pagpeter_TrackMe` @ `9d2e865`, the code behind tls.peet.ws). It returns, per request: JA3, JA4, peetprint, the Akamai HTTP/2 fingerprint, every HTTP/2 frame in order (SETTINGS, WINDOW_UPDATE, HEADERS with header order), and the user agent. Read before building: no outbound calls; pcap is used only for its own TCP fingerprint.

- Image: `cflab-trackme`, built from `lab/trackme/Dockerfile` (built, 2026-11-24)
- Hostname `fp.lab.test` with a self-signed cert, so every client sends SNI (an IP literal would change JA4)
- QUIC off, so L1 covers TLS and HTTP/2 only

```
docker network create cflab
docker run -d --name cflab-fp --network cflab --network-alias fp.lab.test \
  -p 127.0.0.1:8443:443 \
  -v $PWD/lab/trackme/certs:/app/certs:ro -v $PWD/lab/trackme/config.json:/app/config.json:ro \
  cflab-trackme
```

## Clients (run one at a time; this box has about 1 GB free RAM)

| Client | How | Faithful to |
|---|---|---|
| Plain curl | host `curl -k --resolve fp.lab.test:8443:127.0.0.1` | Baseline non-browser |
| Suwayomi OkHttp | `lab/okhttp-client` (OkHttp 5.5.1 on Zulu JDK 25, Suwayomi's default UA) | Suwayomi release build |
| curl-impersonate `chrome152` | lexiforest release v2.3.2, run in a container | The fork |
| FlareSolverr's Chrome | `flaresolverr/flaresolverr:v3.5.2`, `request.get` to `https://fp.lab.test/api/all` | FlareSolverr defaults |
| Headful Chromium baseline | same image's Chromium under Xvfb, no driver | What FlareSolverr's browser should look like |

Results go to `experiments/test-results/L1/<client>.json`, and one comparison table goes in `experiments/test-results/L1/summary.md`.

TCP fingerprint is out of scope here: every client shares this host's kernel, so it is identical by construction.
