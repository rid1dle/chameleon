# Recreating the lab

Everything needed to rebuild every setup in this repo from a fresh clone: the local fingerprint lab (L1, L2), the Cloudflare zone lab (E1, E2), and the engine. Each step says what it produces and how to check it worked.

What "last run" means below: the date the step produced the results committed in `experiments/`. Steps marked **re-checked** were run again while writing this guide.

## 0. Machine

| Need | Why | Arch command |
|---|---|---|
| Docker | every lab server and most clients run in containers | `sudo pacman -S --needed docker` |
| `jq`, `curl` 7.62+ (`--doh-url`), `openssl`, `zsh` | scripts | `sudo pacman -S --needed jq curl openssl zsh` |
| C toolchain, cmake, clang | the engine compiles BoringSSL from source | `sudo pacman -S --needed base-devel cmake clang` |
| Rust 1.85+ | the engine | `rustup toolchain install stable` |

Memory: about 2 GB free is enough if heavy things run one at a time. Build the engine with `CARGO_BUILD_JOBS=4` (peak about 480 MB).

## 1. Secrets

```
cp .env.example .env      # then paste the API token
```

`.env` is gitignored. `.env.example` lists exactly which API calls the token must be allowed to make. Zone and account IDs are looked up by zone name (`scripts/zone/lib.sh`), so they never sit in the repo.

## 2. Pinned sources (`vendor/`, not committed)

```
mkdir -p vendor
git clone https://github.com/pagpeter/TrackMe vendor/pagpeter_TrackMe && git -C vendor/pagpeter_TrackMe checkout 9d2e865
# Only needed to re-read source findings, not to run the lab:
git clone https://github.com/Suwayomi/Suwayomi-Server vendor/Suwayomi_Suwayomi-Server && git -C vendor/Suwayomi_Suwayomi-Server checkout 4081b05
git clone https://github.com/FlareSolverr/FlareSolverr vendor/FlareSolverr_FlareSolverr && git -C vendor/FlareSolverr_FlareSolverr checkout cc2224b
git clone https://github.com/lexiforest/curl-impersonate vendor/lexiforest_curl-impersonate && git -C vendor/lexiforest_curl-impersonate checkout ec2a231
git clone https://github.com/lwthiker/curl-impersonate vendor/lwthiker_curl-impersonate && git -C vendor/lwthiker_curl-impersonate checkout 822dbef
```

Vendor code is untrusted: read it, never build or run it from inside `vendor/` (TrackMe is built by Docker from a copy of its files, step 4).

## 3. Lab certificates

The certificates are committed but their private keys are not, so make a fresh pair for each host. Self-signed, EC P-256, one year, with the hostname in SAN, which is what the committed ones are. **Re-checked.**

```
mkcert() {  # mkcert <hostname> <dir> <cert file name>
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
    -subj "/CN=$1" -addext "subjectAltName=DNS:$1" -keyout "$2/key.pem" -out "$2/$3"
}
mkcert fp.lab.test    lab/trackme/certs chain.pem
mkcert probe.lab.test lab/l2/certs      cert.pem
```

Clients that check certificates get `--ca-file` / `-k` / a trust-all manager in the steps below; none of that changes the ClientHello.

## 4. Images and binaries

```
docker network create cflab
docker build -t cflab-trackme -f lab/trackme/Dockerfile vendor/pagpeter_TrackMe   # TrackMe, Go 1.24
docker build -t cflab-okhttp lab/okhttp-client                                     # OkHttp 5.5.1 on Zulu JDK 25
docker pull flaresolverr/flaresolverr:v3.5.2
docker pull zenika/alpine-chrome:124      # Chromium 124.0.6367.78, for version comparison
docker pull debian:stable-slim            # runs curl-impersonate
docker pull python:3-slim                 # serves the L2 probe page
```

curl-impersonate (lexiforest fork, release v2.3.2):

```
D=lab/bin/curl-impersonate-v2.3.2; mkdir -p $D/x
curl -L -o $D/ci.tgz https://github.com/lexiforest/curl-impersonate/releases/download/v2.3.2/curl-impersonate-v2.3.2.x86_64-linux-gnu.tar.gz
sha256sum $D/ci.tgz   # must be bc9bd2522fe1850dd54c0fff189c8dd606df3f222ab2a905f2dd255123c3f495
tar xzf $D/ci.tgz -C $D/x
```

`lab/bin/` is gitignored. Last run: 2026-11-24.

## 5. L1: wire fingerprints (local only)

Server: TrackMe on `fp.lab.test`, QUIC off, so L1 covers TLS and HTTP/2. **Re-checked.**

```
docker run -d --rm --name cflab-fp --network cflab --network-alias fp.lab.test \
  -p 127.0.0.1:8443:443 \
  -v $PWD/lab/trackme/certs:/app/certs:ro -v $PWD/lab/trackme/config.json:/app/config.json:ro \
  cflab-trackme
```

Clients, one at a time. Each prints TrackMe's JSON; save it as `experiments/test-results/L1/<name>.json`.

| Capture | Command |
|---|---|
| `curl-host` | `curl -k --resolve fp.lab.test:8443:127.0.0.1 https://fp.lab.test:8443/api/all` |
| `okhttp-suwayomi` | `docker run --rm --network cflab cflab-okhttp https://fp.lab.test/api/all` |
| `ci-chrome152`, `ci-firefox155` | `docker run --rm --network cflab -v $PWD/lab/bin/curl-impersonate-v2.3.2/x:/ci:ro debian:stable-slim /ci/curl-impersonate -k --impersonate chrome152 https://fp.lab.test/api/all` (or `firefox155`) |
| `flaresolverr-chrome` | start `docker run -d --rm --name cflab-fs --network cflab -p 127.0.0.1:8191:8191 flaresolverr/flaresolverr:v3.5.2`, then `curl -s localhost:8191/v1 -H 'content-type: application/json' -d '{"cmd":"request.get","url":"https://fp.lab.test/api/all","maxTimeout":60000}'`; the capture is the text inside `.solution.response` |
| `chromium-headful` | inside the FlareSolverr image under Xvfb: `xvfb-run -a python3 scripts/fingerprint-analysis/baseline_chromium.py https://fp.lab.test/api/all` (script header has the details) |
| `chromium152-headless`, `chromium124-headless` | `docker run --rm --network cflab --entrypoint chromium flaresolverr/flaresolverr:v3.5.2 --headless=new --no-sandbox --no-first-run --ignore-certificate-errors --disable-gpu --dump-dom https://fp.lab.test/api/all`; for 124 use `--entrypoint chromium-browser zenika/alpine-chrome:124`. The JSON is inside `<pre>`, HTML-escaped. **Re-checked** 2026-11-24 |
| `cfprobe-default` | `engine/target/debug/cfprobe inspect https://fp.lab.test:8443/api/all --resolve fp.lab.test:8443:127.0.0.1 --ca-file lab/trackme/certs/chain.pem --show-body`; the capture is `.response.body`. **Re-checked** |

Then rebuild the table and compare any two captures:

```
engine/target/debug/cfprobe baselines experiments/test-results/L1 > experiments/test-results/L1/summary-table.md
engine/target/debug/cfprobe diff experiments/test-results/L1/chromium124-headless.json experiments/test-results/L1/chromium152-headless.json --format md
docker stop cflab-fp
```

TCP fingerprint is out of scope: every client shares this host's kernel.

## 6. L2: JavaScript environment (local only)

Serve the probe page as `probe.lab.test`, load it in each browser, read the JSON the page writes into itself.

```
docker run -d --rm --name cflab-probe --network cflab --network-alias probe.lab.test \
  -v $PWD/lab/l2:/srv:ro python:3-slim python3 /srv/serve.py /srv
```

FlareSolverr: `request.get` to `https://probe.lab.test/probe.html` (same as L1). Headful baseline: `baseline_chromium.py https://probe.lab.test/probe.html`. Captures go to `experiments/test-results/L2/`. Last run: 2026-11-24.

## 7. Zone lab: E1, E2 and E4

The zone lab is an echo Worker on `lab.riddlelab.dev` plus one rule per Cloudflare action, listed in `scripts/zone/lib.sh` (`WAF_RULES`, `RL_DESC`):

| Path | Rule | Used by |
|---|---|---|
| `/echo` | none | every run (the "reached" control) |
| `/c/*` | Managed Challenge | E1, E2, E4 |
| `/b/*` | Block | E4 |
| `/j/*` | JS Challenge | E4 |
| `/i/*` | Interactive Challenge | E4 |
| `/r/echo` | Rate limit, 2 requests per 10 s (the Free plan's one rule; its expression is the path only, so it applies to `/r/echo` on every host of the zone) | E4 |

Two scripts create and remove exactly that, nothing else:

```
scripts/zone/up.sh     # upload Worker, attach Custom Domain, add the rules, wait until /echo 200 and /c/echo 403 challenge
scripts/zone/down.sh   # delete each of those by exact name, then confirm none are left and the name is NXDOMAIN
```

**Re-checked 2026-11-24 with all five rules**: `up.sh` added the four custom rules and the rate limit rule and exited 0; `down.sh` deleted all five, the Custom Domain and the Worker, and reported `rules left: 0 custom + 0 rate limit, domains left: 0, scripts left: 0, authoritative DNS: NXDOMAIN`.

State on 2026-11-24: **down**. Both scripts **re-checked** in a full cycle (down, up from a clean zone, down): `up.sh` exited 0 with `/echo -> 200`, `/c/echo -> 403 challenge`, and `cfprobe fingerprint` against the rebuilt Worker gave `same_handshake_as_client: true`, ClientHello 1493 bytes, pseudo order `m,s,a,p`, identical to the original setup. `down.sh` exited 0 with nothing left and the name NXDOMAIN at the zone's nameserver.

Three timing effects the scripts handle, found while testing them:

| Effect | What you would see | How the scripts cope |
|---|---|---|
| After `down.sh`, public resolvers cache NXDOMAIN for the SOA negative TTL (1800 s) | `curl: Could not resolve host` for up to 30 minutes after a rebuild | `up.sh` asks the zone's own nameserver (`scripts/zone/authdns.py`) and connects to that address with `--resolve`. Your browser may still need those 30 minutes |
| The Worker goes live a few seconds before the WAF rule | `/c/echo` answers 200 instead of 403 right after `up.sh` step 3 | `up.sh` polls until both checks pass (usually 2 tries, 3 s apart) |
| The DNS record goes away a few seconds after its Custom Domain | the nameserver answers NOERROR with no records | `down.sh` waits up to 60 s for NXDOMAIN |

`up.sh` reproduces by API what the original setup made with `wrangler deploy` and the dashboard, and is safe to run twice (an existing rule is left alone).

`lab/zone-worker/wrangler.toml` still works with `npx wrangler deploy` if you prefer Wrangler for the Worker; the WAF rule then still comes from `up.sh` step 3 or the dashboard.

**Free plan only.** `request.cf.botManagement` is absent, so no bot score, JA4 or detection IDs. Logpush cannot be used on this zone (`1004 ... missing zone subscription`), and a Transform Rule on `http.request.clearance.uuid` is refused (`20087`). Challenge outcomes come from GraphQL firewall events instead.

### E2: mint a cookie with FlareSolverr

```
docker run -d --rm --name cflab-fs -p 127.0.0.1:8191:8191 flaresolverr/flaresolverr:v3.5.2
mkdir -p ~/cflab-private      # outside the repo: this file holds a live cf_clearance
curl -s localhost:8191/v1 -H 'content-type: application/json' \
  -d '{"cmd":"request.get","url":"https://lab.riddlelab.dev/c/echo","maxTimeout":90000}' > ~/cflab-private/solve.json
docker logs cflab-fs > ~/cflab-private/flaresolverr.log
```

Before committing anything from this run, replace cookie values with their length and remove location and network fields (see section 9).

### E1: replay the cookie from other clients

Within the Challenge Passage window (30 minutes by default):

```
scripts/zone/e1_replay.sh ~/cflab-private/solve.json experiments/test-results/E1/run2
```

Six arms: curl-impersonate without and with the cookie, OkHttp, host curl, curl-impersonate with a changed UA, and a recheck. The script never prints the cookie and strips location, network owner and client IP from every capture.

### Cloudflare's own record

```
scripts/zone/fw_events.sh 2026-11-24T12:55:00Z 2026-11-24T13:05:00Z > experiments/test-results/E1/firewall-events.tsv
```

`managed_challenge_bypassed` is what proves a 200 came from the cookie. **Re-checked**: the rewritten script returns the same 6 events, same ray IDs, as the committed capture for 12:59:50 to 13:00:00.

### E4: one response per action (the engine's classifier fixtures)

```
(cd engine && cargo build)
scripts/zone/e4_capture.sh experiments/test-results/E4
```

Saves `cfprobe inspect --show-body` for `/echo`, each rule path and direct IP access (error 1003), scrubbed of tokens, IP addresses and the cf-ray data-centre suffix, and fails if anything address- or token-like is left. `engine/tests/cloudflare.rs` reads these files.

### Finish

```
scripts/zone/down.sh
docker stop cflab-fs
```

For your own browser after a rebuild, either wait out the 30 minutes or point it at an address from `python3 -I scripts/zone/authdns.py lab.riddlelab.dev`.

## 7b. Proxy (optional; routes cfprobe, the zone scripts and FlareSolverr)

With `CFPROBE_PROXY` unset everything connects directly and says so. To verify proxy routing locally, a pinned gost image serves three authenticated proxies on loopback (password random, never committed):

```
docker pull gogost/gost@sha256:27f4bda42d13f00ef76044cc0fe2fd900e7b7a4e08f3ff67a2826138f9dc877c
P=~/cflab-private/gost; mkdir -p $P
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost -keyout $P/key.pem -out $P/cert.pem && chmod 644 $P/*.pem
PW=$(openssl rand -hex 12)
docker run -d --rm --name cflab-proxy -v $P:/c:ro -p 127.0.0.1:18080:18080 -p 127.0.0.1:18081:18081 -p 127.0.0.1:18443:18443 \
  gogost/gost@sha256:27f4bda42d13f00ef76044cc0fe2fd900e7b7a4e08f3ff67a2826138f9dc877c \
  -L "http://lab:$PW@:18080" -L "socks5://lab:$PW@:18081" -L "https://lab:$PW@:18443?certFile=/c/cert.pem&keyFile=/c/key.pem"
export CFPROBE_PROXY="http://lab:$PW@127.0.0.1:18080"      # or socks5h://...:18081
engine/target/debug/cfprobe proxy-check https://www.cloudflare.com/cdn-cgi/trace
```

Then `scripts/zone/up.sh`, `scripts/phase2/run_zone.sh`, `scripts/phase2/solve.sh` (start FlareSolverr with `--network host` so it reaches the loopback proxy), `scripts/phase2/lifecycle.sh` and `scripts/zone/down.sh` all go through it. `docker logs cflab-proxy` shows every destination it carried. A local proxy shares this host's egress address: it proves routing, not a different egress. Details: `docs/phase2/PROXY_ROUTING.md`. Last run: 2026-11-24.

Tor instead of gost: `scripts/tor.sh up`, then `cfprobe --tor ...` for one command or `eval "$(scripts/tor.sh env)"` for every tool here; `scripts/tor.sh status` shows whether the exit differs from this host's address; `scripts/tor.sh down` stops it (image pinned by digest in the script).

## 8. Engine

```
cd engine
CARGO_BUILD_JOBS=4 cargo test        # 35 tests, offline
cargo build --release
```

The first build compiles BoringSSL (about 75 s). The live commands (`inspect`, `fingerprint`) need either TrackMe (section 5) or the zone lab (section 7) to be up.

## 9. Before committing captures

This repo is public. Every capture must be free of client IP, location, network owner and cookie values. Check:

```
grep -rlE '"(asn|asOrganization|colo|country|city|latitude|longitude|postalCode|region)":[[:space:]]*("[^"<]|[0-9-])' experiments/ \
  || echo "clean"
grep -rlE 'cf_clearance=[^;" ]{20,}' experiments/ || echo "no cookie values"
```

Fields that must stay may hold `<removed>`; the first check ignores those.
