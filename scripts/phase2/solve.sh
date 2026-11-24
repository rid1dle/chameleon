#!/usr/bin/env zsh
# Ask a running FlareSolverr (http://localhost:8191, loopback) to solve URL, through CFPROBE_PROXY when
# one is defined: FlareSolverr's browser then reaches the site only via that proxy. Without one, the
# browser connects directly (announced). The answer, with the cf_clearance value, goes to OUT, which
# should live outside the repo (e.g. ~/cflab-private/).
# Usage: scripts/phase2/solve.sh <url> <out.json>
set -eu
URL=$1; OUT=$2
source ${0:A:h}/../zone/lib.sh
REQ=$(python3 -I - "$URL" <<'PY'
import json, os, sys, urllib.parse
req = {"cmd": "request.get", "url": sys.argv[1], "maxTimeout": 90000}
p = os.environ.get("CFPROBE_PROXY", "").strip()
if p:
    u = urllib.parse.urlsplit(p)
    scheme = "socks5" if u.scheme.startswith("socks5") else u.scheme
    req["proxy"] = {"url": f"{scheme}://{u.hostname}:{u.port}"}
    if u.username:
        req["proxy"]["username"] = urllib.parse.unquote(u.username)
        req["proxy"]["password"] = urllib.parse.unquote(u.password or "")
print(json.dumps(req))
PY
)
# FlareSolverr's own API is on loopback: this call does not leave the machine.
curl --noproxy '*' -s localhost:8191/v1 -H 'content-type: application/json' -d "$REQ" > "$OUT"
jq -c '{status, message, cookies: [.solution.cookies[]?.name]}' "$OUT"
