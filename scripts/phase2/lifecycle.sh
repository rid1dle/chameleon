#!/usr/bin/env zsh
# P2 lifecycle on the zone lab: challenge, clearance issued by a browser solver, replay by cfprobe.
# The solve is FlareSolverr's response (as in E1/E2), kept outside the repo; the cookie is never printed
# (cfprobe redacts cookie values to their length).
# Usage: scripts/phase2/lifecycle.sh <flaresolverr-solve.json> <out-dir>
set -eu
FS_JSON=$1; OUT=$2; mkdir -p $OUT
source ${0:A:h}/../zone/lib.sh
IP=$(python3 -I $ROOT/scripts/zone/authdns.py $LAB_HOST A | sed -n 2p)
CFPROBE=($ROOT/engine/target/debug/cfprobe --resolve "$LAB_HOST:443:$IP")
URL=https://$LAB_HOST/c/echo
UA=$(jq -r '.solution.userAgent' $FS_JSON)
COOKIE="cf_clearance=$(jq -r '.solution.cookies[] | select(.name=="cf_clearance") | .value' $FS_JSON)"
H1=$(mktemp); print '{"tls":{"alpn":["http/1.1"]}}' > $H1

# arm <name> <cfprobe args...>: one request, saves status and analysis (no body, no cookie value).
arm() {
  local name=$1; shift
  "${CFPROBE[@]}" "$@" | jq '{arm: $n, status: .response.status, http_version: .response.http_version,
      sent_cookie: [.request.headers[] | select(.name=="cookie") | .value],
      verdict: .cloudflare.verdict, confidence: .cloudflare.confidence, issued_by: .cloudflare.issued_by,
      challenge_kind: .cloudflare.challenge_kind, evidence: .cloudflare.evidence}' --arg n $name > $OUT/$name.json
  print "$name: $(jq -r '"\(.status) \(.http_version) \(.verdict) (\(.confidence))"' $OUT/$name.json)"
}
arm L0-no-cookie         inspect $URL -H "user-agent: $UA"
arm L1-cookie-solver-ua  inspect $URL -H "user-agent: $UA" -H "cookie: $COOKIE"
arm L2-cookie-cfprobe-ua inspect $URL -H "cookie: $COOKIE"
arm L3-cookie-h1         --config $H1 inspect $URL -H "user-agent: $UA" -H "cookie: $COOKIE"
arm L4-no-cookie-after   inspect $URL -H "user-agent: $UA"
rm -f $H1
