#!/usr/bin/env zsh
# E1: replay one FlareSolverr-minted cf_clearance from other clients against the challenged path.
# Usage: scripts/zone/e1_replay.sh <flaresolverr-response.json> <out-dir>
# The cookie is read from the FlareSolverr response and never printed. Captures are redacted
# (location, client IP, TLS random) before they are written. All arms leave from this host's IPv4,
# the same address FlareSolverr solved from.
set -u
# E1's clients (OkHttp and curl-impersonate in Docker, host curl) are not routed through a proxy.
# Rather than bypass one silently, refuse to run when one is defined.
if [[ -n ${CFPROBE_PROXY:-} ]]; then
  print -u2 "e1_replay.sh predates proxy routing and its clients would connect directly: unset CFPROBE_PROXY to run it"
  exit 2
fi
FS_JSON=$1; OUT=$2; mkdir -p "$OUT"
ROOT=${0:A:h:h:h}
URL=https://${LAB_HOST:-lab.riddlelab.dev}/c/echo
UA=$(jq -r '.solution.userAgent' "$FS_JSON")
COOKIE="cf_clearance=$(jq -r '.solution.cookies[] | select(.name=="cf_clearance") | .value' "$FS_JSON")"
OTHER_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
# Location, network owner and client IP never reach a capture (this repo is public).
REDACT='del(.cf.city,.cf.postalCode,.cf.latitude,.cf.longitude,.cf.region,.cf.regionCode,.cf.timezone,.cf.metroCode,.cf.country,.cf.isEUCountry,.cf.continent,.cf.colo,.cf.asn,.cf.asOrganization,.cf.tlsClientRandom,.cf.tlsExportedAuthenticator,.headers["cf-connecting-ip"],.headers["cf-ipcountry"],.headers["x-real-ip"],.headers["x-forwarded-for"])'

# Runs curl-impersonate chrome152 in the same container setup as L1.
ci() {
  # debian:stable-slim ships no CA bundle; mount the host's so TLS is verified (L1 used -k on a lab cert).
  docker run --rm -v "$ROOT/lab/bin/curl-impersonate-v2.3.2/x:/ci:ro" \
    -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro debian:stable-slim \
    /ci/curl-impersonate --impersonate chrome152 --compressed -s -D /dev/stderr --max-time 20 "$@"
}

# record <arm> <command...>: saves the body, prints status and what the Worker saw.
record() {
  local arm=$1; shift
  local hdrs body
  body=$("$@" 2>"$OUT/$arm.stderr")
  local st=$(grep -m1 -o -E '^(HTTP/[0-9.]+ [0-9]+|STATUS [0-9]+)' "$OUT/$arm.stderr" | awk '{print $2}')
  local mit=$(grep -i -o -E 'cf-mitigated[:=] ?[a-z]+' "$OUT/$arm.stderr" | head -1 | sed -E 's/.*[:=] ?//')
  rm -f "$OUT/$arm.stderr"
  if print -r -- "$body" | jq -e . >/dev/null 2>&1; then
    print -r -- "$body" | jq "$REDACT" > "$OUT/$arm.json"
    print "$arm | $st | ${mit:-none} | $(jq -c '{hasClearance, ciphersSha1: .cf.tlsClientCiphersSha1, helloLen: .cf.tlsClientHelloLength, order: (.cf.requestHeaderNames[0:4]|join(","))}' "$OUT/$arm.json")"
  else
    print "$arm | $st | ${mit:-none} | (non-JSON body, $(print -r -- "$body" | wc -c) bytes)"
  fi
}

print "arm | status | cf-mitigated | Worker saw"
record a0-ci-nocookie        ci -H "User-Agent: $UA" "$URL"
record a1-ci-fsua-cookie     ci -H "User-Agent: $UA" -H "Cookie: $COOKIE" "$URL"
record a2-okhttp-fsua-cookie docker run --rm cflab-okhttp "$URL" "$UA" "$COOKIE"
record a3-curl-fsua-cookie   curl -4 -s -D /dev/stderr --max-time 20 -H "User-Agent: $UA" -H "Cookie: $COOKIE" "$URL"
record a4-ci-otherua-cookie  ci -H "User-Agent: $OTHER_UA" -H "Cookie: $COOKIE" "$URL"
record a5-ci-fsua-cookie-recheck ci -H "User-Agent: $UA" -H "Cookie: $COOKIE" "$URL"
