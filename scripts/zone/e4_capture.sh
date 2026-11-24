#!/usr/bin/env zsh
# E4: one real response per Cloudflare action on the zone lab, as cfprobe sees it. These files are
# the fixtures for the engine's response classifier (engine/src/cloudflare, engine/tests/cloudflare.rs).
# Needs the zone lab up (scripts/zone/up.sh) and the engine built (cd engine && cargo build).
# Usage: scripts/zone/e4_capture.sh <out-dir>
#
# Each file is `cfprobe inspect --show-body` output, scrubbed before it is written (this repo is public):
#   - any run of 40+ token characters in the body or a header value (challenge tokens, NEL report ids)
#   - IPv4 addresses (the block page prints the client IP; the 1003 request URL is the edge address)
#   - the data-centre suffix of cf-ray
#   - for the Worker's echo, the same location, network and TLS random fields e1_replay.sh drops
set -eu
OUT=$1; mkdir -p "$OUT"
source ${0:A:h}/lib.sh
CFPROBE=$ROOT/engine/target/debug/cfprobe
[[ -x $CFPROBE ]] || { print -u2 "build the engine first: cd engine && cargo build"; exit 1 }
# Ask the zone's nameserver, as up.sh does: local resolvers may still cache NXDOMAIN after down.sh.
IP=$(python3 -I $ROOT/scripts/zone/authdns.py $LAB_HOST A | sed -n 2p)
[[ -n $IP ]] || { print -u2 "$LAB_HOST does not resolve at the zone nameserver: is the zone lab up?"; exit 1 }
PROBE=($CFPROBE --resolve "$LAB_HOST:443:$IP")

ECHO_REDACT='del(.cf.city,.cf.postalCode,.cf.latitude,.cf.longitude,.cf.region,.cf.regionCode,.cf.timezone,.cf.metroCode,.cf.country,.cf.isEUCountry,.cf.continent,.cf.colo,.cf.asn,.cf.asOrganization,.cf.tlsClientRandom,.cf.tlsExportedAuthenticator,.headers["cf-connecting-ip"],.headers["cf-ipcountry"],.headers["x-real-ip"],.headers["x-forwarded-for"])'
SCRUB='def s: gsub("[A-Za-z0-9_.~%+=-]{40,}"; "<removed>") | gsub("\\b[0-9]{1,3}(\\.[0-9]{1,3}){3}\\b"; "<removed>");
  .response.headers |= map(if .name == "cf-ray" then .value |= sub("-[A-Z]{3}$"; "-<removed>") else .value |= s end)
  | .connection.remote_addr = "<removed>" | .request.url |= s | .request.headers |= map(.value |= s)
  | if .tls then .tls.client_random = "<removed>" else . end
  | .response.body |= (if $echo then (fromjson | '"$ECHO_REDACT"' | tojson) else . end | s)'

# save <name> <is-worker-echo> <cfprobe inspect args...>: keeps the last exchange printed.
save() {
  local name=$1 echo=$2; shift 2
  "${PROBE[@]}" inspect --show-body "$@" | jq -s '.[-1]' | jq --argjson echo $echo "$SCRUB" > "$OUT/$name.json"
  print "$name: $(jq -r '"\(.response.status) cf-mitigated=\(.response.headers | map(select(.name == "cf-mitigated")) | .[0].value // "none") body \(.response.body | length) chars"' "$OUT/$name.json")"
}

save reached          true  https://$LAB_HOST/echo
save managed          false https://$LAB_HOST/c/echo
save js-challenge     false https://$LAB_HOST/j/echo
save interactive      false https://$LAB_HOST/i/echo
save block            false https://$LAB_HOST/b/echo
# Free plan rule: 2 requests per 10 s, so the 3rd in a row is limited. Wait out any earlier window.
sleep 11
save rate-limited     false https://$LAB_HOST/r/echo --repeat 3
# Error 1003: a request to a Cloudflare edge address with no zone hostname (direct IP access).
save error-1003       false http://$IP/

# Nothing that looks like an address or a long token may be left in the request or response.
# (tls.peer_chain keeps the server certificates' SHA-256 hashes: public, and 64 hex characters.)
for f in $OUT/*.json; do
  if jq '{request, response}' $f | grep -qE '\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b|[A-Za-z0-9_.~%+=-]{40,}'; then
    print -u2 "scrub check failed: $f"; exit 1
  fi
done
print "scrub check passed"
