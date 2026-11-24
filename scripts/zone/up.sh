#!/usr/bin/env zsh
# Recreate the zone lab used by E1 and E2:
#   1. upload the echo Worker (lab/zone-worker/worker.js) as cflab-echo, workers.dev off
#   2. attach it to LAB_HOST as a Custom Domain (Cloudflare creates the proxied DNS record)
#   3. add the WAF custom rule: Managed Challenge on LAB_HOST/c/*
#   4. wait until /echo answers 200 and /c/echo answers 403 with cf-mitigated: challenge,
#      reaching the edge at the address the zone's authoritative nameserver gives (authdns.py)
# Safe to run twice: an existing rule with the same description is left alone, uploads overwrite.
# Usage: scripts/zone/up.sh
set -eu
source ${0:A:h}/lib.sh
WDIR=$ROOT/lab/zone-worker
COMPAT=$(sed -n 's/^compatibility_date = "\(.*\)"/\1/p' $WDIR/wrangler.toml)

print "== 1/4 upload Worker $WORKER (compatibility_date $COMPAT)"
cf -X PUT "$API/accounts/$ACCOUNT_ID/workers/scripts/$WORKER" \
  -F "metadata={\"main_module\":\"worker.js\",\"compatibility_date\":\"$COMPAT\"};type=application/json" \
  -F "worker.js=@$WDIR/worker.js;type=application/javascript+module" | ok
cf -X POST "$API/accounts/$ACCOUNT_ID/workers/scripts/$WORKER/subdomain" \
  -H 'content-type: application/json' --data '{"enabled":false}' | ok

print "== 2/4 Custom Domain $LAB_HOST -> $WORKER"
cf -X PUT "$API/accounts/$ACCOUNT_ID/workers/domains" -H 'content-type: application/json' \
  --data "$(jq -nc --arg h $LAB_HOST --arg s $WORKER --arg z $ZONE_ID \
    '{hostname: $h, service: $s, zone_id: $z, environment: "production"}')" | ok

print "== 3/4 WAF rule: Managed Challenge on $LAB_HOST/c/*"
EP=$(cf "$API/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint")
RULE=$(jq -nc --arg d "$RULE_DESC" --arg h "$LAB_HOST" '{action: "managed_challenge", enabled: true,
  description: $d, expression: ("http.host eq \"" + $h + "\" and starts_with(http.request.uri.path, \"/c/\")")}')
RS=$(jq -r '.result.id // empty' <<<"$EP")
if jq -e --arg d "$RULE_DESC" '.result.rules[]? | select(.description == $d)' <<<"$EP" >/dev/null; then
  print "rule already present, left as is"
elif [[ -n $RS ]]; then
  cf -X POST "$API/zones/$ZONE_ID/rulesets/$RS/rules" -H 'content-type: application/json' --data "$RULE" | ok
else
  cf -X PUT "$API/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" \
    -H 'content-type: application/json' --data "$(jq -nc --argjson r "$RULE" '{rules: [$r]}')" | ok
fi

print "== 4/4 wait for the edge"
# Resolve through the zone's own nameserver: public resolvers may still cache NXDOMAIN from a
# recent down.sh for up to the SOA negative TTL (1800 s), which says nothing about the edge.
# The Worker and the WAF rule reach the edge at different moments, so poll both together.
st=none mit=none ip=
for i in {1..30}; do
  ip=$(python3 -I $ROOT/scripts/zone/authdns.py $LAB_HOST A 2>/dev/null | sed -n 2p)
  if [[ -n $ip ]]; then
    st=$(curl -s -o /dev/null -w '%{http_code}' -m 10 --resolve "$LAB_HOST:443:$ip" "https://$LAB_HOST/echo" || true)
    mit=$(curl -s -o /dev/null -m 10 --resolve "$LAB_HOST:443:$ip" -w '%{http_code} %header{cf-mitigated}' "https://$LAB_HOST/c/echo" || true)
    [[ $st == 200 && $mit == "403 challenge" ]] && break
  fi
  sleep 3
done
pub=$(curl -s -m 10 -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$LAB_HOST&type=A" | jq -r '.Status')
print "edge ${ip:-unresolved}: /echo -> $st   /c/echo -> $mit (after $i tries)"
print "public DNS (1.1.1.1) status: $pub (0 = resolves; 3 = still cached NXDOMAIN, clears within 30 min)"
if [[ $st == 200 && $mit == "403 challenge" ]]; then
  print "zone lab is up"
else
  print -u2 "not ready: expected /echo 200 and /c/echo '403 challenge'"
  exit 1
fi
