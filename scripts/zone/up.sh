#!/usr/bin/env zsh
# Recreate the zone lab used by E1, E2 and the engine's Cloudflare response analysis:
#   1. upload the echo Worker (lab/zone-worker/worker.js) as cflab-echo, workers.dev off
#   2. attach it to LAB_HOST as a Custom Domain (Cloudflare creates the proxied DNS record)
#   3. add the WAF custom rules in lib.sh WAF_RULES (Managed Challenge on /c/, Block on /b/,
#      JS Challenge on /j/, Interactive Challenge on /i/) and the rate limit rule on RL_PATH
#   4. wait until /echo answers 200 and /c/echo answers 403 with cf-mitigated: challenge,
#      reaching the edge at the address the zone's authoritative nameserver gives (authdns.py)
# Safe to run twice: a rule whose description already exists is left alone, uploads overwrite.
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

print "== 3/4 WAF rules (${#WAF_RULES} custom, 1 rate limit) on $LAB_HOST"
EP=$(cf "$API/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint")
RS=$(jq -r '.result.id // empty' <<<"$EP")
missing=()
for spec in $WAF_RULES; do
  parts=( "${(@s:|:)spec}" )
  if jq -e --arg d "${parts[3]}" '.result.rules[]? | select(.description == $d)' <<<"$EP" >/dev/null; then
    print "present: ${parts[3]}"
  else
    missing+=( "$(jq -nc --arg a "${parts[1]}" --arg p "${parts[2]}" --arg d "${parts[3]}" --arg h "$LAB_HOST" \
      '{action: $a, enabled: true, description: $d,
        expression: ("http.host eq \"" + $h + "\" and starts_with(http.request.uri.path, \"" + $p + "\")")}')" )
  fi
done
if (( $#missing )) && [[ -z $RS ]]; then
  cf -X PUT "$API/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" \
    -H 'content-type: application/json' --data "$(print -rl -- $missing | jq -sc '{rules: .}')" | ok
else
  for r in $missing; do
    print "add: $(jq -r .description <<<"$r")"
    cf -X POST "$API/zones/$ZONE_ID/rulesets/$RS/rules" -H 'content-type: application/json' --data "$r" | ok
  done
fi

# Free plan limits: period and mitigation_timeout 10 s, characteristics cf.colo.id + ip.src.
EP=$(cf "$API/zones/$ZONE_ID/rulesets/phases/http_ratelimit/entrypoint")
RS=$(jq -r '.result.id // empty' <<<"$EP")
RL=$(jq -nc --arg d "$RL_DESC" --arg p "$RL_PATH" '{action: "block", enabled: true, description: $d,
  expression: ("http.request.uri.path eq \"" + $p + "\""),
  ratelimit: {characteristics: ["cf.colo.id", "ip.src"], period: 10, requests_per_period: 2, mitigation_timeout: 10}}')
if jq -e --arg d "$RL_DESC" '.result.rules[]? | select(.description == $d)' <<<"$EP" >/dev/null; then
  print "present: $RL_DESC"
elif [[ -n $RS ]]; then
  print "add: $RL_DESC"
  cf -X POST "$API/zones/$ZONE_ID/rulesets/$RS/rules" -H 'content-type: application/json' --data "$RL" | ok
else
  print "add: $RL_DESC"
  cf -X PUT "$API/zones/$ZONE_ID/rulesets/phases/http_ratelimit/entrypoint" \
    -H 'content-type: application/json' --data "$(jq -nc --argjson r "$RL" '{rules: [$r]}')" | ok
fi

print "== deliberate origin failures: ${#ORIGIN_RECORDS} proxied DNS records"
RECS=$(cf "$API/zones/$ZONE_ID/dns_records?per_page=100")
for spec in $ORIGIN_RECORDS; do
  parts=( "${(@s:|:)spec}" )
  fqdn=${parts[1]}.$ZONE_NAME
  if jq -e --arg n $fqdn '.result[]? | select(.name == $n)' <<<"$RECS" >/dev/null; then
    print "present: $fqdn"
  else
    print "add: $fqdn ${parts[2]} ${parts[3]} (${parts[4]})"
    cf -X POST "$API/zones/$ZONE_ID/dns_records" -H 'content-type: application/json' \
      --data "$(jq -nc --arg n $fqdn --arg t ${parts[2]} --arg c ${parts[3]} --arg m "$ORIGIN_COMMENT" \
        '{type: $t, name: $n, content: $c, proxied: true, ttl: 1, comment: $m}')" | ok
  fi
done

print "== 4/4 wait for the edge"
# Resolve through the zone's own nameserver: public resolvers may still cache NXDOMAIN from a
# recent down.sh for up to the SOA negative TTL (1800 s), which says nothing about the edge.
# The Worker and the WAF rule reach the edge at different moments, so poll both together.
st=none mit=none ip=
for i in {1..30}; do
  ip=$(python3 -I $ROOT/scripts/zone/authdns.py $LAB_HOST A 2>/dev/null | sed -n 2p)
  if [[ -n $ip ]]; then
    st=$(rcurl -s -o /dev/null -w '%{http_code}' -m 10 ${=$(pin $LAB_HOST 443 $ip)} "https://$LAB_HOST/echo" || true)
    mit=$(rcurl -s -o /dev/null -m 10 ${=$(pin $LAB_HOST 443 $ip)} -w '%{http_code} %header{cf-mitigated}' "https://$LAB_HOST/c/echo" || true)
    [[ $st == 200 && $mit == "403 challenge" ]] && break
  fi
  sleep 3
done
pub=$(rcurl -s -m 10 -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$LAB_HOST&type=A" | jq -r '.Status')
print "edge ${ip:-unresolved}: /echo -> $st   /c/echo -> $mit (after $i tries)"
print "public DNS (1.1.1.1) status: $pub (0 = resolves; 3 = still cached NXDOMAIN, clears within 30 min)"
if [[ $st == 200 && $mit == "403 challenge" ]]; then
  print "zone lab is up"
else
  print -u2 "not ready: expected /echo 200 and /c/echo '403 challenge'"
  exit 1
fi
