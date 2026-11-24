#!/usr/bin/env zsh
# Remove everything scripts/zone/up.sh creates, and nothing else:
#   - WAF custom rules whose description is exactly one in lib.sh WAF_RULES
#   - the rate limiting rule whose description is exactly RL_DESC
#   - Custom Domains for LAB_HOST that point at the cflab-echo Worker (their DNS record goes with them)
#   - the cflab-echo Worker script
# Each target is listed and matched by name before it is deleted.
# Usage: scripts/zone/down.sh
set -u
source ${0:A:h}/lib.sh

# Descriptions to delete, exactly as up.sh writes them.
DESCS=$(for spec in $WAF_RULES; do print -r -- "${spec##*|}"; done | jq -Rsc 'split("\n") | map(select(length > 0))')

# del_rules PHASE DESCS_JSON: delete the rules in PHASE's entrypoint whose description is in the list.
del_rules() {
  local ep rs id
  ep=$(cf "$API/zones/$ZONE_ID/rulesets/phases/$1/entrypoint")
  rs=$(jq -r '.result.id // empty' <<<"$ep")
  local -a ids
  ids=( ${(f)"$(jq -r --argjson d "$2" '.result.rules[]? | select(.description as $x | any($d[]; . == $x)) | .id' <<<"$ep")"} )
  ids=( ${ids:#} )
  for id in $ids; do
    print "delete rule $id: $(jq -r --arg i $id '.result.rules[] | select(.id == $i) | "\(.description) [\(.expression)]"' <<<"$ep")"
    cf -X DELETE "$API/zones/$ZONE_ID/rulesets/$rs/rules/$id" | ok
  done
  (( $#ids )) || print "none"
}
# left_rules PHASE DESCS_JSON: how many of those rules are still there.
left_rules() {
  cf "$API/zones/$ZONE_ID/rulesets/phases/$1/entrypoint" | jq -r --argjson d "$2" '[.result.rules[]? | select(.description as $x | any($d[]; . == $x))] | length'
}

print "== WAF custom rules: ${(j:, :)${WAF_RULES[@]##*|}}"
del_rules http_request_firewall_custom "$DESCS"
print "== rate limiting rule: $RL_DESC"
del_rules http_ratelimit "$(jq -nc --arg d "$RL_DESC" '[$d]')"

print "== Custom Domains $LAB_HOST -> $WORKER"
DOMS=$(cf "$API/accounts/$ACCOUNT_ID/workers/domains")
ids=( ${(f)"$(jq -r --arg h $LAB_HOST --arg s $WORKER '.result[]? | select(.hostname == $h and .service == $s) | .id' <<<"$DOMS")"} )
ids=( ${ids:#} )
for id in $ids; do
  print "delete domain $id ($LAB_HOST)"
  cf -X DELETE "$API/accounts/$ACCOUNT_ID/workers/domains/$id" -o /dev/null -w 'HTTP %{http_code}\n'
done
(( $#ids )) || print "none"

print "== Worker script $WORKER"
if cf "$API/accounts/$ACCOUNT_ID/workers/scripts" | jq -e --arg w $WORKER '.result[]? | select(.id == $w)' >/dev/null; then
  cf -X DELETE "$API/accounts/$ACCOUNT_ID/workers/scripts/$WORKER" | ok
else
  print "none"
fi

print "== check"
left_waf=$(left_rules http_request_firewall_custom "$DESCS")
left_rl=$(left_rules http_ratelimit "$(jq -nc --arg d "$RL_DESC" '[$d]')")
left_doms=$(cf "$API/accounts/$ACCOUNT_ID/workers/domains" | jq -r --arg h $LAB_HOST '[.result[]? | select(.hostname == $h)] | length')
left_script=$(cf "$API/accounts/$ACCOUNT_ID/workers/scripts" | jq -r --arg w $WORKER '[.result[]? | select(.id == $w)] | length')
# The Custom Domain's DNS record goes away a few seconds after the domain; for a short while the
# nameserver answers NOERROR with no records. Wait up to 60 s for a clean NXDOMAIN.
for i in {1..12}; do
  auth=$(python3 -I $ROOT/scripts/zone/authdns.py $LAB_HOST A 2>/dev/null | head -1)
  [[ $auth == NXDOMAIN ]] && break
  sleep 5
done
print "rules left: $left_waf custom + $left_rl rate limit, domains left: $left_doms, scripts left: $left_script, authoritative DNS: ${auth:-no answer} (NXDOMAIN = record gone)"
[[ $left_waf == 0 && $left_rl == 0 && $left_doms == 0 && $left_script == 0 ]] || exit 1
