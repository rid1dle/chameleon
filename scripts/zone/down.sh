#!/usr/bin/env zsh
# Remove everything scripts/zone/up.sh creates, and nothing else:
#   - WAF custom rules whose description is exactly RULE_DESC
#   - Custom Domains for LAB_HOST that point at the cflab-echo Worker (their DNS record goes with them)
#   - the cflab-echo Worker script
# Each target is listed and matched by name before it is deleted.
# Usage: scripts/zone/down.sh
set -u
source ${0:A:h}/lib.sh

print "== WAF rules described \"$RULE_DESC\""
EP=$(cf "$API/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint")
RS=$(jq -r '.result.id // empty' <<<"$EP")
ids=( ${(f)"$(jq -r --arg d "$RULE_DESC" '.result.rules[]? | select(.description == $d) | .id' <<<"$EP")"} )
ids=( ${ids:#} )
for id in $ids; do
  print "delete rule $id: $(jq -r --arg i $id '.result.rules[] | select(.id == $i) | .expression' <<<"$EP")"
  cf -X DELETE "$API/zones/$ZONE_ID/rulesets/$RS/rules/$id" | ok
done
(( $#ids )) || print "none"

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
left_rules=$(cf "$API/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" | jq -r --arg d "$RULE_DESC" '[.result.rules[]? | select(.description == $d)] | length')
left_doms=$(cf "$API/accounts/$ACCOUNT_ID/workers/domains" | jq -r --arg h $LAB_HOST '[.result[]? | select(.hostname == $h)] | length')
left_script=$(cf "$API/accounts/$ACCOUNT_ID/workers/scripts" | jq -r --arg w $WORKER '[.result[]? | select(.id == $w)] | length')
# The Custom Domain's DNS record goes away a few seconds after the domain; for a short while the
# nameserver answers NOERROR with no records. Wait up to 60 s for a clean NXDOMAIN.
for i in {1..12}; do
  auth=$(python3 -I $ROOT/scripts/zone/authdns.py $LAB_HOST A 2>/dev/null | head -1)
  [[ $auth == NXDOMAIN ]] && break
  sleep 5
done
print "rules left: $left_rules, domains left: $left_doms, scripts left: $left_script, authoritative DNS: ${auth:-no answer} (NXDOMAIN = record gone)"
[[ $left_rules == 0 && $left_doms == 0 && $left_script == 0 ]] || exit 1
