#!/usr/bin/env zsh
# Cloudflare's own record of WAF actions on the lab host (GraphQL firewallEventsAdaptive, all plans).
# Usage: scripts/zone/fw_events.sh <start RFC3339> <end RFC3339>   (token needs Zone Analytics Read)
# Prints TSV: datetime, action, source, method, path, ray, user agent. Client IP is not requested.
set -u
source ${0:A:h}/lib.sh
Q='query($z:String!,$h:String!,$s:Time!,$e:Time!){viewer{zones(filter:{zoneTag:$z}){firewallEventsAdaptive(limit:1000,filter:{datetime_geq:$s,datetime_leq:$e,clientRequestHTTPHost:$h},orderBy:[datetime_ASC]){datetime action source ruleId rayName clientRequestPath clientRequestHTTPMethodName userAgent}}}}'
jq -n --arg q "$Q" --arg z "$ZONE_ID" --arg h "$LAB_HOST" --arg s "$1" --arg e "$2" '{query:$q, variables:{z:$z, h:$h, s:$s, e:$e}}' \
  | cf -X POST -H 'content-type: application/json' "$API/graphql" --data @- \
  | jq -r 'if .errors then (.errors|tostring) else (.data.viewer.zones[0].firewallEventsAdaptive[] | [.datetime, .action, .source, .clientRequestHTTPMethodName, .clientRequestPath, .rayName, .userAgent] | @tsv) end'
