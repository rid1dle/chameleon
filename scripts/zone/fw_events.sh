#!/usr/bin/env zsh
# Cloudflare's own record of WAF actions on the lab host (GraphQL firewallEventsAdaptive, all plans).
# Usage: scripts/zone/fw_events.sh <start RFC3339> <end RFC3339>   (token needs Zone Analytics Read)
# Prints TSV: datetime, action, source, method, path, ray, user agent. Client IP is not requested.
set -u
ROOT=${0:A:h:h:h}
set -a; source "$ROOT/.env"; set +a
ZONE=1bf0ccefa61fb0ffac1e13c779b00154
Q='query($z:String!,$s:Time!,$e:Time!){viewer{zones(filter:{zoneTag:$z}){firewallEventsAdaptive(limit:1000,filter:{datetime_geq:$s,datetime_leq:$e,clientRequestHTTPHost:"lab.riddlelab.dev"},orderBy:[datetime_ASC]){datetime action source ruleId rayName clientRequestPath clientRequestHTTPMethodName userAgent}}}}'
jq -n --arg q "$Q" --arg z "$ZONE" --arg s "$1" --arg e "$2" '{query:$q, variables:{z:$z, s:$s, e:$e}}' \
  | curl -s -X POST -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN_KEY_TEST" -H 'content-type: application/json' \
      https://api.cloudflare.com/client/v4/graphql --data @- \
  | jq -r 'if .errors then (.errors|tostring) else (.data.viewer.zones[0].firewallEventsAdaptive[] | [.datetime, .action, .source, .clientRequestHTTPMethodName, .clientRequestPath, .rayName, .userAgent] | @tsv) end'
