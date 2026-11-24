# Shared setup for scripts/zone/*. Source it, do not run it.
# Reads the API token from .env and looks up the zone and account IDs by zone name, so no IDs
# live in the repo. Override ZONE_NAME or LAB_HOST in .env or the environment to use another zone.

ROOT=${${(%):-%x}:A:h:h:h}
set -a; source "$ROOT/.env"; set +a
: ${CLOUDFLARE_API_TOKEN_KEY_TEST:?set CLOUDFLARE_API_TOKEN_KEY_TEST in .env (see .env.example)}

ZONE_NAME=${ZONE_NAME:-riddlelab.dev}
LAB_HOST=${LAB_HOST:-lab.$ZONE_NAME}
WORKER=cflab-echo
RULE_DESC="cflab E1/E2: managed challenge on /c/"
API=https://api.cloudflare.com/client/v4
AUTH=(-H "Authorization: Bearer $CLOUDFLARE_API_TOKEN_KEY_TEST")

# cf [curl args...] URL: authenticated API call, body on stdout.
cf() { curl -sS "${AUTH[@]}" "$@" }

# ok: read an API response on stdin, print one summary line, fail unless success is true.
# (Not tee /dev/stderr: with stderr redirected to a file, tee reopens and truncates it.)
ok() {
  local r; r=$(jq -c '{ok: .success, errors: [.errors[]?.message]}')
  print -r -- "$r"
  [[ $r == *'"ok":true'* ]]
}

_zone=$(cf "$API/zones?name=$ZONE_NAME")
ZONE_ID=$(jq -r '.result[0].id // empty' <<<"$_zone")
ACCOUNT_ID=$(jq -r '.result[0].account.id // empty' <<<"$_zone")
if [[ -z $ZONE_ID || -z $ACCOUNT_ID ]]; then
  print -u2 "zone $ZONE_NAME not found with this token: $(jq -c '.errors' <<<"$_zone")"
  return 1
fi
unset _zone
