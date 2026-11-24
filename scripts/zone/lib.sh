# Shared setup for scripts/zone/*. Source it, do not run it.
# Reads the API token from .env and looks up the zone and account IDs by zone name, so no IDs
# live in the repo. Override ZONE_NAME or LAB_HOST in .env or the environment to use another zone.

ROOT=${${(%):-%x}:A:h:h:h}
set -a; source "$ROOT/.env"; set +a
: ${CLOUDFLARE_API_TOKEN_KEY_TEST:?set CLOUDFLARE_API_TOKEN_KEY_TEST in .env (see .env.example)}

ZONE_NAME=${ZONE_NAME:-riddlelab.dev}
LAB_HOST=${LAB_HOST:-lab.$ZONE_NAME}
WORKER=cflab-echo
# WAF custom rules up.sh creates and down.sh removes, matched by exact description.
# "action|path prefix|description". /c/ is E1/E2; the rest give Phase 7 one real response per action.
WAF_RULES=(
  "managed_challenge|/c/|cflab E1/E2: managed challenge on /c/"
  "block|/b/|cflab P7: block on /b/"
  "js_challenge|/j/|cflab P7: js challenge on /j/"
  "challenge|/i/|cflab P7: interactive challenge on /i/"
)
# The one rate limiting rule a Free zone gets (phase http_ratelimit). Its expression is the path
# only, so it applies to RL_PATH on every host of the zone.
RL_DESC="cflab P7: rate limit on /r/"
RL_PATH=/r/echo
API=https://api.cloudflare.com/client/v4
AUTH=(-H "Authorization: Bearer $CLOUDFLARE_API_TOKEN_KEY_TEST")

# Route, the same rule as cfprobe: CFPROBE_PROXY set -> every call goes through that proxy (its
# credentials passed in the environment, never on the command line, which `ps` shows to every user);
# not set -> direct, announced once. Ambient proxy variables are ignored either way.
if [[ -n ${CFPROBE_PROXY:-} ]]; then
  _route_proxy=${CFPROBE_PROXY/#socks5:\/\//socks5h://}   # socks5h: the proxy resolves names
  print -u2 "zone scripts: routing management calls through CFPROBE_PROXY"
else
  _route_proxy=
  print -u2 "zone scripts: no proxy defined: running in no-proxy mode (direct connections)"
fi

# rcurl [curl args...]: curl on the route above.
rcurl() {
  if [[ -n $_route_proxy ]]; then
    local tunnel=(); [[ $_route_proxy == http* ]] && tunnel=(--proxytunnel)
    env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy ALL_PROXY="$_route_proxy" NO_PROXY= no_proxy= \
      curl "${tunnel[@]}" "$@"
  else
    env -u ALL_PROXY -u all_proxy -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy curl --noproxy '*' "$@"
  fi
}

# Address pins for curl: --resolve when direct; through a proxy --connect-to, so the proxy is asked
# for the pinned address (as cfprobe does).
pin() { # pin HOST PORT ADDR
  if [[ -n $_route_proxy ]]; then print -- "--connect-to" "$1:$2:$3:$2"; else print -- "--resolve" "$1:$2:$3"; fi
}

# cf [curl args...] URL: authenticated API call, body on stdout.
cf() { rcurl -sS "${AUTH[@]}" "$@" }

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
