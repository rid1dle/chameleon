#!/usr/bin/env zsh
# Local Tor SOCKS proxy for cfprobe ("Tor-assisted" routing), in Docker, pinned by digest.
#
#   scripts/tor.sh up       start it on 127.0.0.1:9150 and wait until Tor has bootstrapped
#   scripts/tor.sh status   bootstrap state, and one proxy-check through it (whether the exit
#                           differs from this host's direct address; addresses are not printed)
#   scripts/tor.sh env      print `export CFPROBE_PROXY=...` so every tool here uses Tor:
#                           eval "$(scripts/tor.sh env)"
#   scripts/tor.sh down     stop it
#
# Then: cfprobe --tor <command> (one command), or the env line above (cfprobe, the zone scripts,
# authdns.py and solve.sh). Tor is a proxy like any other here: if it is down or fails, the request
# fails; nothing falls back to a direct connection. There is deliberately no "new identity" /
# circuit-renewal command: changing exits to get past a site's block or rate limit would be
# circumvention. Tor exits are shared by many users and Cloudflare often challenges them.
set -eu
IMAGE=peterdavehello/tor-socks-proxy@sha256:0cc12d36d31265ce828c8422a7e163a0bf46755e90531f4c7d38a6149f071729
NAME=cflab-tor
ADDR=${CFPROBE_TOR_ADDR:-127.0.0.1:9150}
ROOT=${0:A:h:h}
CFPROBE=$ROOT/engine/target/debug/cfprobe

case ${1:-} in
  up)
    if docker ps --format '{{.Names}}' | grep -qx $NAME; then print "already running on $ADDR"; exit 0; fi
    docker run -d --rm --name $NAME -p "$ADDR:9150" $IMAGE >/dev/null
    for i in {1..60}; do
      docker logs $NAME 2>&1 | grep -q "Bootstrapped 100%" && { print "Tor ready on $ADDR (socks5h://$ADDR)"; exit 0 }
      sleep 2
    done
    print -u2 "Tor did not bootstrap within 120 s: docker logs $NAME"; exit 1 ;;
  down)
    docker stop $NAME >/dev/null 2>&1 && print "Tor stopped" || print "Tor was not running" ;;
  env)
    print "export CFPROBE_PROXY=socks5h://$ADDR" ;;
  status)
    if ! docker ps --format '{{.Names}}' | grep -qx $NAME; then print "not running (scripts/tor.sh up)"; exit 1; fi
    docker logs $NAME 2>&1 | grep Bootstrapped | tail -1
    [[ -x $CFPROBE ]] || { print -u2 "build cfprobe first: cd engine && cargo build"; exit 1 }
    url=https://www.cloudflare.com/cdn-cgi/trace
    direct=$(env -u CFPROBE_PROXY $CFPROBE proxy-check $url 2>/dev/null | jq -r .egress_ip_seen_by_destination)
    $CFPROBE --tor proxy-check $url --expect-egress-ip "$direct" 2>/dev/null \
      | jq -c '{route, status, exit_differs_from_direct: (.egress_matches_expected == false), error, hint}' || true ;;
  *)
    print -u2 "usage: scripts/tor.sh up|status|env|down"; exit 2 ;;
esac
