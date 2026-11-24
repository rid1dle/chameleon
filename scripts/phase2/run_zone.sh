#!/usr/bin/env zsh
# Run the Phase 2 zone matrix (experiments/test-results/P2/matrices/zone.template.json) against the zone
# lab. Fills in the edge address for the direct-IP case, pins lab.riddlelab.dev to that address so a
# stale local resolver cannot send traffic elsewhere, and writes results to <out-dir>.
# Needs the zone lab up (scripts/zone/up.sh) and the engine built.
# Usage: scripts/phase2/run_zone.sh <out-dir> [cfprobe run args...]
set -eu
OUT=$1; shift
source ${0:A:h}/../zone/lib.sh
IP=$(python3 -I $ROOT/scripts/zone/authdns.py $LAB_HOST A | sed -n 2p)
[[ -n $IP ]] || { print -u2 "$LAB_HOST does not resolve at the zone nameserver: is the zone lab up?"; exit 1 }
mkdir -p $OUT
sed "s/{{EDGE_IP}}/$IP/g" $ROOT/experiments/test-results/P2/matrices/zone.template.json > $OUT/matrix.json
$ROOT/engine/target/debug/cfprobe --resolve "$LAB_HOST:443:$IP" --resolve "$LAB_HOST:80:$IP" run $OUT/matrix.json --out $OUT "$@"
