#!/bin/sh
# Measure the throughput of one quick tunnel. For each size in SIZES (MiB):
# a GET and a POST on the HTTP path. For the largest size: the same through
# `podnet connect` (a --forward WebSocket) and through a WebSocket client in
# Python. Then the tunnel must still answer: a GET of the largest size again,
# and a GET of /. Each GET checks the byte count. The log of CI is public: the
# tunnel host is masked before it can be printed, and no output of podnet is
# printed without the mask.
#
#   sh scripts/live-throughput.sh PODNET PROTOCOL [SIZES] [TRANSPORT]
#
# SIZES is a list such as "1 4 16" (default "16"); TRANSPORT is direct
# (default) or warp. The script prints one line for each transfer:
# "rate PROTOCOL+TRANSPORT PATH METHOD MiB/s".
set -eu
podnet=$1
protocol=$2
sizes=${3:-16}
transport=${4:-direct}
dir=$(mktemp -d)
here=$(cd "$(dirname "$0")" && pwd)
port=18090
local=18091
trap 'kill $(jobs -p) 2> /dev/null || true' EXIT
largest=0
for s in $sizes; do [ "$s" -gt "$largest" ] && largest=$s; done
label="$protocol+$transport"

python3 -I "$here/origin-sink.py" "$port" &
sleep 1

"$podnet" tunnel --url "http://127.0.0.1:$port" --forward "tcp://127.0.0.1:$port" \
    --protocol "$protocol" --transport "$transport" --json --no-verify \
    > "$dir/tunnel.out" 2> "$dir/tunnel.err" &
i=0
until grep -q '"event":"ready"' "$dir/tunnel.out" 2> /dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 90 ]; then
        sed -E 's/[a-z0-9-]+\.trycloudflare\.com/<tunnel>.trycloudflare.com/g' "$dir/tunnel.err" | tail -20
        echo "the tunnel is not ready after 90 s"
        exit 1
    fi
    sleep 1
done
url=$(jq -r 'select(.event == "ready") | .url' "$dir/tunnel.out")
host=${url#https://}
# Issue 203: the ready event gives the endpoint for podnet connect.
forward=$(jq -r 'select(.event == "ready") | .forward' "$dir/tunnel.out")
[ "$forward" = "wss://$host/__podnet/ws" ] || { echo "the ready event has no forward endpoint"; exit 1; }
echo "::add-mask::$host"
# A new name takes some seconds to resolve (issue 119).
sh "$(dirname "$0")/live-wait-name.sh" "$host" 240
i=0
until curl -fsS -o /dev/null --max-time 10 "$url/"; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || { echo "the public URL does not answer"; exit 1; }
    sleep 2
done

log() {
    sed -E 's/[a-z0-9-]+\.trycloudflare\.com/<tunnel>.trycloudflare.com/g' "$dir/tunnel.err" | tail -25
}

rate() {
    # rate NAME METHOD URL MIB [CURL ARGUMENT...]
    name=$1 method=$2 target=$3 mib=$4
    shift 4
    want=$((mib * 1048576))
    start=$(date +%s.%N)
    if [ "$method" = GET ]; then
        bytes=$(curl -fsS --max-time 300 -o /dev/null -w '%{size_download}' "$@" "$target") || bytes=fail
    else
        head -c "$want" /dev/zero > "$dir/up.bin"
        bytes=$(curl -fsS --max-time 300 -o /dev/null -w '%{size_upload}' \
            --data-binary "@$dir/up.bin" -H 'Content-Type: application/octet-stream' "$@" "$target") || bytes=fail
    fi
    end=$(date +%s.%N)
    if [ "$bytes" != "$want" ]; then
        echo "rate $label $name $method FAILED: $bytes of $want bytes"
        log
        exit 1
    fi
    echo "rate $label $name $method $(echo "$bytes $start $end" | awk '{ printf "%.2f MiB/s (%d bytes, %.2f s)", $1 / 1048576 / ($3 - $2), $1, $3 - $2 }')"
}

for s in $sizes; do
    rate http GET "$url/$s.bin" "$s"
    rate http POST "$url/sink" "$s"
done

"$podnet" connect -L "tcp://127.0.0.1:$local" "$forward" > "$dir/connect.out" 2> "$dir/connect.err" &
sleep 2
rate connect GET "http://127.0.0.1:$local/$largest.bin" "$largest"
rate connect POST "http://127.0.0.1:$local/sink" "$largest"

# Issue 206: the median time of 20 small requests, a new connection each,
# over the public URL and over podnet connect.
latency() {
    # latency NAME URL
    for _ in $(seq 20); do
        curl -fsS --max-time 30 -o /dev/null -w '%{time_total}\n' "$2" || echo fail
    done > "$dir/lat.txt"
    if grep -q fail "$dir/lat.txt"; then
        echo "latency $label $1: $(grep -c fail "$dir/lat.txt") of 20 requests FAILED"
        log
        exit 1
    fi
    sort -n "$dir/lat.txt" | awk -v n="$1" -v l="$label" '{ a[NR] = $1 } END { printf "latency %s %s: p50 %.0f ms, max %.0f ms (20 requests)\n", l, n, a[int((NR + 1) / 2)] * 1000, a[NR] * 1000 }'
}
latency http "$url/"
latency connect "http://127.0.0.1:$local/"

if python3 -c 'import websockets' 2> /dev/null; then
    python3 -I "$here/ws-client.py" "wss://$host/__podnet/ws" "$largest" | sed "s/^/rate $label /"
fi

# The tunnel still works after the large transfers.
rate "http again" GET "$url/$largest.bin" "$largest"
curl -fsS --max-time 30 "$url/" | grep -qx ok || { echo "the tunnel does not answer after the transfers"; log; exit 1; }
echo "rate $label: the tunnel answers after the transfers"
