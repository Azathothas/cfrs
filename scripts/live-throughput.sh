#!/bin/sh
# Measure the throughput of one quick tunnel: a GET and a POST of SIZE MiB on
# the HTTP path, through `cfrs connect` (a --forward WebSocket), and through
# a WebSocket client in Python on the same forward. The log of CI is public:
# the tunnel host is masked before it can be printed, and no output of cfrs is
# printed without the mask.
#
#   sh scripts/live-throughput.sh CFRS PROTOCOL [SIZE_MIB]
#
# The script prints one line for each path: "rate PATH METHOD MiB/s".
set -eu
cfrs=$1
protocol=$2
size=${3:-16}
dir=$(mktemp -d)
here=$(cd "$(dirname "$0")" && pwd)
port=18090
local=18091
trap 'kill $(jobs -p) 2> /dev/null || true' EXIT

head -c "$((size * 1048576))" /dev/urandom > "$dir/big.bin"
python3 -I "$here/origin-sink.py" "$port" "$dir/big.bin" &
sleep 1

"$cfrs" tunnel --url "http://127.0.0.1:$port" --forward "tcp://127.0.0.1:$port" \
    --protocol "$protocol" --transport direct --json --no-verify \
    > "$dir/tunnel.out" 2> "$dir/tunnel.err" &
i=0
until grep -q '"event":"ready"' "$dir/tunnel.out" 2> /dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        sed -E 's/[a-z0-9-]+\.trycloudflare\.com/<tunnel>.trycloudflare.com/g' "$dir/tunnel.err" | tail -20
        echo "the tunnel is not ready after 60 s"
        exit 1
    fi
    sleep 1
done
url=$(jq -r 'select(.event == "ready") | .url' "$dir/tunnel.out")
host=${url#https://}
echo "::add-mask::$host"
# A new name takes some seconds to resolve.
i=0
until curl -fsS -o /dev/null --max-time 10 "$url/"; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || { echo "the public URL does not answer"; exit 1; }
    sleep 2
done

rate() {
    # rate NAME METHOD URL [CURL ARGUMENT...]
    name=$1 method=$2 target=$3
    shift 3
    start=$(date +%s.%N)
    if [ "$method" = GET ]; then
        bytes=$(curl -fsS --max-time 300 -o /dev/null -w '%{size_download}' "$@" "$target")
    else
        bytes=$(curl -fsS --max-time 300 -o /dev/null -w '%{size_upload}' \
            --data-binary "@$dir/big.bin" -H 'Content-Type: application/octet-stream' "$@" "$target")
    fi
    end=$(date +%s.%N)
    echo "rate $protocol $name $method $(echo "$bytes $start $end" | awk '{ printf "%.2f MiB/s (%d bytes, %.2f s)", $1 / 1048576 / ($3 - $2), $1, $3 - $2 }')"
}

rate http GET "$url/big.bin"
rate http POST "$url/sink"

"$cfrs" connect -L "tcp://127.0.0.1:$local" "wss://$host/__cfrs/ws" > "$dir/connect.out" 2> "$dir/connect.err" &
sleep 2
rate connect GET "http://127.0.0.1:$local/big.bin"
rate connect POST "http://127.0.0.1:$local/sink"

if python3 -c 'import websockets' 2> /dev/null; then
    python3 -I "$here/ws-client.py" "wss://$host/__cfrs/ws" "$size" | sed "s/^/rate $protocol /"
fi

sed -E 's/[a-z0-9-]+\.trycloudflare\.com/<tunnel>.trycloudflare.com/g' "$dir/connect.err" | tail -20
