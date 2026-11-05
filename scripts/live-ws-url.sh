#!/bin/sh
# A WebSocket through a --url origin (issue 56): a WebSocket echo server in
# Python is the origin of `podnet tunnel --url`, and a client sends one message
# through the public URL and must get it back. The tunnel host is masked
# before any output.
#
#   sh scripts/live-ws-url.sh PODNET PROTOCOL
set -eu
podnet=$1
protocol=$2
dir=$(mktemp -d)
port=18095
trap 'kill $(jobs -p) 2> /dev/null || true' EXIT

python3 -I -c '
import asyncio, sys, websockets
async def echo(ws):
    async for message in ws:
        await ws.send(message)
async def main():
    async with websockets.serve(echo, "127.0.0.1", int(sys.argv[1])):
        await asyncio.Future()
asyncio.run(main())
' "$port" &
sleep 1

"$podnet" tunnel --url "http://127.0.0.1:$port" --protocol "$protocol" --transport direct \
    --json --no-verify > "$dir/tunnel.out" 2> "$dir/tunnel.err" &
i=0
until grep -q '"event":"ready"' "$dir/tunnel.out" 2> /dev/null; do
    i=$((i + 1))
    [ "$i" -lt 90 ] || { echo "the tunnel is not ready after 90 s"; exit 1; }
    sleep 1
done
url=$(jq -r 'select(.event == "ready") | .url' "$dir/tunnel.out")
host=${url#https://}
echo "::add-mask::$host"

i=0
until python3 -I -c '
import asyncio, sys, websockets
async def main():
    async with websockets.connect(sys.argv[1], open_timeout=10) as ws:
        await ws.send("ping through a --url origin")
        got = await asyncio.wait_for(ws.recv(), 10)
        assert got == "ping through a --url origin", got
asyncio.run(main())
' "wss://$host/" 2> "$dir/client.err"; do
    i=$((i + 1))
    if [ "$i" -ge 10 ]; then
        tail -3 "$dir/client.err" | sed -E 's/[a-z0-9-]+\.trycloudflare\.com/<tunnel>.trycloudflare.com/g'
        sed -E 's/[a-z0-9-]+\.trycloudflare\.com/<tunnel>.trycloudflare.com/g' "$dir/tunnel.err" | tail -10
        echo "ws-url $protocol: the WebSocket through the --url origin failed"
        exit 1
    fi
    sleep 3
done
echo "ws-url $protocol: the WebSocket through the --url origin echoes"
