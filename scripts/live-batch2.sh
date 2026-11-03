#!/bin/sh
# The live checks of the second batch (issues 132 to 159): warp exit, warp
# scan, the rules of warp proxy, warp forward, a nested session, warp
# export, and a QUIC probe of the front door.
#
#   sh scripts/live-batch2.sh CFRS
#
# The log of CI is public: no line prints a device id, a token, a private
# key or the exit address.
set -eu
cfrs=${1:?usage: live-batch2.sh CFRS}
dir=$(mktemp -d)
pids=""
cleanup() {
    for pid in $pids; do kill "$pid" 2> /dev/null || true; done
    for id in a b; do
        if [ -f "$dir/$id.json" ]; then
            "$cfrs" warp --identity "$dir/$id.json" delete > /dev/null 2>&1 || true
        fi
    done
    # The WireGuard device of --transport wireguard (the state directory).
    "$cfrs" warp export --delete > /dev/null 2>&1 || true
    if [ -f "$dir/wg.json" ]; then
        "$cfrs" warp export --export-identity "$dir/wg.json" --delete > /dev/null 2>&1 || true
    fi
    rm -rf "$dir"
}
trap cleanup EXIT

# Wait for a TCP port, at most 90 s.
wait_port() {
    i=0
    until nc -z 127.0.0.1 "$1" 2> /dev/null; do
        i=$((i + 1))
        if [ "$i" -gt 90 ]; then
            echo "port $1 does not listen after 90 s"
            sed -E 's/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|t\.[0-9a-f-]{8,}/<id>/g' "$2" | tail -20
            exit 1
        fi
        sleep 1
    done
}

echo "== warp exit (issue 147)"
"$cfrs" warp --identity "$dir/a.json" exit --json > "$dir/exit.json"
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert len(d["colo"]) == 3, d["colo"]
print("exit colo", d["colo"], "country", d["loc"], "warp", d["warp"], "rtt_ms", d["rtt_ms"])
' "$dir/exit.json"

echo "== warp scan (issue 139)"
"$cfrs" warp --identity "$dir/a.json" scan --candidate 162.159.198.1 --json > "$dir/scan.json" || true
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
for door in d["doors"]:
    if door["ok"]:
        print("door", door["endpoint"], "tcp", door["tcp_ms"], "ms tls", door["tls_ms"], "ms")
    else:
        print("door", door["endpoint"], "failed")
assert any(door["ok"] for door in d["doors"]), "no door answered"
' "$dir/scan.json"

echo "== warp proxy rules (issues 132, 136, 142)"
printf 'domain:.example.org=reject\n' > "$dir/rules"
# A local web server with a mark of its own (an earlier step of live.yml
# keeps a proxy on 18080).
mkdir -p "$dir/www"
echo "cfrs-batch2-$$" > "$dir/www/mark.txt"
python3 -m http.server 18731 --bind 127.0.0.1 --directory "$dir/www" > /dev/null 2>&1 &
pids="$pids $!"
"$cfrs" warp --identity "$dir/a.json" proxy --listen tcp://127.0.0.1:40010 \
    -r cidr:127.0.0.0/8=direct -r domain:example.com=reject \
    --rules-file "$dir/rules" --run-for 240 > "$dir/rules.log" 2>&1 &
pids="$pids $!"
wait_port 40010 "$dir/rules.log"
curl -fsS --max-time 30 -x socks5h://127.0.0.1:40010 https://www.cloudflare.com/cdn-cgi/trace | grep '^warp=on'
code=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:40010 http://example.com/ || true)
echo "reject over HTTP: $code"
[ "$code" = 403 ]
if curl -sS --max-time 20 -o /dev/null -x socks5h://127.0.0.1:40010 https://example.com/ 2> "$dir/socks.err"; then
    echo "a rejected name was carried"
    exit 1
fi
grep -i 'not allowed\|ruleset\|denied' "$dir/socks.err" || cat "$dir/socks.err"
i=0
until nc -z 127.0.0.1 18731 2> /dev/null; do
    i=$((i + 1)); [ "$i" -lt 40 ] || { echo "the local web server does not listen"; exit 1; }
    sleep 0.25
done
mark=$(curl -fsS --max-time 10 -x socks5h://127.0.0.1:40010 http://127.0.0.1:18731/mark.txt)
[ "$mark" = "cfrs-batch2-$$" ] || { echo "direct to the host: another answer: $mark"; exit 1; }
echo "direct to the host: the mark of the local server"
# The rules file is read again when it changes.
printf 'domain:.example.org=reject\ndomain:.cloudflare.com=reject\n' > "$dir/rules"
sleep 5
code=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:40010 http://www.cloudflare.com/ || true)
echo "reject after the reload: $code"
[ "$code" = 403 ]

echo "== warp forward (issue 143)"
"$cfrs" warp --identity "$dir/a.json" forward -L 127.0.0.1:18443=1.1.1.1:443 --run-for 200 > "$dir/fwd.log" 2>&1 &
pids="$pids $!"
wait_port 18443 "$dir/fwd.log"
curl -fsS --noproxy '*' --max-time 30 --resolve one.one.one.one:18443:127.0.0.1 https://one.one.one.one:18443/cdn-cgi/trace | grep '^warp='

echo "== a nested session (issue 156)"
"$cfrs" --proxy socks5h://127.0.0.1:40010 warp --identity "$dir/b.json" proxy \
    --listen tcp://127.0.0.1:40011 --run-for 180 > "$dir/nested.log" 2>&1 &
pids="$pids $!"
wait_port 40011 "$dir/nested.log"
curl -fsS --max-time 30 -x socks5h://127.0.0.1:40011 https://one.one.one.one/cdn-cgi/trace | grep '^warp=on'

echo "== warp export (issue 148)"
"$cfrs" warp export --export-identity "$dir/wg.json" --format json > "$dir/wg-out.json" 2> /dev/null
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert len(d["private_key"]) == 44 and len(d["peer_public_key"]) == 44
assert d["endpoint"].endswith(":2408"), d["endpoint"]
print("export: keys ok, endpoint port 2408, reserved", "yes" if d["reserved"] else "no")
' "$dir/wg-out.json"
"$cfrs" warp export --export-identity "$dir/wg.json" --delete > /dev/null 2>&1
[ ! -e "$dir/wg.json" ]
echo "export: the device is deleted"

echo "== the ClientHello in records (issue 135)"
for mode in record sni; do
    "$cfrs" warp --identity "$dir/a.json" --no-relay --fragment-client-hello "$mode" probe > "$dir/frag.out" 2>&1 ||
        { grep -E '^(FAIL|TIMEOUT)' "$dir/frag.out"; echo "the front door refused the split ClientHello ($mode)"; exit 1; }
    grep -E '^(tunnel|OK) ' "$dir/frag.out" | head -2
    echo "fragment $mode: ok"
done

echo "== an upload of 16 MiB with each congestion controller (issue 134)"
# Before 0.3.0-beta.9, an upload of more than the send buffer of the stack
# was corrupt (the TLS peer answered bad record mac).
head -c 16777216 /dev/urandom > "$dir/up16"
for cc in none reno cubic; do
    "$cfrs" warp --identity "$dir/a.json" --cc "$cc" proxy --listen tcp://127.0.0.1:40012 --run-for 120 > "$dir/cc.log" 2>&1 &
    pid=$!
    pids="$pids $pid"
    wait_port 40012 "$dir/cc.log"
    out=$(curl -sS -o /dev/null -w '%{http_code} %{speed_upload}' --max-time 90 \
        -x socks5h://127.0.0.1:40012 --data-binary @"$dir/up16" https://speed.cloudflare.com/__up) || true
    echo "upload cc $cc: HTTP ${out%% *}, $(echo "${out#* }" | awk '{ printf "%.2f MB/s", $1 / 1e6 }')"
    kill "$pid" 2> /dev/null || true
    wait "$pid" 2> /dev/null || true
    [ "${out%% *}" = 200 ] || { echo "the upload failed with cc $cc"; exit 1; }
done

echo "== MASQUE over HTTP/3 (issue 157; a report, not a check yet)"
if "$cfrs" warp --identity "$dir/a.json" --no-relay --masque-transport h3 probe > "$dir/h3.out" 2>&1; then
    grep -E '^(tunnel|OK|exit) ' "$dir/h3.out" | head -4
    echo "h3 probe: ok"
    "$cfrs" warp --identity "$dir/a.json" --no-relay --masque-transport h3 proxy --listen tcp://127.0.0.1:40013 --run-for 150 > "$dir/h3p.log" 2>&1 &
    pid=$!
    pids="$pids $pid"
    wait_port 40013 "$dir/h3p.log"
    down=$(curl -sS -o /dev/null -w '%{http_code} %{speed_download}' --max-time 60 -x socks5h://127.0.0.1:40013 'https://speed.cloudflare.com/__down?bytes=20000000') || true
    echo "h3 download 20 MB: HTTP ${down%% *}, $(echo "${down#* }" | awk '{ printf "%.2f MB/s", $1 / 1e6 }')"
    up=$(curl -sS -o /dev/null -w '%{http_code} %{speed_upload}' --max-time 90 -x socks5h://127.0.0.1:40013 --data-binary @"$dir/up16" https://speed.cloudflare.com/__up) || true
    echo "h3 upload 16 MiB: HTTP ${up%% *}, $(echo "${up#* }" | awk '{ printf "%.2f MB/s", $1 / 1e6 }')"
    kill "$pid" 2> /dev/null || true
else
    echo "h3 probe: FAIL"
    sed -E 's/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|t\.[0-9a-f-]{8,}/<id>/g' "$dir/h3.out" | tail -5
fi
# The same download over HTTP/2, for the comparison.
"$cfrs" warp --identity "$dir/a.json" --no-relay proxy --listen tcp://127.0.0.1:40014 --run-for 100 > "$dir/h2p.log" 2>&1 &
pid=$!
pids="$pids $pid"
wait_port 40014 "$dir/h2p.log"
down=$(curl -sS -o /dev/null -w '%{http_code} %{speed_download}' --max-time 60 -x socks5h://127.0.0.1:40014 'https://speed.cloudflare.com/__down?bytes=20000000') || true
echo "h2 download 20 MB: HTTP ${down%% *}, $(echo "${down#* }" | awk '{ printf "%.2f MB/s", $1 / 1e6 }')"
kill "$pid" 2> /dev/null || true

echo "== the WireGuard leg (issue 152; a report, not a check yet)"
if "$cfrs" warp --transport wireguard probe > "$dir/wgp.out" 2>&1; then
    grep -E '^(tunnel|OK|exit) ' "$dir/wgp.out" | head -4
    echo "wireguard probe: ok"
    "$cfrs" warp --transport wireguard proxy --listen tcp://127.0.0.1:40015 --run-for 120 > "$dir/wgproxy.log" 2>&1 &
    pid=$!
    pids="$pids $pid"
    wait_port 40015 "$dir/wgproxy.log"
    down=$(curl -sS -o /dev/null -w '%{http_code} %{speed_download}' --max-time 60 -x socks5h://127.0.0.1:40015 'https://speed.cloudflare.com/__down?bytes=20000000') || true
    echo "wireguard download 20 MB: HTTP ${down%% *}, $(echo "${down#* }" | awk '{ printf "%.2f MB/s", $1 / 1e6 }')"
    up=$(curl -sS -o /dev/null -w '%{http_code} %{speed_upload}' --max-time 90 -x socks5h://127.0.0.1:40015 --data-binary @"$dir/up16" https://speed.cloudflare.com/__up) || true
    echo "wireguard upload 16 MiB: HTTP ${up%% *}, $(echo "${up#* }" | awk '{ printf "%.2f MB/s", $1 / 1e6 }')"
    kill "$pid" 2> /dev/null || true
else
    echo "wireguard probe: FAIL"
    sed -E 's/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|t\.[0-9a-f-]{8,}/<id>/g' "$dir/wgp.out" | tail -5
fi

echo "== QUIC on the front door (issue 157)"
python3 scripts/quic-vn.py 162.159.198.2 443 5 || true
python3 scripts/quic-vn.py 2606:4700:103::2 443 5 || true

for log in "$dir/rules.log" "$dir/fwd.log" "$dir/nested.log"; do
    if grep -q panicked "$log"; then grep -A2 panicked "$log"; exit 1; fi
done
echo "batch 2 live checks: ok"
