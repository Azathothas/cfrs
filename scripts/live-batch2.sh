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
python3 -m http.server 18080 --bind 127.0.0.1 > /dev/null 2>&1 &
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
curl -fsS --max-time 10 -o /dev/null -w 'direct to the host: %{http_code}\n' -x socks5h://127.0.0.1:40010 http://127.0.0.1:18080/
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

echo "== QUIC on the front door (issue 157)"
python3 scripts/quic-vn.py 162.159.198.2 443 5 || true
python3 scripts/quic-vn.py 2606:4700:103::2 443 5 || true

for log in "$dir/rules.log" "$dir/fwd.log" "$dir/nested.log"; do
    if grep -q panicked "$log"; then grep -A2 panicked "$log"; exit 1; fi
done
echo "batch 2 live checks: ok"
