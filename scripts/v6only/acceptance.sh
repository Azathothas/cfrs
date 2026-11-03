#!/bin/sh
# The checks of cfrs on the IPv6-only host of scripts/v6only/up.sh (issue
# 163), from the IPv6-only kit of 2026-11-02. Each check that fails stops
# the script (exit 1). The output goes through scripts/live-run.sh, which
# masks tunnel names, UUIDs and the WARP device.
#
#   sh scripts/v6only/acceptance.sh BINARY
set -eu

bin=$(readlink -f "${1:?usage: acceptance.sh BINARY}")
here=$(cd "$(dirname "$0")" && pwd)
run="sh $here/run.sh"
live="sh $here/../live-run.sh"

say() { printf '\n### %s\n' "$*"; }

say "the host has no IPv4 route"
$run python3 -c "
import errno, socket
s = socket.socket()
try:
    s.connect(('1.1.1.1', 443))
    print('ipv4: connected'); raise SystemExit(1)
except OSError as e:
    print('ipv4:', errno.errorcode.get(e.errno, e.errno))
    raise SystemExit(0 if e.errno == errno.ENETUNREACH else 1)
"

say "doctor: the IPv6 front door and the leg quic+warp"
$run "$bin" doctor --json --samples 3 > v6doctor.json || true
jq -c '.paths[] | select(.id == "masque" or .id == "masque-v6") | {id, verdict}' v6doctor.json
jq -c '.legs[] | {leg, verdict}' v6doctor.json
jq -e '.legs[] | select(.leg == "quic+warp") | .verdict == "ok"' v6doctor.json

say "a quick tunnel with the built-in origin"
$live v6demo $run "$bin" demo --exit-on-verify

say "a quick tunnel with no working system resolver (DoH over IPv6)"
saved=$(sudo cat /etc/netns/v6only/resolv.conf)
printf 'nameserver 2001:db8::53\n' | sudo tee /etc/netns/v6only/resolv.conf > /dev/null
status=0
$live v6doh $run "$bin" demo --exit-on-verify || status=$?
printf '%s\n' "$saved" | sudo tee /etc/netns/v6only/resolv.conf > /dev/null
[ "$status" -eq 0 ]

say "warp tun --default-route with the IPv6 front door"
sudo ip netns exec v6only env CFRS_STATE_DIR=none RUST_LOG=cfrs=info \
    timeout 60 "$bin" warp --ephemeral --masque-endpoint '[2606:4700:103::2]:443' \
    tun --default-route --interface cfrs1 > v6tun.out 2> v6tun.err &
tunpid=$!
i=0
until sudo ip netns exec v6only ip -6 route | grep -q '^::/1 dev cfrs1'; do
    i=$((i + 1))
    if [ "$i" -gt 45 ] || ! kill -0 "$tunpid" 2> /dev/null; then
        sed -E 's/[0-9a-f]{8}-[0-9a-f-]{27}/<id>/g' v6tun.err | tail -15
        echo "warp tun --default-route is not up in the IPv6-only host"
        exit 1
    fi
    sleep 1
done
grep -E '^cfrs: routes' v6tun.out | sed -E 's/[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}/<v6>/g'
sudo ip netns exec v6only ip -6 route | grep -E '^2606:4700:103::2 ' > /dev/null
echo "the front door has a host route outside cfrs1"
sudo ip netns exec v6only curl -fsS -4 --max-time 20 https://1.1.1.1/cdn-cgi/trace | grep '^warp='
sudo kill -INT "$tunpid" 2> /dev/null || true
wait "$tunpid" 2> /dev/null || true
if sudo ip netns exec v6only ip -6 route | grep -q 'cfrs1'; then
    echo "routes of cfrs1 are left"
    exit 1
fi
echo "the routes of cfrs1 are gone"

say "survive: a detached tunnel is started again after a kill"
$run "$bin" demo --detach --name v6survive --ready-timeout 120 > v6survive.json 2> v6survive.err
pid1=$(tail -1 v6survive.json | jq -r '.pid')
sudo kill -9 "$pid1"
i=0
while :; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || { echo "no new instance after 120 s"; exit 1; }
    sleep 2
    pid2=$($run "$bin" ps --json | jq -r '.instances[] | select(.name == "v6survive") | select(.state == "ready") | .pid')
    [ -n "$pid2" ] && [ "$pid2" != "$pid1" ] && break
done
echo "the supervisor started the tunnel again after $((i * 2)) s"
$run "$bin" stop v6survive > /dev/null
say "IPv6-only checks: all passed"
