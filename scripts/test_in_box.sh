#!/bin/sh
# The test box: run podnet as a Unix user whose only egress is a policy proxy,
# as on the sandbox of docs/target-environment.md. It needs Linux, sudo and
# iptables with the owner match (a GitHub runner). It makes no Podman box.
#
#   sh scripts/test_in_box.sh PODNET
#
# The box:
#   * the user podnetbox may open TCP to 127.0.0.1:BOX_PROXY_PORT (the proxy)
#     and to 127.0.0.1:BOX_SILENT_PORT (a fault stand-in) only. Each other
#     packet of the user is refused: no UDP, no direct TCP, no DNS (the
#     system resolver is UDP to 127.0.0.53), no IPv6;
#   * scripts/box/proxy.py: names on 443 and the MASQUE front door by
#     address, with the refusal texts of the sandbox for the rest.
# The box is checked first (scripts/box/probe.py against
# scripts/box/report.txt); a planted wrong policy must fail that check.
#
# Each step prints ok, FAIL or skip. The end is a count. Exit 1 on a FAIL,
# and at once when the binary does not run. BOX_PLANT=exit3 puts a binary
# that exits 3 in the box, to test that the box exits 1.
#
# The tunnel hosts are masked: each podnet command runs through
# scripts/live-run.sh.
set -u
podnet=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
box=podnetbox
port=${BOX_PROXY_PORT:-3128}
silent=${BOX_SILENT_PORT:-3129}
work=$(mktemp -d)
chmod 777 "$work"
# The box user reads the scripts from the work directory: the home of the
# runner may not be readable to other users.
cp -r "$here" "$work/scripts"
here=$work/scripts
cd "$work" || exit 1
pass=0 fail=0 skip=0

cleanup() {
    sudo iptables -D OUTPUT -m owner --uid-owner "$box" -j PODNETBOX 2> /dev/null
    sudo iptables -F PODNETBOX 2> /dev/null
    sudo iptables -X PODNETBOX 2> /dev/null
    sudo ip6tables -D OUTPUT -m owner --uid-owner "$box" -j REJECT 2> /dev/null
    jobs -p | xargs -r kill 2> /dev/null
}
trap cleanup EXIT

verdict() { # verdict NAME ok|FAIL|skip WHY
    case $2 in
        ok) pass=$((pass + 1)) ;;
        FAIL) fail=$((fail + 1)) ;;
        *) skip=$((skip + 1)) ;;
    esac
    echo "box step $1: $2${3:+ ($3)}"
}

# --- the box ---------------------------------------------------------------
id "$box" > /dev/null 2>&1 || sudo useradd -m "$box"
home=$(getent passwd "$box" | cut -d: -f6)
if [ "${BOX_PLANT:-}" = exit3 ]; then
    printf '#!/bin/sh\nexit 3\n' > "$work/planted"
    sudo install -m 755 "$work/planted" "$home/podnet"
else
    sudo install -m 755 "$podnet" "$home/podnet"
fi
sudo iptables -N PODNETBOX
sudo iptables -A PODNETBOX -o lo -p tcp -d 127.0.0.1 --dport "$port" -j ACCEPT
sudo iptables -A PODNETBOX -o lo -p tcp -d 127.0.0.1 --dport "$silent" -j ACCEPT
sudo iptables -A PODNETBOX -p tcp -j REJECT --reject-with tcp-reset
sudo iptables -A PODNETBOX -j REJECT
sudo iptables -I OUTPUT -m owner --uid-owner "$box" -j PODNETBOX
sudo ip6tables -I OUTPUT -m owner --uid-owner "$box" -j REJECT

proxy() { # proxy PORT ARGUMENT... : start the policy proxy
    p=$1
    shift
    python3 -I "$here/box/proxy.py" "$p" "$work/proxy-$p.log" "$@" &
    sleep 1
}
proxy "$port" --allow 162.159.198.2:443

# A fault stand-in for the edge: it accepts and says nothing.
python3 -I -c '
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(16); held = []
while True:
    c, _ = s.accept(); held.append(c)
' "$silent" &

inbox() { # inbox COMMAND...: run as the box user, with the proxy
    sudo -u "$box" env -i HOME="$home" PATH=/usr/bin:/bin LANG=C.UTF-8 \
        HTTPS_PROXY="http://127.0.0.1:$port" PODNET_STATE_DIR="$home/state" "$@"
}

# --- the steps -------------------------------------------------------------
if inbox "$home/podnet" --version > version.out 2>&1; then
    verdict binary ok "$(cat version.out)"
else
    rc=$?
    verdict binary FAIL "podnet --version exited $rc in the box"
    echo "box: $pass ok, $fail FAIL, $skip skip"
    exit 1
fi

if inbox python3 -I "$here/box/probe.py" "$port" "$here/box/report.txt"; then
    verdict probe ok "the box matches scripts/box/report.txt"
else
    verdict probe FAIL "the box does not match scripts/box/report.txt"
fi

proxy $((port + 10)) --open
if inbox python3 -I "$here/box/probe.py" $((port + 10)) "$here/box/report.txt" > planted.out 2>&1; then
    verdict planted-policy FAIL "the probe passed with a proxy that allows each target"
else
    verdict planted-policy ok "the probe fails with a proxy that allows each target"
fi

if inbox sh "$here/live-run.sh" doctor "$home/podnet" doctor --samples 3 --json; then
    if jq -e '(.legs[] | select(.leg == "quic+warp") | .status == "ok")
        and (.legs[] | select(.leg == "http2") | .status == "fail")
        and (.legs[] | select(.leg == "quic") | .status == "fail")' doctor.out > /dev/null; then
        verdict doctor ok "quic and http2 refused, quic+warp ok"
    else
        verdict doctor FAIL "the legs are not quic refused, http2 refused, quic+warp ok"
    fi
else
    verdict doctor FAIL "podnet doctor exited non-zero: no leg can work"
fi

# Negative control: the direct legs cannot work in the box.
start=$(date +%s)
if inbox sh "$here/live-run.sh" direct timeout 90 "$home/podnet" demo --exit-on-verify --transport direct; then
    verdict direct-fails FAIL "--transport direct registered in the box"
else
    verdict direct-fails ok "--transport direct failed after $(($(date +%s) - start)) s"
fi

# The leg under test: quic+warp through the proxy, with the fetch of the
# public URL as the payload proof (demo checks the body "Hello, world").
rc=0
inbox sh "$here/live-run.sh" warp timeout 240 "$home/podnet" demo --exit-on-verify || rc=$?
if [ "$rc" = 0 ]; then
    if grep -q 'leg=quic+warp' warp.err; then
        verdict warp ok "quic+warp registered through the proxy, and the URL answered"
    else
        verdict warp FAIL "demo passed, but not on quic+warp"
    fi
elif [ "$rc" = 75 ] && grep -q '1015' warp.err; then
    # Issue 182: the provision service limits the address of the runner
    # (HTTP 429, error 1015). No leg was tried: not a fault of podnet.
    verdict warp skip "the quick-tunnel service refused the provision for now (429, error 1015)"
else
    verdict warp FAIL "demo failed in the box (exit $rc)"
fi

# Negative control: with the MASQUE address refused, no leg is left.
proxy $((port + 20))
if inbox env HTTPS_PROXY="http://127.0.0.1:$((port + 20))" sh "$here/live-run.sh" nowarp \
    timeout 120 "$home/podnet" demo --exit-on-verify; then
    verdict no-masque FAIL "demo registered with the MASQUE address refused"
else
    verdict no-masque ok "demo failed with the MASQUE address refused"
fi

# Fault stand-in: an edge that accepts and says nothing. The HTTP/2 leg
# must fail in its time limit, not hang.
start=$(date +%s)
# A named-tunnel token: no quick tunnel is provisioned.
token=eyJhIjoiYWNjb3VudCIsInQiOiJmZmQ4NmJkNS0xYmZmLTQ1NmItOGMyYy03NWEwMTRjZGM0YzgiLCJzIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOD0ifQ==
inbox env NO_PROXY=127.0.0.1 PODNET_EDGE="127.0.0.1:$silent" TUNNEL_TOKEN="$token" \
    sh "$here/live-run.sh" silent timeout 120 "$home/podnet" tunnel --hello-world --protocol http2 --transport direct
rc=$?
took=$(($(date +%s) - start))
if [ "$rc" -eq 124 ]; then
    verdict silent-edge FAIL "podnet hung on a silent peer for 120 s"
elif [ "$rc" -ne 0 ]; then
    verdict silent-edge ok "podnet failed after $took s (exit $rc) on a silent peer"
else
    verdict silent-edge FAIL "podnet exited 0 with a silent peer"
fi

if [ -e /dev/net/tun ]; then
    verdict no-tun skip "/dev/net/tun exists on this runner; the box cannot remove it"
fi

echo "box: $pass ok, $fail FAIL, $skip skip"
[ "$fail" -eq 0 ]
