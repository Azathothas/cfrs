#!/bin/sh
# Build an IPv6-only host for a test of cfrs (issue 163), from the
# IPv6-only kit of 2026-11-02. Needs root (sudo), ip, ip6tables and iptables.
#
#   sh scripts/v6only/up.sh BINARY
#
# The result:
#
#   runner      untouched routes; NAT44 for the uplink
#   v6up        IPv4 to the runner (veth, 10.200.77.0/30); cfrs warp tun
#               --default-route makes cfrs0, so v6up has IPv6 and IPv4
#               through WARP; IPv6 forwarding, NAT66 out of cfrs0
#   v6only      IPv6 only (fd00:77::2/64, default route via v6up); no IPv4
#               route and no IPv4 address but 127.0.0.1; resolver
#               2606:4700:4700::1111
#
# scripts/v6only/run.sh runs a command in v6only; scripts/v6only/down.sh
# removes it all. The script prints no address of WARP (the log of a
# workflow is public).
set -eu

bin=$(readlink -f "${1:?usage: up.sh BINARY}")
up=v6up
ns=v6only
log=${V6ONLY_LOG:-/tmp/v6only-tun.log}

say() { printf '==> %s\n' "$*"; }

# The uplink: IPv4 from the runner through a veth and NAT44.
if ! sudo ip netns list | awk '{print $1}' | grep -qx "$up"; then
    say "the uplink namespace $up"
    sudo ip netns add "$up"
    sudo ip link add vh-v6up type veth peer name vc-v6up
    sudo ip link set vc-v6up netns "$up"
    sudo ip addr add 10.200.77.1/30 dev vh-v6up
    sudo ip link set vh-v6up up
    sudo ip netns exec "$up" ip link set lo up
    sudo ip netns exec "$up" ip addr add 10.200.77.2/30 dev vc-v6up
    sudo ip netns exec "$up" ip link set vc-v6up up
    sudo ip netns exec "$up" ip route add default via 10.200.77.1
    sudo sysctl -qw net.ipv4.ip_forward=1
    sudo iptables -t nat -C POSTROUTING -s 10.200.77.0/30 -j MASQUERADE 2> /dev/null ||
        sudo iptables -t nat -A POSTROUTING -s 10.200.77.0/30 -j MASQUERADE
    sudo iptables -C FORWARD -i vh-v6up -j ACCEPT 2> /dev/null ||
        sudo iptables -I FORWARD -i vh-v6up -j ACCEPT
    sudo iptables -C FORWARD -o vh-v6up -j ACCEPT 2> /dev/null ||
        sudo iptables -I FORWARD -o vh-v6up -j ACCEPT
    sudo mkdir -p "/etc/netns/$up"
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' | sudo tee "/etc/netns/$up/resolv.conf" > /dev/null
fi

# WARP in the uplink: the TUN cfrs0 with the default routes of both
# families. The proxy variables of the runner do not reach the namespace.
if ! sudo ip netns exec "$up" ip -6 route | grep -q '^::/1 dev cfrs0'; then
    say "cfrs warp tun --default-route in $up"
    # The log belongs to this user, not to root (SC2024 is wanted).
    # shellcheck disable=SC2024
    sudo ip netns exec "$up" env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy \
        -u ALL_PROXY -u all_proxy CFRS_STATE_DIR=none RUST_LOG=cfrs=info \
        setsid "$bin" warp --ephemeral tun --default-route --interface cfrs0 > "$log" 2>&1 &
    i=0
    until sudo ip netns exec "$up" ip -6 route | grep -q '^::/1 dev cfrs0'; do
        i=$((i + 1))
        if [ "$i" -gt 60 ]; then
            sed -E 's/[0-9a-f]{8}-[0-9a-f-]{27}/<id>/g' "$log" | tail -20
            say "warp tun is not up after 60 s"
            exit 1
        fi
        sleep 1
    done
fi
say "cfrs0 is up in $up"

# The IPv6-only namespace behind the uplink.
if ! sudo ip netns list | awk '{print $1}' | grep -qx "$ns"; then
    say "the IPv6-only namespace $ns"
    sudo ip netns add "$ns"
    sudo ip link add vh-v6only type veth peer name vc-v6only
    sudo ip link set vh-v6only netns "$up"
    sudo ip link set vc-v6only netns "$ns"
    sudo ip netns exec "$up" sysctl -qw net.ipv6.conf.all.forwarding=1
    sudo ip netns exec "$up" ip -6 addr add fd00:77::1/64 dev vh-v6only nodad
    sudo ip netns exec "$up" ip link set vh-v6only up
    sudo ip netns exec "$ns" ip link set lo up
    sudo ip netns exec "$ns" ip -6 addr add fd00:77::2/64 dev vc-v6only nodad
    sudo ip netns exec "$ns" ip link set vc-v6only up
    sudo ip netns exec "$ns" ip -6 route add default via fd00:77::1
    sudo ip netns exec "$up" ip6tables -t nat -A POSTROUTING -s fd00:77::/64 -o cfrs0 -j MASQUERADE
    sudo mkdir -p "/etc/netns/$ns"
    printf 'nameserver 2606:4700:4700::1111\nnameserver 2001:4860:4860::8888\n' |
        sudo tee "/etc/netns/$ns/resolv.conf" > /dev/null
fi

# The checks of the host: no IPv4 route, and IPv6 works.
routes4=$(sudo ip netns exec "$ns" ip -4 route | wc -l)
say "IPv4 routes in $ns: $routes4"
[ "$routes4" -eq 0 ] || { say "$ns has an IPv4 route"; exit 1; }
i=0
until sudo ip netns exec "$ns" curl -fsS -6 --max-time 10 -o /dev/null https://[2606:4700:4700::1111]/cdn-cgi/trace; do
    i=$((i + 1))
    [ "$i" -lt 10 ] || { say "no IPv6 egress from $ns"; exit 1; }
    sleep 2
done
say "up: IPv6 only in $ns (scripts/v6only/run.sh CMD)"
