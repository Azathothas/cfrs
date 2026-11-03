#!/bin/sh
# Remove what scripts/v6only/up.sh made: the namespaces, the veths, the NAT
# rules of the runner, the resolvers and the warp tun process. The routes of
# the runner were never changed.
#
#   sh scripts/v6only/down.sh
set -u

say() { printf '==> %s\n' "$*"; }

say "stopping warp tun"
for pid in $(sudo ip netns pids v6up 2> /dev/null); do
    sudo kill "$pid" 2> /dev/null
done
i=0
while sudo ip netns pids v6up 2> /dev/null | grep -q .; do
    i=$((i + 1))
    [ "$i" -lt 10 ] || break
    sleep 1
done

say "removing the namespaces"
sudo ip netns del v6only 2> /dev/null
sudo ip netns del v6up 2> /dev/null
sudo ip link del vh-v6up 2> /dev/null
sudo rm -rf /etc/netns/v6only /etc/netns/v6up

# Each matching rule goes: -D removes the first match only.
say "removing the NAT44 and forward rules"
while sudo iptables -t nat -C POSTROUTING -s 10.200.77.0/30 -j MASQUERADE 2> /dev/null; do
    sudo iptables -t nat -D POSTROUTING -s 10.200.77.0/30 -j MASQUERADE || break
done
for dir in -i -o; do
    while sudo iptables -C FORWARD "$dir" vh-v6up -j ACCEPT 2> /dev/null; do
        sudo iptables -D FORWARD "$dir" vh-v6up -j ACCEPT || break
    done
done
say "down: $(sudo ip netns list | grep -c '^v6' || true) namespaces of the lab are left"
