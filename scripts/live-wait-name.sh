#!/bin/sh
# Wait until HOST resolves, for at most SECONDS (default 240). Ask the
# system resolver, then DoH at Cloudflare and at Google. When only DoH has
# the address, add it to /etc/hosts, so that curl, python and cfrs resolve
# the name the same way (issue 119: the system resolver of the runner keeps
# a negative answer for a new quick-tunnel name). The script prints no host
# and no address (the log is public).
#
#   sh scripts/live-wait-name.sh HOST [SECONDS]
set -u
host=$1
budget=${2:-240}
start=$(date +%s)
while :; do
    if getent hosts "$host" > /dev/null 2>&1; then
        echo "the name resolves (system) after $(($(date +%s) - start)) s"
        exit 0
    fi
    for doh in "https://1.1.1.1/dns-query" "https://8.8.8.8/resolve"; do
        ip=$(curl -fsS --max-time 5 -H 'accept: application/dns-json' "$doh?name=$host&type=A" 2> /dev/null |
            jq -r '[.Answer[]? | select(.type == 1) | .data][0] // empty' 2> /dev/null)
        if [ -n "$ip" ]; then
            echo "$ip $host" | sudo tee -a /etc/hosts > /dev/null
            echo "the name resolves (DoH) after $(($(date +%s) - start)) s; it is in /etc/hosts"
            exit 0
        fi
    done
    if [ $(($(date +%s) - start)) -ge "$budget" ]; then
        echo "the name does not resolve after $budget s"
        exit 1
    fi
    sleep 3
done
