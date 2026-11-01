#!/bin/sh
# Measure facts of the Cloudflare edge that docs/protocol.md section 6
# records: the SRV answer, the addresses, TLS on TCP 7844 with each SNI,
# ALPN and key group, the ports 443, 8443 and 80, and the first bytes that
# the edge sends after the handshake. It needs dig, openssl and timeout, and
# a host that reaches TCP 7844 (a GitHub runner). It opens no tunnel.
#
#   sh tools/edge-facts.sh [ROOTS_PEM]
#
# Each line is "fact: result". The exit code is 1 when one of the facts that
# cfrs needs is not true: TLS 1.3 on 7844 with SNI h2.cftunnel.com and no
# ALPN verifies against the edge roots, and the edge sends the HTTP/2
# preface first.
set -u
roots=${1:-src/cloudflare/cf-edge-roots.pem}
rc=0

echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "srv _v2-origintunneld._tcp.argotunnel.com: $(dig +short SRV _v2-origintunneld._tcp.argotunnel.com | sort | tr '\n' ' ')"
for region in region1 region2; do
    addrs=$(dig +short A "$region.v2.argotunnel.com" | sort -t. -k4 -n)
    echo "a $region.v2.argotunnel.com: $(echo "$addrs" | grep -c .) addresses: $(echo "$addrs" | tr '\n' ' ')"
done
ip=$(dig +short A region1.v2.argotunnel.com | sort | head -1)
[ -n "$ip" ] || { echo "no address for region1.v2.argotunnel.com"; exit 1; }

# tls LABEL PORT ARGUMENT...: one handshake; print verification, protocol,
# group, ALPN and the time.
tls() {
    label=$1 port=$2
    shift 2
    start=$(date +%s%N)
    out=$(timeout 10 openssl s_client -connect "$ip:$port" -CAfile "$roots" -brief "$@" < /dev/null 2>&1)
    end=$(date +%s%N)
    ms=$(( (end - start) / 1000000 ))
    verify=$(echo "$out" | grep -oE 'Verification: [A-Za-z ]+|verify error:[^:]*:[^ ]*' | head -1)
    proto=$(echo "$out" | grep -oE 'Protocol version: [^ ]+' | head -1)
    group=$(echo "$out" | grep -oE '(Negotiated TLS1.3 group|Server Temp Key): [^,]+' | head -1)
    alpn=$(echo "$out" | grep -oE 'ALPN protocol: [^ ]+' | head -1)
    echo "tls $label ($ip:$port): ${verify:-no verification line}; ${proto:-no TLS}; ${group:-}; ${alpn:-no ALPN}; ${ms} ms"
}

tls "sni=h2.cftunnel.com" 7844 -servername h2.cftunnel.com
tls "sni=probe.cftunnel.com" 7844 -servername probe.cftunnel.com
tls "sni=region1.v2.argotunnel.com" 7844 -servername region1.v2.argotunnel.com
tls "no sni" 7844 -noservername
tls "sni=h2.cftunnel.com alpn=h2" 7844 -servername h2.cftunnel.com -alpn h2
tls "sni=h2.cftunnel.com group=X25519" 7844 -servername h2.cftunnel.com -groups X25519
tls "sni=h2.cftunnel.com group=P-256" 7844 -servername h2.cftunnel.com -groups P-256
tls "port 443" 443 -servername h2.cftunnel.com
tls "port 8443" 8443 -servername h2.cftunnel.com
tls "port 80" 80 -servername h2.cftunnel.com

# The fact that cfrs needs: TLS 1.3, verified, with no ALPN.
need=$(timeout 10 openssl s_client -connect "$ip:7844" -servername h2.cftunnel.com -CAfile "$roots" -brief < /dev/null 2>&1)
if echo "$need" | grep -q 'Verification: OK' && echo "$need" | grep -q 'TLSv1.3' && ! echo "$need" | grep -q 'ALPN protocol'; then
    echo "need: TLS 1.3 with SNI h2.cftunnel.com and no ALPN verifies against $roots: yes"
else
    echo "need: TLS 1.3 with SNI h2.cftunnel.com and no ALPN verifies against $roots: NO"
    rc=1
fi

# The first bytes after the handshake: the edge is the HTTP/2 client.
first=$( (sleep 4) | timeout 6 openssl s_client -connect "$ip:7844" -servername h2.cftunnel.com -CAfile "$roots" -quiet 2> /dev/null | head -c 14 | tr -c '[:print:]' '.')
echo "first bytes from the edge on 7844: \"$first\""
if [ "$first" = "PRI * HTTP/2.0" ]; then
    echo "need: the edge sends the HTTP/2 preface first: yes"
else
    echo "need: the edge sends the HTTP/2 preface first: NO"
    rc=1
fi
exit "$rc"
