#!/usr/bin/env python3
"""Check that the test box has the properties of the measured sandbox,
before any test of cfrs runs in it. Each line of REPORT is "NAME EXPECTED".
Each probe gives a result; the probe prints "ok" or "FAIL" for each line,
and exits 1 when one result is not the expected one.

  python3 -I scripts/box/probe.py PROXY_PORT REPORT
"""

import socket
import sys

PROXY = ("127.0.0.1", int(sys.argv[1]))
REPORT = sys.argv[2]


def direct_tcp():
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close()
        return "open"
    except OSError:
        return "refused"


def udp_dns():
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03api\x0btrycloudflare\x03com\x00\x00\x01\x00\x01"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(query, ("1.1.1.1", 53))
        s.recvfrom(512)
        return "answered"
    except OSError:
        return "refused"


def system_dns():
    try:
        socket.getaddrinfo("api.trycloudflare.com", 443)
        return "answered"
    except OSError:
        return "refused"


def connect(authority):
    """The status line and the body of the proxy answer to CONNECT."""
    try:
        s = socket.create_connection(PROXY, timeout=10)
    except OSError:
        return "no proxy"
    s.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
        code = status[1] if len(status) > 1 else "none"
        if code != "200":
            s.settimeout(2)
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    body += chunk
            except OSError:
                pass
            return f"{code} {body.decode('latin-1').strip()}".replace(" ", "_")
        return code
    finally:
        s.close()


PROBES = {
    "direct-tcp": direct_tcp,
    "udp-dns": udp_dns,
    "system-dns": system_dns,
    "proxy-name-443": lambda: connect("api.trycloudflare.com:443"),
    "proxy-ip-literal": lambda: connect("1.1.1.1:443"),
    "proxy-edge-7844": lambda: connect("region1.v2.argotunnel.com:7844"),
    "proxy-masque": lambda: connect("162.159.198.2:443"),
}

failed = 0
for line in open(REPORT):
    line = line.split("#", 1)[0].strip()
    if not line:
        continue
    name, expected = line.split()
    got = PROBES[name]()
    verdict = "ok" if got == expected else "FAIL"
    failed += verdict == "FAIL"
    print(f"probe {name}: {got} (expected {expected}): {verdict}")
print(f"probe: {failed} of the facts differ from {REPORT}")
sys.exit(1 if failed else 0)
