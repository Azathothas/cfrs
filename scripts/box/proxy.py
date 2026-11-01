#!/usr/bin/env python3
"""The policy proxy of the test box: an HTTP CONNECT proxy with the policy of
the measured sandbox (docs/target-environment.md).

* CONNECT to a name on port 443 is allowed.
* CONNECT to an IP literal is refused: "403 not a public host".
* CONNECT to another port is refused: "403 not on the egress allowlist".
* --allow HOST:PORT opens one more target (for example the MASQUE front
  door 162.159.198.2:443). --open allows each target (a planted wrong
  policy, for the check of the probe).
* A request that is not CONNECT gets 405.

Each decision is one line in LOG: "allow HOST:PORT" or "refuse HOST:PORT".

  python3 -I scripts/box/proxy.py PORT LOG [--allow HOST:PORT]... [--open]
"""

import ipaddress
import socket
import sys
import threading

PORT = int(sys.argv[1])
LOG = sys.argv[2]
ALLOW = set()
OPEN = False
args = sys.argv[3:]
while args:
    a = args.pop(0)
    if a == "--allow":
        ALLOW.add(args.pop(0).lower())
    elif a == "--open":
        OPEN = True
    else:
        sys.exit(f"proxy.py: unknown argument {a}")
LOCK = threading.Lock()


def log(line: str) -> None:
    with LOCK, open(LOG, "a") as f:
        f.write(line + "\n")


def decide(host: str, port: int):
    """None to allow, else the refusal text."""
    target = f"{host}:{port}".lower()
    if OPEN or target in ALLOW:
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return "not a public host"
    except ValueError:
        pass
    if port != 443:
        return "not on the egress allowlist"
    return None


def relay(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def answer(client: socket.socket, status: str, body: str) -> None:
    data = body.encode()
    client.sendall(
        f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {len(data)}\r\n"
        f"Connection: close\r\n\r\n".encode() + data
    )
    client.close()


def serve(client: socket.socket) -> None:
    head = b""
    while b"\r\n\r\n" not in head:
        data = client.recv(4096)
        if not data or len(head) > 16384:
            client.close()
            return
        head += data
    line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = line.split()
    if len(parts) < 3 or parts[0] != "CONNECT":
        answer(client, "405 Method Not Allowed", "CONNECT only\n")
        return
    authority = parts[1]
    host, _, port = authority.rpartition(":")
    try:
        port = int(port)
    except ValueError:
        answer(client, "400 Bad Request", "bad authority\n")
        return
    why = decide(host, port)
    if why is not None:
        log(f"refuse {authority}")
        answer(client, "403 Forbidden", why + "\n")
        return
    try:
        upstream = socket.create_connection((host.strip("[]"), port), timeout=10)
        upstream.settimeout(None)
    except OSError as e:
        log(f"fail {authority}")
        answer(client, "502 Bad Gateway", f"{e}\n")
        return
    log(f"allow {authority}")
    client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    rest = head.split(b"\r\n\r\n", 1)[1]
    if rest:
        upstream.sendall(rest)
    threading.Thread(target=relay, args=(client, upstream), daemon=True).start()
    relay(upstream, client)


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", PORT))
listener.listen(64)
while True:
    c, _ = listener.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
