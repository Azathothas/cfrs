#!/usr/bin/env python3
"""An HTTP CONNECT proxy for the live check. It writes the target of each
CONNECT to LOG (one line each) and relays the bytes.

  python3 -I scripts/connect-proxy.py PORT LOG
"""

import socket
import sys
import threading


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


def serve(client: socket.socket, log: str, lock: threading.Lock) -> None:
    head = b""
    while b"\r\n\r\n" not in head:
        data = client.recv(4096)
        if not data:
            client.close()
            return
        head += data
        if len(head) > 16384:
            client.close()
            return
    line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = line.split()
    if len(parts) < 2 or parts[0] != "CONNECT":
        client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        client.close()
        return
    target = parts[1]
    host, _, port = target.rpartition(":")
    with lock:
        with open(log, "a", encoding="utf-8") as f:
            f.write(target + "\n")
    try:
        upstream = socket.create_connection((host.strip("[]"), int(port)), timeout=15)
        upstream.settimeout(None)
    except OSError:
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        client.close()
        return
    client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    rest = head.split(b"\r\n\r\n", 1)[1]
    if rest:
        upstream.sendall(rest)
    threading.Thread(target=relay, args=(client, upstream), daemon=True).start()
    relay(upstream, client)


def main() -> int:
    port, log = int(sys.argv[1]), sys.argv[2]
    lock = threading.Lock()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(64)
    while True:
        client, _ = listener.accept()
        threading.Thread(target=serve, args=(client, log, lock), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
