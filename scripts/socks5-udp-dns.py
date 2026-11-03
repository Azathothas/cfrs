#!/usr/bin/env python3
"""Send DNS queries through a SOCKS5 UDP ASSOCIATE and count the answers.

    python3 scripts/socks5-udp-dns.py HOST PORT DEST [COUNT]

DEST is IP:PORT (ATYP 1 or 4; an IPv6 address is in brackets) or NAME:PORT
(ATYP 3). Each query asks for the A record of example.com. The script
prints one line "udp DEST: N of COUNT answered" and exits 1 when no query
is answered. The live workflow uses it (issues 112 and 114).
"""

import ipaddress
import socket
import struct
import sys


def dest_header(dest):
    host, _, port = dest.rpartition(":")
    host = host.strip("[]")
    port = int(port)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode()
        return b"\x03" + bytes([len(name)]) + name + struct.pack(">H", port)
    if ip.version == 4:
        return b"\x01" + ip.packed + struct.pack(">H", port)
    return b"\x04" + ip.packed + struct.pack(">H", port)


def query(qid):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in b"example.com".split(b"."):
        q += bytes([len(label)]) + label
    return q + b"\x00" + struct.pack(">HH", 1, 1)


def main():
    host, port, dest = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    count = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    control = socket.create_connection((host, port), timeout=20)
    control.sendall(b"\x05\x01\x00")
    if control.recv(2) != b"\x05\x00":
        sys.exit("the proxy refused the method")
    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    reply = control.recv(262)
    if len(reply) < 10 or reply[1] != 0:
        sys.exit(f"UDP ASSOCIATE failed: {reply.hex()}")
    relay_ip = socket.inet_ntoa(reply[4:8])
    relay_port = struct.unpack(">H", reply[8:10])[0]
    if relay_ip == "0.0.0.0":
        relay_ip = host
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(6)
    header = b"\x00\x00\x00" + dest_header(dest)
    answered = 0
    for n in range(count):
        qid = 0x1200 + n
        udp.sendto(header + query(qid), (relay_ip, relay_port))
        try:
            while True:
                data, _ = udp.recvfrom(4096)
                atyp = data[3]
                skip = {1: 10, 4: 22}.get(atyp, 7 + data[4] if len(data) > 4 else 0)
                if data[skip:skip + 2] == struct.pack(">H", qid):
                    answered += 1
                    break
        except socket.timeout:
            pass
    print(f"udp {dest}: {answered} of {count} answered")
    control.close()
    sys.exit(0 if answered else 1)


if __name__ == "__main__":
    main()
