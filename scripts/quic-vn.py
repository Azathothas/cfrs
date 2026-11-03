#!/usr/bin/env python3
"""Ask a UDP endpoint for its QUIC versions (issue 157).

    python3 scripts/quic-vn.py HOST PORT [TIMEOUT]

The script sends one QUIC Initial-shaped packet (1200 bytes) with a
reserved version (RFC 9000, section 15). A QUIC server answers with a
Version Negotiation packet that lists the versions it speaks. The script
prints them and exits 0. With no answer, or another answer, it exits 1.
It uses the standard library only.
"""
import os
import socket
import sys

KNOWN = {
    0x00000001: "QUIC v1 (RFC 9000)",
    0x6B3343CF: "QUIC v2 (RFC 9369)",
    0xFF00001D: "draft-29",
}


def main():
    if len(sys.argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    host, port = sys.argv[1], int(sys.argv[2])
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0
    dcid, scid = os.urandom(8), os.urandom(8)
    packet = bytes([0xC0]) + bytes.fromhex("1a2a3a4a")
    packet += bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    packet += b"\x00" * (1200 - len(packet))
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (host, port))
        answer, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError) as err:
        print(f"quic {host}:{port}: no answer ({err})")
        return 1
    if len(answer) < 7 or not answer[0] & 0x80 or answer[1:5] != b"\x00\x00\x00\x00":
        print(f"quic {host}:{port}: an answer that is not Version Negotiation ({len(answer)} bytes)")
        return 1
    i = 5
    dlen = answer[i]
    echoed_dcid = answer[i + 1:i + 1 + dlen]
    i += 1 + dlen
    slen = answer[i]
    echoed_scid = answer[i + 1:i + 1 + slen]
    i += 1 + slen
    if echoed_dcid != scid or echoed_scid != dcid:
        print(f"quic {host}:{port}: the connection ids are not ours")
        return 1
    versions = [int.from_bytes(answer[j:j + 4], "big") for j in range(i, len(answer) - 3, 4)]
    names = [KNOWN.get(v, f"0x{v:08x}") for v in versions]
    print(f"quic {host}:{port}: version negotiation: " + ", ".join(names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
