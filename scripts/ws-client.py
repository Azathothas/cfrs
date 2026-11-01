"""A WebSocket client for scripts/live-throughput.sh: it sends a GET of the
file through a --forward endpoint and counts the bytes of the answer. It
measures the server half of the bridge with no `cfrs connect`.

    python3 -I scripts/ws-client.py wss://HOST/__cfrs/ws SIZE_MIB
"""

import asyncio
import sys
import time

import websockets

URL = sys.argv[1]
SIZE = int(sys.argv[2]) * 1048576


async def main():
    async with websockets.connect(URL, max_size=None, compression=None) as ws:
        start = time.monotonic()
        await ws.send(b"GET /big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        got = 0
        while got < SIZE:
            message = await ws.recv()
            got += len(message)
        took = time.monotonic() - start
        print(f"python-ws GET {SIZE / 1048576 / took:.2f} MiB/s ({got} bytes, {took:.2f} s)")


asyncio.run(main())
