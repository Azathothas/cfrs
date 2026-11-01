"""An HTTP/1.1 origin for the throughput test of scripts/live-throughput.sh.

GET /N.bin gives N MiB of a fixed pattern; another GET gives "ok". POST
reads the body and gives its length.

    python3 -I scripts/origin-sink.py PORT
"""

import http.server
import re
import sys

PORT = int(sys.argv[1])
CHUNK = bytes(range(256)) * 256  # 64 KiB


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        m = re.fullmatch(r"/(\d{1,4})\.bin", self.path)
        if not m:
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        size = int(m.group(1)) * 1048576
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        left = size
        while left > 0:
            n = min(left, len(CHUNK))
            self.wfile.write(CHUNK[:n])
            left -= n

    def do_POST(self):
        left = int(self.headers.get("Content-Length", "0"))
        got = 0
        while left > 0:
            chunk = self.rfile.read(min(left, 1 << 16))
            if not chunk:
                break
            got += len(chunk)
            left -= len(chunk)
        body = f"{got}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
