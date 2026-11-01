"""An HTTP/1.1 origin for the throughput test of scripts/live-throughput.sh.

GET of any path gives the file; POST reads the body and gives its length.

    python3 -I scripts/origin-sink.py PORT FILE
"""

import http.server
import sys

PORT = int(sys.argv[1])
FILE = sys.argv[2]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        with open(FILE, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

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
