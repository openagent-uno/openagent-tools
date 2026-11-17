"""Private versioned HTTP transport. Hosts authorize originals before posting."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import sys
from threading import BoundedSemaphore

from . import MAX_BYTES, inspect, result, text

SLOTS = BoundedSemaphore(2)


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass  # Never put media, filenames or peer inputs in logs.

    def send_json(self, status, value):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.send_json(200 if self.path == "/health" else 404, {"version": "1"})

    def do_POST(self):
        if self.path != "/v1/inspect":
            return self.send_json(404, {"version": "1"})
        if self.headers.get("Transfer-Encoding"):
            return self.send_json(400, result("unreadable", text("A bounded Content-Length is required.")))
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = 0
        if not 0 < size <= MAX_BYTES:
            return self.send_json(413, result("unreadable", text("Attachment exceeds the byte limit or is empty.")))
        if not SLOTS.acquire(blocking=False):
            return self.send_json(503, result("unreadable", text("Media inspection is busy.")))
        try:
            data = self.rfile.read(size)
            if len(data) != size:
                return self.send_json(400, result("unreadable", text("Incomplete attachment.")))
            mime = self.headers.get("Content-Type", "application/octet-stream")[:128]
            proc = subprocess.run(
                [sys.executable, "-m", "openagent_media_inspector", "--inspect", mime],
                input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=32,
                check=True,
            )
            self.send_json(200, json.loads(proc.stdout))
        except (subprocess.SubprocessError, OSError, ValueError):
            self.send_json(200, result("unreadable", text("Attachment could not be decoded within the runtime limits.")))
        finally:
            SLOTS.release()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--inspect":
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (28, 30))
        print(json.dumps(inspect(sys.stdin.buffer.read(MAX_BYTES + 1), sys.argv[2])))
    else:
        ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
