"""Private versioned HTTP transport. Hosts authorize originals before posting."""

import json
import os
from urllib.request import Request, urlopen, build_opener, ProxyHandler, HTTPRedirectHandler
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import sys
from threading import BoundedSemaphore

from . import MAX_BYTES, inspect, result, text

SLOTS = BoundedSemaphore(2)
GATEWAY = os.environ.get("OPENAGENT_MEDIA_DECODER_URL", "").rstrip("/")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


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
        shared = self.path == "/v1/inspect-url" and bool(GATEWAY)
        large = self.path == "/v1/inspect-video" and not GATEWAY
        if not shared and not large and (self.path != "/v1/inspect" or GATEWAY):
            return self.send_json(404, {"version": "1"})
        if self.headers.get("Transfer-Encoding"):
            return self.send_json(400, result("unreadable", text("A bounded Content-Length is required.")))
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = 0
        if not 0 < size <= (16384 if shared else 150_000_000 if large else MAX_BYTES):
            return self.send_json(413, result("unreadable", text("Attachment exceeds the byte limit or is empty.")))
        if not SLOTS.acquire(blocking=False):
            return self.send_json(503, result("unreadable", text("Media inspection is busy.")))
        try:
            data = self.rfile.read(size)
            if len(data) != size:
                return self.send_json(400, result("unreadable", text("Incomplete attachment.")))
            if shared:
                payload = json.loads(data)
                if not isinstance(payload, dict) or set(payload) != {"url"}:
                    raise ValueError("Only an authorized URL is accepted")
                # Fetching runs separately with a hard deadline (including DNS),
                # then forwards bytes only to the fixed private decoder.
                fetched = subprocess.run([sys.executable, "-m", "openagent_media_inspector", "--fetch"],
                    input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=125, check=True).stdout
                opener = build_opener(ProxyHandler({}), NoRedirect())
                with opener.open(Request(GATEWAY + "/v1/inspect-video", data=fetched,
                        headers={"Content-Type": "video/mp4"}), timeout=190) as response:
                    decoded = response.read(12_000_001)
                if len(decoded) > 12_000_000:
                    raise ValueError("Oversized decoder response")
                return self.send_json(200, json.loads(decoded))
            mime = self.headers.get("Content-Type", "application/octet-stream")[:128]
            proc = subprocess.run(
                [sys.executable, "-m", "openagent_media_inspector", "--inspect-video" if large else "--inspect", mime],
                input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=185 if large else 32,
                check=True,
            )
            self.send_json(200, json.loads(proc.stdout))
        except (subprocess.SubprocessError, OSError, ValueError):
            self.send_json(200, result("unreadable", text("Attachment could not be decoded within the runtime limits.")))
        finally:
            SLOTS.release()


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--fetch":
        from .shared_links import fetch
        data, _ = fetch(json.loads(sys.stdin.buffer.read(16385))["url"])
        sys.stdout.buffer.write(data)
    elif len(sys.argv) == 3 and sys.argv[1] in ("--inspect", "--inspect-video"):
        import resource
        large = sys.argv[1] == "--inspect-video"
        resource.setrlimit(resource.RLIMIT_CPU, (170, 180) if large else (28, 30))
        print(json.dumps(inspect(sys.stdin.buffer.read((150_000_000 if large else MAX_BYTES) + 1), sys.argv[2], large_media=large)))
    else:
        ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
