"""Credential-free shared-media retrieval. Deploy separately from the decoder."""

import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit

MAX_DOWNLOAD_BYTES = 150_000_000
DOWNLOAD_SECONDS = 120
MAX_REDIRECTS = 5


def checked_url(url, provider=None):
    if not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 33 for c in url) or "\\" in url:
        raise ValueError("Invalid shared URL")
    u = urlsplit(url)
    if u.scheme != "https" or u.port not in (None, 443) or u.username or u.password or u.fragment:
        raise ValueError("Only credential-free HTTPS URLs are supported")
    host = u.hostname or ""
    allowed = {
        "drive": host in ("drive.google.com", "drive.usercontent.google.com"),
        "dropbox": host in ("dropbox.com", "www.dropbox.com", "dl.dropboxusercontent.com") or host.endswith(".dl.dropboxusercontent.com"),
        "wetransfer": host in ("we.tl", "wetransfer.com", "www.wetransfer.com", "download.wetransfer.com") or host.endswith(".wetransfer.net"),
    }
    matched = next((name for name, ok in allowed.items() if ok and (provider is None or provider == name)), None)
    if not matched:
        raise ValueError("Shared-media provider or redirect is not allowed")
    return u, matched


def normalize(url):
    u, provider = checked_url(url)
    if provider == "drive":
        match = re.fullmatch(r"/file/d/([A-Za-z0-9_-]{10,200})(?:/view|/preview)?/?", u.path)
        if u.hostname != "drive.google.com" or not match:
            raise ValueError("A Google Drive file sharing URL is required")
        url = "https://drive.usercontent.google.com/download?" + urlencode({"id": match[1], "export": "download", "confirm": "t"})
    elif provider == "dropbox":
        if not u.path.startswith(("/s/", "/scl/fi/")):
            raise ValueError("A Dropbox file sharing URL is required")
        query = parse_qs(u.query, keep_blank_values=True)
        query.pop("raw", None)
        query["dl"] = ["1"]
        url = urlunsplit((u.scheme, u.netloc, u.path, urlencode(query, doseq=True), ""))
    return url, provider


def public_addresses(host):
    addresses = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError("Provider DNS must resolve only to public addresses")
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    """Connect to the validated address while retaining hostname TLS verification."""
    def connect(self):
        address = public_addresses(self.host)[0]
        sock = socket.create_connection((address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def request(url, provider, deadline, *, payload=None, limit=MAX_DOWNLOAD_BYTES, json_response=False):
    for redirect in range(MAX_REDIRECTS + 1):
        u, _ = checked_url(url, provider)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Shared-media download deadline exceeded")
        connection = PinnedHTTPS(u.hostname, timeout=min(10, remaining), context=ssl.create_default_context())
        try:
            headers = {"Accept": "application/json" if json_response else "video/*,audio/*,application/octet-stream", "Accept-Encoding": "identity", "User-Agent": "OpenAgent-Media-Inspector/0.2"}
            body = json.dumps(payload).encode() if payload is not None else None
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request("POST" if body else "GET", u.path + ("?" + u.query if u.query else ""), body, headers)
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                if redirect == MAX_REDIRECTS or payload is not None:
                    raise ValueError("Unsupported shared-media redirect")
                url = urljoin(url, response.getheader("Location", ""))
                checked_url(url, provider)
                continue
            if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
                raise ValueError("Shared media is not available without credentials")
            mime = response.getheader("Content-Type", "").split(";", 1)[0].lower().strip()
            if json_response:
                allowed = mime == "application/json"
            else:
                allowed = mime.startswith(("video/", "audio/")) or mime == "application/octet-stream"
            if not allowed:
                raise ValueError("Shared URL did not return supported media")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or not 0 < int(length) <= limit):
                raise ValueError("Shared media exceeds the byte limit or is empty")
            data = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Shared-media download deadline exceeded")
                if connection.sock:
                    connection.sock.settimeout(min(10, remaining))
                chunk = response.read1(min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise ValueError("Shared media exceeds the byte limit")
            if not data or (length is not None and len(data) != int(length)):
                raise ValueError("Incomplete shared media")
            return bytes(data), mime
        finally:
            connection.close()
    raise ValueError("Too many redirects")


def fetch(url):
    url, provider = normalize(url)
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    if provider == "wetransfer":
        # Resolve the short link without consuming a landing page or accepting its content.
        if urlsplit(url).hostname == "we.tl":
            for _ in range(MAX_REDIRECTS):
                u, _ = checked_url(url, provider)
                conn = PinnedHTTPS(u.hostname, timeout=min(10, max(.1, deadline - time.monotonic())), context=ssl.create_default_context())
                try:
                    conn.request("GET", u.path + ("?" + u.query if u.query else ""), headers={"Accept-Encoding": "identity"})
                    response = conn.getresponse()
                    if response.status not in (301, 302, 303, 307, 308):
                        raise ValueError("WeTransfer short link is unavailable")
                    url = urljoin(url, response.getheader("Location", ""))
                    checked_url(url, provider)
                finally:
                    conn.close()
                if urlsplit(url).hostname != "we.tl":
                    break
        u, _ = checked_url(url, provider)
        match = re.fullmatch(r"/downloads/([a-fA-F0-9]{32})(?:/([a-fA-F0-9]{32}))?/([a-fA-F0-9]{4,64})/?", u.path)
        if not match or u.hostname not in ("wetransfer.com", "www.wetransfer.com"):
            raise ValueError("A public WeTransfer download link is required")
        payload = {"security_hash": match[3], "intent": "entire_transfer"}
        if match[2]:
            payload["recipient_id"] = match[2]
        metadata, _ = request(f"https://wetransfer.com/api/v4/transfers/{match[1]}/download", provider, deadline, payload=payload, limit=65536, json_response=True)
        url = json.loads(metadata).get("direct_link")
        checked_url(url, provider)
    data, mime = request(url, provider, deadline)
    if not (data[4:8] == b"ftyp" or data.startswith((b"\x1aE\xdf\xa3", b"OggS", b"ID3", b"fLaC", b"RIFF")) or data[:2] in (b"\xff\xfb", b"\xff\xf1", b"\xff\xf9")):
        raise ValueError("Shared URL did not return self-contained media")
    return data, mime
