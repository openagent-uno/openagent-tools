from io import BytesIO
import json
import socket
import time

import pytest
from openagent_media_inspector import inspect
from openagent_media_inspector import shared_links as links


def test_normalize_provider_links():
    url, provider = links.normalize("https://drive.google.com/file/d/neutral_file_123/view?usp=sharing")
    assert provider == "drive"
    assert url == "https://drive.usercontent.google.com/download?id=neutral_file_123&export=download&confirm=t"
    url, provider = links.normalize("https://www.dropbox.com/scl/fi/abc/video.mp4?rlkey=fixture&dl=0")
    assert provider == "dropbox" and "dl=1" in url and "rlkey=fixture" in url


@pytest.mark.parametrize("url", [
    "http://drive.google.com/file/d/neutral_file_123/view", "https://drive.google.com.evil.test/file/d/neutral_file_123",
    "https://user:password@drive.google.com/file/d/neutral_file_123", "https://127.0.0.1/",
    "https://drive.google.com:444/file/d/neutral_file_123", "https://drive.google.com/drive/folders/neutral_file_123",
    "https://drive.google.com\\@evil.test/", "https://drive.google.com/file/d/neutral_file_123\n",
    "https://www.dropbox.com/home", "https://example.test/video.mp4",
])
def test_untrusted_urls_are_rejected(url):
    with pytest.raises(ValueError):
        links.normalize(url)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "192.168.1.1"])
def test_dns_rebinding_and_mixed_private_answers_are_denied(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(None, None, None, None, ("8.8.8.8", 443)), (None, None, None, None, (address, 443))])
    with pytest.raises(ValueError):
        links.public_addresses("drive.google.com")


class Response:
    def __init__(self, body=b"media", status=200, **headers):
        self.status, self.headers, self.body = status, headers, BytesIO(body)
    def getheader(self, name, default=None):
        return self.headers.get(name, default)
    def read1(self, limit):
        return self.body.read(limit)


def transport(monkeypatch, *responses):
    calls = []
    queue = iter(responses)
    class Connection:
        sock = None
        def __init__(self, host, **kwargs):
            self.host = host
        def request(self, method, path, body=None, headers=None):
            calls.append((self.host, method, path, body, headers))
        def getresponse(self):
            return next(queue)
        def close(self):
            pass
    monkeypatch.setattr(links, "PinnedHTTPS", Connection)
    return calls


@pytest.mark.parametrize("response", [
    Response(**{"Content-Type": "text/html"}), Response(**{"Content-Type": "video/mp4", "Content-Length": "150000001"}),
    Response(**{"Content-Type": "video/mp4", "Content-Encoding": "gzip"}),
    Response(**{"Content-Type": "video/mp4", "Content-Length": "8"}),
    Response(status=302, Location="https://evil.test/media"), Response(status=302, Location="http://drive.google.com/file"),
    Response(status=302, Location="https://www.dropbox.com/s/cross-provider/video"),
])
def test_content_type_size_length_encoding_and_redirect_guards(monkeypatch, response):
    calls = transport(monkeypatch, response)
    with pytest.raises(ValueError):
        links.request("https://drive.usercontent.google.com/download?id=test", "drive", time.monotonic() + 2)
    assert len(calls) == 1


def test_stream_limit_and_deadline(monkeypatch):
    transport(monkeypatch, Response(body=b"123456", **{"Content-Type": "video/mp4"}))
    with pytest.raises(ValueError):
        links.request("https://drive.usercontent.google.com/download", "drive", time.monotonic() + 2, limit=5)
    with pytest.raises(TimeoutError):
        links.request("https://drive.usercontent.google.com/download", "drive", time.monotonic() - 1)


def test_wetransfer_short_link_and_download_are_credential_free(monkeypatch):
    media = b"\x00\x00\x00\x18ftypmp42" + b"fixture"
    calls = transport(monkeypatch,
        Response(status=302, Location="https://wetransfer.com/downloads/" + "a" * 32 + "/123456"),
        Response(body=json.dumps({"direct_link": "https://download.wetransfer.com/fixture.mp4"}).encode(), **{"Content-Type": "application/json"}),
        Response(body=media, **{"Content-Type": "video/mp4"}))
    assert links.fetch("https://we.tl/t-fixture")[0] == media
    assert calls[1][1] == "POST"
    assert json.loads(calls[1][3]) == {"security_hash": "123456", "intent": "entire_transfer"}
    assert all("Cookie" not in c[4] and "Authorization" not in c[4] for c in calls)


def video(seconds):
    import av
    import numpy as np
    buf = BytesIO()
    with av.open(buf, mode="w", format="mp4") as container:
        stream = container.add_stream("mpeg4", rate=1)
        stream.width, stream.height, stream.pix_fmt = 64, 64, "yuv420p"
        for _ in range(seconds):
            for packet in stream.encode(av.VideoFrame.from_ndarray(np.zeros((64, 64, 3), dtype=np.uint8), format="rgb24")):
                container.mux(packet)
        for packet in stream.encode():
            container.mux(packet)
    return buf.getvalue()


def test_real_84_second_video_early_and_final_frames():
    response = inspect(video(84), "video/mp4", large_media=True)
    messages = [b["text"] for b in response["content"] if b["type"] == "text"]
    assert response["status"] == "partial"
    assert any("84.00s" in t for t in messages)
    assert any("2.00s" in t for t in messages)
    assert any("83.00s" in t for t in messages)
    assert sum(b["type"] == "image" for b in response["content"]) == 5


def test_media_duration_and_legacy_bytes_stay_bounded():
    assert inspect(video(181), "video/mp4", large_media=True)["status"] == "unreadable"
    assert inspect(b"x" * 5_000_001, "video/mp4")["status"] == "unreadable"
