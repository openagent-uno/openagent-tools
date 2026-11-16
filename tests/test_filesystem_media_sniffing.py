"""read_media_file recognises media by content when the name has no extension.

Content-addressed stores (for example ``sha256/<digest>`` attachment paths)
keep no extension, so a PNG used to come back as base64 text labelled
application/octet-stream and the model never saw the image.
"""
import base64

import pytest
from openagent_filesystem.server import FilesystemServer

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
SAMPLES = {
    "image/png": PNG,
    "image/jpeg": b"\xff\xd8\xff\xe0" + b"\x00" * 32,
    "image/gif": b"GIF89a" + b"\x00" * 32,
    "image/webp": b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 24,
    "audio/ogg": b"OggS" + b"\x00" * 32,
    "audio/wav": b"RIFF\x24\x00\x00\x00WAVEfmt " + b"\x00" * 24,
    "audio/mpeg": b"ID3\x04" + b"\x00" * 32,
    "audio/flac": b"fLaC" + b"\x00" * 32,
}


@pytest.mark.asyncio
@pytest.mark.parametrize("mime", sorted(SAMPLES))
async def test_extensionless_media_is_returned_as_a_media_block(tmp_path, mime):
    path = tmp_path / "0b60406810dd9c4acca8874db9b252d6"
    path.write_bytes(SAMPLES[mime])
    result = await FilesystemServer(tmp_path, allowed_roots=[tmp_path]).call(
        "read_media_file", {"path": str(path)})
    block = result.to_wire()["content"][0]
    assert block["type"] == mime.split("/")[0]
    assert block["mimeType"] == mime
    assert base64.b64decode(block["data"]) == SAMPLES[mime]


@pytest.mark.asyncio
async def test_unknown_bytes_stay_base64_text(tmp_path):
    path = tmp_path / "blob"
    path.write_bytes(b"\x00\x01binary")
    result = await FilesystemServer(tmp_path, allowed_roots=[tmp_path]).call(
        "read_media_file", {"path": str(path)})
    wire = result.to_wire()
    assert wire["content"][0]["type"] == "text"
    assert wire["_meta"]["mimeType"] == "application/octet-stream"


@pytest.mark.asyncio
async def test_a_known_extension_still_wins(tmp_path):
    path = tmp_path / "shot.png"
    path.write_bytes(PNG)
    result = await FilesystemServer(tmp_path).call("read_media_file", {"path": str(path)})
    assert result.to_wire()["content"][0]["mimeType"] == "image/png"
