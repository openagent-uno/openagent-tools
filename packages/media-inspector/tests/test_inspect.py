from io import BytesIO
from zipfile import ZipFile

from PIL import Image
from openagent_media_inspector import inspect


def test_plain_and_protected_binary():
    assert inspect(b"row,value\nsample,42", "application/octet-stream")["content"][0]["text"].endswith("sample,42")
    assert inspect(b"\x00\xff\xfe", "application/octet-stream")["status"] == "unreadable"


def test_image_and_scanned_pdf_render_real_bytes():
    img = Image.new("RGB", (640, 400), "#237343")
    for fmt, mime in [("PNG", "image/png"), ("PDF", "application/pdf")]:
        buf = BytesIO()
        img.save(buf, fmt)
        response = inspect(buf.getvalue(), mime)
        assert response["status"] == "read"
        assert any(x["type"] == "image" and x["data"].startswith("/9j/") for x in response["content"])


def test_office_text_without_external_entities():
    def build(value):
        buf = BytesIO()
        with ZipFile(buf, "w") as archive:
            archive.writestr("word/document.xml", value)
        return buf.getvalue()

    safe = '<doc xmlns:w="urn:word"><w:t>Sample terms 53</w:t></doc>'
    assert inspect(build(safe), "application/octet-stream")["content"][-1]["text"] == "Sample terms 53"
    hostile = '<!DOCTYPE doc [<!ENTITY e SYSTEM "file:///etc/passwd">]><doc>&e;</doc>'
    assert inspect(build(hostile), "application/octet-stream")["status"] == "unreadable"
