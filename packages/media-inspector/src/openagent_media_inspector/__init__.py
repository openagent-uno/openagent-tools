"""Bounded, network-independent inspection of caller-authorized attachment bytes."""

import base64
from contextlib import closing
from io import BytesIO
from itertools import islice
import os
from pathlib import Path
import warnings
import re
from xml.etree import ElementTree
from zipfile import ZipFile

MAX_BYTES = 5_000_000
MAX_CHARS = 20_000
MAX_SECONDS = 60
PIXELS = 16_000_000


def text(value):
    return {"type": "text", "text": value[:MAX_CHARS]}


def jpeg(image):
    image.thumbnail((1600, 1600))
    buf = BytesIO()
    image.convert("RGB").save(buf, "JPEG", quality=86)
    return {"type": "image", "mimeType": "image/jpeg", "data": base64.b64encode(buf.getvalue()).decode("ascii")}


def result(status, *content):
    return {"version": "1", "status": status, "content": list(content)}


def picture(body):
    from PIL import Image, ImageOps

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(BytesIO(body)) as img:
            if img.width * img.height > PIXELS:
                return result("unreadable", text("Image exceeds the pixel limit."))
            partial = getattr(img, "n_frames", 1) > 1
            return result("partial" if partial else "read", text("First frame of animated image." if partial else "Image preview."), jpeg(ImageOps.exif_transpose(img)))


def pdf(body):
    import pypdfium2 as pdfium

    content = []
    chars = 0
    with pdfium.PdfDocument(body) as doc:
        for index in range(min(len(doc), 4)):
            with closing(doc[index]) as page, closing(page.get_textpage()) as words:
                message = words.get_text_range(0, min(words.count_chars(), MAX_CHARS - chars)).strip() if chars < MAX_CHARS else ""
                if message:
                    chars += len(message)
                    content.append(text(f"Page {index + 1}:\n{message}"))
                # Even on text PDFs show the page: a text layer does not show
                # stamps, signatures, or the layout of a scanned attachment.
                width, height = page.get_size()
                if min(width, height) > 0:
                    with closing(page.render(scale=min(2.0, 1600 / max(width, height)))) as bitmap:
                        content.append(jpeg(bitmap.to_pil()))
        if not content:
            return result("unreadable", text("PDF has no readable pages."))
        partial = len(doc) > 4 or chars >= MAX_CHARS
        return result("partial" if partial else "read", text(f"Preview of {min(len(doc), 4)} of {len(doc)} PDF pages."), *content)


def av_open(body):
    import av

    # Use a memory buffer and only self-contained media demuxers; do not
    # process playlists, network URLs, or references to external inputs.
    return av.open(BytesIO(body), options={
        "protocol_whitelist": "pipe",
        "format_whitelist": "mov,mp4,m4a,3gp,3g2,mj2,matroska,webm,ogg,wav,mp3,flac,aac",
    })


def frames(body):
    content = []
    with av_open(body) as media:
        if not media.streams.video:
            return content
        stream = media.streams.video[0]
        if not stream.width or not stream.height or stream.width * stream.height > PIXELS:
            return [text("Video frame size is outside the supported bounds.")]
        seconds = min(MAX_SECONDS, (media.duration or 0) / 1_000_000)
        targets = [0.0, seconds / 2, max(0.0, seconds - min(0.5, seconds / 4))] if seconds > 1 else [0.0]
        last = None
        for frame in islice(media.decode(stream), 3600):
            at = float(frame.time or 0)
            if at > MAX_SECONDS:
                break
            if frame.width * frame.height > PIXELS:
                break
            if last is None or at >= targets[0]:
                content.extend((text(f"Sampled video frame at {at:.2f}s."), jpeg(frame.to_image())))
                last = at
                targets.pop(0)
                if not targets:
                    break
    return content


def speech(body):
    import av
    import numpy as np

    samples = []
    remaining = MAX_SECONDS * 16000
    with av_open(body) as media:
        if not media.streams.audio:
            return None, False, "No audio track."
        converter = av.AudioResampler(format="s16", layout="mono", rate=16000)
        for frame in media.decode(audio=0):
            for resampled in converter.resample(frame):
                pcm = resampled.to_ndarray().reshape(-1)[:remaining]
                samples.append(pcm)
                remaining -= len(pcm)
                if not remaining:
                    break
            if not remaining:
                break
        if remaining:
            for resampled in converter.resample(None):
                pcm = resampled.to_ndarray().reshape(-1)[:remaining]
                samples.append(pcm)
                remaining -= len(pcm)
    if not samples:
        return None, False, "No decoded audio samples."
    model_path = Path(os.environ.get("OPENAGENT_SPEECH_MODEL", "/model"))
    if not (model_path / "model.bin").is_file():
        return None, False, "Local speech model is unavailable."
    audio = np.concatenate(samples).astype(np.float32) / 32768.0
    if not audio.size or float(np.max(np.abs(audio))) < 0.003:
        return None, False, "No audible speech detected."
    from faster_whisper import WhisperModel

    model = WhisperModel(str(model_path), device="cpu", compute_type="int8", cpu_threads=2, local_files_only=True)
    segments, _ = model.transcribe(audio, beam_size=2, vad_filter=True, condition_on_previous_text=False)
    transcript = " ".join(s.text.strip() for s in segments if s.text.strip()).strip()
    return transcript or None, not remaining, "No intelligible speech detected."


def office(body):
    # Read selected ZIP members in place. Do not extract paths, follow
    # relationships, evaluate formulas or run macros.
    with ZipFile(BytesIO(body)) as archive:
        names = archive.namelist()
        if len(names) > 512 or len(set(names)) != len(names):
            return result("unreadable", text("Unsupported document archive structure."))

        def xml(name):
            with archive.open(name) as part:
                data = part.read(1_000_001)
            if len(data) > 1_000_000 or b"\x00" in data or b"<!" in data:
                raise ValueError("Untrusted or oversized XML")
            return ElementTree.fromstring(data)

        def strings(root):
            return " ".join(e.text.strip() for e in root.iter() if e.tag.endswith("}t") and e.text and e.text.strip())

        if "word/document.xml" in names:
            value = strings(xml("word/document.xml"))
        elif any(re.fullmatch(r"ppt/slides/slide\d+\.xml", n) for n in names):
            slides = sorted((n for n in names if re.fullmatch(r"ppt/slides/slide\d+\.xml", n)), key=lambda n: int(n[16:-4]))
            value = "\n".join(f"{name}: {strings(xml(name))}" for name in slides[:4])
        else:
            sheets = sorted(n for n in names if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n))[:4]
            if not sheets:
                return result("unreadable", text("Archive format is not supported."))
            shared = [strings(si) for si in xml("xl/sharedStrings.xml")] if "xl/sharedStrings.xml" in names else []
            cells = []
            for sheet in sheets:
                cells.append(sheet)
                for cell in islice(xml(sheet).iterfind(".//{*}c"), 2000):
                    raw = cell.findtext("{*}v") or strings(cell)
                    if cell.get("t") == "s" and raw.isdecimal() and int(raw) < len(shared):
                        raw = shared[int(raw)]
                    if raw:
                        cells.append(f"{cell.get('r', '?')}: {raw}")
            value = "\n".join(cells)
        return result("partial", text("Office document text/cached values; visual layout, signatures and formulas not verified."), text(value)) if value.strip() else result("unreadable", text("Document has no accessible text."))


def inspect(body, mime):
    """Return MCP text and image content with an explicit coverage status."""
    if not 0 < len(body) <= MAX_BYTES:
        return result("unreadable", text("Attachment is empty or exceeds the byte limit."))
    mime = mime.split(";", 1)[0].lower().strip()
    try:
        if mime.startswith("image/") or body.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF8")):
            return picture(body)
        if mime == "application/pdf" or body.startswith(b"%PDF-"):
            return pdf(body)
        if mime.startswith(("audio/", "video/")) or body[4:8] == b"ftyp" or body.startswith((b"OggS", b"ID3", b"fLaC")) or body[8:12] == b"WAVE":
            video = mime.startswith("video/") or body[4:8] == b"ftyp"
            parts = frames(body) if video else []
            try:
                transcript, clipped, reason = speech(body)
            except Exception:
                transcript, clipped, reason = None, False, "Audio track could not be transcribed."
            if transcript:
                parts.append(text("Machine transcript" + (f" (first {MAX_SECONDS}s)" if clipped else "") + ":\n" + transcript))
            else:
                parts.append(text(reason))
            has_evidence = bool(transcript) or any(p["type"] == "image" for p in parts)
            return result("partial" if has_evidence and (video or clipped) else "read" if has_evidence else "unreadable", *parts)
        if body.startswith(b"PK\x03\x04"):
            return office(body)
        decoded = body.decode("utf-8-sig")
        if "\x00" not in decoded and all(c.isprintable() or c in "\r\n\t" for c in decoded):
            return result("partial" if len(decoded) > MAX_CHARS else "read", text(decoded))
    except (UnicodeError, ValueError, OSError, RuntimeError):
        pass
    except Exception:
        # The decoder must not expose process paths, document contents or a
        # vendor traceback through an error returned to an agent.
        pass
    return result("unreadable", text("Format is unsupported, protected, damaged, or outside the decoding limits."))
