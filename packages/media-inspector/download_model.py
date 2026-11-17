"""Fetch the exact CPU speech model used by the release image."""
import hashlib
from pathlib import Path
import sys
from urllib.request import urlopen

REV = "d90ca5fe260221311c53c58e660288d3deb8d356"
FILES = {
    "config.json": (2249, "3baa18e2b321a2f489614607852a729fcd516480"),
    "model.bin": (75538270, "dcb76c6586fc06cbdac6dd21f14cfd129cc4cdd9dce19bf4ffa62e59cbe6e6d1"),
    "tokenizer.json": (2203239, "7818adb6de9fa3064d3ff81226fdd675be1f6344"),
    "vocabulary.txt": (459861, "c9074644d9d1205686f16d411564729461324b75"),
}


def fetch(destination):
    destination.mkdir(parents=True, exist_ok=True)
    for name, (size, expected) in FILES.items():
        with urlopen(f"https://huggingface.co/Systran/faster-whisper-tiny/resolve/{REV}/{name}?download=true", timeout=45) as response:
            body = response.read(size + 1)
        digest = (hashlib.sha256(body).hexdigest() if len(expected) == 64 else
                  hashlib.sha1(f"blob {size}\0".encode() + body, usedforsecurity=False).hexdigest())
        if len(body) != size or digest != expected:
            raise ValueError(f"Speech model checksum mismatch: {name}")
        (destination / name).write_bytes(body)


if __name__ == "__main__":
    fetch(Path(sys.argv[1]))
