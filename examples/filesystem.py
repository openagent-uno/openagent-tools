"""Independent, bounded filesystem capability example; Python 3.11+."""
import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

from openagent_filesystem import FilesystemServer


async def main():
    with TemporaryDirectory(prefix="openagent-tool-demo-") as directory:
        root = Path(directory).resolve()
        (root / "fixture.txt").write_text("hello from a generic tool", encoding="utf-8")
        provider = FilesystemServer(root, allowed_roots=[root])
        try:
            result = await provider.call("read_text_file", {"path": "fixture.txt"})
            print(result.content)
        finally:
            await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
