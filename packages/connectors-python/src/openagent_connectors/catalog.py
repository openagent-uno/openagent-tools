"""Read the generated catalog bundled with the versioned Python adapter."""
from importlib.resources import files
import json


def bundled_catalog():
    # The release builder regenerates this resource from the Go runner. It is
    # discovery data, never another adapter implementation or credential store.
    document = json.loads(files("openagent_connectors").joinpath("catalog.json").read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("connectors"), list):
        raise ValueError("Invalid bundled connector catalog")
    return [dict(item) for item in document["connectors"] if not item.get("nativeKind")]
