"""Small, fail-closed unified-diff applicator for a single existing text file."""

from __future__ import annotations

import re


class PatchError(ValueError):
    pass


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$")


def apply_unified_patch(content: str, patch: str) -> tuple[str, int]:
    """Apply ordinary unified hunks; reject stale or ambiguous context.

    File headers are informational: the caller chooses the already-authorized
    file path. New-file, delete-file and binary patches are deliberately out of
    scope so a diff cannot redirect a write to another path.
    """
    lines = content.splitlines()
    patch_lines = patch.splitlines()
    if not patch_lines or len(patch.encode("utf-8")) > 1_000_000:
        raise PatchError("patch is empty or exceeds 1 MB")
    index = 0
    while index < len(patch_lines) and not patch_lines[index].startswith("@@ "):
        if not patch_lines[index].startswith(("--- ", "+++ ", "diff ", "index ")):
            raise PatchError("expected a unified diff header or @@ hunk")
        index += 1
    if index == len(patch_lines):
        raise PatchError("patch has no hunks")

    result: list[str] = []
    source = 0
    hunk_count = 0
    while index < len(patch_lines):
        match = _HUNK.fullmatch(patch_lines[index])
        if match is None:
            raise PatchError("expected an @@ hunk header")
        old_start = int(match.group(1))
        old_count = int(match.group(2) or 1)
        new_count = int(match.group(4) or 1)
        position = old_start - 1 if old_count else old_start
        if position < source or position > len(lines):
            raise PatchError("hunks overlap or refer beyond the file")
        result.extend(lines[source:position])
        source = position
        index += 1
        consumed = 0
        produced = 0
        while index < len(patch_lines) and not patch_lines[index].startswith("@@ "):
            line = patch_lines[index]
            if line.startswith("\\ No newline at end of file"):
                raise PatchError("patches with newline markers are not supported")
            if not line or line[0] not in {" ", "+", "-"}:
                raise PatchError("invalid unified diff line")
            text = line[1:]
            if line[0] in {" ", "-"}:
                if source >= len(lines) or lines[source] != text:
                    raise PatchError(f"patch context does not match at line {source + 1}")
                source += 1
                consumed += 1
            if line[0] in {" ", "+"}:
                result.append(text)
                produced += 1
            index += 1
        if consumed != old_count or produced != new_count:
            raise PatchError("hunk line counts do not match its header")
        hunk_count += 1
    result.extend(lines[source:])
    newline = "\r\n" if "\r\n" in content else "\n"
    updated = newline.join(result)
    if content.endswith(("\n", "\r")) and result:
        updated += newline
    return updated, hunk_count
