"""Unrestricted local filesystem MCP-compatible tools."""

from __future__ import annotations

import asyncio
import base64
import difflib
import fnmatch
import json
import mimetypes
import os
import shutil
import stat
import string
import sys
from uuid import uuid4
from pathlib import Path
from typing import Any

from openagent_tool_protocol.types import (
    HostError,
    ServerManifest,
    ToolClassification,
    ToolManifest,
    ToolResult,
)
from openagent_tool_protocol.util import integer_arg, json_result, require_string

_OBJECT = {"type": "object", "additionalProperties": False}
_MAX_INLINE_BYTES = 25 * 1024 * 1024
_MAX_ATTACHMENT_BYTES = 32 * 1024 * 1024


def _read_error(path: Path, error: OSError | UnicodeError) -> HostError:
    if sys.platform == "darwin" and isinstance(error, PermissionError):
        return HostError("filesystem_access_denied",
            "macOS denied this read. An interactive Desktop client can ask the user for one-time access. "
            "The user can also select the file in the chat attachment picker.", {"path": str(path)})
    return HostError("filesystem_error", f"cannot read {path}: {error}")


def _read_regular_file(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise HostError("invalid_arguments", "Read source must be a regular file")
            if before.st_size > limit:
                raise HostError("result_too_large", f"File exceeds the {limit}-byte limit",
                    {"path": str(path), "size": before.st_size, "limit": limit})
            with os.fdopen(fd, "rb", closefd=False) as file:
                content = file.read(before.st_size + 1)
            after = os.fstat(fd)
            if (len(content) != before.st_size or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns):
                raise HostError("file_changed", "File changed during the read")
            return content
        finally:
            os.close(fd)
    except OSError as exc:
        raise _read_error(path, exc) from exc


def _read_text(path: Path) -> str:
    try:
        return _read_regular_file(path, _MAX_INLINE_BYTES).decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeError as exc:
        raise _read_error(path, exc) from exc


def _sniff_media_mime(data: bytes) -> str | None:
    """Media type from the leading bytes, for names without an extension.

    Content-addressed stores keep files as ``<digest>`` with no suffix.
    """
    head = data[:16]
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "audio/wav"
    if head.startswith(b"OggS"):
        return "audio/ogg"
    if head.startswith(b"fLaC"):
        return "audio/flac"
    if head.startswith(b"ID3") or head[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "audio/mpeg"
    return None


def _schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {**_OBJECT, "properties": properties, "required": required or []}


class FilesystemServer:
    # Thread-backed filesystem writes must finish before releasing mutation leases.
    cancellation_requires_drain = True
    manifest = ServerManifest(
        name="filesystem",
        version="1.0.1",
        instructions=(
            "Operate on the filesystem at this capability's registered destination. "
            "A client registration means the verified user's computer; a server "
            "registration means the agent's server environment. Paths cannot select another destination."
        ),
        tools=(
            ToolManifest(
                "read_text_file",
                "Read a UTF-8 text file. Optional head or tail returns only that many lines.",
                _schema(
                    {
                        "path": {"type": "string"},
                        "head": {"type": "integer", "minimum": 1},
                        "tail": {"type": "integer", "minimum": 1},
                    },
                    ["path"],
                ),
            ),
            ToolManifest(
                "read_media_file",
                "Read a local image or audio file as an MCP media content block; the type comes from the extension or, without one, from the file content.",
                _schema({"path": {"type": "string"}}, ["path"]),
            ),
            ToolManifest(
                "attach_file",
                "Add an accessible file from this exact computer to the current session as a binary attachment, up to 32 MiB.",
                _schema({"path": {"type": "string"}}, ["path"]),
                ToolClassification.READ_ONLY,
            ),
            ToolManifest(
                "read_multiple_files",
                "Read several UTF-8 text files in one call.",
                _schema(
                    {"paths": {"type": "array", "items": {"type": "string"}, "minItems": 1}},
                    ["paths"],
                ),
            ),
            ToolManifest(
                "write_file",
                "Create or overwrite a UTF-8 text file.",
                _schema(
                    {"path": {"type": "string"}, "content": {"type": "string"}},
                    ["path", "content"],
                ),
                ToolClassification.MUTATING,
            ),
            ToolManifest(
                "edit_file",
                "Apply exact text replacements and optionally return a dry-run diff.",
                _schema(
                    {
                        "path": {"type": "string"},
                        "edits": {
                            "type": "array",
                            "minItems": 1,
                            "items": {
                                "type": "object",
                                "properties": {
                                    "oldText": {"type": "string"},
                                    "newText": {"type": "string"},
                                },
                                "required": ["oldText", "newText"],
                                "additionalProperties": False,
                            },
                        },
                        "dryRun": {"type": "boolean", "default": False},
                    },
                    ["path", "edits"],
                ),
                ToolClassification.MUTATING,
            ),
            ToolManifest(
                "create_directory",
                "Create a directory and missing parents.",
                _schema({"path": {"type": "string"}}, ["path"]),
                ToolClassification.MUTATING,
            ),
            ToolManifest(
                "list_directory",
                "List a directory, distinguishing files and subdirectories.",
                _schema({"path": {"type": "string"}}, ["path"]),
            ),
            ToolManifest(
                "list_directory_with_sizes",
                "List directory entries with byte sizes, sorted by name or size.",
                _schema(
                    {
                        "path": {"type": "string"},
                        "sortBy": {"type": "string", "enum": ["name", "size"]},
                    },
                    ["path"],
                ),
            ),
            ToolManifest(
                "directory_tree",
                "Return a bounded recursive JSON directory tree.",
                _schema(
                    {
                        "path": {"type": "string"},
                        "max_depth": {"type": "integer", "minimum": 1, "maximum": 20},
                        "max_entries": {"type": "integer", "minimum": 1, "maximum": 20000},
                    },
                    ["path"],
                ),
            ),
            ToolManifest(
                "move_file",
                "Move or rename a file or directory without overwriting the destination.",
                _schema(
                    {"source": {"type": "string"}, "destination": {"type": "string"}},
                    ["source", "destination"],
                ),
                ToolClassification.MUTATING,
            ),
            ToolManifest(
                "search_files",
                "Recursively find paths whose name or relative path matches a glob pattern.",
                _schema(
                    {
                        "path": {"type": "string"},
                        "pattern": {"type": "string"},
                        "excludePatterns": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "max_results": {"type": "integer", "minimum": 1, "maximum": 10000},
                    },
                    ["path", "pattern"],
                ),
            ),
            ToolManifest(
                "get_file_info",
                "Return metadata for a file or directory.",
                _schema({"path": {"type": "string"}}, ["path"]),
            ),
            ToolManifest(
                "list_allowed_directories",
                "Report that device consent grants the complete local filesystem.",
                _schema({}),
            ),
        ),
    )

    def __init__(
        self,
        cwd: str | Path | None = None,
        *,
        allowed_roots: list[str | Path] | tuple[str | Path, ...] | None = None,
    ):
        self.cwd = Path(cwd or Path.cwd()).expanduser().resolve()
        self.allowed_roots = (
            tuple(Path(root).expanduser().resolve() for root in allowed_roots)
            if allowed_roots is not None
            else None
        )
        if self.allowed_roots is not None and not self.allowed_roots:
            raise HostError("invalid_configuration", "allowed_roots cannot be empty")

    def _path(self, raw: str) -> Path:
        path = Path(raw).expanduser()
        resolved = path.resolve() if path.is_absolute() else (self.cwd / path).resolve()
        if self.allowed_roots is not None and not any(
            resolved == root or root in resolved.parents for root in self.allowed_roots
        ):
            raise HostError(
                "access_denied",
                f"path is outside allowed roots: {resolved}",
                {"allowed_roots": [str(root) for root in self.allowed_roots]},
            )
        return resolved

    async def call(self, tool: str, args: dict[str, Any]) -> ToolResult:
        handler = getattr(self, f"_tool_{tool}", None)
        if handler is None:
            raise HostError("tool_not_found", f"filesystem has no tool {tool!r}")
        return await asyncio.to_thread(handler, args)

    async def close(self) -> None:
        return None

    def _tool_read_text_file(self, args: dict[str, Any]) -> ToolResult:
        if "head" in args and "tail" in args:
            raise HostError("invalid_arguments", "head and tail are mutually exclusive")
        bound = "head" if "head" in args else "tail" if "tail" in args else None
        count = integer_arg(args, bound, 1, minimum=1, maximum=1_000_000) if bound else None
        path = self._path(require_string(args, "path"))
        text = _read_text(path)
        if count is not None:
            lines = text.splitlines()
            text = "\n".join(lines[:count] if bound == "head" else lines[-count:])
        return ToolResult.text(text, meta={"path": str(path)})

    def _tool_read_media_file(self, args: dict[str, Any]) -> ToolResult:
        path = self._path(require_string(args, "path"))
        data = _read_regular_file(path, _MAX_INLINE_BYTES)
        mime = mimetypes.guess_type(path.name)[0] or _sniff_media_mime(data) or "application/octet-stream"
        if mime.startswith("image/"):
            block_type = "image"
        elif mime.startswith("audio/"):
            block_type = "audio"
        else:
            return ToolResult.text(
                base64.b64encode(data).decode("ascii"),
                meta={"path": str(path), "mimeType": mime, "encoding": "base64"},
            )
        return ToolResult(
            content=[
                {
                    "type": block_type,
                    "data": base64.b64encode(data).decode("ascii"),
                    "mimeType": mime,
                }
            ],
            meta={"path": str(path), "size": len(data)},
        )

    def _tool_attach_file(self, args: dict[str, Any]) -> ToolResult:
        path = self._path(require_string(args, "path"))
        content = _read_regular_file(path, _MAX_ATTACHMENT_BYTES)
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        return ToolResult(content=[{
            "type": "resource",
            "resource": {"uri": f"urn:openagent:file:{uuid4()}", "mimeType": mime,
                         "blob": base64.b64encode(content).decode("ascii")},
            "_meta": {"openagent/file-delivery": {"filename": path.name}},
        }])

    def _tool_read_multiple_files(self, args: dict[str, Any]) -> ToolResult:
        raw_paths = args.get("paths")
        if not isinstance(raw_paths, list) or not raw_paths or not all(
            isinstance(item, str) and item for item in raw_paths
        ):
            raise HostError("invalid_arguments", "paths must be a non-empty string array")
        values: list[dict[str, Any]] = []
        for raw in raw_paths:
            path = self._path(raw)
            try:
                values.append({"path": str(path), "content": _read_text(path)})
            except HostError as exc:
                values.append({"path": str(path), "error": str(exc)})
        return json_result({"files": values})

    def _tool_write_file(self, args: dict[str, Any]) -> ToolResult:
        path = self._path(require_string(args, "path"))
        content = require_string(args, "content", allow_empty=True)
        try:
            path.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise HostError("filesystem_error", f"cannot write {path}: {exc}") from exc
        return json_result({"ok": True, "path": str(path), "bytes": len(content.encode())})

    def _tool_edit_file(self, args: dict[str, Any]) -> ToolResult:
        path = self._path(require_string(args, "path"))
        edits = args.get("edits")
        if not isinstance(edits, list) or not edits:
            raise HostError("invalid_arguments", "edits must be a non-empty array")
        try:
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise HostError("filesystem_error", f"cannot read {path}: {exc}") from exc
        updated = original
        replacements = 0
        for edit in edits:
            if not isinstance(edit, dict):
                raise HostError("invalid_arguments", "each edit must be an object")
            old = edit.get("oldText")
            new = edit.get("newText")
            if not isinstance(old, str) or not isinstance(new, str) or not old:
                raise HostError("invalid_arguments", "edits require non-empty oldText and newText")
            count = updated.count(old)
            if count == 0:
                raise HostError("text_not_found", f"oldText was not found in {path}")
            updated = updated.replace(old, new)
            replacements += count
        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=str(path),
                tofile=str(path),
            )
        )
        dry_run = bool(args.get("dryRun", False))
        if not dry_run:
            try:
                path.write_text(updated, encoding="utf-8")
            except OSError as exc:
                raise HostError("filesystem_error", f"cannot write {path}: {exc}") from exc
        return json_result(
            {
                "ok": True,
                "path": str(path),
                "dry_run": dry_run,
                "replacements": replacements,
                "diff": diff,
            }
        )

    def _tool_create_directory(self, args: dict[str, Any]) -> ToolResult:
        path = self._path(require_string(args, "path"))
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise HostError("filesystem_error", f"cannot create {path}: {exc}") from exc
        return json_result({"ok": True, "path": str(path)})

    def _tool_list_directory(self, args: dict[str, Any]) -> ToolResult:
        path = self._path(require_string(args, "path"))
        try:
            entries = sorted(path.iterdir(), key=lambda item: item.name.lower())
        except OSError as exc:
            raise _read_error(path, exc) from exc
        lines = [f"[{'DIR' if item.is_dir() else 'FILE'}] {item.name}" for item in entries]
        return ToolResult.text("\n".join(lines), structured={"path": str(path), "entries": lines})

    def _tool_list_directory_with_sizes(self, args: dict[str, Any]) -> ToolResult:
        path = self._path(require_string(args, "path"))
        sort_by = args.get("sortBy", "name")
        if sort_by not in {"name", "size"}:
            raise HostError("invalid_arguments", "sortBy must be 'name' or 'size'")
        try:
            values = [
                {
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0,
                }
                for item in path.iterdir()
            ]
        except OSError as exc:
            raise HostError("filesystem_error", f"cannot list {path}: {exc}") from exc
        values.sort(key=lambda item: item[sort_by] if sort_by == "size" else item["name"].lower())
        return json_result({"path": str(path), "entries": values})

    def _tool_directory_tree(self, args: dict[str, Any]) -> ToolResult:
        root = self._path(require_string(args, "path"))
        max_depth = integer_arg(args, "max_depth", 5, minimum=1, maximum=20)
        max_entries = integer_arg(args, "max_entries", 5000, minimum=1, maximum=20000)
        count = 0
        truncated = False

        def visit(path: Path, depth: int) -> dict[str, Any]:
            nonlocal count, truncated
            node: dict[str, Any] = {
                "name": path.name or str(path),
                "path": str(path),
                "type": "directory" if path.is_dir() else "file",
            }
            count += 1
            if count >= max_entries:
                truncated = True
                return node
            if path.is_dir() and depth < max_depth:
                children: list[dict[str, Any]] = []
                try:
                    entries = sorted(path.iterdir(), key=lambda item: item.name.lower())
                except OSError as exc:
                    node["error"] = str(exc)
                    return node
                for item in entries:
                    if count >= max_entries:
                        truncated = True
                        break
                    children.append(visit(item, depth + 1))
                node["children"] = children
            return node

        if not root.exists():
            raise HostError("filesystem_error", f"path does not exist: {root}")
        return json_result({"tree": visit(root, 0), "truncated": truncated})

    def _tool_move_file(self, args: dict[str, Any]) -> ToolResult:
        source = self._path(require_string(args, "source"))
        destination = self._path(require_string(args, "destination"))
        if destination.exists():
            raise HostError("filesystem_error", f"destination already exists: {destination}")
        try:
            shutil.move(str(source), str(destination))
        except OSError as exc:
            raise HostError("filesystem_error", f"cannot move {source}: {exc}") from exc
        return json_result({"ok": True, "source": str(source), "destination": str(destination)})

    def _tool_search_files(self, args: dict[str, Any]) -> ToolResult:
        root = self._path(require_string(args, "path"))
        pattern = require_string(args, "pattern")
        excludes = args.get("excludePatterns", [])
        if not isinstance(excludes, list) or not all(isinstance(item, str) for item in excludes):
            raise HostError("invalid_arguments", "excludePatterns must be a string array")
        max_results = integer_arg(args, "max_results", 1000, minimum=1, maximum=10000)
        glob_pattern = pattern if any(char in pattern for char in "*?[") else f"*{pattern}*"
        matches: list[str] = []
        try:
            iterator = root.rglob("*")
            for item in iterator:
                relative = item.relative_to(root).as_posix()
                if any(fnmatch.fnmatch(relative, excluded) for excluded in excludes):
                    continue
                if fnmatch.fnmatch(item.name, glob_pattern) or fnmatch.fnmatch(
                    relative, glob_pattern
                ):
                    matches.append(str(item))
                    if len(matches) >= max_results:
                        break
        except OSError as exc:
            raise HostError("filesystem_error", f"cannot search {root}: {exc}") from exc
        return json_result(
            {"path": str(root), "pattern": pattern, "matches": matches, "truncated": len(matches) >= max_results}
        )

    def _tool_get_file_info(self, args: dict[str, Any]) -> ToolResult:
        path = self._path(require_string(args, "path"))
        try:
            stat = path.stat()
        except OSError as exc:
            raise HostError("filesystem_error", f"cannot stat {path}: {exc}") from exc
        return json_result(
            {
                "path": str(path),
                "size": stat.st_size,
                "type": "directory" if path.is_dir() else "file",
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "accessed": stat.st_atime,
                "permissions": oct(stat.st_mode & 0o777),
            }
        )

    def _tool_list_allowed_directories(self, args: dict[str, Any]) -> ToolResult:
        del args
        if self.allowed_roots is not None:
            return json_result(
                {
                    "unrestricted": False,
                    "roots": [str(root) for root in self.allowed_roots],
                }
            )
        if os.name == "nt":
            roots = [f"{letter}:\\" for letter in string.ascii_uppercase if Path(f"{letter}:\\").exists()]
        else:
            roots = ["/"]
        return json_result({"unrestricted": True, "roots": roots})
