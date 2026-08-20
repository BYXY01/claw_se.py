"""File operations tool (ported from LC, fixes #10/#13 applied).

- Quick mode: file_op("path", "read"/"write"/"append").
- Handle mode: file_op("path", "open", mode=...) -> file_op(handle, ...) -> file_op(handle, "close").
- Fix #10: before any write/append the existing file is backed up to `<path>.bak`;
  a failed write rolls the file back automatically, and a "rollback" operation
  restores the last backup manually.
- Fix #13: write/append/rollback targeting a `.py` under the protected dirs
  (modules/, src_dev/) is blocked by the self-directory guard.
"""
import os
import shutil
from pathlib import Path
from typing import Optional

from langchain_core.tools import tool

from .core import config as core_config
from .core.security import protected_dirs
from .core.security.rules import is_protected_path

# file handle registry
_file_handles: dict[str, dict] = {}
_next_handle_id: int = 1

_BACKUP_SUFFIX = ".bak"


def _guard_target(path: str) -> Optional[str]:
    """Return a block message when the target is a protected `.py` (fix #13)."""
    target = Path(path).expanduser()
    if is_protected_path(target, protected_dirs(core_config.app_root())):
        return f"[SE] Blocked (self-directory guard): {path}"
    return None


def _backup_file(path: str) -> None:
    """Back up an existing file to `<path>.bak` before modifying it (fix #10)."""
    src = Path(path)
    if src.exists():
        shutil.copy2(src, str(src) + _BACKUP_SUFFIX)


def _rollback_file(path: str) -> str:
    """Restore `<path>.bak` over the current file.

    Args:
        path: the file to restore.

    Returns:
        A status message.
    """
    bak = Path(path).with_suffix(Path(path).suffix + _BACKUP_SUFFIX)
    if not bak.exists():
        return f"Error: no backup found for '{path}'"
    shutil.copy2(bak, path)
    return f"Rolled back '{path}' from backup"


def _safe_write(path: str, content: str, mode: str = "w") -> str:
    """Write content with backup + auto-rollback on failure.

    Args:
        path: target file path.
        content: content to write.
        mode: 'w' or 'a'.

    Returns:
        A status message.
    """
    guard = _guard_target(path)
    if guard:
        return guard
    _backup_file(path)
    try:
        with open(path, mode, encoding="utf-8") as f:
            f.write(content)
        return f"File '{path}' {'appended' if mode == 'a' else 'written'} successfully ({len(content)} chars)"
    except OSError as e:
        _rollback_file(path)
        return f"Error writing '{path}': {e}; rolled back from backup"


@tool
def file_op(
    path_or_handle: str,
    operation: str,
    mode: str = "r",
    content: str = None,
    pos: int = None,
    size: int = None,
    encoding: str = "utf-8",
    insert: bool = False,
) -> str:
    """File operations tool.

    Two modes:
    1. Quick mode: file_op("path", "read" / "write" / "append")
    2. Handle mode: file_op("path", "open", mode="r") -> file_op(handle, "read") -> file_op(handle, "close")

    Writes are backed up to `<path>.bak` first and auto-rollback on failure;
    use operation='rollback' to restore manually (fix #10).

    Args:
        path_or_handle: file path or handle ID.
        operation: open/close/read/write/append/seek/tell/flush/list/rollback.
        mode: open mode.
        content: content to write.
        pos: seek position.
        size: number of bytes to read.
        encoding: file encoding, default utf-8.
        insert: whether to insert at the current position (handle write).

    Returns:
        File content or a status/error message.
    """
    global _next_handle_id

    try:
        is_handle = path_or_handle.startswith("file_") and path_or_handle[5:].isdigit()

        # quick mode: direct path operations
        if not is_handle and operation in ("read", "write", "append", "rollback"):
            path = path_or_handle
            if operation == "read":
                if not os.path.exists(path):
                    return f"Error: File '{path}' not found"
                with open(path, "r", encoding=encoding) as f:
                    return f.read()
            elif operation == "write":
                if content is None:
                    return "Error: 'content' parameter required for write operation"
                return _safe_write(path, content, "w")
            elif operation == "append":
                if content is None:
                    return "Error: 'content' parameter required for append operation"
                return _safe_write(path, content, "a")
            elif operation == "rollback":
                guard = _guard_target(path)
                if guard:
                    return guard
                return _rollback_file(path)

        # handle mode
        if operation == "open":
            path = path_or_handle
            if path in _file_handles:
                return f"File already open: {path}"
            guard = _guard_target(path)
            if guard and ("w" in mode or "a" in mode or "+" in mode):
                return guard
            file_obj = open(path, mode or "r", encoding=encoding)
            handle_id = f"file_{_next_handle_id}"
            _next_handle_id += 1
            _file_handles[handle_id] = {"file": file_obj, "path": path, "mode": mode}
            return f"File opened with handle: {handle_id} | Path: {path} | Mode: {mode}"

        handle_id = path_or_handle
        if handle_id not in _file_handles:
            return f"Handle not found: {handle_id}"
        file_obj = _file_handles[handle_id]["file"]
        path = _file_handles[handle_id]["path"]

        if operation == "close":
            file_obj.close()
            del _file_handles[handle_id]
            return f"File closed: {handle_id}"
        elif operation == "read":
            return file_obj.read(size) if size else file_obj.read()
        elif operation == "write":
            if content is None:
                return "Error: 'content' parameter required for write operation"
            guard = _guard_target(path)
            if guard:
                return guard
            _backup_file(path)
            try:
                if insert:
                    current_pos = file_obj.tell()
                    remaining = file_obj.read()
                    file_obj.seek(current_pos)
                    file_obj.write(content + remaining)
                else:
                    file_obj.write(content)
                file_obj.flush()
                return f"Written to {handle_id}"
            except OSError as e:
                _rollback_file(path)
                return f"Error writing {handle_id}: {e}; rolled back from backup"
        elif operation == "seek":
            if pos is None:
                return "Error: 'pos' parameter required for seek operation"
            file_obj.seek(pos)
            return f"Seeked to position {pos} in {handle_id}"
        elif operation == "tell":
            return f"Current position in {handle_id}: {file_obj.tell()}"
        elif operation == "flush":
            file_obj.flush()
            return f"Flushed {handle_id}"
        elif operation == "list":
            lines = []
            for hid, info in _file_handles.items():
                lines.append(f"Handle: {hid} | Path: {info['path']} | Mode: {info['mode']}")
            return "Open files:\n" + "\n".join(lines) if lines else "No open files"
        else:
            return (
                f"Error: Unknown operation '{operation}'. "
                f"Supported: open, close, read, write, append, seek, tell, flush, list, rollback"
            )

    except Exception as e:
        return f"Error: {e}"


FEATURE = {
    "name": "file",
    "version": "0.1",
    "desc": "File operations: read/write/append with .bak backup + rollback",
    "tools": [file_op],
    "hooks": {},
    "guard_key": "path_or_handle",
}
