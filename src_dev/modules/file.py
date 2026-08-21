"""File operations - one stateless entry point (agent-friendly).

- read  : read a file (optional line window via offset/limit, keeps context small).
- write : overwrite with `.bak` backup + auto-rollback (fix #10).
- append: append with `.bak` backup + auto-rollback (fix #10).
- rollback: restore the last `.bak` manually.
- info  : report size / line count so the agent can gauge before reading.

No stateful handle mode (no open/close/handle ids) - the LLM manages nothing
across calls. Fix #13: write/append/rollback targeting a `.py` under the
protected dirs (modules/, src_dev/) is blocked by the self-directory guard.
"""
import shutil
from pathlib import Path
from typing import Optional

from langchain_core.tools import tool

from .core import config as core_config
from .core.security import protected_dirs
from .core.security.rules import is_protected_path

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
def file_op(path: str, operation: str = "read", content: str = None,
            offset: int = 0, limit: Optional[int] = None,
            start_line: Optional[int] = None, end_line: Optional[int] = None) -> str:
    """File operations: read / write / append / replace / rollback / info (stateless).

    Args:
        path: file path.
        operation: 'read' (default, with offset/limit line window),
            'write', 'append', 'replace', 'rollback', or 'info'.
        content: content for write/append/replace.
        offset: 0-based line to start reading from (read only).
        limit: max lines to return (read only; default all).
        start_line: 1-based first line to replace (replace only).
        end_line: 1-based last line to replace (replace only; default = start_line).

    Returns:
        File content / file info / a status or error message.
    """
    try:
        if operation == "read":
            if offset < 0:
                return "Error: offset must be >= 0"
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            window = lines[offset:]
            if limit is not None and limit >= 0:
                window = window[:limit]
            return "".join(window) or "(empty)"

        if operation == "write":
            if content is None:
                return "Error: 'content' parameter required for write"
            return _safe_write(path, content, "w")

        if operation == "append":
            if content is None:
                return "Error: 'content' parameter required for append"
            return _safe_write(path, content, "a")

        if operation == "replace":
            if content is None:
                return "Error: 'content' parameter required for replace"
            if start_line is None or start_line < 1:
                return "Error: 'start_line' (1-based) required for replace"
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            end = end_line if end_line is not None else start_line
            if end < start_line or end > len(lines):
                return f"Error: invalid line range {start_line}-{end} (file has {len(lines)} lines)"
            guard = _guard_target(path)
            if guard:
                return guard
            _backup_file(path)
            try:
                replacement = content if content.endswith("\n") else content + "\n"
                new_lines = lines[:start_line - 1] + [replacement] + lines[end:]
                with open(path, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                return f"Replaced lines {start_line}-{end} in '{path}'"
            except OSError as e:
                _rollback_file(path)
                return f"Error replacing in '{path}': {e}; rolled back"

        if operation == "rollback":
            guard = _guard_target(path)
            if guard:
                return guard
            return _rollback_file(path)

        if operation == "info":
            p = Path(path)
            stat = p.stat()
            with open(path, "r", encoding="utf-8") as f:
                lines = sum(1 for _ in f)
            return f"Path: {path} | Size: {stat.st_size} bytes | Lines: {lines}"

        return f"Error: Unknown operation '{operation}'. Supported: read, write, append, replace, rollback, info"
    except FileNotFoundError:
        return f"Error: File '{path}' not found"
    except OSError as e:
        return f"Error: {e}"


FEATURE = {
    "name": "file",
    "version": "0.2.0",
    "desc": "File operations: read (line window)/write/append/replace with .bak + rollback",
    "tools": [file_op],
    "hooks": {},
    "guard_key": "path",
}
