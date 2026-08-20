"""Decision engine + self-referential defense (ported from ND, fixes #1/#13).

- classify(text) returns BLOCK / ALLOW / ASK / UNKNOWN; priority black > white > ask > unknown.
- Blacklist includes self-referential features (script dir / own files injected at startup, fix #1).
- learned features also take part in blocking.
- Self-directory guard (fix #13): self_dir_match() hard-blocks any target that points
  at a `.py` under `modules/` / `src_dev/` — the execution-level fallback of the
  self-referential defense, so the agent cannot tamper with its own module sources
  even when the blacklist does not match.
"""
import logging
import re
from pathlib import Path
from typing import Optional

from . import store as store_mod

logger = logging.getLogger("Claw_SE.security.rules")

BLOCK = "block"
ALLOW = "allow"
ASK = "ask"
UNKNOWN = "unknown"


def self_dir_match(target: str, protected_dirs: list[Path]) -> Optional[str]:
    """Check whether a target points at a `.py` under one of the protected dirs.

    Matches both absolute paths and relative fragments inside command strings
    (e.g. `rm modules/core/__init__.py`, `echo x > src_dev/modules/exec.py`).

    Args:
        target: target string (file path or command string).
        protected_dirs: protected directory list.

    Returns:
        The matched path fragment if hit, None otherwise.
    """
    if not target:
        return None
    for protected in protected_dirs:
        protected = Path(protected).resolve()
        # 1) absolute / normalized path: target itself is a protected `.py`
        try:
            resolved = Path(target.split()[0]).expanduser().resolve()
        except (OSError, ValueError):
            resolved = None
        if resolved is not None and _is_protected_py(resolved, protected):
            return str(resolved)
        # 2) command string contains "<protected-dir>/...xxx.py"
        escaped = re.escape(str(protected))
        pattern = re.compile(rf"{escaped}[^\s'\"]*\.py\b")
        m = pattern.search(target)
        if m:
            return m.group(0)
        # 3) relative fragments (modules/xxx.py or src_dev/xxx.py)
        base_names = {protected.name, "src_dev", "modules"}
        for base in base_names:
            frag = re.compile(rf"{re.escape(base)}[\\/][^\s'\"]*\.py\b")
            m = frag.search(target)
            if m:
                return m.group(0)
    return None


def _is_protected_py(path: Path, protected: Path) -> bool:
    try:
        path.resolve().relative_to(protected)
    except ValueError:
        return False
    return path.suffix == ".py"


def is_protected_path(path: Path, protected_dirs: list[Path]) -> bool:
    """Directly decide whether a path is a protected `.py` (for exec/file modules)."""
    try:
        resolved = path.expanduser().resolve()
    except (OSError, ValueError):
        return False
    for protected in protected_dirs:
        if _is_protected_py(resolved, Path(protected)):
            return True
    return False


class Rules:
    """Three-list decision engine + self-directory guard.

    Args:
        store: Store instance (list cache).
        protected_dirs: protected dirs (modules/, src_dev/, ...); their `.py` files
            cannot be modified/deleted at the execution level.
    """

    def __init__(self, store: "store_mod.Store", protected_dirs: Optional[list[Path]] = None):
        self._store = store
        self._protected_dirs = [Path(p).resolve() for p in (protected_dirs or [])]

    def classify(self, text: str) -> str:
        """Decide which list the text belongs to. Priority: black > white > ask > unknown.

        Args:
            text: text to judge (command / path).

        Returns:
            One of BLOCK / ALLOW / ASK / UNKNOWN.
        """
        if not text:
            return UNKNOWN
        if (self._store.match_any(text, "blacklist")
                or self._store.match_any(text, "self")
                or self._store.match_any(text, "learned")):
            return BLOCK
        if self._store.match_any(text, "whitelist"):
            return ALLOW
        if self._store.match_any(text, "asklist"):
            return ASK
        return UNKNOWN

    # ---- self-directory guard (execution-level fallback, fix #13) ----
    def self_dir_check(self, target: str) -> Optional[str]:
        """Check whether the target points at a `.py` under a protected directory.

        Args:
            target: target string (file path or command string).

        Returns:
            The matched path fragment if hit, None otherwise.
        """
        return self_dir_match(target, self._protected_dirs)

    def is_protected_path(self, path: Path) -> bool:
        """Directly decide whether a path is a protected `.py` (for exec/file modules)."""
        return is_protected_path(path, self._protected_dirs)
