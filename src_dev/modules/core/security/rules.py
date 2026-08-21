"""Decision engine + self-referential defense (fixes #1/#13).

- classify(text) returns BLOCK / ALLOW / ASK / UNKNOWN; priority black > white > ask > unknown.
- Blacklist includes self-referential features (script dir / own files injected at startup, fix #1).
- Self-directory guard (fix #13): self_dir_match() hard-blocks any target that points at
  agent-owned, never-writable content:
    - any `.py` under `modules/` / `src_dev/` (the agent's own code);
    - the whole `modules/core/` directory (security kernel + its data/lists);
    - any `config/*.json` (security / module / provider switches).
  Deliberately editable (NOT protected): `prompt_library/**` (identity/user .md,
  changeable with user consent) and `modules/*/data/**` (runtime module data).
"""
import logging
import re
from pathlib import Path
from typing import Optional

from . import store as store_mod

logger = logging.getLogger("claw_se.security.rules")

BLOCK = "block"
ALLOW = "allow"
ASK = "ask"
UNKNOWN = "unknown"


def self_dir_match(target: str, protected_dirs: list[Path]) -> Optional[str]:
    """Check whether a target points at agent-owned, never-writable content.

    Matches both absolute paths and relative fragments inside command strings
    (e.g. `rm modules/core/__init__.py`, `echo x > config/security.json`).

    Args:
        target: target string (file path or command string).
        protected_dirs: protected directory list.

    Returns:
        The matched path fragment if hit, None otherwise.
    """
    if not target:
        return None
    protected = [Path(p).resolve() for p in protected_dirs]
    modules_root = protected[0]
    app_root = protected[1] if len(protected) > 1 else protected[0].parent

    # 1) absolute / normalized path
    try:
        resolved = Path(target.split()[0]).expanduser().resolve()
    except (OSError, ValueError):
        resolved = None
    if resolved is not None and _is_self_defense(str(resolved), modules_root, app_root):
        return str(resolved)

    # 2) command string / relative fragments
    patterns = [
        rf"{re.escape(str(modules_root))}[^\s'\"]+",   # absolute <modules-root>/...
        rf"{re.escape(str(app_root))}[^\s'\"]+",       # absolute <app-root>/...
        r"modules[\\/]core[^\s'\"]*",                  # modules/core/... (whole dir)
        r"modules[\\/][^\s'\"]*\.py\b",                # modules/*.py
        r"config[\\/][^\s'\"]*\.json\b",               # config/*.json
        r"src_dev[\\/][^\s'\"]*\.py\b",                # src_dev/*.py
        r"[^\s'\"]*\.env(?:[.][^\s'\"]*)?",            # any token containing .env
    ]
    for pat in patterns:
        for m in re.finditer(pat, target):
            if _is_self_defense(m.group(0), modules_root, app_root):
                return m.group(0)
    return None


def _is_self_defense(fragment: str, modules_root: Path, app_root: Path) -> bool:
    """Decide whether a path fragment is agent-owned, never-writable content.

    Args:
        fragment: a path fragment (absolute or relative) from a target string.
        modules_root: the modules/ directory.
        app_root: the dev body root.

    Returns:
        True when the fragment is protected (code / security kernel / config json).
    """
    fragment = fragment.strip().strip("'\"")
    normalized = fragment.replace("\\", "/")
    # any `.env` / `.env.*` file anywhere - secrets live there, never readable or
    # writable by the agent regardless of which directory it sits in
    env_name = normalized.rstrip("/").rsplit("/", 1)[-1]
    if env_name == ".env" or env_name.startswith(".env."):
        return True
    # whole security kernel dir: modules/core/<anything>
    if re.match(r"^(.*/)?modules/core(/|$)", normalized):
        return True
    # config/*.json
    if re.match(r"^(.*/)?config/[^/]+\.json$", normalized):
        return True
    # any .py under modules/ or the dev root
    if re.match(r"^(.*/)?(modules|src_dev)(/|$)", normalized) and normalized.endswith(".py"):
        return True
    # absolute resolved-path fallback (for fragments that resolve to a real path)
    try:
        path = Path(fragment).expanduser().resolve()
        rel = path.relative_to(modules_root)
        if rel.parts and rel.parts[0] == "core":
            return True
        if path.suffix == ".py":
            return True
    except ValueError:
        pass
    try:
        path = Path(fragment).expanduser().resolve()
        path.relative_to(app_root / "config")
        if path.suffix == ".json":
            return True
    except ValueError:
        pass
    return False


def is_protected_path(path: Path, protected_dirs: list[Path]) -> bool:
    """Directly decide whether a path is protected (for exec/file modules)."""
    try:
        resolved = path.expanduser().resolve()
    except (OSError, ValueError):
        return False
    protected = [Path(p).resolve() for p in protected_dirs]
    modules_root = protected[0]
    app_root = protected[1] if len(protected) > 1 else protected[0].parent
    return _is_self_defense(str(resolved), modules_root, app_root)


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
                or self._store.match_any(text, "self")):
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
