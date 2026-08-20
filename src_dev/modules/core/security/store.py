"""List persistence (ported from ND, fixes #4 and #6 applied).

Fix #4: ND re-reads the file on every check and its lock only guards writes.
- Memory cache: one in-process copy of the lists, loaded once at startup.
- Write-through: write operations flush to disk synchronously.
- Atomic write: write a temp file first, then os.replace.
- Read/write lock: threading.RLock guards both reads and writes.

Fix #6: store "features", not whole commands (when judging dangerous, the judge
extracts a generalizable feature such as `whoami`); blacklist hits may be
reviewed once (see wrapper.review_on_block).

Five lists:
- blacklist : static blacklist keywords (0-token permanent block)
- self      : self-referential features (script dir / own files, injected at startup)
- learned   : self-learned features (auto-accumulated by judge/input layer, tied to LLM detection switch)
- whitelist : allowlist (execute directly)
- asklist   : ask list (four-choice)
- overrides : user review records (allow-once / deny-once, used for the threshold upgrade prompt)

Persistence layout (paths from config/security.json's *_file, relative to app_root):
- blacklist.json : {"keywords": [...], "self": [...], "learned": [...], "version": "..."}
- whitelist.json / asklist.json / overrides.json : plain arrays
"""
import datetime
import json
import logging
import os
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger("Claw_SE.security.store")

KEYWORD_LISTS = ("blacklist", "self", "learned", "whitelist", "asklist")
OVERRIDES_LIST = "overrides"


class Store:
    """List persistence: memory cache + write-through + RLock + atomic write.

    Args:
        security_config: dict from config/security.json (with relative list paths).
        app_root: dev body root (src_dev/), used to resolve relative list paths.
    """

    def __init__(self, security_config: dict, app_root: Path):
        self._cfg = security_config or {}
        self._root = app_root
        self._lock = threading.RLock()
        self._data: dict[str, list] = {
            "blacklist": [],
            "self": [],
            "learned": [],
            "whitelist": [],
            "asklist": [],
            "overrides": [],
        }
        self._load_all()

    # ---- path resolution ----
    def _resolve(self, key: str) -> Path:
        rel = self._cfg.get(key, "")
        path = Path(rel).expanduser() if rel else Path()
        if not path.is_absolute():
            path = self._root / path
        return path

    def blacklist_path(self) -> Path:
        """Path of the blacklist file (holds keywords/self/learned)."""
        return self._resolve("blacklist_file")

    def _file_for(self, name: str) -> Optional[Path]:
        mapping = {
            "blacklist": "blacklist_file",
            "self": "blacklist_file",
            "learned": "blacklist_file",
            "whitelist": "whitelist_file",
            "asklist": "asklist_file",
            "overrides": "overrides_file",
        }
        key = mapping.get(name)
        return self._resolve(key) if key else None

    # ---- initial load (one-shot) ----
    def _load_all(self) -> None:
        # blacklist file: {keywords, self, learned, version}
        bl = self._read_json_file(self.blacklist_path())
        if isinstance(bl, dict):
            self._data["blacklist"] = list(bl.get("keywords", []))
            self._data["self"] = list(bl.get("self", []))
            self._data["learned"] = list(bl.get("learned", []))
        for name in ("whitelist", "asklist", "overrides"):
            path = self._file_for(name)
            if path is None:
                continue
            arr = self._read_json_file(path)
            self._data[name] = list(arr) if isinstance(arr, list) else []
        logger.info("store loaded: blacklist=%d self=%d learned=%d whitelist=%d asklist=%d",
                    len(self._data["blacklist"]), len(self._data["self"]),
                    len(self._data["learned"]), len(self._data["whitelist"]),
                    len(self._data["asklist"]))

    def _read_json_file(self, path: Path):
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("failed to read %s: %s", path, e)
            return None

    # ---- atomic write ----
    def _atomic_write(self, path: Path, payload) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)

    def _save_list(self, name: str) -> None:
        # blacklist/self/learned all live inside the blacklist file as a combined dict
        if name in ("blacklist", "self", "learned"):
            payload = {
                "keywords": self._data["blacklist"],
                "self": self._data["self"],
                "learned": self._data["learned"],
                "version": self._cfg.get("version", "v1"),
            }
            self._atomic_write(self.blacklist_path(), payload)
            return
        path = self._file_for(name)
        if path is not None:
            self._atomic_write(path, self._data[name])

    # ---- queries ----
    def match_any(self, text: str, name: str) -> bool:
        """Containment match: does text hit any feature of the named list?

        Args:
            text: text to judge (command / path / input).
            name: list name (blacklist/self/learned/whitelist/asklist).

        Returns:
            True if any feature matches, False otherwise.
        """
        if not text:
            return False
        lowered = text.lower()
        with self._lock:
            for item in self._data.get(name, []):
                if item and item.lower() in lowered:
                    return True
        return False

    def get_list(self, name: str) -> list:
        """Return a read-only snapshot of a list's current content."""
        with self._lock:
            return list(self._data.get(name, []))

    # ---- write operations (write-through + atomic) ----
    def add(self, feature: str, name: str) -> str:
        """Add a feature to the named list and flush to disk immediately.

        Args:
            feature: feature string (store features, not whole commands).
            name: list name.

        Returns:
            A confirmation message.
        """
        feature = feature.strip()
        if not feature:
            return "empty feature, not added"
        with self._lock:
            lst = self._data.setdefault(name, [])
            if feature not in lst:
                lst.append(feature)
                self._save_list(name)
                return f"Added to {name}: {feature}"
            return f"Already in {name}: {feature}"

    def learn(self, feature: str) -> str:
        """Self-learn: write a dangerous feature into the learned list.

        Tied to the LLM detection switch (no independent switch).
        """
        return self.add(feature, "learned")

    def add_self(self, feature: str) -> str:
        """Add a self-referential feature (script dir / own file) to the self list."""
        return self.add(feature, "self")

    def ensure_self(self, features: list[str]) -> None:
        """Ensure a set of self-referential features are all present (idempotent)."""
        with self._lock:
            changed = False
            for f in features:
                if f and f not in self._data["self"]:
                    self._data["self"].append(f)
                    changed = True
            if changed:
                self._save_list("self")

    def log_override(self, cmd: str, action: str) -> str:
        """Record a user review action (allow-once / deny-once, ...).

        Args:
            cmd: the reviewed command/feature.
            action: action name (allow_once / deny_once / review_block, ...).

        Returns:
            A confirmation message.
        """
        with self._lock:
            self._data["overrides"].append({
                "cmd": cmd,
                "action": action,
                "time": datetime.datetime.now().isoformat(),
            })
            self._save_list("overrides")
        return f"Override recorded: {cmd} -> {action}"

    def override_count(self, cmd: str, action: str) -> int:
        """Count how many times a command was reviewed with a given action.

        Used for the override-threshold whitelist upgrade prompt (fix #7).
        """
        with self._lock:
            return sum(
                1 for o in self._data["overrides"]
                if isinstance(o, dict) and o.get("cmd") == cmd and o.get("action") == action
            )
