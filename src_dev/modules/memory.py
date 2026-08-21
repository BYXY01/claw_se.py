"""Memory module: remember / recall (ladder 3).

- Plain `.md` content files under modules/memory/data/ (content data, never templated, D9/D10).
- Lightweight text search by keyword / date, no vector or semantic (D13).
- Default OFF in config/modules.json (opt-in, design decision Q5).
- data_dir=True: the module creates its own data folder under modules/ at runtime (B3).
"""
import datetime
import logging
from pathlib import Path

from langchain_core.tools import tool

from .core import config as core_config

logger = logging.getLogger("claw_se.memory")


def _data_dir() -> Path:
    """Ensure and return the memory data directory (modules/memory/data/)."""
    d = core_config.app_root() / "modules" / "memory" / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _daily_file(date: str) -> Path:
    """Return the memory file for a date (YYYY-MM-DD), defaulting to today."""
    day = date.strip() or datetime.date.today().isoformat()
    return _data_dir() / f"{day}.md"


@tool
def remember(content: str, tags: str = "", date: str = "") -> str:
    """Save a memory entry (append to the daily memory file).

    Args:
        content: the memory content to remember.
        tags: optional comma-separated tags.
        date: optional date (YYYY-MM-DD); defaults to today.

    Returns:
        A confirmation message.
    """
    body = (content or "").strip()
    if not body:
        return "Error: 'content' required for remember."
    day = date.strip() or datetime.date.today().isoformat()
    path = _daily_file(day)
    now = datetime.datetime.now().strftime("%H:%M")
    tag_str = f" [{tags.strip()}]" if tags.strip() else ""
    entry = f"### {now}{tag_str}\n{body}\n"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(entry)
    logger.info("memory saved: %s", path.name)
    return f"Remembered into {path.name} ({len(body)} chars)"


@tool
def recall(query: str = "", date: str = "", limit: int = 10) -> str:
    """Search memory by keyword / date (lightweight text search, no vectors).

    Args:
        query: keyword to match against memory entries (empty matches everything).
        date: restrict to a date (YYYY-MM-DD); empty searches all days.
        limit: max number of matching lines to return.

    Returns:
        Matching memory lines, or a "no match" message.
    """
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 10
    if limit < 1:
        limit = 10

    files: list[Path] = []
    if date.strip():
        f = _daily_file(date)
        if f.exists():
            files.append(f)
    else:
        files = sorted(_data_dir().glob("*.md"))

    q = (query or "").strip().lower()
    results: list[str] = []
    for f in files:
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            logger.warning("memory read failed %s: %s", f, e)
            continue
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if q and q not in stripped.lower():
                continue
            results.append(f"{f.stem} | {stripped}")
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break

    if not results:
        return "No matching memories."
    return "\n".join(results)


FEATURE = {
    "name": "memory",
    "version": "0.1",
    "desc": "Memory: remember/recall (plain .md, keyword+date search)",
    "tools": [remember, recall],
    "hooks": {},
    "data_dir": True,
}
