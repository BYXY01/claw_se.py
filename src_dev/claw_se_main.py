"""Claw_SE development entry (dev-only; the single-file claw_se.py is built at ladder 4).

Thin wrapper: the actual boot + main loop lives in modules.core.boot.run()
so the dev entry and the single-file entry share the same logic.

Run:  python claw_se_main.py   (from src_dev/)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # ensure `import modules` works

from modules.core.boot import run  # noqa: E402

if __name__ == "__main__":
    run()
