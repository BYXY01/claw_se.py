"""Platform / packaging-state detection (single source of truth).

Per requirement book §15.2: all IS_* checks live in core/env.py only;
other modules import and consume the results, never writing platform checks
at the top of their own files.

- IS_WIN    : Windows platform
- IS_FROZEN : frozen into an exe by PyInstaller (deps are bundled)
- IS_BUNDLE : running directly as the single-file claw_se.py (first-run self-release)
- IS_DEV    : anything else = development mode (multi-file inside src_dev/)
"""
import os
import sys

IS_WIN: bool = sys.platform.startswith("win") or os.name == "nt"
IS_FROZEN: bool = bool(getattr(sys, "frozen", False))
IS_BUNDLE: bool = (not IS_FROZEN) and os.path.basename(sys.argv[0]) == "claw_se.py"
IS_DEV: bool = (not IS_FROZEN) and (not IS_BUNDLE)
