"""Single-file distribution support (ladder 4; mostly stubs in dev mode).

- ensure_deps(): auto-install the core 4 deps into ~/.claw_se/site-packages when missing
  (user never has to pip manually); on failure print a hint and degrade gracefully.
- self_release(): first-run self-extraction of modules/config/prompt_library into cwd
  (CLAW_SE_HOME overrides); --reset-core re-releases a corrupted core.
- keyring_ref(): reserved interface for keyring-backed secret lookup (MVP uses .env).

In dev mode (src_dev/) all of these are no-ops because the tree already exists and
the environment already has the deps.
"""
import logging
import os
import subprocess
import sys
from pathlib import Path

from . import env

logger = logging.getLogger("Claw_SE.loader")

CORE_DEPS = ["langchain", "langchain-openai", "langchain-core", "python-dotenv"]
# importable names corresponding to CORE_DEPS (pip names != module names)
_CORE_IMPORTS = ["langchain", "langchain_openai", "langchain_core", "dotenv"]

_APP_HOME = Path.home() / ".claw_se"
_DEPS_TARGET = _APP_HOME / "site-packages"
_DEPS_HASH = _APP_HOME / "deps_hash.json"


def _deps_available() -> bool:
    """Check whether the core deps are importable."""
    import importlib

    for mod in _CORE_IMPORTS:
        try:
            importlib.import_module(mod)
        except ImportError:
            return False
    return True


def ensure_deps() -> bool:
    """Ensure core dependencies are available (auto-install when missing).

    Returns:
        True when all deps are usable; False when install failed (caller degrades gracefully).
    """
    if env.IS_FROZEN:
        return True  # deps are bundled inside the exe
    if _deps_available():
        return True
    try:
        _DEPS_TARGET.mkdir(parents=True, exist_ok=True)
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--target", str(_DEPS_TARGET), *CORE_DEPS]
        )
        sys.path.insert(0, str(_DEPS_TARGET))
        return _deps_available()
    except (OSError, subprocess.CalledProcessError) as e:
        print("Warning: failed to auto-install dependencies. "
              "Please run manually: pip install " + " ".join(CORE_DEPS))
        print(f"  detail: {e}")
        return False


def self_release(root: Path, reset_core: bool = False) -> Path:
    """Self-extract bundled modules/config/prompt_library to disk (ladder 4).

    Dev mode: the tree already exists at `root`, nothing to release.

    Args:
        root: target root (cwd or CLAW_SE_HOME).
        reset_core: whether to re-release a corrupted core.

    Returns:
        The release root path.
    """
    logger.info("self_release: dev mode, no-op for root=%s (reset_core=%s)", root, reset_core)
    return root


def keyring_ref(service: str, key: str) -> str:
    """Reserved interface for keyring-backed secrets (MVP uses .env only).

    Args:
        service: keyring service name.
        key: key name.

    Returns:
        The secret value (currently empty; keyring support is a later milestone).
    """
    return os.environ.get(key, "")
