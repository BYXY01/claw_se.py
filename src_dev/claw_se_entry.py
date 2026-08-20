"""Single-file entry for the built claw_se.py (ladder 4).

This file is the runtime template: builder.py replaces the `_PAYLOAD` placeholder
line below with the full embedded file map and produces the distributed claw_se.py.
The single file is the ONLY runnable form of the product (no dev entry).

Runtime flow:
1. self_release(): extract modules/ config/ prompt_library/ to the release root
   (CLAW_SE_HOME override, default cwd); refuse to start on a stripped/empty payload.
   Existing files are never overwritten (user edits preserved); --reset-core
   re-releases only modules/core.
2. ensure_deps(): auto-install the core 4 deps into ~/.claw_se/site-packages when
   missing (user never has to pip manually); failure degrades gracefully.
3. Add the release root to sys.path, then import modules.core.boot.run().
"""
import os
import subprocess
import sys
from pathlib import Path

_PAYLOAD: dict[str, str] = {}  # <-- builder.py replaces this line with the embedded file map

_CORE_DEPS = ["langchain", "langchain-openai", "langchain-core", "python-dotenv"]
_CORE_IMPORTS = ["langchain", "langchain_openai", "langchain_core", "dotenv"]

_BANNER = "Claw_SE (Small + Security edition, single-file build)"


def _release_root() -> Path:
    """Release target: CLAW_SE_HOME override, else the current working directory."""
    override = os.environ.get("CLAW_SE_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path.cwd()


def self_release(root: Path, reset_core: bool = False) -> Path:
    """Extract the embedded modules/config/prompt_library to the release root.

    Args:
        root: release target directory.
        reset_core: re-release a corrupted core (delete + rewrite modules/core only).

    Returns:
        The release root.

    Raises:
        SystemExit: when the payload is empty/stripped (bare-run defense).
    """
    if not _PAYLOAD:
        print(f"[SE] {_BANNER}: invalid or stripped single file, refusing to start "
              "(bare-run defense). Please re-download claw_se.py from the release.")
        sys.exit(1)

    if reset_core:
        core_dir = root / "modules" / "core"
        if core_dir.exists():
            import shutil
            shutil.rmtree(core_dir)
            print(f"[SE] reset: removed corrupted {core_dir}")

    written = 0
    for rel, content in sorted(_PAYLOAD.items()):
        if reset_core and not rel.startswith("modules/core/"):
            continue  # --reset-core only re-releases core
        target = root / rel
        if target.exists() and not reset_core:
            continue  # never overwrite existing (user may have edited prompts/lists/config)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        written += 1
    print(f"[SE] {_BANNER}: released {written} files to {root}")
    return root


def _deps_available() -> bool:
    """Check whether the core deps are importable (stdlib only)."""
    import importlib
    for mod in _CORE_IMPORTS:
        try:
            importlib.import_module(mod)
        except ImportError:
            return False
    return True


def ensure_deps() -> bool:
    """Auto-install the core deps into ~/.claw_se/site-packages when missing.

    Returns:
        True when all deps are usable; False when install failed (degrade gracefully).
    """
    if _deps_available():
        return True
    target = Path.home() / ".claw_se" / "site-packages"
    target.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--target", str(target), *_CORE_DEPS])
        sys.path.insert(0, str(target))
        return _deps_available()
    except (OSError, subprocess.CalledProcessError) as e:
        print("Warning: failed to auto-install dependencies. "
              "Please run manually: pip install " + " ".join(_CORE_DEPS))
        print(f"  detail: {e}")
        return False


def main() -> None:
    """Entry: release, ensure deps, then boot."""
    reset_core = "--reset-core" in sys.argv
    root = self_release(_release_root(), reset_core=reset_core)
    sys.path.insert(0, str(root))
    if not ensure_deps():
        # degrade gracefully: continue starting (modules will fail with clear ImportError)
        pass
    from modules.core.boot import run  # noqa: E402 - requires the release root on sys.path
    run()


if __name__ == "__main__":
    main()
