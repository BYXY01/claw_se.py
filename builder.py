"""claw_se single-file builder (internal)."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC_DEV = ROOT / "src_dev"

_PLACE = "_PAYLOAD: dict[str, str] = {}"
_VERSION = (ROOT / "version.txt").read_text(encoding="utf-8").strip()
_BN = f'#!/usr/bin/env python3\n# claw_se.py - claw_se (Small + Security edition) v{_VERSION} single-file build\n'
_X = {".env"}

_H = r'''
import os
import subprocess
import sys
from pathlib import Path
_PAYLOAD: dict[str, str] = {}
_CORE_DEPS = ["langchain", "langchain-openai", "langchain-core", "python-dotenv", "psutil"]
_CORE_IMPORTS = ["langchain", "langchain_openai", "langchain_core", "dotenv", "psutil"]
_BANNER = "claw_se (Small + Security edition, single-file build)"
_FALLBACK_PROMPT = (
    "You are a local AI assistant protected by a security layer. "
    "You can run commands (execute), handle files (file_op), and query info (get_info). "
    "Stay concise and only do what the user explicitly asks."
)
'''

_R = r'''
def _release_root() -> Path:
    """Release target: CLAW_SE_HOME override, else the current working directory."""
    override = os.environ.get("CLAW_SE_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path.cwd()
def _refuse(reason: str) -> None:
    print(f"[SE] {_BANNER}: {reason}")
    sys.exit(1)
def self_release(root: Path, reset_core: bool = False) -> Path:
    """Extract the embedded modules/config/prompt_library to the release root.
    - A stripped/empty payload refuses to start.
    - Existing files are NEVER overwritten (modules/config/prompts are all user
      editable by design); --reset-core deletes and re-releases only modules/core.
    Args:
        root: release target directory.
        reset_core: re-release a corrupted core (delete + rewrite modules/core only).
    Returns:
        The release root.
    """
    if not _PAYLOAD:
        _refuse("invalid or stripped single file, refusing to start (bare-run defense). "
                "Please re-download claw_se.py from the release.")
    if reset_core:
        core_dir = root / "modules" / "core"
        if core_dir.exists():
            import shutil
            shutil.rmtree(core_dir)
            print(f"[SE] reset: removed corrupted {core_dir}")
    written = 0
    for rel, content in sorted(_PAYLOAD.items()):
        if reset_core and not rel.startswith("modules/core/"):
            continue
        target = root / rel
        if target.exists() and not reset_core:
            continue
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
'''

_L = r'''
def _ensure_genuine_run(modules_mod) -> None:
    """Refuse to run the main loop in non-genuine contexts (defense in depth).
    Even though the main loop only exists inside this single file, it refuses to
    boot when:
    - the payload is missing/stripped (not a genuine build),
    - the platform is Windows but the process is not the frozen exe (Windows
      ships as claw_se.exe only; a bare `python claw_se.py` is refused), or
    - the `modules` package it would drive comes from the cloned development
      tree (src_dev/) - i.e. someone is running this loop against a dev tree
      instead of a proper release.
    """
    if not _PAYLOAD:
        _refuse("invalid or stripped single file, refusing to start (bare-run defense). "
                "Please re-download claw_se.py from the release.")
    on_windows = sys.platform.startswith("win") or os.name == "nt"
    if on_windows and not getattr(sys, "frozen", False):
        _refuse("Windows must run the frozen build (claw_se.exe). "
                "Download claw_se.exe from the release; do not run 'python claw_se.py'.")
    module_path = getattr(modules_mod, "__file__", "")
    try:
        inside_src_dev = "src_dev" in Path(module_path).resolve().parts
    except (OSError, TypeError):
        inside_src_dev = False
    if inside_src_dev:
        _refuse("refusing to run the main loop against the development source tree. "
                "Build the single file first: python builder.py, then run claw_se.py.")
def _load_system_prompt(root: Path) -> str:
    """Compose the system prompt from prompt_library (IDENTITY + RULES).
    Args:
        root: the release root.
    Returns:
        The system prompt string.
    """
    parts: list[str] = []
    for name in ("IDENTITY", "RULES"):
        p = root / "prompt_library" / f"{name}.md"
        if p.exists():
            content = p.read_text(encoding="utf-8").strip()
            if content:
                parts.append(content)
    return "\n\n".join(parts) if parts else _FALLBACK_PROMPT
def _detection_needs_judge(security_config: dict) -> bool:
    """Whether the current switch settings require the independent judge."""
    detect = str(security_config.get("detect", "auto")).lower()
    input_detect = str(security_config.get("input_detect", "off")).lower()
    return detect != "off" or input_detect == "full" or input_detect.startswith("random:")
def _boot(root: Path) -> None:
    """The main loop, embedded in this single file only (imports happen after release)."""
    import logging
    import time
    from langchain_core.messages import HumanMessage
    from langgraph.checkpoint.memory import InMemorySaver
    import modules
    from modules.core import config as core_config
    from modules.core import env
    from modules.core import factory
    from modules.core.msgio import TerminalBackend, get_io
    from modules.core.security import build_stack
    logger = logging.getLogger("claw_se.boot")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    _v = getattr(sys.modules.get("__main__"), "version", "unknown")
    logger.info("claw_se version: %s", _v)
    _ensure_genuine_run(modules)
    core_config.ensure_config_files(root)
    core_config.load_env()
    security_config = core_config.load_security_config()
    judge = None
    if _detection_needs_judge(security_config):
        try:
            judge = factory.build_judge(core_config.load_providers_config())
        except KeyError as e:
            logger.warning("judge disabled: %s", e)
    ctx, guard = build_stack(security_config, root, judge=judge)
    entry = Path(sys.argv[0]).resolve()
    self_dirs = [str(root), str(root / "modules")]
    if env.IS_BUNDLE or env.IS_FROZEN:
        edir = entry.parent
        self_dirs += [str(edir), str(edir / "modules")]
    ctx.store.ensure_self(list(dict.fromkeys(self_dirs)))
    loaded = modules.discover(security_config)
    tools = modules.collect_tools(loaded)
    guard_map = modules.collect_guard_map(loaded)
    logger.info("loaded modules: %s", ", ".join(loaded.keys()))
    logger.info("registered tools: %s", ", ".join(getattr(t, "name", str(t)) for t in tools))
    if "delegate" in loaded:
        from modules import delegate as delegate_mod
        delegate_mod.configure(ctx, all_tools=tools, tool_guards=guard_map)
    system_prompt = _load_system_prompt(root)
    try:
        agent = factory.build_agent(
            role="main", tools=tools, tool_guards=guard_map,
            system_prompt=system_prompt, ctx=ctx,
            checkpointer=InMemorySaver(),
            summarize={"trigger": ("fraction", 0.7), "keep": ("messages", 20)},
        )
    except KeyError as e:
        print(f"Error: cannot resolve the main model ({e}). Copy config/providers.example.json to config/providers.json and set your key in .env.")
        sys.exit(1)
    io = get_io()
    io.set_input_guard(guard)
    io.register(TerminalBackend())
    io.send("claw_se started (Small + Security edition, single-file). "
            "Type a message, Ctrl+C to exit.")
    thread_id = {"configurable": {"thread_id": "main"}}
    while True:
        try:
            msg = io.receive()
            if msg is None:
                time.sleep(0.1)  # no input on any channel: rest, don't spin
                continue
            user_input = msg.text
            channel = msg.channel
            logger.info("User: %s", user_input.replace("\n", "\\n"))
            io.send("\nAI: ", channel=channel)
            io.set_current_channel(channel)
            try:
                response = agent.invoke(
                    {"messages": [HumanMessage(content=user_input)]}, config=thread_id)
            finally:
                io.set_current_channel(None)
            ai_response = response["messages"][-1].content if isinstance(response, dict) else str(response)
            io.send(ai_response if isinstance(ai_response, str) else str(ai_response), channel=channel)
            io.send("", channel=channel)
            logger.info("AI: %s", str(ai_response).replace("\n", "\\n"))
        except KeyboardInterrupt:
            io.send("\nExited.")
            break
        except Exception as e:
            io.send(f"\nError: {e}")
def main() -> None:
    """Entry: release, ensure deps, then run the embedded main loop."""
    reset_core = "--reset-core" in sys.argv
    root = self_release(_release_root(), reset_core=reset_core)
    sys.path.insert(0, str(root))
    ensure_deps()
    _boot(root)
if __name__ == "__main__":
    main()
'''

_T = _H + _R + _L


def _src():
    p = {}
    for f in sorted(SRC_DEV.rglob("*")):
        if f.is_dir():
            continue
        r = f.relative_to(SRC_DEV).as_posix()
        if r in _X or "__pycache__" in r or r.endswith(".pyc") or "/data/" in r:
            continue
        p[r] = f.read_text(encoding="utf-8")
    return p


def build(out):
    entry = _T.replace(_PLACE, "_PAYLOAD = " + json.dumps(_src(), ensure_ascii=False, indent=2))
    entry = "\n".join(l for l in entry.splitlines() if l.strip())
    out.mkdir(parents=True, exist_ok=True)
    target = out / "claw_se.py"
    target.write_text(_BN + f'version = "{_VERSION}"\n' + entry, encoding="utf-8")
    print(f"[builder] wrote {target} ({target.stat().st_size} bytes)")
    return target


def _exe(f):
    import importlib
    import subprocess
    try:
        importlib.import_module("PyInstaller")
    except ImportError:
        print("[builder] PyInstaller not installed; skipping claw_se.exe")
        return False
    # Runtime deps that are imported LAZILY (inside functions / the boot loop) are
    # not picked up by PyInstaller's static scan, so they must be declared here or
    # the exe breaks at runtime (e.g. process-kill needs psutil, the boot loop
    # needs langgraph.checkpoint.memory). Executable deps are auto-detected.
    hidden_imports = [
        "langchain_openai",
        "langchain_core",
        "psutil",
        "langgraph",
        "langgraph.checkpoint.memory",
    ]
    args = [sys.executable, "-m", "PyInstaller", "--onefile", "--console",
            "--name", "claw_se"]
    for mod in hidden_imports:
        args += ["--hidden-import", mod]
    args.append(str(f))
    subprocess.check_call(args)
    return True


if __name__ == "__main__":
    import argparse as _a
    ap = _a.ArgumentParser()
    ap.add_argument("--exe", action="store_true")
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args()
    f = build(a.out or Path.cwd())
    if a.exe:
        _exe(f)
