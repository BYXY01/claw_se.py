"""Security kernel package: exports the built stack and graded module-load validation.

Graded module check (fix #14):
- strict mode -> full validation for every module load
              (FEATURE legitimacy / malicious features / path escape)
- normal mode -> only NEW modules (never validated, per persistent module_trust.json)
              get one validation; already-trusted modules load directly
- hard risks (path escape / malicious features) are ALWAYS intercepted,
  regardless of strict/normal mode.
"""
import json
import logging
from pathlib import Path
from typing import Optional

from .judge import InputGuard, SafetyJudge
from .rules import Rules
from .store import Store
from .wrapper import SecurityConfig, SecurityContext, secure_tool, secure_tools

__all__ = [
    "InputGuard", "SafetyJudge", "Rules", "Store",
    "SecurityConfig", "SecurityContext", "secure_tool", "secure_tools",
    "build_stack", "protected_dirs", "ModuleTrust", "validate_module",
]

logger = logging.getLogger("Claw_SE.security")

# Malicious markers always scanned for (hard risk, mode-independent).
MALICIOUS_PATTERNS = [
    "eval(",
    "exec(",
    "os.system(",
    "pickle.load",
    "pty.spawn",
    "__import__(",
    "socket.socket",
]

_REQUIRED_FEATURE_KEYS = ("name", "desc", "tools")


def protected_dirs(app_root: Path) -> list[Path]:
    """Return the self-directory-guard protected dirs for a given app root.

    Both the modules/ dir and the whole dev root (src_dev/) are protected:
    the agent must never modify/delete its own `.py` sources (fix #13).
    """
    return [app_root / "modules", app_root]


def build_stack(security_config: dict, app_root: Path,
                judge: Optional[SafetyJudge] = None) -> tuple[SecurityContext, InputGuard]:
    """Assemble the full security stack (store + rules + config + context + input guard).

    Args:
        security_config: dict from config/security.json.
        app_root: dev body root (src_dev/), for list file paths.
        judge: optional independent SafetyJudge (built by factory from providers + .env).

    Returns:
        (SecurityContext, InputGuard).
    """
    st = Store(security_config, app_root)
    ru = Rules(st, protected_dirs(app_root))
    cfg = SecurityConfig.from_dict(security_config)
    ctx = SecurityContext(st, ru, cfg, judge)
    guard = InputGuard(security_config, judge=judge, store=st)
    return ctx, guard


# ---- graded module-load validation ----
class ModuleTrust:
    """Persistent record of already-validated modules (module_trust.json).

    JSON format: {"trusted": ["exec", "file", ...]}.

    Args:
        path: path to the trust file.
    """

    def __init__(self, path: Path):
        self._path = path
        self._names: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._names = set(data.get("trusted", []))
        except (json.JSONDecodeError, TypeError, OSError) as e:
            logger.warning("failed to read module_trust: %s", e)

    def contains(self, name: str) -> bool:
        return name in self._names

    def add(self, name: str) -> None:
        self._names.add(name)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps({"trusted": sorted(self._names)}, ensure_ascii=False, indent=2)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(self._path)
        except OSError as e:
            logger.warning("failed to persist module_trust: %s", e)


def scan_malicious(module) -> list[str]:
    """Scan a module's source for malicious markers (hard risk, always checked).

    Args:
        module: imported module object.

    Returns:
        List of matched markers.
    """
    try:
        src = Path(module.__file__).read_text(encoding="utf-8")
    except (OSError, TypeError):
        return []
    hits = [m for m in MALICIOUS_PATTERNS if m in src]
    return hits


def check_module_features(module) -> list[str]:
    """Validate FEATURE legitimacy (required keys / tools callable / hooks callable).

    Args:
        module: imported module object.

    Returns:
        List of problems (empty when valid).
    """
    errors = []
    feat = getattr(module, "FEATURE", None)
    if not isinstance(feat, dict):
        return ["missing FEATURE dict"]
    for key in _REQUIRED_FEATURE_KEYS:
        if key not in feat:
            errors.append(f"FEATURE missing key: {key}")
    tools = feat.get("tools", [])
    if not isinstance(tools, list):
        errors.append("FEATURE.tools must be a list")
    for t in tools if isinstance(tools, list) else []:
        if not callable(t) and not hasattr(t, "name"):
            errors.append(f"FEATURE.tools entry not a tool: {t!r}")
    hooks = feat.get("hooks", {})
    if not isinstance(hooks, dict):
        errors.append("FEATURE.hooks must be a dict")
    else:
        for name, hook in hooks.items():
            if not callable(hook):
                errors.append(f"FEATURE.hooks[{name}] not callable")
    return errors


def check_module_paths(module, modules_root: Path) -> list[str]:
    """Check a module file stays inside the modules root (path escape, hard risk).

    Args:
        module: imported module object.
        modules_root: modules/ directory.

    Returns:
        List of problems (empty when ok).
    """
    try:
        f = Path(module.__file__).resolve()
        modules_root.resolve().relative_to(modules_root.resolve())  # no-op, normalize check below
        f.relative_to(modules_root.resolve())
    except (ValueError, TypeError, OSError):
        return [f"module file outside modules root: {getattr(module, '__file__', '?')}"]
    return []


def validate_module(module_name: str, module, security_config: dict,
                    app_root: Path, trust: ModuleTrust, strict: bool = False) -> tuple[bool, list[str]]:
    """Run the graded module-load validation.

    Args:
        module_name: module name.
        module: imported module object.
        security_config: dict from config/security.json (strict flag source).
        app_root: dev body root (src_dev/).
        trust: ModuleTrust persistent record.
        strict: True -> validate every module; False -> only new modules.

    Returns:
        (ok, problems). ok=False means the module must not load.
    """
    if strict is None:
        strict = str(security_config.get("module_check", "normal")).lower() == "strict"

    modules_root = app_root / "modules"
    hard_errors: list[str] = []
    hard_errors += scan_malicious(module)
    hard_errors += check_module_paths(module, modules_root)
    # hard risks always block, regardless of strict/normal mode
    if hard_errors:
        return False, hard_errors

    if not strict and trust.contains(module_name):
        return True, []  # already trusted -> load directly

    feature_errors = check_module_features(module)
    if feature_errors:
        return False, feature_errors

    trust.add(module_name)
    return True, []
