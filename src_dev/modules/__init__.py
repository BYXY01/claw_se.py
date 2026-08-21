"""Feature discovery and loading for claw_se.

Each peripheral module (single `.py` under modules/) may declare a FEATURE dict:
    FEATURE = {
        "name": "exec",
        "version": "0.1",
        "desc": "human readable description",
        "tools": [callable, ...],      # exposed to the model via @tool
        "hooks": {"on_load": ..., "on_unload": ...},
        "data_dir": True,              # optional: create own data dir under modules/
        "guard_key": "command",        # security-judgment parameter name
    }

Install-style plugins live under plugins/<id>/ (manifest.json + plugin.py) and are
loaded through the same graded security checks - see modules/core/plugins.py.
Their tools / guard_keys / channels are merged into the same shared pipelines.

Rules:
- modules/core/ is the kernel: always imported, cannot be disabled, never lent out.
- Peripheral modules are enabled/disabled by config/modules.json (default enabled).
- Every loaded module passes the graded security check (strict=full, normal=only new
  via module_trust.json; hard risks always block).
- on_load/on_unload lifecycle hooks are invoked when present.
"""
import importlib
import logging
import os
from pathlib import Path
from typing import Optional

from .core import config as core_config
from .core.plugins import PluginLoader, LoadedPlugin
from .core.security import ModuleTrust, validate_module

logger = logging.getLogger("claw_se.modules")

_MODULES_ROOT = Path(__file__).resolve().parent
_APP_ROOT = _MODULES_ROOT.parent

# Plugins live under modules/ as modules/<plugin_id>/ (manifest.json + plugin.py).
_PLUGINS_ROOT = _MODULES_ROOT

# Plugins loaded by the most recent discover(); collect_tools/collect_guard_map
# merge their capabilities so callers keep one uniform pipeline.
_PLUGINS: list[LoadedPlugin] = []


def discover(security_config: Optional[dict] = None, strict: Optional[bool] = None,
             trust_path: Optional[Path] = None) -> dict:
    """Discover and load core + enabled peripheral modules (with security checks).

    Args:
        security_config: dict from config/security.json; loaded when None.
        strict: module-check mode override (True=validate all, False=only new modules).
        trust_path: module_trust.json path; defaults to the hardcoded
            modules/core/security/data/module_trust.json under the app root.

    Returns:
        dict mapping module name -> loaded module object (peripheral only; core is infrastructure).
    """
    security_config = security_config if security_config is not None else core_config.load_security_config()
    trust = ModuleTrust(trust_path or (_APP_ROOT / "modules/core/security/data/module_trust.json"))

    # forced: kernel import (always loads, cannot be disabled)
    importlib.import_module("modules.core")

    cfg = core_config.load_modules_config()
    loaded: dict[str, object] = {}
    for path in sorted(_MODULES_ROOT.glob("*.py")):
        if path.name == "__init__.py":
            continue
        name = path.stem
        enabled = cfg.get(name, True)
        if not enabled:
            logger.info("module disabled: %s", name)
            continue
        try:
            module = importlib.import_module(f"modules.{name}")
        except Exception as e:  # noqa: BLE001 - a broken module must not break discovery
            logger.error("failed to import module %s: %s", name, e)
            continue

        ok, problems = validate_module(name, module, security_config, _APP_ROOT, trust, strict)
        if not ok:
            logger.error("module %s rejected by security check: %s", name, problems)
            continue

        loaded[name] = module
        logger.info("module loaded: %s", name)

        feat = getattr(module, "FEATURE", None) or {}
        on_load = (feat.get("hooks") or {}).get("on_load")
        if callable(on_load):
            try:
                on_load()
            except Exception as e:  # noqa: BLE001 - hook failure must not break discovery
                logger.error("module %s on_load failed: %s", name, e)

    # install-style plugins (subdirs of modules/ with a manifest.json)
    global _PLUGINS
    _PLUGINS = []
    loader = PluginLoader(_PLUGINS_ROOT, security_config, _APP_ROOT,
                          strict=bool(strict), env=dict(os.environ))
    _PLUGINS = [p for p in loader.load_all() if cfg.get(p.plugin_id, True)]
    for plugin in _PLUGINS:
        logger.info("plugin enabled: %s", plugin.plugin_id)
    return loaded


def collect_tools(loaded: dict) -> list:
    """Collect tool callables from loaded modules AND plugins.

    Args:
        loaded: mapping of module name -> loaded module.

    Returns:
        List of tool callables to hand to the agent.
    """
    tools: list = []
    for name, module in loaded.items():
        feat = getattr(module, "FEATURE", None)
        if not feat:
            logger.warning("module %s has no FEATURE dict", name)
            continue
        for tool in feat.get("tools", []) or []:
            if hasattr(tool, "name") or callable(tool):
                tools.append(tool)
    from .core.plugins import collect_tools as collect_plugin_tools
    tools += collect_plugin_tools(_PLUGINS)
    return tools


def collect_guard_map(loaded: dict) -> dict[str, str]:
    """Collect tool name -> guard_key mapping from loaded modules AND plugins.

    Args:
        loaded: mapping of module name -> loaded module.

    Returns:
        Mapping used by secure_tools to decide the security-relevant parameter.
    """
    guard_map: dict[str, str] = {}
    for name, module in loaded.items():
        feat = getattr(module, "FEATURE", None)
        if not feat:
            continue
        gk = feat.get("guard_key")
        if not gk:
            continue
        for tool in feat.get("tools", []) or []:
            tname = getattr(tool, "name", None)
            if tname:
                guard_map[tname] = gk
    from .core.plugins import collect_guard_map as collect_plugin_guard_map
    guard_map.update(collect_plugin_guard_map(_PLUGINS))
    return guard_map


def collect_hooks(loaded: dict) -> dict:
    """Collect lifecycle/extension hooks from loaded modules AND plugins.

    Args:
        loaded: mapping of module name -> loaded module.

    Returns:
        dict mapping hook name -> list of callables.
    """
    hooks: dict[str, list] = {}
    for module in loaded.values():
        feat = getattr(module, "FEATURE", None)
        if not feat:
            continue
        for hook_name, hook in (feat.get("hooks") or {}).items():
            if callable(hook):
                hooks.setdefault(hook_name, []).append(hook)
    for plugin in _PLUGINS:
        for hook_name, hook in plugin.api.hooks():
            if callable(hook):
                hooks.setdefault(hook_name, []).append(hook)
    return hooks


def wire_plugin_channels() -> None:
    """Register channel capabilities of loaded plugins into the MsgIO bus."""
    if not _PLUGINS:
        return
    from .core.msgio import get_io
    from .core.plugins import wire_channels
    wire_channels(_PLUGINS, register_channel=get_io().register)
