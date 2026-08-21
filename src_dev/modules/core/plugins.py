"""Install-style plugin loader (0.0.102).

A plugin is a directory under the modules/ folder:
    modules/<plugin_id>/
        manifest.json   # static, auditable declaration (audited WITHOUT importing code)
        plugin.py       # dynamic capability: `def PLUGIN(api)` registers via the facade

Capability kinds (OpenClaw-like breadth): TOOL (AI tools / feature extensions),
CHANNEL (message channels - a web panel is just an HTTP channel, no separate
kind), HOOK (lifecycle/event hooks), PROVIDER (model providers). TOOL, CHANNEL
and HOOK are wired to host seams in this milestone; PROVIDER is recognized and
collected but connected in a later milestone (model-provider milestone).

Capability -> host seam (the only place the loader knows about the host):
    tool     -> shared tools + guard map (factory.secure_tools wraps them)
    channel  -> msgio.register (thread-bridged bus)
    hook     -> lifecycle/event hooks pipeline
    provider -> (reserved) factory.register_provider, later milestone

A plugin does NOT import the kernel: PLUGIN only ever sees the injected
PluginAPI facade (register_tool / register_channel / register_hook /
register_provider / env / auth / data_dir).
Security:
- manifest.json is statically audited before plugin.py is ever imported;
- plugin.py goes through the same graded checks as modules (hard risks always
  block, path must stay inside plugins/);
- tools registered via the api carry a guard_key, merged into the shared
  tool -> guard map so secure_tools wraps them exactly like module tools.
"""
import enum
import importlib.util
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .security import scan_malicious

logger = logging.getLogger("claw_se.plugins")

_REQUIRED_MANIFEST_KEYS = ("id", "name", "version", "capabilities")


class Kind(str, enum.Enum):
    """Capability kinds a plugin can declare and register."""

    TOOL = "tool"
    CHANNEL = "channel"
    HOOK = "hook"
    PROVIDER = "provider"

    @classmethod
    def parse(cls, value: str) -> Optional["Kind"]:
        """Parse a manifest capability string into a Kind, or None when invalid."""
        try:
            return cls(str(value).lower())
        except ValueError:
            return None


@dataclass
class Manifest:
    """Statically-audited plugin declaration (no plugin code executed)."""

    plugin_id: str
    name: str
    version: str
    capabilities: list["Kind"]
    requires: list[str] = field(default_factory=list)
    auth: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def classify(directory: Path) -> str:
    """Classify a directory: 'plugin' when it carries a manifest.json, else 'tool'.

    A manifest.json is the gate: anything with one MUST go through the full
    plugin chain (static audit -> graded check -> injected api) and can never be
    demoted to a bare tool, or the security checks would be bypassed.

    Args:
        directory: the candidate plugin directory.

    Returns:
        'plugin' or 'tool'.
    """
    return "plugin" if (directory / "manifest.json").exists() else "tool"


def _audit_manifest(path: Path) -> Manifest:
    """Statically read and validate manifest.json (never imports plugin code).

    Args:
        path: path to manifest.json.

    Returns:
        The audited Manifest.

    Raises:
        ValueError: on any structural/security problem with the manifest.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise ValueError(f"manifest.json unreadable: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("manifest.json must be a JSON object")
    missing = [k for k in _REQUIRED_MANIFEST_KEYS if not data.get(k)]
    if missing:
        raise ValueError(f"manifest missing required keys: {missing}")
    capabilities: list[Kind] = []
    for value in data.get("capabilities", []):
        kind = Kind.parse(value)
        if kind is None:
            raise ValueError(f"unknown capability: {value}")
        capabilities.append(kind)
    if not capabilities:
        raise ValueError("manifest declares no capabilities")
    auth = data.get("auth", [])
    if not isinstance(auth, list) or not all(isinstance(a, str) for a in auth):
        raise ValueError("manifest auth must be a list of env key names")
    requires = data.get("requires", [])
    if not isinstance(requires, list) or not all(isinstance(r, str) for r in requires):
        raise ValueError("manifest requires must be a list")
    return Manifest(
        plugin_id=str(data["id"]),
        name=str(data["name"]),
        version=str(data["version"]),
        capabilities=capabilities,
        requires=requires,
        auth=auth,
        raw=data,
    )


class PluginAPI:
    """The ONLY surface a plugin may touch - the kernel stays out of reach.

    Plugins live under the modules/ folder as modules/<plugin_id>/ and receive
    this facade in PLUGIN(api). Every capability kind has a register_* method;
    the loader collects what was registered and wires the wired kinds.

    Args:
        plugin_id: the plugin's id.
        manifest: the audited manifest (read-only).
        data_dir: this plugin's private data directory (created on demand).
        env: environment snapshot (secrets come from .env, never the manifest).
    """

    def __init__(self, plugin_id: str, manifest: Manifest, data_dir: Path, env: dict):
        self._plugin_id = plugin_id
        self._manifest = manifest
        self._data_dir = data_dir
        self._env = env
        self._tools: list[tuple] = []
        self._channels: list = []
        self._hooks: list[tuple] = []
        self._providers: list[tuple] = []

    @property
    def manifest(self) -> Manifest:
        """The audited manifest (read-only)."""
        return self._manifest

    @property
    def data_dir(self) -> Path:
        """This plugin's private data directory (created on first use)."""
        self._data_dir.mkdir(parents=True, exist_ok=True)
        return self._data_dir

    def register_tool(self, tool, guard_key: Optional[str] = None) -> None:
        """Register an AI tool / feature extension with its security guard_key.

        Args:
            tool: a callable or langchain @tool.
            guard_key: the security-judgment parameter name, or None when the
                tool needs no guarding.
        """
        self._tools.append((tool, guard_key))

    def register_channel(self, backend) -> None:
        """Register a message channel backend (Kind.CHANNEL)."""
        self._channels.append(backend)

    def make_msg(self, text: str):
        """Wrap inbound text into a bus message tagged with this plugin's channel.

        Lets a channel plugin produce bus messages without importing the kernel
        (the Msg construction happens here, inside the facade).

        Args:
            text: the raw inbound text.

        Returns:
            A Msg carrying this plugin's id as the channel name.
        """
        from .msgio import Msg
        return Msg(channel=self._plugin_id, text=text)

    def register_hook(self, name: str, hook) -> None:
        """Register a lifecycle/event hook (Kind.HOOK).

        Args:
            name: hook name (e.g. on_load / on_unload / on_message_received).
            hook: the callable to invoke for the hook.
        """
        self._hooks.append((name, hook))

    def register_provider(self, provider_meta: dict, *, review: bool = True) -> None:
        """Register a model-provider descriptor (Kind.PROVIDER, wired in a later milestone).

        Security contract: a provider is only ever used through the unified agent
        factory (never a bare ChatOpenAI), and - when `review` is True and the
        security config enables the independent judge - every message routed via
        this provider passes the security reviewer. review=False is reserved for
        explicitly-exempt local/trusted providers and must be justified.

        Args:
            provider_meta: provider metadata (name / models / api_base / ...).
            review: whether messages via this provider must pass the security
                reviewer when the judge switch is enabled (default True).
        """
        self._providers.append((provider_meta, review))

    def env(self, key: str, default: str = "") -> str:
        """Read an environment variable (secrets come from .env).

        Args:
            key: environment variable name.
            default: fallback when unset.
        """
        return self._env.get(key, default)

    def auth(self, key: str) -> str:
        """Read a secret DECLARED in manifest auth - undeclared reads are refused.

        Args:
            key: an env key name listed in the manifest's auth.

        Returns:
            The secret value ("" when unset).

        Raises:
            KeyError: when the key was not declared in manifest auth.
        """
        if key not in self._manifest.auth:
            raise KeyError(f"plugin {self._plugin_id} tried to read undeclared secret: {key}")
        return self._env.get(key, "")

    def tools(self) -> list:
        """Registered (tool, guard_key) pairs, read by the loader for wiring."""
        return list(self._tools)

    def channels(self) -> list:
        """Registered channel backends, read by the loader for wiring."""
        return list(self._channels)

    def hooks(self) -> list:
        """Registered (name, callable) hooks, read by the loader for wiring."""
        return list(self._hooks)

    def providers(self) -> list:
        """Registered (provider_meta, review) pairs, read by the loader (future wiring)."""
        return list(self._providers)


@dataclass
class LoadedPlugin:
    """A successfully audited + activated plugin and its registered capabilities."""

    plugin_id: str
    manifest: Manifest
    api: PluginAPI
    module: object


class PluginLoader:
    """Discover -> audit -> validate -> activate -> wire plugins from modules/.

    Plugin directories live inside the modules/ folder; any subdirectory that
    carries a manifest.json is a plugin (modules/core/ has none and is skipped).

    Args:
        plugins_root: the modules/ directory (plugins are its subdirectories).
        security_config: dict from config/security.json.
        app_root: the dev body root (for path-escape checks).
        strict: True validates every plugin, False only new ones.
        env: optional environment snapshot (defaults to os.environ).
    """

    def __init__(self, plugins_root: Path, security_config: dict, app_root: Path,
                 strict: bool = False, env: Optional[dict] = None):
        self._root = plugins_root
        self._security_config = security_config
        self._app_root = app_root
        self._strict = strict
        self._env = env if env is not None else dict(os.environ)

    def discover(self) -> list[Path]:
        """Return plugin directories (those with a manifest.json), sorted by id.

        Returns:
            Sorted list of plugin directory paths (empty when plugins/ is absent).
        """
        if not self._root.is_dir():
            return []
        return sorted(p for p in self._root.iterdir() if p.is_dir() and classify(p) == "plugin")

    def load_all(self) -> list[LoadedPlugin]:
        """Audit + validate + activate every discovered plugin.

        Returns:
            Successfully loaded plugins; broken ones are logged and skipped.
        """
        loaded: list[LoadedPlugin] = []
        for directory in self.discover():
            plugin = self._load_one(directory)
            if plugin is not None:
                loaded.append(plugin)
        return loaded

    def _load_one(self, directory: Path) -> Optional[LoadedPlugin]:
        plugin_id = directory.name

        # 1. static audit of the manifest (no plugin code is imported yet)
        try:
            manifest = _audit_manifest(directory / "manifest.json")
        except ValueError as e:
            logger.error("plugin %s rejected (manifest): %s", plugin_id, e)
            return None
        if manifest.plugin_id != plugin_id:
            logger.error("plugin %s rejected: manifest id mismatch (%s)",
                         plugin_id, manifest.plugin_id)
            return None

        # 2. graded security check on plugin.py (hard risks always block)
        module = self._import_module(directory, plugin_id)
        if module is None:
            return None
        problems = self._validate_module(module, directory)
        if problems:
            logger.error("plugin %s rejected by security check: %s", plugin_id, problems)
            return None

        # 3. activate through the injected facade
        entry = getattr(module, "PLUGIN", None)
        if not callable(entry):
            logger.error("plugin %s rejected: no callable PLUGIN(api)", plugin_id)
            return None
        api = PluginAPI(plugin_id, manifest, directory / "data", self._env)
        try:
            entry(api)
        except Exception as e:  # noqa: BLE001 - a broken plugin must not break the loader
            logger.error("plugin %s activate failed: %s", plugin_id, e)
            return None

        loaded_plugin = LoadedPlugin(plugin_id, manifest, api, module)
        logger.info("plugin loaded: %s (capabilities: %s)",
                    plugin_id, [k.value for k in manifest.capabilities])
        return loaded_plugin

    def _import_module(self, directory: Path, plugin_id: str):
        """Import plugin.py as a fresh, uniquely-named module."""
        spec_name = f"_claw_se_plugin_{plugin_id}"
        try:
            spec = importlib.util.spec_from_file_location(spec_name, directory / "plugin.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception as e:  # noqa: BLE001
            logger.error("plugin %s import failed: %s", plugin_id, e)
            return None

    def _validate_module(self, module, directory: Path) -> list[str]:
        """Graded plugin check: malicious markers + path escape (hard risks).

        Args:
            module: the imported plugin.py module.
            directory: the plugin's directory.

        Returns:
            List of problems (empty when the plugin is accepted).
        """
        problems: list[str] = []
        problems += scan_malicious(module)
        try:
            source = Path(module.__file__).resolve()
            source.relative_to(directory.resolve())
        except (ValueError, TypeError, OSError):
            problems.append(f"plugin.py outside its plugin directory: {getattr(module, '__file__', '?')}")
        return problems


def wire_channels(plugins: list[LoadedPlugin], register_channel) -> None:
    """Wire registered channel backends into the MsgIO bus (Kind.CHANNEL).

    Args:
        plugins: loaded plugins.
        register_channel: callable(backend) registering a channel into MsgIO.
    """
    if register_channel is None:
        return
    for plugin in plugins:
        for backend in plugin.api.channels():
            try:
                register_channel(backend)
            except Exception as e:  # noqa: BLE001
                logger.error("plugin %s channel wiring failed: %s", plugin.plugin_id, e)


def collect_tools(plugins: list[LoadedPlugin]) -> list:
    """Collect tool callables registered by plugins.

    Args:
        plugins: loaded plugins.

    Returns:
        List of tool callables.
    """
    tools: list = []
    for plugin in plugins:
        for tool, _guard_key in plugin.api.tools():
            if hasattr(tool, "name") or callable(tool):
                tools.append(tool)
    return tools


def collect_guard_map(plugins: list[LoadedPlugin]) -> dict[str, str]:
    """Collect tool name -> guard_key from plugins.

    Args:
        plugins: loaded plugins.

    Returns:
        Mapping merged into the shared guard map used by secure_tools.
    """
    guard_map: dict[str, str] = {}
    for plugin in plugins:
        for tool, guard_key in plugin.api.tools():
            name = getattr(tool, "name", None)
            if name and guard_key:
                guard_map[name] = guard_key
    return guard_map
