"""Configuration loading (dev-root resolution + three JSON files + .env keys).

- .env                 : secrets only (named by provider prefix; providers.json references them via key_ref)
- config/modules.json  : peripheral module toggles (core/ cannot be disabled)
- config/security.json : dual switches / detection mode / sampling ratio / list file paths
- config/providers.json: model catalog (model / base_url / key_ref, no "role" field)

Path convention: this file lives at src_dev/modules/core/config.py,
three levels up is the dev body root src_dev/ (= APP_ROOT).
For single-file distribution (ladder 4) the root is overridden by CLAW_SE_HOME / cwd
and handled in the loader layer.
"""
import json
import os
from pathlib import Path

from dotenv import load_dotenv

# config.py -> core/ -> modules/ -> src_dev/ (dev body root)
_DEV_ROOT = Path(__file__).resolve().parent.parent.parent


def app_root() -> Path:
    """Return the dev body root (src_dev/).

    In bundled/single-file mode (ladder 4) the loader overrides this with
    CLAW_SE_HOME / cwd; in dev mode it is always src_dev/.
    """
    override = os.environ.get("CLAW_SE_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return _DEV_ROOT


def config_dir() -> Path:
    """Return the config/ directory."""
    return app_root() / "config"


def load_env(root: Path | None = None) -> None:
    """Load .env secrets into environment variables (do not override existing vars)."""
    target = (root or app_root()) / ".env"
    load_dotenv(target, override=False)


def _read_json(path: Path, default: dict) -> dict:
    """Read a JSON config file, falling back to the default on any error."""
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
        return default
    except (json.JSONDecodeError, OSError):
        return default


def load_modules_config(root: Path | None = None) -> dict:
    """Load peripheral module toggles: {module_name: bool}. core/ cannot be disabled."""
    path = (root or app_root()) / "config" / "modules.json"
    data = _read_json(path, {})
    modules = data.get("modules", {})
    return modules if isinstance(modules, dict) else {}


def load_security_config(root: Path | None = None) -> dict:
    """Load security config: dual switches / detection mode / list file paths / default keywords."""
    path = (root or app_root()) / "config" / "security.json"
    return _read_json(path, _SECURITY_DEFAULTS)


def load_providers_config(root: Path | None = None) -> dict:
    """Load the model catalog: providers + role_map."""
    path = (root or app_root()) / "config" / "providers.json"
    return _read_json(path, {"providers": {}, "role_map": {}})


_SECURITY_DEFAULTS: dict = {
    "firewall": "on",               # switch A: static firewall on/off
    "detect": "auto",               # switch B: tool layer off/auto/full
    "input_detect": "off",          # input layer: off/random:x/heuristic/full
    "check_ratio": 0.1,             # random-sampling probability (used when random:x has no x)
    "judge_max_retries": 1,
    "review_on_block": False,       # whether a blacklist hit can be reviewed once (fix #6)
    "override_threshold": 3,        # same command allowed-once N times -> prompt to whitelist
    "blacklist_file": "modules/core/security/data/blacklist.json",
    "whitelist_file": "modules/core/security/data/whitelist.json",
    "asklist_file": "modules/core/security/data/asklist.json",
    "overrides_file": "modules/core/security/data/overrides.json",
    "module_trust_file": "modules/core/security/data/module_trust.json",
    "version": "v1",
}
