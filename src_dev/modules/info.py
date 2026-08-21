"""Self-cognition tool: report system and program info."""
import os
import platform
import sys

from langchain_core.tools import tool


def _single_file_version() -> str:
    """The running single file's version (`version` on __main__), if any."""
    main = sys.modules.get("__main__")
    return getattr(main, "version", "unknown") if main is not None else "unknown"


@tool
def get_info() -> str:
    """Get current system environment and program info (AI self-cognition).

    Returns:
        Multi-line key: value listing.
    """
    info = {
        "claw_se_version": _single_file_version(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version.split()[0],
        "current_directory": os.getcwd(),
    }
    return "\n".join(f"{k}: {v}" for k, v in info.items())


FEATURE = {
    "name": "info",
    "version": "0.1",
    "desc": "Self-cognition: query system and program info",
    "tools": [get_info],
    "hooks": {},
}
