"""Self-cognition tool: report system and program info (ported from LC)."""
import os
import platform
import sys

from langchain_core.tools import tool


@tool
def get_info() -> str:
    """Get current system environment and program info (AI self-cognition).

    Returns:
        Multi-line key: value listing.
    """
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version.split()[0],
        "current_directory": os.getcwd(),
        "script_name": os.path.basename(__file__),
        "script_path": os.path.abspath(__file__),
    }
    return "\n".join(f"{k}: {v}" for k, v in info.items())


FEATURE = {
    "name": "info",
    "version": "0.1",
    "desc": "Self-cognition: query system and program info",
    "tools": [get_info],
    "hooks": {},
}
