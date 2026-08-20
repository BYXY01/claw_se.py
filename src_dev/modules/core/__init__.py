"""core package: the embedded kernel (cannot be disabled, never lent out).

Holds platform/env detection, config loading, MsgIO bus, the unified agent
factory, single-file loader, and the security kernel.
"""
from . import config, env, factory, loader, msgio, security

__all__ = ["config", "env", "factory", "loader", "msgio", "security"]
