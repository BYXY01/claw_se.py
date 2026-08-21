"""core package: the embedded kernel (cannot be disabled, never lent out).

Holds platform/env detection, config loading, MsgIO bus, the unified agent
factory, and the security kernel. (Single-file release/deps live in the built
claw_se.py, not here.)
"""
from . import config, env, factory, msgio, security

__all__ = ["config", "env", "factory", "msgio", "security"]
