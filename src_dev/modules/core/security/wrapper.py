"""secure() security wrapper (ported from ND, fixes #3/#7/#13/#14 applied).

Unified check chain (every execution is checked, no exceptions, fix #14):
```
tool call arrives
 |- self-directory guard (0 token, hard, always)     -> block on hit (fix #13)
 |- static blacklist (blacklist/self/learned, 0 token) -> block (reviewable once, fix #6)
 |- whitelist hit -> execute directly (still passes static blacklist + self-dir guard)
 |- asklist hit   -> four-choice interaction
 `- unknown       -> independent safety judge
       |- safe       -> execute + add to whitelist
       |- dangerous  -> block + feature into learned (self-learning)
       `- cannot tell / failure -> degrade to four-choice (fix #2)
```
Fix #3: tool modules declare `guard_key` in FEATURE (e.g. command/path_or_handle),
replacing ND's "guess the parameter name" _extract_cmd.
Fix #7: when overrides reach the threshold (same command allowed-once many times),
prompt to upgrade to whitelist.
"""
import inspect
import logging
from functools import wraps
from typing import Optional

from langchain_core.tools import StructuredTool

from ..interaction.base import get_interaction
from . import rules as rules_mod
from . import store as store_mod
from .judge import SafetyJudge

logger = logging.getLogger("Claw_SE.security.wrapper")

EXECUTE = "execute"
BLOCKED = "blocked"
ASK = "ask"

_ASK_OPTIONS = ["add to whitelist", "allow once", "deny once", "add to blacklist"]
_REVIEW_OPTIONS = ["allow once", "deny once"]
_UPGRADE_OPTIONS = ["upgrade to whitelist", "not yet"]


class SecurityConfig:
    """Dual-switch configuration.

    - firewall_on       : switch A (static firewall on/off)
    - detect_mode       : switch B (tool layer off/auto/full)
    - review_on_block   : whether a blacklist hit may be reviewed once (fix #6)
    - override_threshold: "allow-once" count that triggers the whitelist upgrade prompt (fix #7)
    """

    def __init__(self, firewall_on: bool = True, detect_mode: str = "auto",
                 review_on_block: bool = False, override_threshold: int = 3):
        self.firewall_on = firewall_on
        self.detect_mode = detect_mode
        self.review_on_block = review_on_block
        self.override_threshold = override_threshold

    @classmethod
    def from_dict(cls, data: dict) -> "SecurityConfig":
        """Build from config/security.json."""
        cfg = cls()
        cfg.firewall_on = str(data.get("firewall", "on")).lower() == "on"
        cfg.detect_mode = str(data.get("detect", "auto")).lower()
        cfg.review_on_block = bool(data.get("review_on_block", False))
        try:
            cfg.override_threshold = int(data.get("override_threshold", 3))
        except (TypeError, ValueError):
            cfg.override_threshold = 3
        return cfg


class SecurityContext:
    """Context for one security decision: lists, rules, judge, switch config."""

    def __init__(self, store: "store_mod.Store", rules: "rules_mod.Rules",
                 config: SecurityConfig, judge: Optional[SafetyJudge] = None):
        self.store = store
        self.rules = rules
        self.config = config
        self.judge = judge


def _decide(ctx: SecurityContext, value: str) -> tuple[str, str]:
    """Run the full check chain, returning (decision, payload).

    EXECUTE -> payload empty; BLOCKED -> payload is the block message; ASK -> caller runs four-choice.
    """
    # 0. self-directory guard (hard, always checked, fix #13)
    matched_self = ctx.rules.self_dir_check(value)
    if matched_self:
        return BLOCKED, f"[SE] Blocked (self-directory guard): {matched_self}"

    # 1. three-list decision (0 token)
    verdict = ctx.rules.classify(value)
    if verdict == rules_mod.BLOCK:
        if ctx.config.firewall_on and not ctx.config.review_on_block:
            return BLOCKED, f"[SE] Blocked (blacklist hit): {value}"
        if ctx.config.firewall_on and ctx.config.review_on_block:
            return ASK, value
        # firewall off (switch A off) -> keep evaluating below
        verdict = rules_mod.UNKNOWN

    if verdict == rules_mod.ALLOW:
        return EXECUTE, ""

    if verdict == rules_mod.ASK:
        return ASK, value

    # 2. unknown -> safety judge (switch B)
    if ctx.config.detect_mode == "off":
        return EXECUTE, ""
    if ctx.judge is None:
        logger.warning("detect_mode=%s but no judge available, degrading to ask", ctx.config.detect_mode)
        return ASK, value

    try:
        result = ctx.judge.review(value)
    except Exception as e:  # noqa: BLE001 - any judge failure degrades to ask (fix #2)
        logger.warning("judge raised, degrading to ask: %s", e)
        return ASK, value
    if result.get("allow") is True:
        ctx.store.add(value, "whitelist")  # safe -> whitelist (0-token direct pass next time)
        return EXECUTE, ""
    if result.get("allow") is False:
        feature = result.get("feature")
        if feature:
            ctx.store.learn(feature)  # dangerous -> feature into learned (self-learning)
        reason = result.get("reason", "")
        return BLOCKED, f"[SE] Blocked (judge judged dangerous): {value}\nReason: {reason}"
    # allow=None (cannot tell / failure) -> ask the user (fix #2)
    return ASK, value


def _ask_user(ctx: SecurityContext, value: str, execute, *args, **kwargs) -> str:
    """Four-choice interaction: whitelist / allow-once / deny-once / blacklist."""
    interaction = get_interaction()
    options = _REVIEW_OPTIONS if ctx.config.review_on_block else _ASK_OPTIONS
    choice = interaction.ask_four(f"Command [{value}] needs your decision:", options)

    if choice == "add to whitelist":
        ctx.store.add(value, "whitelist")
        return execute(*args, **kwargs)
    if choice == "allow once":
        ctx.store.log_override(value, "allow_once")
        count = ctx.store.override_count(value, "allow_once")
        if count >= ctx.config.override_threshold:
            upgrade = interaction.ask_four(
                f"[{value}] was allowed once {count} times; upgrade to whitelist?", _UPGRADE_OPTIONS)
            if upgrade == "upgrade to whitelist":
                ctx.store.add(value, "whitelist")
        return execute(*args, **kwargs)
    if choice == "deny once":
        ctx.store.log_override(value, "deny_once")
        return f"[SE] Denied per your choice: {value}"
    if choice == "add to blacklist":
        ctx.store.add(value, "blacklist")
        return f"[SE] Added to blacklist and blocked: {value}"
    return f"[SE] No decision made, blocked: {value}"


def _extract_guard_values(bound_args, guard_key) -> list[str]:
    """Extract all non-empty security-relevant string values from bound args.

    guard_key may be a single param name or a list of candidate names; every
    non-empty string value found is a candidate for the check chain
    (fix #3: declared in FEATURE, no guessing).
    """
    keys = guard_key if isinstance(guard_key, (list, tuple)) else [guard_key]
    values: list[str] = []
    for key in keys:
        raw = bound_args.get(key)
        if isinstance(raw, str) and raw.strip():
            values.append(raw.strip())
    return values


def _secure_callable(func, guard_key: Optional[str], ctx: SecurityContext):
    """Wrap a callable with the security decision layer, keeping its signature."""
    sig = inspect.signature(func)

    @wraps(func)
    def wrapper(*args, **kwargs):
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        candidates = _extract_guard_values(bound.arguments, guard_key)
        if not candidates:
            # No security-relevant target (e.g. execute(operation="list") or background `input`)
            # -> nothing to classify, treated as passing the check.
            # (fix #8: background `input` is intentionally NOT checked; the user has already
            #  confirmed the target process.)
            return func(*args, **kwargs)
        ask_value: Optional[str] = None
        for value in candidates:
            decision, payload = _decide(ctx, value)
            if decision == BLOCKED:
                logger.warning("secured tool blocked: %s", payload)
                return payload
            if decision == ASK:
                ask_value = value
                break
        if ask_value is not None:
            return _ask_user(ctx, ask_value, func, *args, **kwargs)
        return func(*args, **kwargs)

    return wrapper


def secure_tool(tool, guard_key: Optional[str], ctx: SecurityContext) -> StructuredTool:
    """Wrap a single tool (@tool StructuredTool or a raw function) with the security layer.

    Args:
        tool: the tool to wrap.
        guard_key: security-judgment parameter name (from FEATURE["guard_key"]).
        ctx: security decision context.

    Returns:
        The wrapped StructuredTool.
    """
    if isinstance(tool, StructuredTool):
        wrapped = _secure_callable(tool.func, guard_key, ctx)
        return StructuredTool.from_function(
            func=wrapped,
            name=tool.name,
            description=tool.description or tool.func.__doc__ or "",
            args_schema=tool.args_schema,
        )
    wrapped = _secure_callable(tool, guard_key, ctx)
    return StructuredTool.from_function(func=wrapped)


def secure_tools(tools: list, guard_map: Optional[dict[str, str]], ctx: SecurityContext) -> list:
    """Wrap a list of tools with the security decision layer.

    Args:
        tools: the tool list.
        guard_map: tool name -> guard_key mapping (from each module's FEATURE["guard_key"]).
        ctx: security decision context.

    Returns:
        The wrapped tool list.
    """
    guard_map = guard_map or {}
    secured = []
    for t in tools:
        name = getattr(t, "name", None)
        gk = guard_map.get(name) if name else None
        secured.append(secure_tool(t, gk, ctx))
    return secured
