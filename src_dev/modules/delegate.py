"""Dynamic multi-model delegation: task_to_submodel (ladder 3).

Implements A6-A8:
- Signature aligned to A6:
    task_to_submodel(prompt_name, input_data, model_id, full_context_share=True,
                     context_content=None, tools_to_share=None, session_id=None, **model_params)
- Runtime context trimming (A7): full_context_share=False requires an explicit
  context_content snippet -> natural "isolation mode" against sensitive leaks.
- Least-privilege tool sharing (A8): tools_to_share restricts which tools the
  sub-agent may use (e.g. only read_file, never delete_file).
- Sub-agents always go through factory.build_agent + secure() (fix #11, no bare
  ChatOpenAI); recursion depth <= max_depth (fix #5).

The tool needs the security context + tool catalog, injected at boot via configure().
The tool itself has no guard_key: it is a coordination tool (nothing to classify);
the sub-agent's actual tools (exec/file/...) are what get secured.
"""
import logging
from typing import Optional

from langchain_core.tools import tool

from .core import config as core_config
from .core import factory as factory_mod
from .core.security.wrapper import SecurityContext

logger = logging.getLogger("Claw_SE.delegate")

_ctx: Optional[SecurityContext] = None
_all_tools: dict[str, object] = {}
_tool_guards: dict[str, str] = {}
_max_depth: int = 2
_depths: dict[str, int] = {}  # session_id -> current recursion depth


def configure(ctx: SecurityContext, all_tools: Optional[list] = None,
              tool_guards: Optional[dict[str, str]] = None, max_depth: int = 2) -> None:
    """Inject runtime dependencies at boot (called by the entry after build_stack).

    Args:
        ctx: security decision context (shared with the main agent).
        all_tools: the main agent's tool catalog (to resolve tools_to_share by name).
        tool_guards: tool name -> guard_key mapping (from module FEATUREs).
        max_depth: max delegation recursion depth (fix #5).
    """
    global _ctx, _all_tools, _tool_guards, _max_depth
    _ctx = ctx
    _all_tools = {getattr(t, "name", str(t)): t for t in (all_tools or [])}
    _tool_guards = dict(tool_guards or {})
    _max_depth = int(max_depth)
    logger.info("delegate configured: %d tools, max_depth=%d", len(_all_tools), _max_depth)


def _prompt_text(prompt_name: str) -> str:
    """Resolve a delegation prompt: prompt_library file or the literal text.

    Args:
        prompt_name: a name like "delegate/code" (looked up under prompt_library/)
            or a raw prompt string.

    Returns:
        The prompt text.
    """
    name = (prompt_name or "").strip()
    if not name:
        return "You are a helpful sub-agent."
    root = core_config.app_root()
    for ext in (".md", ".txt"):
        candidate = name if name.endswith(ext) else name + ext
        p = root / "prompt_library" / candidate
        if p.exists():
            return p.read_text(encoding="utf-8").strip()
    return name


def _resolve_shared_tools(tools_to_share: str) -> list:
    """Map a comma/space-separated tool name list to tool objects (least privilege, A8).

    Args:
        tools_to_share: e.g. "read_file,get_info"; empty means no tools.

    Returns:
        The resolved tool objects (unknown names are dropped).
    """
    names = [n for n in tools_to_share.replace(",", " ").split() if n]
    if not names:
        return []
    return [_all_tools[n] for n in names if n in _all_tools]


def _guard_map_for(shared_tools: list) -> dict:
    """Guard-key map limited to the shared tool subset."""
    return {getattr(t, "name", None): _tool_guards[getattr(t, "name", None)]
            for t in shared_tools if getattr(t, "name", None) in _tool_guards}


@tool
def task_to_submodel(
    prompt_name: str = "",
    input_data: str = "",
    model_id: str = "",
    full_context_share: bool = True,
    context_content: str = "",
    tools_to_share: str = "",
    session_id: str = "",
) -> str:
    """Delegate a subtask to a sub-model (secure, least privilege, context-trimmed).

    Args:
        prompt_name: prompt name under prompt_library/ (or a literal prompt string).
        input_data: the task input to send to the sub-model.
        model_id: optional "provider.model" override (default: role_map["delegate"]).
        full_context_share: share context; when False, context_content must be given
            (isolation mode, A7).
        context_content: explicit context snippet for isolation mode.
        tools_to_share: comma/space separated tool names the sub-agent may use
            (least privilege, A8).
        session_id: id to track recursion depth (fix #5).

    Returns:
        The sub-model's reply text.
    """
    sid = session_id or "default"
    depth = _depths.get(sid, 0)
    if depth >= _max_depth:
        return f"[SE] Delegation depth exceeded max_depth={_max_depth}, blocked."
    if not full_context_share and not context_content:
        return "[SE] full_context_share=False requires explicit context_content (isolation mode)."
    if _ctx is None:
        return "[SE] delegate not configured (boot-time configure() missing)."

    shared = _resolve_shared_tools(tools_to_share)
    gmap = _guard_map_for(shared)
    logger.info("delegate session=%s depth=%d shared_tools=%s model_id=%s",
                sid, depth, [getattr(t, "name", str(t)) for t in shared], model_id or "role_map")

    _depths[sid] = depth + 1
    try:
        return factory_mod.ask_model(
            prompt=_prompt_text(prompt_name),
            input_data=input_data,
            model_id=model_id or None,
            full_context_share=full_context_share,
            context_content=context_content or None,
            tools_to_share=shared,
            tool_guards=gmap,
            ctx=_ctx,
            session_id=sid,
            depth=depth,
            max_depth=_max_depth,
        )
    except RuntimeError as e:
        return f"[SE] {e}"
    finally:
        _depths[sid] = depth


FEATURE = {
    "name": "delegate",
    "version": "0.1",
    "desc": "Dynamic multi-model delegation: task_to_submodel (context trim + least privilege)",
    "tools": [task_to_submodel],
    "hooks": {},
}
