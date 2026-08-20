"""Shared boot + main loop (used by the dev entry and the single-file entry).

Boot sequence:
1. Load .env secrets + config/security.json + config/providers.json.
2. Build the security stack (store/rules/config/context/input guard) and the
   independent judge (only when detection needs it).
3. Inject self-referential features into the self list (fix #1).
4. Discover modules (graded security check) and collect tools + guard map.
5. Configure the delegate module (ladder 3).
6. Build the secure main agent via factory.build_agent (the only seam).
7. Register the terminal channel, mount the input guard, run the MsgIO loop.
"""
import logging
import sys
from pathlib import Path

import modules
from langchain_core.messages import HumanMessage
from modules.core import config as core_config
from modules.core import factory
from modules.core.msgio import TerminalBackend, get_io
from modules.core.security import build_stack

logger = logging.getLogger("Claw_SE.boot")

_FALLBACK_PROMPT = (
    "You are a local AI assistant protected by a security layer. "
    "You can run commands (execute), handle files (file_op), and query info (get_info). "
    "Stay concise and only do what the user explicitly asks."
)


def load_system_prompt(root: Path) -> str:
    """Compose the system prompt from prompt_library (IDENTITY + RULES).

    Protocol over parser: files are loaded as text and glued together; the LLM
    does the semantic interpretation (A2). Falls back to a minimal default.

    Args:
        root: app root (src_dev/ or the release root).

    Returns:
        The system prompt string.
    """
    parts: list[str] = []
    for name in ("IDENTITY", "RULES"):
        p = root / "prompt_library" / f"{name}.md"
        if p.exists():
            content = p.read_text(encoding="utf-8").strip()
            if content:
                parts.append(content)
    if parts:
        return "\n\n".join(parts)
    return _FALLBACK_PROMPT


def _detection_needs_judge(security_config: dict) -> bool:
    """Whether the current switch settings require the independent judge."""
    detect = str(security_config.get("detect", "auto")).lower()
    input_detect = str(security_config.get("input_detect", "off")).lower()
    return detect != "off" or input_detect == "full" or input_detect.startswith("random:")


def run() -> None:
    """Boot security, build the agent, run the MsgIO loop (the shared entry)."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    core_config.load_env()
    root = core_config.app_root()
    security_config = core_config.load_security_config()

    # independent judge (SECURITY_MODEL via role_map["judge"], temperature=0)
    judge = None
    if _detection_needs_judge(security_config):
        try:
            judge = factory.build_judge(core_config.load_providers_config())
        except KeyError as e:
            logger.warning("judge disabled: %s", e)

    ctx, guard = build_stack(security_config, root, judge=judge)

    # self-referential defense (fix #1): script dir + modules dir into self list
    ctx.store.ensure_self([str(root), str(root / "modules")])

    # module discovery (graded security check)
    loaded = modules.discover(security_config)
    tools = modules.collect_tools(loaded)
    guard_map = modules.collect_guard_map(loaded)
    logger.info("loaded modules: %s", ", ".join(loaded.keys()))
    logger.info("registered tools: %s", ", ".join(getattr(t, "name", str(t)) for t in tools))

    # ladder 3: give the delegate module its runtime deps (security ctx + tool catalog)
    if "delegate" in loaded:
        from modules import delegate as delegate_mod
        delegate_mod.configure(ctx, all_tools=tools, tool_guards=guard_map)

    system_prompt = load_system_prompt(root)

    try:
        agent = factory.build_agent(
            role="main", tools=tools, tool_guards=guard_map,
            system_prompt=system_prompt, ctx=ctx,
        )
    except KeyError as e:
        print(f"Error: cannot resolve the main model ({e}). Check config/providers.json and .env.")
        sys.exit(1)

    io = get_io()
    io.set_input_guard(guard)
    io.register(TerminalBackend())
    io.send("Claw_SE started (security edition). Type a message, Ctrl+C to exit.")

    messages = []
    while True:
        try:
            msg = io.receive()
            if msg is None:
                continue
            user_input = msg.text
            channel = msg.channel
            messages.append(HumanMessage(content=user_input))
            logger.info("User: %s", user_input.replace("\n", "\\n"))

            io.send("\nAI: ", channel=channel)
            response = agent.invoke({"messages": messages})
            if isinstance(response, dict):
                ai_response = response["messages"][-1].content
                messages = response["messages"]
            else:
                ai_response = str(response)
            io.send(ai_response if isinstance(ai_response, str) else str(ai_response), channel=channel)
            io.send("", channel=channel)
            logger.info("AI: %s", str(ai_response).replace("\n", "\\n"))

        except KeyboardInterrupt:
            io.send("\nExited.")
            break
        except Exception as e:
            io.send(f"\nError: {e}")
