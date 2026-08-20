"""Unified agent factory: the ONLY seam for creating agents (fix #11/#12).

- build_agent(role, model_id, tools, system_prompt, **kw): main / delegate / judge all
  go through this one entry; tools are always wrapped with secure() first.
- ask_model(...): dynamic sub-model delegation with max_depth guard (fix #5).
- Security is injected at the exit of this seam, so no agent can be created
  bare (`ChatOpenAI()` outside the factory is forbidden).

Model resolution (providers.json + role_map):
- role_map[role] = "provider.model", e.g. "deepseek.main".
- key_ref from the model spec points at the .env variable holding the secret.
"""
import logging
import os
from typing import Optional

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from . import config as core_config
from .security.judge import SafetyJudge
from .security.wrapper import SecurityContext, secure_tools

logger = logging.getLogger("Claw_SE.factory")


def resolve_model_spec(providers_cfg: dict, role: str, model_id: Optional[str] = None) -> tuple[dict, dict]:
    """Resolve provider + model spec from role_map (or an explicit model_id).

    Args:
        providers_cfg: dict from config/providers.json.
        role: role name (main / judge / delegate:code, ...).
        model_id: explicit "provider.model" override (takes precedence over role_map).

    Returns:
        (provider dict, model spec dict).

    Raises:
        KeyError: if the provider/model cannot be resolved.
    """
    role_map = providers_cfg.get("role_map", {}) or {}
    providers = providers_cfg.get("providers", {}) or {}
    key = model_id or role_map.get(role)
    if not key:
        raise KeyError(f"no model resolution for role '{role}' (missing role_map entry or model_id)")
    if "." not in key:
        raise KeyError(f"model key must be 'provider.model', got '{key}'")
    provider_name, model_name = key.split(".", 1)
    provider = providers.get(provider_name)
    if not provider:
        raise KeyError(f"unknown provider '{provider_name}' in providers.json")
    model_spec = provider.get("models", {}).get(model_name)
    if not model_spec:
        raise KeyError(f"unknown model '{model_name}' under provider '{provider_name}'")
    return provider, model_spec


def build_chat_model(provider: dict, model_spec: dict, temperature: Optional[float] = None) -> ChatOpenAI:
    """Build a ChatOpenAI client, injecting the secret via key_ref from .env.

    Args:
        provider: provider dict (api_base).
        model_spec: model spec dict (model / key_ref).
        temperature: optional temperature override.

    Returns:
        A ChatOpenAI instance.
    """
    api_key = os.environ.get(model_spec.get("key_ref", ""), "")
    kwargs: dict = {
        "api_key": api_key,
        "base_url": provider.get("api_base", ""),
        "model": model_spec.get("model", ""),
    }
    if temperature is not None:
        kwargs["temperature"] = temperature
    return ChatOpenAI(**kwargs)


def build_judge(providers_cfg: dict) -> SafetyJudge:
    """Build the independent safety judge (SECURITY_MODEL via role_map["judge"], temperature=0).

    Args:
        providers_cfg: dict from config/providers.json.

    Returns:
        A SafetyJudge instance.
    """
    provider, spec = resolve_model_spec(providers_cfg, "judge")
    return SafetyJudge(
        api_key=os.environ.get(spec.get("key_ref", ""), ""),
        base_url=provider.get("api_base", ""),
        model=spec.get("model", ""),
    )


def build_agent(role: str = "main", model_id: Optional[str] = None, tools: Optional[list] = None,
                tool_guards: Optional[dict[str, str]] = None,
                system_prompt: Optional[str] = None, ctx: Optional[SecurityContext] = None,
                **kwargs):
    """Build a secure agent from the unified factory.

    Args:
        role: role name (main / judge / delegate:xxx), used with role_map.
        model_id: explicit "provider.model" override.
        tools: raw tool list (auto-wrapped with secure()).
        tool_guards: tool name -> guard_key mapping (from module FEATUREs).
        system_prompt: system prompt string.
        ctx: security decision context; when None, a pass-through context is used
            so that tools are still wrapped but everything is allowed (internal use).
        **kwargs: extra args passed to create_agent.

    Returns:
        A compiled agent graph.
    """
    provider, spec = resolve_model_spec(core_config.load_providers_config(), role, model_id)
    model = build_chat_model(provider, spec)
    tools = tools or []
    if ctx is not None:
        tools = secure_tools(tools, tool_guards, ctx)
    return create_agent(model=model, tools=tools, system_prompt=system_prompt, **kwargs)


def ask_model(prompt: str = "", input_data: str = "", model_id: Optional[str] = None,
              full_context_share: bool = True, context_content: Optional[str] = None,
              tools_to_share: Optional[list] = None, tool_guards: Optional[dict[str, str]] = None,
              ctx: Optional[SecurityContext] = None, session_id: Optional[str] = None,
              depth: int = 0, max_depth: int = 2, **model_params) -> str:
    """Dynamically delegate a task to a sub-model (fix #5: max_depth recursion guard).

    Signature follows A6 task_to_submodel. The sub-agent is created via build_agent,
    so it passes through the factory + secure() (fix #11, no bare ChatOpenAI).

    Args:
        prompt: system prompt for the sub-agent.
        input_data: the task input message.
        model_id: explicit "provider.model" to use.
        full_context_share: share the full context; when False, context_content must be given.
        context_content: explicit context snippet for isolation mode (A7).
        tools_to_share: subset of tools to share (least privilege, A8).
        tool_guards: tool name -> guard_key mapping for the shared tools.
        ctx: security decision context.
        session_id: optional session id (reserved).
        depth: current recursion depth.
        max_depth: max recursion depth (default 2).
        **model_params: extra model params (reserved).

    Returns:
        The sub-agent's reply text.

    Raises:
        RuntimeError: when recursion depth exceeds max_depth.
    """
    if depth >= max_depth:
        raise RuntimeError(f"delegation depth exceeded max_depth={max_depth}")
    if not full_context_share and not context_content:
        raise ValueError("full_context_share=False requires explicit context_content")

    messages: list = []
    if full_context_share:
        messages.append(SystemMessage(content=prompt))
    elif context_content:
        messages.append(SystemMessage(content=prompt))
        messages.append(HumanMessage(content=context_content))
    messages.append(HumanMessage(content=input_data))

    sub_agent = build_agent(
        role="delegate",
        model_id=model_id,
        tools=tools_to_share or [],
        tool_guards=tool_guards,
        system_prompt=prompt,
        ctx=ctx,
    )
    response = sub_agent.invoke({"messages": messages})
    last = response["messages"][-1]
    return last.content if hasattr(last, "content") else str(last)
