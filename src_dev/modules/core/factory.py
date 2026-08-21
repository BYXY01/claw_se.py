"""Unified agent factory: the ONLY seam for creating agents (fix #11/#12).

The factory only MANUFACTURES agents:
- build_agent(role, model_id, tools, system_prompt, **kw): main / delegate / judge all
  go through this one entry; tools are always wrapped with secure() first.
- build_judge(...): the independent safety-judge model instance (SECURITY_MODEL).

Extensions (delegation, etc.) are plugin modules that CALL this factory's
capabilities - e.g. delegate.py builds its sub-agent via build_agent here, so
security is always injected at this seam (no bare ChatOpenAI outside).

Model resolution (providers.json + role_map):
- role_map[role] = "provider.model", e.g. "deepseek.main".
- key_ref from the model spec points at the .env variable holding the secret.
"""
import logging
import os
from typing import Optional

from langchain.agents import create_agent
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

    The model's `ctx` from providers.json is exposed as `profile.max_input_tokens`
    so LangChain's SummarizationMiddleware can auto-summarize at a fraction of the
    model's actual context window.

    Args:
        provider: provider dict (api_base).
        model_spec: model spec dict (model / key_ref / ctx).
        temperature: optional temperature override.

    Returns:
        A ChatOpenAI instance.
    """
    api_key = os.environ.get(model_spec.get("key_ref", ""), "")
    kwargs: dict = {
        "api_key": api_key,
        "base_url": provider.get("api_base", ""),
        "model": model_spec.get("model", ""),
        "profile": {"max_input_tokens": int(model_spec.get("ctx", 8192))},
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
                checkpointer=None, summarize=None, **kwargs):
    """Build a secure agent from the unified factory.

    Args:
        role: role name (main / judge / delegate:xxx), used with role_map.
        model_id: explicit "provider.model" override.
        tools: raw tool list (auto-wrapped with secure()).
        tool_guards: tool name -> guard_key mapping (from module FEATUREs).
        system_prompt: system prompt string.
        ctx: security decision context; when None, a pass-through context is used
            so that tools are still wrapped but everything is allowed (internal use).
        checkpointer: LangChain/LangGraph checkpointer (e.g. InMemorySaver) for
            conversation-state persistence per thread_id.
        summarize: optional dict {trigger, keep} to auto-summarize the conversation
            when it grows too long (ConversationSummaryMemory via LangChain's
            SummarizationMiddleware); None disables it.
        **kwargs: extra args passed to create_agent.

    Returns:
        A compiled agent graph.
    """
    provider, spec = resolve_model_spec(core_config.load_providers_config(), role, model_id)
    model = build_chat_model(provider, spec)
    tools = tools or []
    if ctx is not None:
        tools = secure_tools(tools, tool_guards, ctx)
    kw = dict(kwargs)
    if checkpointer is not None:
        kw["checkpointer"] = checkpointer
    if summarize:
        from langchain.agents.middleware import SummarizationMiddleware
        trigger = summarize.get("trigger") if isinstance(summarize, dict) else ("tokens", 3000)
        keep = summarize.get("keep", ("messages", 20)) if isinstance(summarize, dict) else ("messages", 20)
        middleware = list(kw.get("middleware", ())) + [
            SummarizationMiddleware(model=model, trigger=trigger, keep=keep)]
        kw["middleware"] = middleware
    return create_agent(model=model, tools=tools, system_prompt=system_prompt, **kw)
