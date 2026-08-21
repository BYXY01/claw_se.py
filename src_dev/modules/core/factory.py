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
- A model spec may declare "fallback": ["provider2.model2", ...] - the primary is
  tried first and, on failure (network / rate-limit / timeout), the next provider
  in the chain is tried. ModelFailoverMiddleware gives each model at most two
  attempts (one retry) before failing over to the next; all exhausted -> raise.
"""
import logging
import os
from typing import Optional

from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware
from langchain_openai import ChatOpenAI

from . import config as core_config
from .security.judge import SafetyJudge
from .security.wrapper import SecurityContext, secure_tools

logger = logging.getLogger("claw_se.factory")

# Providers contributed by plugins (Kind.PROVIDER): name -> (provider_meta, review).
# They participate in model resolution but agents are STILL built through the
# factory seam - no bare ChatOpenAI - and every tool call / message keeps passing
# the security chain. review=True (default) means messages routed via this
# provider must pass the security reviewer when the judge switch is enabled.
_PLUGIN_PROVIDERS: dict[str, tuple[dict, bool]] = {}


def register_provider(provider_meta: dict, *, review: bool = True) -> None:
    """Register a provider contributed by a plugin into the factory's resolution.

    Args:
        provider_meta: provider descriptor {"name", "api_base", "models": {...}}.
        review: whether messages via this provider must pass the security reviewer.

    Raises:
        KeyError: when provider_meta has no "name".
    """
    name = provider_meta.get("name")
    if not name:
        raise KeyError("provider_meta must declare a 'name'")
    _PLUGIN_PROVIDERS[name] = (provider_meta, review)
    logger.info("factory registered provider from plugin: %s", name)


def _resolve_provider(provider_name: str, providers: dict) -> Optional[dict]:
    """Resolve a provider from providers.json, falling back to plugin providers."""
    provider = providers.get(provider_name)
    if provider is not None:
        return provider
    entry = _PLUGIN_PROVIDERS.get(provider_name)
    return entry[0] if entry is not None else None


class ModelFailoverMiddleware(AgentMiddleware):
    """Failover chain: retry each model once, then switch to the next.

    For every model in `models` (primary first, then configured fallbacks) the
    model call is attempted at most twice (initial + one retry) - covering
    transient network / rate-limit / timeout failures. If all attempts on a model
    fail, the next model is tried; when every model is exhausted the last
    exception is re-raised.
    """

    _MAX_ATTEMPTS = 2

    def __init__(self, models: list):
        self._models = models
        super().__init__()

    def wrap_model_call(self, request, handler):
        last_exc: Optional[Exception] = None
        for model in self._models:
            for _attempt in range(self._MAX_ATTEMPTS):
                try:
                    return handler(request.override(model=model))
                except Exception as e:  # noqa: BLE001 - any failure trips the retry/failover
                    last_exc = e
        raise last_exc  # type: ignore[misc]

    async def awrap_model_call(self, request, handler):
        last_exc: Optional[Exception] = None
        for model in self._models:
            for _attempt in range(self._MAX_ATTEMPTS):
                try:
                    return await handler(request.override(model=model))
                except Exception as e:  # noqa: BLE001
                    last_exc = e
        raise last_exc  # type: ignore[misc]


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
    provider = _resolve_provider(provider_name, providers)
    if not provider:
        raise KeyError(f"unknown provider '{provider_name}' in providers.json or plugins")
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


def resolve_model_chain(providers_cfg: dict, role: str, model_id: Optional[str] = None) -> list[tuple[dict, dict]]:
    """Resolve the primary + fallback (provider, model_spec) chain for a role.

    The primary is role_map[role] (or an explicit model_id); each model spec may
    declare `fallback` (a list of "provider.model" keys) tried in order after it.
    Duplicate keys are skipped.

    Args:
        providers_cfg: dict from config/providers.json.
        role: role name (main / judge / delegate:code, ...).
        model_id: explicit "provider.model" override (takes precedence over role_map).

    Returns:
        Ordered list of (provider, model_spec) - first is the primary.

    Raises:
        KeyError: if the primary or any fallback cannot be resolved.
    """
    role_map = providers_cfg.get("role_map", {}) or {}
    providers = providers_cfg.get("providers", {}) or {}

    def _resolve(key: str) -> tuple[dict, dict]:
        if "." not in key:
            raise KeyError(f"model key must be 'provider.model', got '{key}'")
        provider_name, model_name = key.split(".", 1)
        provider = _resolve_provider(provider_name, providers)
        if not provider:
            raise KeyError(f"unknown provider '{provider_name}' in providers.json or plugins")
        model_spec = provider.get("models", {}).get(model_name)
        if not model_spec:
            raise KeyError(f"unknown model '{model_name}' under provider '{provider_name}'")
        return provider, model_spec

    primary_key = model_id or role_map.get(role)
    if not primary_key:
        raise KeyError(f"no model resolution for role '{role}' (missing role_map entry or model_id)")
    chain: list[tuple[dict, dict]] = []
    seen: set[str] = set()
    for key in [primary_key, *(_resolve(primary_key)[1].get("fallback") or [])]:
        if key in seen:
            continue
        seen.add(key)
        chain.append(_resolve(key))
    return chain


def build_model_chain(providers_cfg: dict, role: str = "main", model_id: Optional[str] = None,
                      temperature: Optional[float] = None) -> list:
    """Build the chat-model chain (primary first, then configured fallbacks).

    Args:
        providers_cfg: dict from config/providers.json.
        role: role name (main / delegate:xxx, ...).
        model_id: explicit "provider.model" override.
        temperature: optional temperature override.

    Returns:
        List of chat models: [primary, fallback1, ...]. The caller wires the
        primary into create_agent and the rest into ModelFallbackMiddleware.
    """
    chain = resolve_model_chain(providers_cfg, role, model_id)
    return [build_chat_model(provider, spec, temperature) for provider, spec in chain]


def _failover_middleware(models: list):
    """Build the failover middleware for the full model chain.

    Args:
        models: the full chain (primary first, then fallbacks).

    Returns:
        A ModelFailoverMiddleware, or None when there is only the primary.
    """
    if len(models) <= 1:
        return None
    return ModelFailoverMiddleware(models)


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
    providers_cfg = core_config.load_providers_config()
    models = build_model_chain(providers_cfg, role, model_id)
    primary = models[0]
    tools = tools or []
    if ctx is not None:
        tools = secure_tools(tools, tool_guards, ctx)
    kw = dict(kwargs)
    if checkpointer is not None:
        kw["checkpointer"] = checkpointer
    middleware = list(kw.get("middleware", ()))
    failover_mw = _failover_middleware(models)
    if failover_mw is not None:
        middleware.append(failover_mw)
    if summarize:
        from langchain.agents.middleware import SummarizationMiddleware
        trigger = summarize.get("trigger") if isinstance(summarize, dict) else ("tokens", 3000)
        keep = summarize.get("keep", ("messages", 20)) if isinstance(summarize, dict) else ("messages", 20)
        middleware.append(SummarizationMiddleware(model=primary, trigger=trigger, keep=keep))
    if middleware:
        kw["middleware"] = middleware
    return create_agent(model=primary, tools=tools, system_prompt=system_prompt, **kw)
