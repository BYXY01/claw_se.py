"""(0.0.103) model failover: resolve_model_chain + ModelFailoverMiddleware
(retry each model once, then switch to the next; all exhausted -> fail)."""
import pytest

from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.tools import tool

from conftest import make_providers_config
from modules.core.factory import ModelFailoverMiddleware, resolve_model_chain


class _Fake(GenericFakeChatModel):
    """A fake chat model that fails the first `fail_times` calls, then serves messages."""

    tag: str = "?"
    fail_times: int = 0
    calls: int = 0

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError(f"{self.tag} fail#{self.calls}")
        return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)


@tool
def probe(value: str) -> str:
    """Probe tool."""
    return value


def _providers_with_fallback() -> dict:
    cfg = make_providers_config()
    cfg["providers"]["deepseek"]["models"]["main"]["fallback"] = ["backup.main"]
    cfg["providers"]["backup"] = {
        "api_base": "https://backup.example/v1",
        "models": {"main": {"model": "backup-chat", "key_ref": "BACKUP_API_KEY", "ctx": 100}},
    }
    return cfg


def test_resolve_model_chain_primary_then_fallback():
    chain = resolve_model_chain(_providers_with_fallback(), "main")
    assert [spec["model"] for _provider, spec in chain] == ["deepseek-chat", "backup-chat"]
    # a role without a chain resolves to a single primary
    assert len(resolve_model_chain(_providers_with_fallback(), "judge")) == 1


def test_resolve_model_chain_dedups_repeated_keys():
    cfg = _providers_with_fallback()
    cfg["providers"]["backup"]["models"]["main"]["fallback"] = ["deepseek.main"]
    chain = resolve_model_chain(cfg, "main")
    assert [spec["model"] for _p, spec in chain] == ["deepseek-chat", "backup-chat"]


def test_failover_retries_primary_then_switches():
    """Primary fails both attempts -> backup fails once then succeeds."""
    primary = _Fake(messages=iter(["x"]), tag="P", fail_times=999)
    backup = _Fake(messages=iter(["backup-ok"]), tag="B", fail_times=1)
    agent = create_agent(model=primary, tools=[probe], system_prompt="t",
                         middleware=[ModelFailoverMiddleware([primary, backup])])
    result = agent.invoke({"messages": [{"role": "user", "content": "hi"}]})["messages"][-1].content
    assert result == "backup-ok"
    assert primary.calls == 2  # initial + one retry
    assert backup.calls == 2


def test_failover_raises_when_all_models_fail():
    primary = _Fake(messages=iter(["x"]), tag="P", fail_times=999)
    backup = _Fake(messages=iter(["x"]), tag="B", fail_times=999)
    agent = create_agent(model=primary, tools=[probe], system_prompt="t",
                         middleware=[ModelFailoverMiddleware([primary, backup])])
    with pytest.raises(Exception):
        agent.invoke({"messages": [{"role": "user", "content": "hi"}]})
    assert primary.calls == 2
    assert backup.calls == 2
