"""Ladder 3: delegation (task_to_submodel) + memory (remember/recall)."""
from langchain_core.messages import SystemMessage
from langchain_core.tools import tool

import modules
from modules.core import factory as factory_mod
from modules.core.security import protected_dirs
from modules.core.security.rules import Rules
from modules.core.security.store import Store
from modules.core.security.wrapper import SecurityConfig, SecurityContext


def make_ctx(security_config, app_root):
    store = Store(security_config, app_root)
    rules = Rules(store, protected_dirs(app_root))
    cfg = SecurityConfig.from_dict(security_config)
    return SecurityContext(store, rules, cfg, judge=None)


# ---------------- discovery ----------------
def test_discover_delegate_enabled_memory_off(tmp_path, security_config):
    security_config["module_trust_file"] = str(tmp_path / "module_trust.json")
    loaded = modules.discover(security_config)
    assert "delegate" in loaded
    assert "memory" not in loaded  # default off (opt-in)
    names = {getattr(t, "name", None) for t in modules.collect_tools(loaded)}
    assert "task_to_submodel" in names


# ---------------- delegate internals ----------------
def test_delegate_prompt_resolution(tmp_path, security_config, monkeypatch):
    from modules import delegate as d
    monkeypatch.setenv("CLAW_SE_HOME", str(tmp_path))
    lib = tmp_path / "prompt_library"
    lib.mkdir(parents=True, exist_ok=True)
    (lib / "code_review.md").write_text("You are a code reviewer.", encoding="utf-8")
    assert "code reviewer" in d._prompt_text("code_review")
    assert d._prompt_text("just a literal prompt") == "just a literal prompt"
    assert "helpful sub-agent" in d._prompt_text("")


def test_delegate_resolve_shared_tools(tmp_path, security_config):
    from modules import delegate as d

    @tool
    def read_file(path: str) -> str:
        """Read a file."""
        return path

    @tool
    def delete_file(path: str) -> str:
        """Delete a file."""
        return path

    d.configure(None, all_tools=[read_file, delete_file], tool_guards={})
    shared = d._resolve_shared_tools("read_file")
    assert [getattr(t, "name", None) for t in shared] == ["read_file"]
    assert d._resolve_shared_tools("read_file,delete_file")  # both
    assert d._resolve_shared_tools("") == []  # least privilege default: none


# ---------------- delegate tool behavior (no network) ----------------
def test_delegate_requires_context_in_isolation(tmp_path, security_config):
    from modules import delegate as d
    ctx = make_ctx(security_config, tmp_path)
    d.configure(ctx, max_depth=2)
    out = d.task_to_submodel.invoke(
        {"prompt_name": "p", "input_data": "i", "full_context_share": False, "context_content": ""})
    assert "requires explicit context_content" in out


def test_delegate_depth_limit(tmp_path, security_config, monkeypatch):
    from modules import delegate as d
    ctx = make_ctx(security_config, tmp_path)
    d.configure(ctx, max_depth=1)
    monkeypatch.setattr(factory_mod, "delegate_model", lambda **k: "sub ok")

    # depth 0 < max_depth=1 -> proceeds
    out = d.task_to_submodel.invoke({"prompt_name": "p", "input_data": "i"})
    assert out == "sub ok"
    # force depth to the limit -> blocked (fix #5)
    d._depths["default"] = 1
    out = d.task_to_submodel.invoke({"prompt_name": "p", "input_data": "i"})
    assert "max_depth" in out
    d._depths.pop("default", None)


def test_delegate_not_configured_message(tmp_path, security_config):
    from modules import delegate as d
    d.configure(None, max_depth=2)  # ctx=None
    out = d.task_to_submodel.invoke({"prompt_name": "p", "input_data": "i"})
    assert "not configured" in out


# ---------------- factory.delegate_model (context trimming + depth guard) ----------------
def test_delegate_model_context_trimming(tmp_path, security_config, monkeypatch):
    captured = {}

    class FakeSubAgent:
        def invoke(self, payload):
            captured["messages"] = payload["messages"]
            return {"messages": [SystemMessage(content="ok")]}

    monkeypatch.setattr(factory_mod, "build_agent", lambda **k: FakeSubAgent())
    out = factory_mod.delegate_model(
        prompt="P", input_data="I", full_context_share=False, context_content="CTX")
    assert out == "ok"
    texts = [getattr(m, "content", "") for m in captured["messages"]]
    assert "P" in texts and "CTX" in texts and "I" in texts


def test_delegate_model_requires_context_in_isolation():
    import pytest
    with pytest.raises(ValueError):
        factory_mod.delegate_model(prompt="P", input_data="I", full_context_share=False, context_content=None)


def test_delegate_model_depth_guard():
    import pytest
    with pytest.raises(RuntimeError):
        factory_mod.delegate_model(prompt="P", input_data="I", depth=2, max_depth=2)


# ---------------- sub-agent secure injection + least privilege (fix #11/A8) ----------------
def test_sub_agent_tools_least_privilege(tmp_path, security_config, monkeypatch):
    """tools_to_share filters the sub-agent's tools (A8) and guards follow (fix #11)."""
    from modules import delegate as d
    ctx = make_ctx(security_config, tmp_path)

    @tool
    def read_file(path: str) -> str:
        """Read a file."""
        return f"read:{path}"

    @tool
    def delete_file(path: str) -> str:
        """Delete a file."""
        return f"deleted:{path}"

    d.configure(ctx, all_tools=[read_file, delete_file],
                tool_guards={"read_file": "path", "delete_file": "path"}, max_depth=2)

    captured = {}

    def fake_delegate_model(**kw):
        captured["tools"] = kw.get("tools_to_share", [])
        captured["guards"] = kw.get("tool_guards", {})
        return "ok"

    monkeypatch.setattr(factory_mod, "delegate_model", fake_delegate_model)

    out = d.task_to_submodel.invoke(
        {"prompt_name": "p", "input_data": "i", "tools_to_share": "read_file"})
    assert out == "ok"
    names = [getattr(t, "name", None) for t in captured["tools"]]
    assert names == ["read_file"]  # delete_file NOT shared (least privilege, A8)
    assert set(captured["guards"]) == {"read_file"}  # guards follow the shared subset


def test_sub_agent_secure_injection(tmp_path, security_config, monkeypatch):
    """Every shared tool is secured before the sub-agent gets it (fix #11)."""
    ctx = make_ctx(security_config, tmp_path)

    @tool
    def read_file(path: str) -> str:
        """Read a file."""
        return f"read:{path}"

    captured = {}

    def fake_create_agent(*args, **kwargs):
        captured["tools"] = kwargs.get("tools", [])
        return {"messages": [SystemMessage(content="ok")]}

    monkeypatch.setattr(factory_mod, "create_agent", fake_create_agent)
    monkeypatch.setattr(factory_mod, "build_chat_model",
                        lambda provider, spec, temperature=None: None)

    factory_mod.build_agent(role="delegate", tools=[read_file],
                            tool_guards={"read_file": "path"},
                            system_prompt="sub", ctx=ctx)
    secured_read = captured["tools"][0]
    assert "Blocked" in secured_read.invoke({"path": "modules/exec.py"})  # self-dir guard
    assert secured_read.invoke({"path": "notes.txt"}) == "read:notes.txt"


# ---------------- memory ----------------
def test_memory_remember_and_recall(tmp_path, monkeypatch):
    from modules import memory as m
    monkeypatch.setenv("CLAW_SE_HOME", str(tmp_path))
    assert "Remembered" in m.remember.invoke({"content": "server uses port 8080", "tags": "infra"})
    assert "Remembered" in m.remember.invoke({"content": "meeting at 3pm", "date": "2026-08-21"})
    # keyword search across all days
    out = m.recall.invoke({"query": "port 8080"})
    assert "port 8080" in out and "server uses port 8080" in out
    # date-filtered (daily detail)
    out2 = m.recall.invoke({"date": "2026-08-21"})
    assert "meeting at 3pm" in out2
    assert "port 8080" not in out2
    # no match
    assert "No matching" in m.recall.invoke({"query": "zzzznone"})


def test_memory_uses_module_data_dir(tmp_path, monkeypatch):
    from modules import memory as m
    monkeypatch.setenv("CLAW_SE_HOME", str(tmp_path))
    m.remember.invoke({"content": "entry", "date": "2026-08-22"})
    data_file = tmp_path / "modules" / "memory" / "data" / "2026-08-22.md"
    assert data_file.exists()
    assert "entry" in data_file.read_text(encoding="utf-8")
