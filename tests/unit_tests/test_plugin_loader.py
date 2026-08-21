"""(0.0.102) plugin loader: manifest audit, classify, graded checks, capability
wiring (tool / channel / hook / provider) through the injected facade."""
import json

import pytest

from modules.core.msgio import MsgIO, get_io
from modules.core.plugins import Kind, Manifest, PluginAPI, PluginLoader
from modules.core.plugins import _audit_manifest, classify, collect_guard_map, collect_tools
from modules.core.plugins import wire_channels


def _make_plugin(root, plugin_id, manifest, plugin_src):
    directory = root / plugin_id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (directory / "plugin.py").write_text(plugin_src, encoding="utf-8")
    return directory


def _loader(root, strict=False, env=None):
    return PluginLoader(root, {"firewall": "on", "detect": "off"}, root.parent,
                        strict=strict, env=env if env is not None else {})


TOOL_PLUGIN = '''
from langchain_core.tools import tool

@tool
def hello(name: str) -> str:
    """Say hello to a name."""
    return f"hello {name}"

def PLUGIN(api):
    api.register_tool(hello, guard_key="name")
'''

TOOL_MANIFEST = {
    "id": "hello", "name": "hello", "version": "0.1",
    "requires": [], "auth": [], "capabilities": ["tool"],
}


def test_classify_plugin_vs_tool(tmp_path):
    plugin_dir = _make_plugin(tmp_path, "hello", TOOL_MANIFEST, TOOL_PLUGIN)
    assert classify(plugin_dir) == "plugin"
    assert classify(tmp_path / "no_manifest_dir") == "tool"


def test_manifest_audit_valid(tmp_path):
    d = _make_plugin(tmp_path, "hello", TOOL_MANIFEST, "")
    manifest = _audit_manifest(d / "manifest.json")
    assert manifest.plugin_id == "hello"
    assert manifest.capabilities == [Kind.TOOL]
    assert manifest.auth == []


@pytest.mark.parametrize("bad", [
    {"name": "x", "version": "1", "capabilities": ["tool"]},  # missing id
    {"id": "x", "name": "x", "version": "1", "capabilities": ["nope"]},  # bad capability
    {"id": "x", "name": "x", "version": "1", "capabilities": [], "auth": "KEY"},  # auth not list
    {"id": "x", "name": "x", "version": "1", "capabilities": []},  # empty capabilities
])
def test_manifest_audit_rejects_bad(tmp_path, bad):
    d = tmp_path / "bad"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError):
        _audit_manifest(d / "manifest.json")


def test_plugin_loads_tool_and_guard(tmp_path):
    _make_plugin(tmp_path, "hello", TOOL_MANIFEST, TOOL_PLUGIN)
    plugins = _loader(tmp_path).load_all()
    assert len(plugins) == 1
    api = plugins[0].api
    assert [(t.name, gk) for t, gk in api.tools()] == [("hello", "name")]
    assert [t.name for t in collect_tools(plugins)] == ["hello"]
    assert collect_guard_map(plugins) == {"hello": "name"}


def test_plugin_rejects_malicious_source(tmp_path):
    malicious = '''
def PLUGIN(api):
    import os
    os.system("whoami")
'''
    _make_plugin(tmp_path, "evil", {**TOOL_MANIFEST, "id": "evil"}, malicious)
    assert _loader(tmp_path).load_all() == []


def test_plugin_rejects_id_mismatch(tmp_path):
    _make_plugin(tmp_path, "hello", {**TOOL_MANIFEST, "id": "other"}, TOOL_PLUGIN)
    assert _loader(tmp_path).load_all() == []


def test_plugin_rejects_missing_pluggable_entry(tmp_path):
    _make_plugin(tmp_path, "hello", TOOL_MANIFEST, "X = 1\n")
    assert _loader(tmp_path).load_all() == []


def test_plugin_auth_requires_declaration(tmp_path):
    manifest = Manifest(plugin_id="p", name="p", version="1",
                        capabilities=[Kind.TOOL], auth=[])
    api = PluginAPI("p", manifest, tmp_path / "data", {"SECRET": "v"})
    with pytest.raises(KeyError):
        api.auth("UNDECLARED")
    assert api.env("SECRET") == "v"  # plain env reads are always allowed


def test_plugin_channel_wires_into_msgio(tmp_path):
    MsgIO.reset_io()
    channel_plugin = '''
class PingBackend:
    name = "ping"
    blocking = False
    def __init__(self):
        self.sent = []
    def send(self, text):
        self.sent.append(text)
    def poll(self):
        return None

def PLUGIN(api):
    api.register_channel(PingBackend())
'''
    _make_plugin(tmp_path, "ping", {**TOOL_MANIFEST, "id": "ping",
                                    "capabilities": ["channel"]}, channel_plugin)
    plugins = _loader(tmp_path).load_all()
    assert len(plugins) == 1
    io = get_io()
    wire_channels(plugins, register_channel=io.register)
    assert "ping" in io.channels
    io.send("hello", channel="ping")  # routed through msgio without error
    MsgIO.reset_io()


def test_plugin_hook_and_provider_review_flag(tmp_path):
    hook_plugin = '''
def on_load():
    return "loaded"

def PLUGIN(api):
    api.register_hook("on_load", on_load)
    api.register_provider({"name": "remote", "models": {}}, review=True)
    api.register_provider({"name": "local"}, review=False)
'''
    _make_plugin(tmp_path, "caps", {**TOOL_MANIFEST, "id": "caps",
                                    "capabilities": ["hook", "provider"]}, hook_plugin)
    plugins = _loader(tmp_path).load_all()
    assert len(plugins) == 1
    api = plugins[0].api
    assert [name for name, _hook in api.hooks()] == ["on_load"]
    metas = api.providers()
    assert metas == [({"name": "remote", "models": {}}, True), ({"name": "local"}, False)]
