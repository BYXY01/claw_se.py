"""Ladder 4: single-file distribution - builder, self-release, reset-core, bare-run defense."""
import sys

import builder


def _import_built(tmp_path):
    """Build claw_se.py into tmp_path and import it as a fresh module."""
    builder.build(tmp_path)
    sys.path.insert(0, str(tmp_path))
    sys.modules.pop("claw_se", None)  # avoid cross-test cached-module pollution
    import claw_se
    return claw_se


def test_builder_produces_single_file(tmp_path):
    out = builder.build(tmp_path)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "_PAYLOAD = {" in content
    assert "self_release" in content
    assert "_ensure_genuine_run" in content
    assert "_boot" in content
    # never embeds the real secret file or runtime data
    assert '"src_dev/.env"' not in content
    assert '".env":' not in content
    assert '"modules/core/security/data"' not in content


def test_builder_excludes_secrets_and_dev_entry(tmp_path):
    payload = builder._src()
    assert ".env" not in payload
    assert "claw_se_entry.py" not in payload  # runtime template lives inside builder
    # no top-level (src_dev-root) entry scripts are shipped
    assert not any("/" not in rel and rel.endswith(".py") for rel in payload)
    assert "modules/core/factory.py" in payload
    assert "config/providers.example.json" in payload
    assert "prompt_library/IDENTITY.md" in payload


def test_single_file_self_release_and_user_data_not_overwritten(tmp_path):
    c = _import_built(tmp_path)
    release_root = tmp_path / "home"
    c.self_release(release_root)
    assert (release_root / "modules/core/security/rules.py").exists()
    assert (release_root / "config/providers.example.json").exists()
    assert (release_root / "prompt_library/IDENTITY.md").exists()
    # user data (config/prompt) is never overwritten on a second run
    target = release_root / "prompt_library" / "IDENTITY.md"
    target.write_text("# user edited\n", encoding="utf-8")
    c.self_release(release_root)
    assert target.read_text(encoding="utf-8") == "# user edited\n"


def test_single_file_restores_nothing_modules_editable(tmp_path):
    """Modules stay editable (open design): a user edit to a released module is
    NOT overwritten; a broken core is fixed via --reset-core instead."""
    c = _import_built(tmp_path)
    release_root = tmp_path / "home_edit"
    c.self_release(release_root)
    exec_py = release_root / "modules" / "exec.py"
    exec_py.write_text("# user tweak\n", encoding="utf-8")
    c.self_release(release_root)
    assert exec_py.read_text(encoding="utf-8") == "# user tweak\n"  # not overwritten


def test_single_file_reset_core_only(tmp_path):
    c = _import_built(tmp_path)
    release_root = tmp_path / "home2"
    c.self_release(release_root)
    rules_py = release_root / "modules/core/security/rules.py"
    orig = rules_py.read_text(encoding="utf-8")
    rules_py.write_text("# corrupted\n", encoding="utf-8")
    user_file = release_root / "prompt_library" / "IDENTITY.md"
    user_file.write_text("# user\n", encoding="utf-8")
    c.self_release(release_root, reset_core=True)
    assert rules_py.read_text(encoding="utf-8") == orig  # core re-released
    assert user_file.read_text(encoding="utf-8") == "# user\n"  # user data untouched


def test_single_file_refuses_stripped_payload(tmp_path):
    c = _import_built(tmp_path)
    c._PAYLOAD = {}
    import pytest
    with pytest.raises(SystemExit):
        c.self_release(tmp_path / "home3")


def test_single_file_ensure_deps_available(tmp_path):
    c = _import_built(tmp_path)
    assert c._deps_available() is True  # deps already present in this env
    assert c.ensure_deps() is True


def test_no_boot_in_dev_tree():
    """Structural gate: the dev tree has no boot/main-loop entry (it lives in
    builder.py), so cloning the repo alone cannot run the app - you must build."""
    from pathlib import Path
    src_dev = Path(__file__).resolve().parents[2] / "src_dev"
    assert not (src_dev / "modules" / "core" / "boot.py").exists()
    assert not (src_dev / "claw_se_main.py").exists()
    assert not (src_dev / "claw_se_entry.py").exists()
    # the main loop lives only inside builder.py's embedded template
    builder_src = Path(__file__).resolve().parents[2] / "builder.py"
    text = builder_src.read_text(encoding="utf-8")
    assert "_boot" in text
    assert "Claw_SE started" in text


def test_embedded_loop_refuses_dev_tree(tmp_path):
    """Even though the loop is single-file-only, it keeps the runtime check:
    driving it against the cloned dev tree (src_dev modules) is refused."""
    import pytest
    c = _import_built(tmp_path)
    import modules  # resolves to src_dev in the test env
    with pytest.raises(SystemExit):
        c._ensure_genuine_run(modules)
    # a genuine release-like module path passes the dev-tree part of the check
    import types
    fake = types.ModuleType("modules")
    fake.__file__ = str(tmp_path / "release" / "modules" / "__init__.py")
    c._ensure_genuine_run(fake)  # no SystemExit
    # a stripped payload refuses regardless of module path
    c._PAYLOAD = {}
    with pytest.raises(SystemExit):
        c._ensure_genuine_run(fake)


def test_released_modules_offline_security(tmp_path):
    """Regression: ladder 1 security still holds against the released modules."""
    c = _import_built(tmp_path)
    release_root = tmp_path / "home4"
    c.self_release(release_root)
    sys.path.insert(0, str(release_root))
    try:
        from modules.core.security import protected_dirs
        from modules.core.security.rules import Rules
        from modules.core.security.store import Store
        from modules.core.security.wrapper import SecurityConfig, SecurityContext, secure_tool
        from modules.exec import execute

        cfg = {"blacklist_file": str(tmp_path / "b.json"),
               "whitelist_file": str(tmp_path / "w.json"),
               "asklist_file": str(tmp_path / "a.json"),
               "overrides_file": str(tmp_path / "o.json"),
               "firewall": "on", "detect": "off"}
        store = Store(cfg, tmp_path)
        rules = Rules(store, protected_dirs(release_root))
        ctx = SecurityContext(store, rules, SecurityConfig.from_dict(cfg))
        secured = secure_tool(execute, "command", ctx)
        store.add("rm -rf", "blacklist")
        assert "Blocked" in secured.invoke({"operation": "run", "command": "rm -rf /x"})
        assert "hello" in secured.invoke({"operation": "run", "command": "echo hello"})
        assert "self-directory" in secured.invoke(
            {"operation": "run", "command": "rm modules/exec.py"})
    finally:
        sys.path.remove(str(release_root))
        sys.modules.pop("claw_se", None)
