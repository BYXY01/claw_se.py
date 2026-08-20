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
    assert "_PAYLOAD =" in content
    assert "self_release" in content
    # never embeds the real secret file or runtime data
    assert '"src_dev/.env"' not in content
    assert '".env":' not in content
    assert '"modules/core/security/data"' not in content


def test_builder_excludes_secrets_and_dev_entry(tmp_path):
    payload = builder.collect_payload()
    assert ".env" not in payload
    assert "claw_se_entry.py" not in payload  # runtime template, injected by builder
    # no top-level (src_dev-root) entry scripts are shipped
    assert not any("/" not in rel and rel.endswith(".py") for rel in payload)
    assert "modules/core/boot.py" in payload
    assert "config/security.json" in payload
    assert "prompt_library/IDENTITY.md" in payload


def test_single_file_self_release_and_no_overwrite(tmp_path):
    c = _import_built(tmp_path)
    release_root = tmp_path / "home"
    c.self_release(release_root)
    assert (release_root / "modules/core/security/rules.py").exists()
    assert (release_root / "config/security.json").exists()
    assert (release_root / "prompt_library/IDENTITY.md").exists()
    # user edit preserved on second run
    target = release_root / "modules/exec.py"
    target.write_text("# user edited\n", encoding="utf-8")
    c.self_release(release_root)
    assert target.read_text(encoding="utf-8") == "# user edited\n"


def test_single_file_reset_core_only(tmp_path):
    c = _import_built(tmp_path)
    release_root = tmp_path / "home2"
    c.self_release(release_root)
    rules_py = release_root / "modules/core/security/rules.py"
    orig = rules_py.read_text(encoding="utf-8")
    rules_py.write_text("# corrupted\n", encoding="utf-8")
    user_file = release_root / "modules/exec.py"
    user_file.write_text("# user\n", encoding="utf-8")
    c.self_release(release_root, reset_core=True)
    assert rules_py.read_text(encoding="utf-8") == orig  # core re-released
    assert user_file.read_text(encoding="utf-8") == "# user\n"  # user file untouched


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
