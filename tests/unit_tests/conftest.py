"""Pytest config: make the Claw_SE dev body importable and share helpers."""
import sys
from pathlib import Path

import pytest

SRC_DEV = Path(__file__).resolve().parents[2] / "src_dev"
sys.path.insert(0, str(SRC_DEV))

from modules.core.security import protected_dirs  # noqa: E402


class ToolCallingFake:
    """Fake chat model that supports bind_tools (create_agent requires it).

    Wraps GenericFakeChatModel; bind_tools returns self so agent creation succeeds
    without any network access. Messages are served from the given iterator.
    """

    def __new__(cls, messages):
        from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

        class _Fake(GenericFakeChatModel):
            def bind_tools(self, tools, **kwargs):
                return self

        return _Fake(messages=iter(messages))


def make_security_config(tmp_path: Path) -> dict:
    """Build a security config dict whose data files live under tmp_path."""
    data_dir = tmp_path / "security_data"
    return {
        "firewall": "on",
        "detect": "off",
        "input_detect": "off",
        "review_on_block": False,
        "override_threshold": 3,
        "blacklist_file": str(data_dir / "blacklist.json"),
        "whitelist_file": str(data_dir / "whitelist.json"),
        "asklist_file": str(data_dir / "asklist.json"),
        "overrides_file": str(data_dir / "overrides.json"),
        "module_trust_file": str(data_dir / "module_trust.json"),
        "version": "v1",
    }


@pytest.fixture
def security_config(tmp_path) -> dict:
    """Security config fixture pointing at tmp_path. detect=off (offline-safe)."""
    return make_security_config(tmp_path)


@pytest.fixture
def app_root(tmp_path) -> Path:
    """An isolated app root; protected dirs derived from it."""
    return tmp_path


@pytest.fixture
def protected(tmp_path) -> list:
    """Protected dirs derived from the fixture app root."""
    return protected_dirs(tmp_path)
