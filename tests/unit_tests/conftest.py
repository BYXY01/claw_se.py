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
    """Build a security config dict (tunables only; list paths are hardcoded)."""
    return {
        "firewall": "on",
        "detect": "off",
        "input_detect": "off",
        "review_on_block": False,
        "override_threshold": 3,
        "version": "v1",
    }


def make_providers_config() -> dict:
    """A test model catalog (provider/model/key_ref) for factory resolution."""
    return {
        "providers": {
            "deepseek": {
                "api_base": "https://api.deepseek.com/v1",
                "models": {
                    "main": {"model": "deepseek-chat", "key_ref": "DEEPSEEK_API_KEY", "ctx": 8192},
                    "judge": {"model": "deepseek-chat", "key_ref": "DEEPSEEK_API_KEY", "ctx": 8192},
                },
            },
        },
        "role_map": {
            "main": "deepseek.main",
            "judge": "deepseek.judge",
            "delegate": "deepseek.main",
        },
    }


@pytest.fixture
def providers_config() -> dict:
    """A test model catalog for factory resolution."""
    return make_providers_config()


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
