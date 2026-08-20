"""Interaction layer: unified interface for security prompts / notifications (MVP: terminal)."""
from abc import ABC, abstractmethod


class InteractionProvider(ABC):
    """Unified interaction entry: security prompts and notifications go through here."""

    @abstractmethod
    def ask_four(self, question: str, options: list[str]) -> str:
        """Ask a four-choice question and return the chosen option text."""

    @abstractmethod
    def notify(self, content: str, target: str = "") -> str:
        """Send a notification."""


_interaction: InteractionProvider | None = None


def set_interaction(provider: InteractionProvider) -> None:
    """Set the global interaction provider."""
    global _interaction
    _interaction = provider


def get_interaction() -> InteractionProvider:
    """Return the global interaction provider; fall back to TerminalProvider when unset."""
    global _interaction
    if _interaction is None:
        from .terminal import TerminalProvider  # lazy import avoids the base<->terminal cycle
        _interaction = TerminalProvider()
    return _interaction
