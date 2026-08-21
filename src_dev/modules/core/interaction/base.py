"""Interaction layer: unified interface for security prompts / notifications.

ask_four/notify accept a channel so security prompts and notifications can
be routed to the channel the request came from, not always the terminal.
"""
from abc import ABC, abstractmethod


class InteractionProvider(ABC):
    """Unified interaction entry: security prompts and notifications go through here."""

    @abstractmethod
    def ask_four(self, question: str, options: list[str], *, channel: str = "") -> str:
        """Ask a four-choice question and return the chosen option text.

        Args:
            question: prompt text.
            options: option list (e.g. ["add to whitelist", "allow once", "deny once", "add to blacklist"]).
            channel: route the prompt to this channel ("" = default/terminal).

        Returns:
            The chosen option text.
        """

    @abstractmethod
    def notify(self, content: str, target: str = "", *, channel: str = "") -> str:
        """Send a notification.

        Args:
            content: message body.
            target: display target label.
            channel: route the notification to this channel ("" = default/terminal).

        Returns:
            The notification content.
        """


_interaction: InteractionProvider | None = None


def set_interaction(provider: InteractionProvider | None) -> None:
    """Set (or clear) the global interaction provider."""
    global _interaction
    _interaction = provider


def get_interaction() -> InteractionProvider:
    """Return the global interaction provider; fall back to ChannelInteraction when unset."""
    global _interaction
    if _interaction is None:
        from .channel import ChannelInteraction  # lazy import avoids the base<->channel cycle
        _interaction = ChannelInteraction()
    return _interaction
