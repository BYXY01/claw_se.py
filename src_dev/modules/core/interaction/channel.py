"""Channel-routing interaction provider.

Routes security prompts / notifications through the MsgIO bus to a named
channel instead of always hitting the terminal. ask_four with a channel sends
the question there and waits for the user's choice on the same channel - safe
because it runs while the main loop is blocked inside the agent call, so
nothing else consumes the answer. With channel="" it behaves like the terminal
provider.
"""
import time

from ..msgio import get_msg_io
from .base import InteractionProvider
from .terminal import TerminalProvider


class ChannelInteraction(InteractionProvider):
    """Interaction that routes to a named channel via the MsgIO bus."""

    def __init__(self) -> None:
        self._terminal = TerminalProvider()

    def ask_four(self, question: str, options: list[str], *, channel: str = "") -> str:
        """Ask a four-choice question, routed to a channel.

        Args:
            question: prompt text.
            options: option list (e.g. ["add to whitelist", "allow once", "deny once", "add to blacklist"]).
            channel: route the prompt to this channel ("" = terminal).

        Returns:
            The chosen option text.
        """
        if not channel:
            return self._terminal.ask_four(question, options)
        msg_io = get_msg_io()
        msg_io.send(question, channel=channel)
        for i, opt in enumerate(options, 1):
            msg_io.send(f"  [{i}] {opt}", channel=channel)
        while True:
            msg = msg_io.poll_channel(channel)
            if msg is None:
                time.sleep(0.1)
                continue
            try:
                idx = int(msg.text.strip())
                if 1 <= idx <= len(options):
                    return options[idx - 1]
            except ValueError:
                pass
            msg_io.send("Invalid choice, try again", channel=channel)

    def notify(self, content: str, target: str = "", *, channel: str = "") -> str:
        """Send a notification, routed to a channel.

        Args:
            content: message body.
            target: display target label.
            channel: route the notification to this channel ("" = terminal).

        Returns:
            The notification content.
        """
        if not channel:
            return self._terminal.notify(content, target)
        msg_io = get_msg_io()
        msg_io.send(f"[{target or channel}] {content}", channel=channel)
        return content
