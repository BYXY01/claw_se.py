"""MSGIO - global unified message input/output layer.

Core idea: every message in the program travels through the same MsgIO bus
instead of touching stdin/stdout/network directly. Different channels
(terminal, web, IM, ...) implement MsgBackend and register with the bus.

- MsgIO is a global singleton (get_io()) so every module shares one message port.
- send() broadcasts to all registered channels.
- receive() polls all channels and returns a Msg carrying its channel.
- Adding a channel = implement a MsgBackend + register(), no business-code changes.

Enhancement: receive() runs the input-layer security hook
(input_guard.check) before returning a message; injection hits are intercepted,
a notice is echoed back, and the message never reaches the main loop.
"""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # avoid circular import (input_guard does not import msgio)
    from .security.judge import InputGuard

logger = logging.getLogger("Claw_SE.msgio")


@dataclass
class Msg:
    """A unified message.

    Attributes:
        channel: source channel name (terminal / telegram / web).
        text: message body.
    """

    channel: str
    text: str


class MsgBackend(ABC):
    """Channel backend abstraction: unified send/receive, business layer ignores the channel."""

    name = "abstract"
    """Unique channel identifier, used at registration."""

    @abstractmethod
    def send(self, text: str) -> None:
        """Send a message to the channel user.

        Args:
            text: message content.
        """

    @abstractmethod
    def receive(self) -> Optional[Msg]:
        """Receive one message from this channel (non-blocking semantics by backend).

        Returns:
            A message, or None if there is nothing to receive / the channel is gone.
        """

    def close(self) -> None:
        """Close the channel (optional)."""


class TerminalBackend(MsgBackend):
    """Terminal channel: stdin/stdout."""

    name = "terminal"

    def __init__(self, prompt: str = "claw_se> "):
        self.prompt = prompt

    def send(self, text: str) -> None:
        print(text, flush=True)

    def receive(self) -> Optional[Msg]:
        try:
            line = input(self.prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not line:
            return None
        return Msg(channel=self.name, text=line)


class MsgIO:
    """Global message bus: manages all channels and unifies send/receive."""

    _instance: Optional["MsgIO"] = None

    def __init__(self) -> None:
        self._backends: dict[str, MsgBackend] = {}
        self._poll_order: list[str] = []
        self._input_guard: Optional["InputGuard"] = None

    @classmethod
    def get_io(cls) -> "MsgIO":
        """Return the global MsgIO singleton."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_io(cls) -> None:
        """Reset the global singleton (mainly for tests)."""
        cls._instance = None

    def set_input_guard(self, guard: "InputGuard") -> None:
        """Mount the input-layer security hook (SE enhancement).

        Args:
            guard: input-layer checker providing check(text) -> Optional[feature].
        """
        self._input_guard = guard

    def register(self, backend: MsgBackend) -> None:
        """Register a channel backend.

        Args:
            backend: backend instance. Registering the same name replaces the old one.
        """
        name = backend.name
        old = self._backends.get(name)
        if old is not None and old is not backend:
            try:
                old.close()
            except Exception:  # noqa: BLE001 - backend close must not break registration
                pass
        self._backends[name] = backend
        if name not in self._poll_order:
            self._poll_order.append(name)
        logger.info("msgio registered channel: %s", name)

    def unregister(self, name: str) -> None:
        """Remove a channel backend.

        Args:
            name: channel name.
        """
        backend = self._backends.pop(name, None)
        if backend is not None:
            try:
                backend.close()
            except Exception:  # noqa: BLE001
                pass
            if name in self._poll_order:
                self._poll_order.remove(name)
            logger.info("msgio unregistered channel: %s", name)

    @property
    def channels(self) -> list[str]:
        """List of registered channel names."""
        return list(self._poll_order)

    def send(self, text: str, channel: Optional[str] = None) -> None:
        """Send a message.

        Args:
            text: message content.
            channel: target channel name; None broadcasts to all channels.
        """
        if channel is not None:
            backend = self._backends.get(channel)
            if backend is not None:
                backend.send(text)
            else:
                logger.warning("send to unknown channel: %s", channel)
            return

        for name in self._poll_order:
            backend = self._backends.get(name)
            if backend is not None:
                try:
                    backend.send(text)
                except Exception as e:  # noqa: BLE001 - one channel failure must not break others
                    logger.error("channel %s send failed: %s", name, e)

    def receive(self) -> Optional[Msg]:
        """Poll all channels and return the first usable message (already input-checked).

        If a channel returns a message that fails the input-layer check, a notice
        "[SE] Blocked (input injection)" is echoed to that channel and the message is skipped.

        Returns:
            A message that passed the check, or None if no channel has one.
        """
        for name in self._poll_order:
            backend = self._backends.get(name)
            if backend is None:
                continue
            try:
                msg = backend.receive()
            except Exception as e:  # noqa: BLE001
                logger.error("channel %s receive failed: %s", name, e)
                continue
            if msg is None:
                continue
            if self._input_guard is not None:
                feature = self._input_guard.check(msg.text)
                if feature is not None:
                    backend.send(f"[SE] Blocked (input injection): {feature}")
                    logger.warning("input_guard blocked msg from %s: %s", name, feature)
                    continue
            return msg
        return None

    def close(self) -> None:
        """Close all channels."""
        for name in list(self._poll_order):
            self.unregister(name)


def get_io() -> MsgIO:
    """Return the global MsgIO singleton (convenience)."""
    return MsgIO.get_io()
