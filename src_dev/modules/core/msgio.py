"""MSGIO - global unified message input/output layer.

Core idea: every message in the program travels through the same MsgIO bus
instead of touching stdin/stdout/network directly. Different channels
(terminal, web, IM, ...) implement MsgBackend and register with the bus.

- MsgIO is a global singleton (get_io()) so every module shares one message port.
- send() broadcasts to all registered channels (or targets one by name).
- receive() polls all channels and returns a Msg carrying its channel - it never
  blocks: blocking backends are bridged by a worker thread into a queue,
  non-blocking backends are polled directly.
- Adding a channel = implement a MsgBackend + register(), no business-code changes.

(0.0.101) multi-channel: each backend declares whether receive() blocks.
  - blocking=True  -> the bus wraps it in a _ThreadBridge (a worker thread runs
    the blocking receive() and feeds a queue); poll() reads the queue, so a
    blocking channel (terminal input(), IM long connection) coexists with others
    without freezing the main loop.
  - blocking=False -> the backend implements a genuinely non-blocking poll()
    and is polled directly by the bus.

Enhancement: receive() runs the input-layer security hook
(input_guard.check) before returning a message; injection hits are intercepted,
a notice is echoed back, and the message never reaches the main loop.
"""
import logging
import queue
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # avoid circular import (input_guard does not import msgio)
    from .security.judge import InputGuard

logger = logging.getLogger("claw_se.msgio")


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
    blocking = True
    """Whether receive() blocks. True (default) backends are thread-bridged;
    False backends must implement a genuinely non-blocking poll()."""

    @abstractmethod
    def send(self, text: str) -> None:
        """Send a message to the channel user.

        Args:
            text: message content.
        """

    def poll(self) -> Optional[Msg]:
        """Non-blocking: return one pending message or None (never blocks).

        Non-blocking backends (blocking=False) override this. Blocking backends
        are thread-bridged and never have poll() called directly.
        """
        return None

    def receive(self) -> Optional[Msg]:
        """Blocking receive (default: poll until a message arrives).

        Blocking backends override this to block for real (e.g. terminal
        input()); non-blocking backends keep the default and are polled directly.

        Returns:
            A message, or None if the channel is gone.
        """
        while True:
            msg = self.poll()
            if msg is not None:
                return msg
            time.sleep(0.05)

    def close(self) -> None:
        """Close the channel (optional)."""


class TerminalBackend(MsgBackend):
    """Terminal channel: stdin/stdout (blocking receive, thread-bridged)."""

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


class _ThreadBridge:
    """Bridge a blocking backend into the bus: a worker thread runs the blocking
    receive() and feeds a queue, so poll() never blocks the main loop."""

    def __init__(self, backend: MsgBackend):
        self._backend = backend
        self._queue: "queue.Queue[Optional[Msg]]" = queue.Queue()
        self._closed = False
        self._thread = threading.Thread(
            target=self._run, name=f"msgio-bridge-{backend.name}", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._closed:
            try:
                msg = self._backend.receive()
            except Exception as e:  # noqa: BLE001 - a channel failure must not kill the bridge
                logger.error("channel %s bridge receive failed: %s", self._backend.name, e)
                msg = None
            if self._closed:
                break
            if msg is not None:
                self._queue.put(msg)
            else:
                time.sleep(0.05)

    def poll(self) -> Optional[Msg]:
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            return None

    def send(self, text: str) -> None:
        self._backend.send(text)

    def close(self) -> None:
        self._closed = True


class MsgIO:
    """Global message bus: manages all channels and unifies send/receive."""

    _instance: Optional["MsgIO"] = None

    def __init__(self) -> None:
        self._backends: dict[str, MsgBackend] = {}
        self._poll_order: list[str] = []
        self._input_guard: Optional["InputGuard"] = None
        self._current_channel: Optional[str] = None

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

        Blocking backends are wrapped in a worker-thread bridge so the bus never
        blocks on them; non-blocking backends are polled directly.

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
        self._backends[name] = _ThreadBridge(backend) if backend.blocking else backend
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

    @property
    def current_channel(self) -> Optional[str]:
        """The channel of the message being handled (set by the main loop, read
        by the interaction layer to route security prompts back to the caller)."""
        return self._current_channel

    def set_current_channel(self, name: Optional[str]) -> None:
        """Track which channel the main loop is currently handling.

        Args:
            name: channel name, or None when no message is being handled.
        """
        self._current_channel = name

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
        """Poll all channels (never blocks) and return the first usable message.

        Blocking channels were bridged into queues at registration, so this only
        touches non-blocking poll()/queue reads. If a channel returns a message
        that fails the input-layer check, a notice "[SE] Blocked (input
        injection)" is echoed to that channel and the message is skipped.

        Returns:
            A message that passed the check, or None if no channel has one.
        """
        for name in self._poll_order:
            backend = self._backends.get(name)
            if backend is None:
                continue
            try:
                msg = backend.poll()
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

    def poll_channel(self, name: str) -> Optional[Msg]:
        """Poll a single channel's backlog directly (no input guard).

        Used by the interaction layer while waiting for a reply to a security
        prompt - the answer is a response to a question, not a new command.

        Args:
            name: channel name.

        Returns:
            One pending message from that channel, or None.
        """
        backend = self._backends.get(name)
        if backend is None:
            return None
        try:
            return backend.poll()
        except Exception as e:  # noqa: BLE001
            logger.error("channel %s poll failed: %s", name, e)
            return None

    def close(self) -> None:
        """Close all channels."""
        for name in list(self._poll_order):
            self.unregister(name)


def get_io() -> MsgIO:
    """Return the global MsgIO singleton (convenience)."""
    return MsgIO.get_io()
