"""(0.0.101): msgio multi-channel - blocking backends thread-bridged, receive()
never blocks, interaction routes by channel."""
import queue
import threading
import time

from modules.core.interaction.channel import ChannelInteraction
from modules.core.msgio import Msg, MsgBackend, MsgIO, TerminalBackend, get_io


class BlockingBackend(MsgBackend):
    """A backend whose receive() blocks until a message arrives (like input())."""

    name = "blocking"
    blocking = True

    def __init__(self):
        self._inbox: "queue.Queue[str | Msg]" = queue.Queue()
        self._outbox: list[str] = []

    def send(self, text: str) -> None:
        self._outbox.append(text)

    def receive(self):
        item = self._inbox.get()  # blocks, like terminal input()
        if isinstance(item, Msg):
            return item
        return Msg(channel=self.name, text=item)

    def push(self, text: str) -> None:
        self._inbox.put(text)


class LoopbackBackend(MsgBackend):
    """Non-blocking in-memory channel: send() records, poll() drains a queue."""

    name = "loopback"
    blocking = False

    def __init__(self):
        self._inbox: "queue.Queue[Msg]" = queue.Queue()
        self._sent: list[str] = []

    def send(self, text: str) -> None:
        self._sent.append(text)

    def poll(self):
        try:
            return self._inbox.get_nowait()
        except queue.Empty:
            return None

    def push(self, text: str) -> None:
        self._inbox.put(Msg(channel=self.name, text=text))


def _wait_for(io: MsgIO, timeout: float = 2.0):
    """Poll io.receive() until a message arrives (bridge delivery is async)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = io.receive()
        if msg is not None:
            return msg
        time.sleep(0.02)
    return None


def test_blocking_backend_is_thread_bridged():
    """A blocking backend's message reaches receive() without blocking the bus."""
    MsgIO.reset_io()
    io = get_io()
    backend = BlockingBackend()
    io.register(backend)
    backend.push("hello from blocking")
    msg = _wait_for(io)
    assert msg is not None
    assert msg.text == "hello from blocking"
    assert msg.channel == "blocking"
    io.send("reply", channel="blocking")
    assert backend._outbox[-1] == "reply"
    io.close()


def test_multichannel_terminal_plus_loopback_nonblocking():
    """Terminal (blocking, bridged) + loopback (non-blocking) coexist; both
    directions work and receive() never blocks on the terminal."""
    MsgIO.reset_io()
    io = get_io()
    loop = LoopbackBackend()
    io.register(TerminalBackend())
    io.register(loop)
    assert set(io.channels) == {"terminal", "loopback"}
    loop.push("hi from loopback")
    msg = _wait_for(io)
    assert msg is not None
    assert msg.channel == "loopback"
    assert msg.text == "hi from loopback"
    io.send("direct reply", channel="loopback")
    assert loop._sent[-1] == "direct reply"
    # broadcast reaches the non-blocking channel too
    io.send("broadcast")
    assert any("broadcast" in s for s in loop._sent)
    io.close()


def test_interaction_routes_by_channel():
    """ask_four/notify route to the named channel, not the terminal."""
    MsgIO.reset_io()
    io = get_io()
    loop = LoopbackBackend()
    io.register(loop)
    provider = ChannelInteraction()

    def answer() -> None:
        time.sleep(0.05)
        loop.push("2")  # the user picks option 2 on the loopback channel

    threading.Thread(target=answer, daemon=True).start()
    choice = provider.ask_four("pick one", ["a", "b", "c"], channel="loopback")
    assert choice == "b"
    assert any("pick one" in s for s in loop._sent)
    assert any("[2] b" in s for s in loop._sent)

    provider.notify("done", channel="loopback")
    assert any("done" in s for s in loop._sent)
    MsgIO.reset_io()


def test_interaction_defaults_to_terminal_provider():
    """ChannelInteraction with channel='' delegates to terminal behavior (no MsgIO)."""
    MsgIO.reset_io()
    provider = ChannelInteraction()
    result = provider.notify("hello", channel="")
    assert result == "hello"
    MsgIO.reset_io()
