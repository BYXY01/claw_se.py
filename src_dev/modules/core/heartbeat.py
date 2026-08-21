"""Periodic synthetic check-in (heartbeat) for the main loop.

Not a message channel: the main loop itself consults the heartbeat when idle and
runs an unsolicited agent turn. The reply goes nowhere (no user on the heartbeat
side) - the point is the agent's periodic self-check, not a conversation.

Disabled by default (security-first: the agent only acts when prompted unless the
user explicitly turns the heartbeat on).
"""
import threading
import time
from typing import Optional


class Heartbeat:
    """A timer the main loop consults; due() flips when a beat is scheduled.

    Args:
        every: seconds between beats (>= 0.1).
        prompt: the synthetic user message delivered on each beat.
    """

    def __init__(self, every: float, prompt: str):
        self._every = max(0.1, float(every))
        self._prompt = prompt
        self._due = False
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="claw_se-heartbeat", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            time.sleep(self._every)
            with self._lock:
                self._due = True

    def due(self) -> Optional[str]:
        """Return the heartbeat prompt if a beat is due (and clear it), else None.

        Returns:
            The synthetic prompt for one unsolicited agent turn, or None.
        """
        with self._lock:
            if not self._due:
                return None
            self._due = False
            return self._prompt

    @property
    def every(self) -> float:
        return self._every

    @property
    def prompt(self) -> str:
        return self._prompt
