"""(0.0.103) heartbeat: a main-loop concern (not a msgio channel), off by default."""
import time

from modules.core.config import load_security_config
from modules.core.heartbeat import Heartbeat


def test_heartbeat_disabled_by_default():
    sec = load_security_config()
    assert sec.get("heartbeat", {}).get("every", 0) == 0


def test_heartbeat_due_and_consumed():
    hb = Heartbeat(0.05, "beat: anything needing attention?")
    assert hb.due() is None  # nothing scheduled yet
    time.sleep(0.15)
    assert hb.due() == "beat: anything needing attention?"
    assert hb.due() is None  # consumed: only one turn per beat
