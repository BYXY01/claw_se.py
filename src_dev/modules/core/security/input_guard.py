"""Input-layer injection guard (new; neither LC nor ND had it).

Runs on MsgIO.receive() before a message reaches the main loop.

- Static blocking uses the SAME blacklist as the tool layer (one unified 0-token
  list seeded with dangerous commands + prompt-injection features). Containment
  match, always checked, blocks/strips on hit.
- LLM detection, four modes (configurable in config/security.json):
    off          : static injection check only, no LLM
    random:x     : with probability x, run the full LLM check
    heuristic    : offline keyword heuristic (no LLM), a lighter middle ground
    full         : always run the LLM check
- Self-learning has no independent switch: whenever LLM detection is on,
  full/random modes judging dangerous write the feature into the learned blacklist.
"""
import logging
import random
from typing import Optional

from .store import _DEFAULT_BLACKLIST_KEYWORDS, _DEFAULT_INJECTION_FEATURES

logger = logging.getLogger("Claw_SE.security.input_guard")

# Heuristic markers used by the offline `heuristic` mode (lightweight semantic hint).
_HEURISTIC_MARKERS = [
    "prompt injection",
    "system prompt",
    "leak secrets",
    "privilege escalation",
    "unlock restrictions",
    "bypass security",
]

_HEURISTIC_WEIGHT = 0.4  # fraction of markers required to flag


class InputGuard:
    """Input-layer injection guard.

    Args:
        security_config: dict from config/security.json (input_detect / check_ratio).
        judge: optional SafetyJudge used by LLM modes (full / random:x).
        store: optional Store; its unified blacklist is the static feature source.
    """

    def __init__(self, security_config: dict, judge=None, store=None):
        cfg = security_config or {}
        self._mode = str(cfg.get("input_detect", "off")).lower()
        self._ratio = cfg.get("check_ratio", 0.1)
        try:
            self._ratio = float(self._ratio)
        except (TypeError, ValueError):
            self._ratio = 0.1
        self._judge = judge
        self._store = store

    def _static_features(self) -> list[str]:
        """Static features: the unified blacklist (dangerous + injection), or the seed default."""
        if self._store is not None:
            return self._store.get_list("blacklist")
        return list(_DEFAULT_BLACKLIST_KEYWORDS) + list(_DEFAULT_INJECTION_FEATURES)

    def check(self, text: str) -> Optional[str]:
        """Check a message; return the matched feature if it should be blocked, else None.

        Args:
            text: the incoming message.

        Returns:
            The matched feature (blocked) or None (allowed through).
        """
        if not text:
            return None

        # 1. static blacklist (0 token, always)
        lowered = text.lower()
        for feature in self._static_features():
            if feature and feature.lower() in lowered:
                logger.info("input_guard static hit: %s", feature)
                return feature

        # 2. LLM detection per mode
        mode = self._mode
        if mode == "off":
            return None
        if mode == "heuristic":
            return self._heuristic(text)
        if mode.startswith("random:"):
            try:
                prob = float(mode.split(":", 1)[1])
            except (TypeError, ValueError):
                prob = self._ratio
            if random.random() > prob:
                return None
            return self._llm_check(text)
        if mode == "full":
            return self._llm_check(text)
        return None

    def _heuristic(self, text: str) -> Optional[str]:
        """Offline heuristic: flag when enough markers appear (no LLM, no self-learning)."""
        lowered = text.lower()
        hits = [m for m in _HEURISTIC_MARKERS if m.lower() in lowered]
        if hits and len(hits) >= max(1, round(len(_HEURISTIC_MARKERS) * _HEURISTIC_WEIGHT)):
            return hits[0]
        return None

    def _llm_check(self, text: str) -> Optional[str]:
        """Full LLM check via the independent judge.

        On dangerous: write the judge-extracted feature into the learned blacklist
        (self-learning is implicit whenever LLM detection is on).
        """
        if self._judge is None:
            return None
        result = self._judge.review(text)
        if result.get("allow") is False:
            feature = result.get("feature")
            if self._store is not None and feature:
                self._store.learn(feature)
            return feature or result.get("reason") or "input"
        return None
