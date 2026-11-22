"""M.K v2.2 — Global Circuit Breaker & Anti-Crash Verification Guard.

Ensures that if any single domain, external tool, or search check triggers
CAPTCHA/human verification or repeated errors, M.K gracefully skips it
without ever causing a cascade failure across other modules.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict


class DomainCircuitBreaker:
    """Tracks consecutive blocks/errors per domain and trips safely when threshold is reached."""

    def __init__(self, failure_threshold: int = 3, cooldown_seconds: float = 60.0) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown_seconds = max(5.0, cooldown_seconds)
        self._failures: Dict[str, int] = defaultdict(int)
        self._open_until: Dict[str, float] = {}

    def is_open(self, key: str) -> bool:
        until = self._open_until.get(key.lower(), 0.0)
        if until > time.monotonic():
            return True
        if until > 0.0:
            self._open_until.pop(key.lower(), None)
            self._failures[key.lower()] = 0
        return False

    def record_success(self, key: str) -> None:
        k = key.lower()
        self._failures[k] = 0
        self._open_until.pop(k, None)

    def record_failure(self, key: str) -> bool:
        """Record a block/verification/error; returns True if circuit just tripped open."""
        k = key.lower()
        self._failures[k] += 1
        if self._failures[k] >= self.failure_threshold:
            self._open_until[k] = time.monotonic() + self.cooldown_seconds
            return True
        return False
