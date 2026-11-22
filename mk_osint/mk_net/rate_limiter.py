"""Per-domain async rate limiter with jitter and dynamic Retry-After cooldowns."""

from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict
from typing import Dict
from urllib.parse import urlparse


class PerDomainRateLimiter:
    """Enforces polite request pacing per domain to avoid hammering target servers."""

    def __init__(
        self,
        base_delay_ms: float = 250.0,
        jitter_ms: float = 150.0,
    ) -> None:
        self.base_delay_s = max(0.0, base_delay_ms / 1000.0)
        self.jitter_s = max(0.0, jitter_ms / 1000.0)
        self._locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._next_allowed: Dict[str, float] = {}

    @staticmethod
    def extract_domain(url: str) -> str:
        parsed = urlparse(url)
        return (parsed.hostname or "unknown").lower()

    async def acquire(self, url: str) -> float:
        """Wait until the domain's next request window opens; returns actual sleep seconds."""
        domain = self.extract_domain(url)
        slept = 0.0
        async with self._locks[domain]:
            now = time.monotonic()
            next_ts = self._next_allowed.get(domain, 0.0)
            if next_ts > now:
                slept = next_ts - now
                await asyncio.sleep(slept)
                now = time.monotonic()
            jitter = random.uniform(0.0, self.jitter_s) if self.jitter_s > 0 else 0.0
            self._next_allowed[domain] = now + self.base_delay_s + jitter
        return slept

    def register_cooldown(self, url: str, seconds: float) -> None:
        """Push back the next allowed request window for a domain (e.g. after HTTP 429)."""
        domain = self.extract_domain(url)
        cooldown_until = time.monotonic() + max(0.0, seconds)
        current = self._next_allowed.get(domain, 0.0)
        if cooldown_until > current:
            self._next_allowed[domain] = cooldown_until
