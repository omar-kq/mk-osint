"""Standard, well-formed HTTP header profiles for MENA & global OSINT queries."""

from __future__ import annotations

import random
from typing import Dict, Optional


DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
]


class HeaderProfileBuilder:
    """Builds clean, standards-compliant HTTP headers with MENA locale support."""

    def __init__(self, prefer_arabic: bool = True) -> None:
        self.prefer_arabic = prefer_arabic

    def build(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        accept_lang = (
            "ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7"
            if self.prefer_arabic
            else "en-US,en;q=0.9,ar;q=0.7"
        )
        headers = {
            "User-Agent": random.choice(DEFAULT_USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": accept_lang,
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if extra:
            headers.update(extra)
        return headers
