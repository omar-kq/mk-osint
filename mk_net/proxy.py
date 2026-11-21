"""Proxy & Tor OPSEC configuration manager for M.K."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from mk_core.config import ConfigManager


SUPPORTED_SCHEMES = {"http", "https", "socks5", "socks5h"}


@dataclass(frozen=True)
class ProxyConfig:
    """Validated proxy endpoint configuration."""

    enabled: bool
    url: Optional[str] = None
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None

    @property
    def is_tor_default(self) -> bool:
        return bool(
            self.enabled
            and self.host in {"127.0.0.1", "localhost"}
            and self.port in {9050, 9150}
        )


class ProxyManager:
    """Validates and supplies SOCKS5 / Tor / HTTP proxy settings for researcher OPSEC."""

    def __init__(self, config: ConfigManager) -> None:
        self.config = config

    def get_proxy_config(self) -> ProxyConfig:
        enabled = bool(self.config.get("opsec.use_proxy", False))
        raw_url = self.config.get("opsec.proxy_url")
        if not enabled or not raw_url:
            return ProxyConfig(enabled=False)

        parsed = urlparse(str(raw_url).strip())
        scheme = (parsed.scheme or "").lower()
        if scheme not in SUPPORTED_SCHEMES:
            raise ValueError(
                f"Unsupported proxy scheme '{scheme}'. Expected one of {sorted(SUPPORTED_SCHEMES)}."
            )
        if not parsed.hostname or not parsed.port:
            raise ValueError(f"Invalid proxy URL '{raw_url}': missing host or port.")

        return ProxyConfig(
            enabled=True,
            url=str(raw_url).strip(),
            scheme=scheme,
            host=parsed.hostname,
            port=parsed.port,
        )

    def httpx_proxy_url(self) -> Optional[str]:
        cfg = self.get_proxy_config()
        return cfg.url if cfg.enabled else None
