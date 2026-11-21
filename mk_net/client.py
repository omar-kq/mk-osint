"""Unified asynchronous HTTP client for M.K with OPSEC, pacing, and retries."""

from __future__ import annotations

import asyncio
import inspect
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from mk_core.config import ConfigManager
from mk_core.models import OSINTResult, ScanStatus, TargetType
from mk_net.classifier import ResponseClassifier, SiteRule
from mk_net.headers import HeaderProfileBuilder
from mk_net.proxy import ProxyManager
from mk_net.rate_limiter import PerDomainRateLimiter

try:
    import httpx

    HAS_HTTPX = True
except ImportError:  # pragma: no cover
    HAS_HTTPX = False


@dataclass
class NetworkResponse:
    """Normalized HTTP response returned by MKAsyncClient."""

    url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    text: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error_reason: Optional[str] = None


class MKAsyncClient:
    """Polite, OPSEC-aware async HTTP client shared by all M.K network modules."""

    def __init__(self, config: ConfigManager) -> None:
        self.config = config
        self.proxy_manager = ProxyManager(config)
        self.headers_builder = HeaderProfileBuilder(prefer_arabic=True)
        self.rate_limiter = PerDomainRateLimiter(
            base_delay_ms=float(config.get("opsec.rate_limit_delay_ms", 250)),
            jitter_ms=float(config.get("opsec.jitter_ms", 150)),
        )
        self.timeout_s = float(config.get("opsec.timeout_seconds", 12.0))
        self.max_retries = int(config.get("opsec.max_retries", 2))
        self.respect_retry_after = bool(config.get("opsec.respect_retry_after", True))
        self._client: Any = None

    async def __aenter__(self) -> "MKAsyncClient":
        if not HAS_HTTPX:
            raise RuntimeError(
                "httpx is not installed. Run: pip install -r requirements_phase2.txt"
            )
        proxy_url = self.proxy_manager.httpx_proxy_url()
        client_kwargs: Dict[str, Any] = {
            "timeout": httpx.Timeout(self.timeout_s),
            "follow_redirects": True,
            "verify": True,
        }
        if proxy_url:
            # Compatible with both httpx >=0.26 ('proxy') and older Debian/Kali httpx ('proxies')
            sig = inspect.signature(httpx.AsyncClient.__init__)
            if "proxy" in sig.parameters:
                client_kwargs["proxy"] = proxy_url
            else:
                client_kwargs["proxies"] = proxy_url

        self._client = httpx.AsyncClient(**client_kwargs)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> NetworkResponse:
        """Execute a rate-limited request with clean exponential backoff & error labels."""
        if self._client is None:
            raise RuntimeError("MKAsyncClient must be used inside 'async with'.")

        attempt = 0
        while True:
            attempt += 1
            await self.rate_limiter.acquire(url)
            headers = self.headers_builder.build(extra_headers)
            t0 = time.perf_counter()

            try:
                resp = await self._client.request(method.upper(), url, headers=headers)
                elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                resp_headers = {k: v for k, v in resp.headers.items()}

                if resp.status_code == 429 and attempt <= self.max_retries:
                    retry_s = self._parse_retry_after(resp_headers.get("retry-after"), attempt)
                    self.rate_limiter.register_cooldown(url, retry_s)
                    if self.respect_retry_after and retry_s <= 15.0:
                        await asyncio.sleep(retry_s)
                        continue

                if 500 <= resp.status_code <= 599 and attempt <= self.max_retries:
                    await asyncio.sleep(min(4.0, 0.75 * (2 ** (attempt - 1))))
                    continue

                return NetworkResponse(
                    url=url,
                    final_url=str(resp.url),
                    status_code=resp.status_code,
                    text=resp.text[:65536],
                    headers=resp_headers,
                    elapsed_ms=elapsed_ms,
                )

            except Exception as exc:  # noqa: BLE001
                elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                reason = self._classify_exception(exc)
                if attempt <= self.max_retries and "Timeout" in reason:
                    await asyncio.sleep(min(3.0, 0.5 * attempt))
                    continue
                return NetworkResponse(
                    url=url,
                    elapsed_ms=elapsed_ms,
                    error_reason=reason,
                )

    async def probe_site(
        self,
        module_name: str,
        rule: SiteRule,
        target: str,
        target_type: TargetType,
    ) -> OSINTResult:
        """Probe a single SiteRule and return a fully classified OSINTResult."""
        target_url = rule.url_template.format(target=target)
        if rule.detection_mode == "passive_dork":
            status, reason = ResponseClassifier.classify(rule, status_code=None)
            return OSINTResult(
                module_name=module_name,
                source_name=rule.name,
                target=target,
                target_type=target_type,
                status=status,
                reason=reason,
                url=target_url,
                category=rule.category,
            )

        net_resp = await self.fetch(target_url)
        status, reason = ResponseClassifier.classify(
            rule=rule,
            status_code=net_resp.status_code,
            body_text=net_resp.text,
            headers=net_resp.headers,
            final_url=net_resp.final_url,
            error_reason=net_resp.error_reason,
        )
        return OSINTResult(
            module_name=module_name,
            source_name=rule.name,
            target=target,
            target_type=target_type,
            status=status,
            reason=reason,
            url=net_resp.final_url or target_url,
            category=rule.category,
            http_status=net_resp.status_code,
            response_time_ms=net_resp.elapsed_ms,
        )

    @staticmethod
    def _parse_retry_after(raw: Optional[str], attempt: int) -> float:
        if raw and raw.strip().isdigit():
            return float(raw.strip())
        return float(min(10, 2 ** attempt))

    @staticmethod
    def _classify_exception(exc: Exception) -> str:
        name = type(exc).__name__
        msg = str(exc).lower()
        if "timeout" in name.lower() or "timed out" in msg:
            return f"Timeout ({name})"
        if "ssl" in name.lower() or "certificate" in msg:
            return "SSL Certificate Error"
        if "dns" in msg or "name or service not known" in msg or "getaddrinfo" in msg:
            return "DNS Resolution Failed"
        if "proxy" in name.lower() or "socks" in msg:
            return "Proxy Connection Failed"
        if "connect" in name.lower():
            return "Connection Refused/Reset"
        return f"{name}"
