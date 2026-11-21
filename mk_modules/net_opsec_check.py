"""Phase 2 OPSEC & Network Readiness diagnostic module for M.K."""

from __future__ import annotations

from typing import List

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule
from mk_net.client import HAS_HTTPX
from mk_net.proxy import ProxyManager


class NetOPSECCheckModule(BaseOSINTModule):
    """Audits M.K's local OPSEC posture (proxy/Tor config, rate-limit, httpx availability)."""

    metadata = ModuleMetadata(
        name="net_opsec_check",
        display_name="Network & OPSEC Posture Check",
        version="1.0.0",
        description="Verifies proxy/Tor configuration, per-domain rate limits, and async HTTP engine readiness.",
        supported_targets=[
            TargetType.USERNAME,
            TargetType.EMAIL,
            TargetType.PHONE,
            TargetType.DOMAIN,
            TargetType.IP,
        ],
        category="opsec",
        requires_network=False,
        passive_only=True,
        enabled_by_default=False,  # Run on demand via `-m net_opsec_check`
    )

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        pm = ProxyManager(self.config)
        results: List[OSINTResult] = []

        try:
            proxy_cfg = pm.get_proxy_config()
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="Proxy / Tor Routing",
                    target=target,
                    target_type=target_type,
                    status=ScanStatus.FOUND,
                    category="opsec",
                    extracted_data={
                        "proxy_enabled": proxy_cfg.enabled,
                        "proxy_url": proxy_cfg.url or "DIRECT",
                        "is_tor_default": proxy_cfg.is_tor_default,
                        "rate_limit_ms": self.config.get("opsec.rate_limit_delay_ms"),
                        "jitter_ms": self.config.get("opsec.jitter_ms"),
                    },
                )
            )
        except ValueError as exc:
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="Proxy / Tor Routing",
                    target=target,
                    target_type=target_type,
                    status=ScanStatus.ERROR,
                    reason=str(exc),
                    category="opsec",
                )
            )

        results.append(
            OSINTResult(
                module_name=self.metadata.name,
                source_name="Async HTTP Engine (httpx)",
                target=target,
                target_type=target_type,
                status=ScanStatus.FOUND if HAS_HTTPX else ScanStatus.ERROR,
                reason=None if HAS_HTTPX else "Missing httpx[socks] - run pip install -r requirements_phase2.txt",
                category="opsec",
            )
        )
        return results
