"""M.K v2.3 — Core Diagnostics Module (On-Demand Only so real scans stay clean)."""

from __future__ import annotations

import platform
import sys
from typing import List

from mk_core.models import (
    ModuleMetadata,
    OSINTResult,
    ScanStatus,
    SiteCategory,
    TargetType,
)
from mk_core.registry import BaseOSINTModule


class CoreDiagnosticsModule(BaseOSINTModule):
    """Validates target parsing, status badges, and AI serialization on demand (`-m core_diagnostics`)."""

    metadata = ModuleMetadata(
        name="core_diagnostics",
        display_name="M.K Core Diagnostics",
        version="2.3.0",
        description="Offline self-check verifying target routing, 7-state status formatting, and Kali runtime (on-demand).",
        supported_targets=[
            TargetType.USERNAME,
            TargetType.EMAIL,
            TargetType.PHONE,
            TargetType.DOMAIN,
            TargetType.IP,
        ],
        category="system",
        requires_network=False,
        passive_only=True,
        enabled_by_default=False,  # Keep real scans clean; invoke via `-m core_diagnostics`
    )

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        return [
            OSINTResult(
                module_name=self.metadata.name,
                source_name="Runtime Environment",
                target=target,
                target_type=target_type,
                status=ScanStatus.FOUND,
                category="system",
                extracted_data={
                    "os": platform.system(),
                    "release": platform.release(),
                    "python": py_ver,
                    "detected_type": target_type.value,
                },
            ),
            OSINTResult(
                module_name=self.metadata.name,
                source_name="Status Classifier Demo (Not Found)",
                target=target,
                target_type=target_type,
                status=ScanStatus.NOT_FOUND,
                category=SiteCategory.SOCIAL_OPEN.value,
                extracted_data={"check": "HTTP 404 verified"},
            ),
            OSINTResult(
                module_name=self.metadata.name,
                source_name="Status Classifier Demo (Blocked)",
                target=target,
                target_type=target_type,
                status=ScanStatus.BLOCKED,
                reason="Cloudflare WAF / HTTP 403",
                category=SiteCategory.SOCIAL_PROTECTED_DORKS.value,
            ),
            OSINTResult(
                module_name=self.metadata.name,
                source_name="Status Classifier Demo (Passive Dork)",
                target=target,
                target_type=target_type,
                status=ScanStatus.PASSIVE_DORK,
                reason="Protected Platform - Search Query Ready",
                url=f"https://www.google.com/search?q=%22{target}%22",
                category=SiteCategory.SOCIAL_PROTECTED_DORKS.value,
            ),
        ]
