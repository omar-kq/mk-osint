"""M.K Phase 9 — Auto-discovered MENA Bilingual Dork Builder Module."""

from __future__ import annotations

from typing import List

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule
from mk_intel.dork_builder import MENADorkBuilder


class MENADorksModule(BaseOSINTModule):
    """Generates a structured pack of passive MENA search queries for any target."""

    metadata = ModuleMetadata(
        name="mena_dorks",
        display_name="MENA Bilingual Dork Builder",
        version="1.0.0",
        description="Builds targeted passive search queries across Google, Bing, and Yandex for MENA platforms and public documents.",
        supported_targets=[
            TargetType.USERNAME,
            TargetType.EMAIL,
            TargetType.PHONE,
            TargetType.DOMAIN,
            TargetType.KEYWORD,
        ],
        category="dorks",
        requires_network=False,
        passive_only=True,
        enabled_by_default=False,  # Run on demand via `-m mena_dorks`
    )

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        include_opt = bool(
            self.config.get("mena.enable_optional_academic_gov_dorks", False)
        )
        dorks = MENADorkBuilder.build_for_target(
            target, include_optional_academic_gov=include_opt
        )
        return [
            OSINTResult(
                module_name=self.metadata.name,
                source_name=f"[{d.engine.upper()}] {d.title}",
                target=target,
                target_type=target_type,
                status=ScanStatus.PASSIVE_DORK,
                reason="Passive Dork Ready",
                url=d.url,
                category=d.category,
                extracted_data={"query": d.query, "engine": d.engine},
            )
            for d in dorks
        ]
