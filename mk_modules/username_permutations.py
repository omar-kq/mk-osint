"""M.K Phase 11 — Auto-discovered Arabic/Franco Username Permutation Module."""

from __future__ import annotations

from typing import List

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule
from mk_intel.permutations import generate_username_permutations, has_arabic


class UsernamePermutationModule(BaseOSINTModule):
    """Generates MENA-tailored username variants (including Arabic -> Latin & Franco-Arab)."""

    metadata = ModuleMetadata(
        name="username_permutations",
        display_name="Arabic / Franco Username Permutations",
        version="1.0.0",
        description="Generates Latin & Franco-Arab handle variants for Arabic or English names/usernames.",
        supported_targets=[TargetType.USERNAME, TargetType.KEYWORD],
        category="permutations",
        requires_network=False,
        passive_only=True,
        enabled_by_default=False,  # Run on demand via `-m username_permutations`
    )

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        region = str(self.config.get("mena.default_region", "EG")).lower()
        variants = generate_username_permutations(target, region_code=region, max_variants=30)
        if not variants:
            return [
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="Permutation Generator",
                    target=target,
                    target_type=target_type,
                    status=ScanStatus.NOT_FOUND,
                    reason="No valid permutations generated",
                    category="permutations",
                )
            ]

        return [
            OSINTResult(
                module_name=self.metadata.name,
                source_name="MENA Handle Variants",
                target=target,
                target_type=target_type,
                status=ScanStatus.FOUND,
                category="permutations",
                extracted_data={
                    "contains_arabic": has_arabic(target),
                    "region_suffix": region,
                    "variant_count": len(variants),
                    "variants": variants,
                },
            )
        ]
