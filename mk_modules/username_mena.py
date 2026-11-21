"""M.K Phase 4 — MENA + Global Asynchronous Username OSINT Module.

Features:
  - Scans across 115+ MENA & global platforms organized in 15 categories.
  - Uses Phase 2's MKAsyncClient (per-domain rate limiting, proxy/Tor OPSEC,
    and 6-state classification: FOUND / NOT_FOUND / BLOCKED (reason) /
    RATE_LIMITED (reason) / ERROR (reason) / PASSIVE_DORK).
  - Extracts outbound social links automatically from discovered Link-in-Bio pages.
  - Keeps Category 15 (Academic / Public Gov Dorks) strictly opt-in via config.
"""

from __future__ import annotations

import asyncio
import re
from typing import List, Optional, Sequence
from urllib.parse import quote_plus

from mk_core.models import (
    ModuleMetadata,
    OSINTResult,
    ScanStatus,
    SiteCategory,
    TargetType,
)
from mk_core.registry import BaseOSINTModule
from mk_data.site_loader import load_mena_sites
from mk_net.classifier import ResponseClassifier, SiteRule
from mk_net.client import HAS_HTTPX, MKAsyncClient


OUTBOUND_LINK_RE = re.compile(
    r'https?://(?:www\.)?(?:t\.me|instagram\.com|facebook\.com|x\.com|twitter\.com|'
    r'tiktok\.com|youtube\.com|github\.com|linkedin\.com|snapchat\.com|khamsat\.com|'
    r'mostaql\.com|behance\.net|soundcloud\.com|kick\.com|twitch\.tv)/[^\s"\'<>]{2,120}',
    re.IGNORECASE,
)


def extract_bio_links(html_text: str, limit: int = 12) -> List[str]:
    """Extract unique public social/portfolio URLs from a Link-in-Bio HTML page."""
    if not html_text:
        return []
    seen = set()
    links: List[str] = []
    for match in OUTBOUND_LINK_RE.findall(html_text):
        cleaned = match.rstrip(".,;)")
        if cleaned not in seen:
            seen.add(cleaned)
            links.append(cleaned)
            if len(links) >= limit:
                break
    return links


class UsernameMENAModule(BaseOSINTModule):
    """High-speed MENA-prioritized username OSINT scanner across 15 categories."""

    metadata = ModuleMetadata(
        name="username_mena",
        display_name="MENA + Global Username Engine (15 Categories)",
        version="1.0.0",
        description="Checks usernames across 115+ MENA & global platforms with 6-state status classification and Link-in-Bio extraction.",
        supported_targets=[TargetType.USERNAME],
        category="username",
        requires_network=True,
        passive_only=False,
        enabled_by_default=True,
    )

    def __init__(
        self,
        config,
        categories: Optional[Sequence[str]] = None,
        passive_only: bool = False,
    ) -> None:
        super().__init__(config)
        self.categories = categories
        self.passive_only = passive_only

    @staticmethod
    def sanitize_username(raw: str) -> str:
        return raw.strip().lstrip("@")

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        username = self.sanitize_username(target)
        catalog = load_mena_sites(self.config)
        include_opt = bool(
            self.config.get("mena.enable_optional_academic_gov_dorks", False)
        )
        rules = catalog.filter(
            categories=self.categories,
            include_optional_academic_gov=include_opt,
            passive_only=self.passive_only,
        )

        # Separate passive dorks (zero network calls) from active HTTP probes
        passive_rules = [r for r in rules if r.detection_mode == "passive_dork"]
        active_rules = [r for r in rules if r.detection_mode != "passive_dork"]

        results: List[OSINTResult] = []
        encoded = quote_plus(username)
        for rule in passive_rules:
            url = rule.url_template.format(target=encoded)
            status, reason = ResponseClassifier.classify(rule, status_code=None)
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name=rule.name,
                    target=username,
                    target_type=target_type,
                    status=status,
                    reason=reason,
                    url=url,
                    category=rule.category,
                )
            )

        if not active_rules:
            return results

        if not HAS_HTTPX:
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="HTTPX Engine Check",
                    target=username,
                    target_type=target_type,
                    status=ScanStatus.ERROR,
                    reason="httpx[socks] not installed - only passive dorks generated",
                    category="system",
                )
            )
            return results

        max_conc = int(self.config.get("app.max_concurrency", 15))
        sem = asyncio.Semaphore(max(1, max_conc))

        async with MKAsyncClient(self.config) as client:
            async def _probe(rule: SiteRule) -> OSINTResult:
                async with sem:
                    url = rule.url_template.format(target=username)
                    net_resp = await client.fetch(url)
                    status, reason = ResponseClassifier.classify(
                        rule=rule,
                        status_code=net_resp.status_code,
                        body_text=net_resp.text,
                        headers=net_resp.headers,
                        final_url=net_resp.final_url,
                        error_reason=net_resp.error_reason,
                    )
                    extracted = {}
                    if (
                        status == ScanStatus.FOUND
                        and rule.category == SiteCategory.LINK_IN_BIO.value
                    ):
                        bio_links = extract_bio_links(net_resp.text)
                        if bio_links:
                            extracted["linked_accounts"] = bio_links

                    return OSINTResult(
                        module_name=self.metadata.name,
                        source_name=rule.name,
                        target=username,
                        target_type=target_type,
                        status=status,
                        reason=reason,
                        url=net_resp.final_url or url,
                        category=rule.category,
                        http_status=net_resp.status_code,
                        response_time_ms=net_resp.elapsed_ms,
                        extracted_data=extracted,
                    )

            probed = await asyncio.gather(*(_probe(r) for r in active_rules))
            results.extend(probed)

        return results
