"""M.K v2.3 — MENA + Global Asynchronous Username OSINT Module (With Auto Avatar & Bio Extraction)."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional, Sequence
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
OG_IMAGE_RE = re.compile(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
OG_DESC_RE = re.compile(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)


def extract_bio_links(html_text: str, limit: int = 12) -> List[str]:
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


def extract_public_avatar_and_bio(html_text: str) -> Dict[str, Any]:
    """Extract public og:image (avatar) + Google Lens link + og:description (bio) from FOUND pages."""
    out: Dict[str, Any] = {}
    if not html_text:
        return out
    img_m = OG_IMAGE_RE.search(html_text)
    if img_m:
        img_url = img_m.group(1).strip()
        if img_url.startswith("http"):
            out["avatar_url"] = img_url
            out["google_lens"] = f"https://lens.google.com/uploadbyurl?url={quote_plus(img_url)}"
    desc_m = OG_DESC_RE.search(html_text)
    if desc_m:
        bio = " ".join(desc_m.group(1).strip().split())[:160]
        if bio:
            out["bio"] = bio
    return out


class UsernameMENAModule(BaseOSINTModule):
    """High-speed MENA-prioritized username OSINT scanner with auto Avatar/Bio/Google Lens extraction."""

    metadata = ModuleMetadata(
        name="username_mena",
        display_name="MENA + Global Username Engine (15 Categories)",
        version="2.3.0",
        description="Checks usernames across 165+ MENA & global platforms with anti-false-positive verification and auto Avatar/Google Lens/Bio extraction.",
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
        include_opt = bool(self.config.get("mena.enable_optional_academic_gov_dorks", False))
        rules = catalog.filter(
            categories=self.categories,
            include_optional_academic_gov=include_opt,
            passive_only=self.passive_only,
        )

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
                    reason="httpx[socks] not installed",
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
                        target=username,
                    )
                    extracted: Dict[str, Any] = {}
                    if status == ScanStatus.FOUND:
                        extracted.update(extract_public_avatar_and_bio(net_resp.text))
                        if rule.category == SiteCategory.LINK_IN_BIO.value:
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
