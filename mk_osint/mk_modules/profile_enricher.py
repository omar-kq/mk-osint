"""M.K v2.2 — Public Profile Enrichment, Google Lens Avatar Match, Bio Origin & Fake-Account Scorer.

Extracts public metadata (bio, avatar URL, followers/following/repos, account creation date)
from open public profiles (no login required), generates direct Google Lens & Yandex reverse
image links, generates Bio Origin search queries (for slogans/poems/cross-profile reuse),
and computes a heuristic Fake/Bot Authenticity Score.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule
from mk_net.circuit_breaker import DomainCircuitBreaker
from mk_net.client import HAS_HTTPX, MKAsyncClient


OG_IMAGE_RE = re.compile(r'<meta\s+property=["\']og:image["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE)
OG_DESC_RE = re.compile(r'<meta\s+property=["\']og:description["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE)
OG_TITLE_RE = re.compile(r'<meta\s+property=["\']og:title["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE)


def build_google_lens_url(image_url: str) -> str:
    return f"https://lens.google.com/uploadbyurl?url={quote_plus(image_url)}"


def build_yandex_reverse_url(image_url: str) -> str:
    return f"https://yandex.com/images/search?rpt=imageview&url={quote_plus(image_url)}"


def build_bio_origin_dork(bio_text: str) -> str:
    cleaned = " ".join(bio_text.strip().split())[:140]
    return f'https://www.google.com/search?q={quote_plus(chr(34) + cleaned + chr(34))}'


def compute_authenticity_score(
    has_avatar: bool,
    bio: str,
    followers: int = 0,
    following: int = 0,
    activity_count: int = 0,
) -> Dict[str, Any]:
    """Heuristic authenticity score (0-100) to flag likely fake/empty/bot accounts."""
    score = 20
    signals: List[str] = []

    if has_avatar:
        score += 20
    else:
        signals.append("No custom avatar")

    if bio and len(bio.strip()) >= 8:
        score += 20
    else:
        signals.append("Empty or minimal bio")

    if activity_count >= 3:
        score += 20
    elif activity_count == 0:
        signals.append("Zero public activity/posts")

    if followers >= 5:
        score += 20
    if following > 50 and followers <= 2:
        score -= 20
        signals.append("High following / near-zero followers ratio")

    clamped = max(0, min(100, score))
    verdict = "Likely Authentic" if clamped >= 65 else "Uncertain / Low Signal" if clamped >= 40 else "Possible Fake / Dormant"
    return {"authenticity_score": clamped, "verdict": verdict, "risk_signals": signals}


def parse_telegram_public_og(html_text: str) -> Dict[str, Optional[str]]:
    """Extract public title, bio, and avatar URL from a Telegram t.me page."""
    title_m = OG_TITLE_RE.search(html_text or "")
    desc_m = OG_DESC_RE.search(html_text or "")
    img_m = OG_IMAGE_RE.search(html_text or "")
    return {
        "title": title_m.group(1).strip() if title_m else None,
        "bio": desc_m.group(1).strip() if desc_m else None,
        "avatar_url": img_m.group(1).strip() if img_m else None,
    }


class PublicProfileEnricherModule(BaseOSINTModule):
    """Enriches public profiles with Bio Origin Dorks, Google Lens links, & Authenticity Score."""

    metadata = ModuleMetadata(
        name="profile_enricher",
        display_name="Public Profile Enricher (Bio Origin + Google Lens + Fake Score)",
        version="2.2.0",
        description="Extracts public bio, avatar URL, followers/activity (GitHub/Telegram), generates Google Lens & Bio Origin links, and computes Fake/Bot score.",
        supported_targets=[TargetType.USERNAME],
        category="enrichment",
        requires_network=True,
        passive_only=True,
        enabled_by_default=True,
    )

    def __init__(self, config, offline_only: bool = False) -> None:
        super().__init__(config)
        self.offline_only = offline_only
        self.breaker = DomainCircuitBreaker(failure_threshold=2, cooldown_seconds=60.0)

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        username = target.strip().lstrip("@")
        if self.offline_only or not HAS_HTTPX:
            return [
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="Profile Enricher (Offline Mode)",
                    target=username,
                    target_type=target_type,
                    status=ScanStatus.PASSIVE_DORK,
                    reason="Online fetch skipped in offline mode",
                    url=f"https://www.google.com/search?q=%22{quote_plus(username)}%22",
                    category="enrichment",
                )
            ]

        results: List[OSINTResult] = []
        async with MKAsyncClient(self.config) as client:
            # 1. GitHub Public Profile API (no login needed)
            if not self.breaker.is_open("api.github.com"):
                gh_resp = await client.fetch(
                    f"https://api.github.com/users/{quote_plus(username)}",
                    extra_headers={"Accept": "application/vnd.github+json"},
                )
                if gh_resp.status_code == 200:
                    self.breaker.record_success("api.github.com")
                    data = json.loads(gh_resp.text)
                    bio = (data.get("bio") or "").strip()
                    avatar = data.get("avatar_url") or ""
                    auth = compute_authenticity_score(
                        has_avatar=bool(avatar),
                        bio=bio,
                        followers=int(data.get("followers", 0)),
                        following=int(data.get("following", 0)),
                        activity_count=int(data.get("public_repos", 0)),
                    )
                    extracted: Dict[str, Any] = {
                        "name": data.get("name"),
                        "bio": bio,
                        "followers": data.get("followers", 0),
                        "following": data.get("following", 0),
                        "public_repos": data.get("public_repos", 0),
                        "created_at": data.get("created_at"),
                        "avatar_url": avatar,
                        **auth,
                    }
                    if avatar:
                        extracted["google_lens_url"] = build_google_lens_url(avatar)
                        extracted["yandex_reverse_url"] = build_yandex_reverse_url(avatar)
                    if bio:
                        extracted["bio_origin_dork"] = build_bio_origin_dork(bio)

                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="GitHub Public Profile",
                            target=username,
                            target_type=target_type,
                            status=ScanStatus.FOUND,
                            url=data.get("html_url"),
                            category="enrichment",
                            extracted_data=extracted,
                        )
                    )
                elif gh_resp.status_code in {403, 429}:
                    self.breaker.record_failure("api.github.com")
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="GitHub Public Profile",
                            target=username,
                            target_type=target_type,
                            status=ScanStatus.RATE_LIMITED,
                            reason=f"GitHub API Limit (HTTP {gh_resp.status_code}) — Skipped Safely",
                            category="enrichment",
                        )
                    )

            # 2. Telegram Public OG Profile (t.me)
            if not self.breaker.is_open("t.me"):
                tg_resp = await client.fetch(f"https://t.me/{quote_plus(username)}")
                if tg_resp.status_code == 200 and "tgme_page_title" in tg_resp.text:
                    self.breaker.record_success("t.me")
                    og = parse_telegram_public_og(tg_resp.text)
                    bio = og["bio"] or ""
                    avatar = og["avatar_url"] or ""
                    extracted = {
                        "display_name": og["title"],
                        "bio": bio,
                        "avatar_url": avatar,
                        **compute_authenticity_score(has_avatar=bool(avatar), bio=bio, activity_count=1),
                    }
                    if avatar:
                        extracted["google_lens_url"] = build_google_lens_url(avatar)
                        extracted["yandex_reverse_url"] = build_yandex_reverse_url(avatar)
                    if bio:
                        extracted["bio_origin_dork"] = build_bio_origin_dork(bio)
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="Telegram Public Profile",
                            target=username,
                            target_type=target_type,
                            status=ScanStatus.FOUND,
                            url=f"https://t.me/{username}",
                            category="enrichment",
                            extracted_data=extracted,
                        )
                    )

        return results
