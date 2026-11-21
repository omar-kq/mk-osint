"""M.K Phase 5 — Email OSINT Intelligence Module.

Capabilities:
  1. Syntax validation, Gmail canonicalization, & candidate username extraction.
  2. Disposable (including Arabic Mohmal), Webmail, Corporate, & MENA TLD profiling.
  3. DNS MX / SPF / DMARC record inspection (via dnspython when installed).
  4. Gravatar public profile lookup via MD5 hash.
  5. GitHub public user search API lookup.
  6. Optional official HaveIBeenPwned v3 API check (if HIBP_API_KEY env var is set).
  7. Passive public search dorks for email mentions without triggering IP bans.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule
from mk_data.email_intel_data import (
    DISPOSABLE_DOMAINS,
    FREE_WEBMAIL_PROVIDERS,
    MENA_COUNTRY_TLDS,
)
from mk_net.client import HAS_HTTPX, MKAsyncClient

try:
    import dns.resolver  # type: ignore

    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover
    HAS_DNSPYTHON = False


EMAIL_STRICT_RE = re.compile(
    r"^(?P<local>[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64})@(?P<domain>[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)$"
)


def parse_and_profile_email(email: str) -> Dict[str, Any]:
    """Perform offline structural analysis, canonicalization, and username candidate extraction."""
    cleaned = email.strip().lower()
    match = EMAIL_STRICT_RE.match(cleaned)
    if not match:
        return {"valid": False, "normalized": cleaned}

    local = match.group("local")
    domain = match.group("domain")

    # Canonicalize Gmail dot/plus aliases
    canonical_local = local
    if domain in {"gmail.com", "googlemail.com"}:
        canonical_local = local.split("+", 1)[0].replace(".", "")
    elif "+" in local:
        canonical_local = local.split("+", 1)[0]

    # Classify domain type
    if domain in DISPOSABLE_DOMAINS:
        provider_type = "disposable"
    elif domain in FREE_WEBMAIL_PROVIDERS:
        provider_type = "free_webmail"
    else:
        provider_type = "corporate_or_custom"

    # Detect MENA country TLD
    mena_country: Optional[str] = None
    for tld, country_name in MENA_COUNTRY_TLDS.items():
        if domain.endswith(tld):
            mena_country = country_name
            break

    # Extract candidate usernames for cross-module correlation (Phase 9)
    candidates = []
    for variant in (
        local.split("+", 1)[0],
        canonical_local,
        local.split("+", 1)[0].replace(".", "_"),
        local.split("+", 1)[0].replace(".", ""),
    ):
        if variant and variant not in candidates:
            candidates.append(variant)

    md5_hash = hashlib.md5(cleaned.encode("utf-8")).hexdigest()
    return {
        "valid": True,
        "normalized": cleaned,
        "canonical_email": f"{canonical_local}@{domain}",
        "local_part": local,
        "domain": domain,
        "provider_type": provider_type,
        "is_disposable": provider_type == "disposable",
        "mena_country": mena_country,
        "gravatar_md5": md5_hash,
        "candidate_usernames": candidates,
    }


def _query_dns_records_sync(domain: str) -> Tuple[List[str], Optional[str], Optional[str], Optional[str]]:
    """Query MX, SPF, and DMARC records via dnspython (run in worker thread)."""
    if not HAS_DNSPYTHON:
        return [], None, None, "dnspython not installed (run pip install -r requirements_phase5.txt)"

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6.0
    mx_hosts: List[str] = []
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None

    try:
        for rdata in resolver.resolve(domain, "MX"):
            mx_hosts.append(str(rdata.exchange).rstrip("."))
    except Exception as exc:  # noqa: BLE001
        return [], None, None, f"MX Lookup Failed ({type(exc).__name__})"

    try:
        for rdata in resolver.resolve(domain, "TXT"):
            txt = "".join(
                part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                for part in getattr(rdata, "strings", [str(rdata)])
            )
            if txt.lower().startswith("v=spf1"):
                spf_record = txt
                break
    except Exception:  # noqa: BLE001
        pass

    try:
        for rdata in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt = "".join(
                part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                for part in getattr(rdata, "strings", [str(rdata)])
            )
            if txt.lower().startswith("v=dmarc1"):
                dmarc_record = txt
                break
    except Exception:  # noqa: BLE001
        pass

    return mx_hosts, spf_record, dmarc_record, None


class EmailOSINTModule(BaseOSINTModule):
    """Comprehensive public Email OSINT module (DNS, Gravatar, GitHub, official HIBP, Dorks)."""

    metadata = ModuleMetadata(
        name="email_osint",
        display_name="Email OSINT Intelligence",
        version="1.0.0",
        description="Profiles emails (disposable/MENA TLD/username candidates), checks DNS MX/SPF/DMARC, Gravatar, GitHub, optional HIBP API, and passive dorks.",
        supported_targets=[TargetType.EMAIL],
        category="email",
        requires_network=True,
        passive_only=False,
        enabled_by_default=True,
    )

    def __init__(self, config, offline_only: bool = False) -> None:
        super().__init__(config)
        self.offline_only = offline_only

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        profile = parse_and_profile_email(target)
        if not profile["valid"]:
            return [
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="Email Syntax Validator",
                    target=target,
                    target_type=target_type,
                    status=ScanStatus.ERROR,
                    reason="Invalid email syntax",
                    category="email",
                )
            ]

        email = profile["normalized"]
        domain = profile["domain"]
        md5_hash = profile["gravatar_md5"]
        results: List[OSINTResult] = [
            OSINTResult(
                module_name=self.metadata.name,
                source_name="Email Structural Profile",
                target=email,
                target_type=target_type,
                status=ScanStatus.FOUND,
                category="email",
                extracted_data={
                    "canonical": profile["canonical_email"],
                    "provider_type": profile["provider_type"],
                    "is_disposable": profile["is_disposable"],
                    "mena_country": profile["mena_country"] or "Global/Unspecified",
                    "candidate_usernames": profile["candidate_usernames"],
                },
            )
        ]

        # Passive search dorks (always generated, zero IP ban risk)
        enc = quote_plus(email)
        dorks = [
            ("Google Public Mentions", f"https://www.google.com/search?q=%22{enc}%22"),
            (
                "Public Docs & CVs (PDF/DOC)",
                f"https://www.google.com/search?q=%22{enc}%22+(filetype:pdf+OR+filetype:docx+OR+filetype:txt)",
            ),
            (
                "GitHub / Pastebin Public Mentions",
                f"https://www.google.com/search?q=(site:github.com+OR+site:pastebin.com)+%22{enc}%22",
            ),
        ]
        for label, dork_url in dorks:
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name=label,
                    target=email,
                    target_type=target_type,
                    status=ScanStatus.PASSIVE_DORK,
                    reason="Passive Search Query Ready",
                    url=dork_url,
                    category="email",
                )
            )

        if self.offline_only:
            return results

        # DNS MX / SPF / DMARC check
        mx_hosts, spf_rec, dmarc_rec, dns_err = await asyncio.to_thread(
            _query_dns_records_sync, domain
        )
        if dns_err:
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="DNS MX / SPF / DMARC",
                    target=email,
                    target_type=target_type,
                    status=ScanStatus.ERROR,
                    reason=dns_err,
                    category="email",
                )
            )
        else:
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="DNS MX / SPF / DMARC",
                    target=email,
                    target_type=target_type,
                    status=ScanStatus.FOUND if mx_hosts else ScanStatus.NOT_FOUND,
                    reason=None if mx_hosts else "No MX records found",
                    category="email",
                    extracted_data={
                        "mx_hosts": mx_hosts[:5],
                        "has_spf": bool(spf_rec),
                        "has_dmarc": bool(dmarc_rec),
                    },
                )
            )

        if not HAS_HTTPX:
            return results

        async with MKAsyncClient(self.config) as client:
            # 1. Gravatar public profile JSON
            grav_url = f"https://www.gravatar.com/{md5_hash}.json"
            grav_resp = await client.fetch(grav_url)
            if grav_resp.error_reason:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="Gravatar",
                        target=email,
                        target_type=target_type,
                        status=ScanStatus.ERROR,
                        reason=grav_resp.error_reason,
                        url=grav_url,
                        category="email",
                    )
                )
            elif grav_resp.status_code == 200:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="Gravatar",
                        target=email,
                        target_type=target_type,
                        status=ScanStatus.FOUND,
                        url=f"https://gravatar.com/{md5_hash}",
                        category="email",
                        http_status=200,
                        response_time_ms=grav_resp.elapsed_ms,
                    )
                )
            elif grav_resp.status_code == 404:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="Gravatar",
                        target=email,
                        target_type=target_type,
                        status=ScanStatus.NOT_FOUND,
                        category="email",
                        http_status=404,
                    )
                )
            else:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="Gravatar",
                        target=email,
                        target_type=target_type,
                        status=ScanStatus.BLOCKED if grav_resp.status_code == 403 else ScanStatus.ERROR,
                        reason=f"HTTP {grav_resp.status_code}",
                        category="email",
                    )
                )

            # 2. GitHub public user search API
            gh_url = f"https://api.github.com/search/users?q={quote_plus(email)}+in:email"
            gh_resp = await client.fetch(
                gh_url, extra_headers={"Accept": "application/vnd.github+json"}
            )
            if gh_resp.error_reason:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="GitHub Public API",
                        target=email,
                        target_type=target_type,
                        status=ScanStatus.ERROR,
                        reason=gh_resp.error_reason,
                        category="email",
                    )
                )
            elif gh_resp.status_code == 403 or gh_resp.status_code == 429:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="GitHub Public API",
                        target=email,
                        target_type=target_type,
                        status=ScanStatus.RATE_LIMITED,
                        reason=f"GitHub API Limit (HTTP {gh_resp.status_code})",
                        category="email",
                    )
                )
            elif gh_resp.status_code == 200 and '"total_count": 0' not in gh_resp.text and '"total_count":0' not in gh_resp.text:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="GitHub Public API",
                        target=email,
                        target_type=target_type,
                        status=ScanStatus.FOUND,
                        url=f"https://github.com/search?q={quote_plus(email)}&type=users",
                        category="email",
                        http_status=200,
                    )
                )
            else:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="GitHub Public API",
                        target=email,
                        target_type=target_type,
                        status=ScanStatus.NOT_FOUND,
                        category="email",
                        http_status=gh_resp.status_code,
                    )
                )

            # 3. Official HaveIBeenPwned v3 API (only when user supplies HIBP_API_KEY)
            hibp_key = os.getenv("HIBP_API_KEY")
            if hibp_key:
                hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}?truncateResponse=true"
                hibp_resp = await client.fetch(
                    hibp_url,
                    extra_headers={"hibp-api-key": hibp_key, "user-agent": "MK-OSINT-Framework"},
                )
                if hibp_resp.status_code == 200:
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="HaveIBeenPwned (Official API)",
                            target=email,
                            target_type=target_type,
                            status=ScanStatus.FOUND,
                            url="https://haveibeenpwned.com/",
                            category="email",
                            extracted_data={"breach_summary_raw": hibp_resp.text[:500]},
                        )
                    )
                elif hibp_resp.status_code == 404:
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="HaveIBeenPwned (Official API)",
                            target=email,
                            target_type=target_type,
                            status=ScanStatus.NOT_FOUND,
                            category="email",
                        )
                    )
                else:
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="HaveIBeenPwned (Official API)",
                            target=email,
                            target_type=target_type,
                            status=ScanStatus.RATE_LIMITED if hibp_resp.status_code == 429 else ScanStatus.ERROR,
                            reason=hibp_resp.error_reason or f"HTTP {hibp_resp.status_code}",
                            category="email",
                        )
                    )

        return results
