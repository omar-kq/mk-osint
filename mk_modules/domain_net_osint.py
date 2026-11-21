"""M.K Phase 7 — Passive Domain, DNS, RDAP/WHOIS, Certificate Transparency & IP/ASN OSINT.

Capabilities:
  1. Domain normalization, Arabic IDN/Punycode decoding, & MENA TLD detection.
  2. IPv4/IPv6 classification (Public vs Private/RFC1918/Loopback/Reserved).
  3. DNS records lookup (A, AAAA, MX, NS, TXT via dnspython or socket fallback).
  4. Passive RDAP (modern JSON WHOIS) for domains & IPs via MKAsyncClient.
  5. Passive Certificate Transparency subdomain discovery via crt.sh.
  6. Passive infrastructure links (Shodan, Censys, VirusTotal, Wayback Machine).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule
from mk_data.email_intel_data import MENA_COUNTRY_TLDS
from mk_net.client import HAS_HTTPX, MKAsyncClient

try:
    import dns.resolver  # type: ignore

    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover
    HAS_DNSPYTHON = False


def normalize_domain(raw: str) -> str:
    """Strip scheme/path/port and return lowercase hostname."""
    text = raw.strip().lower()
    if "://" in text:
        text = urlparse(text).hostname or text
    else:
        text = text.split("/", 1)[0].split(":", 1)[0]
    return text.rstrip(".")


def decode_idn_domain(domain: str) -> str:
    """Decode punycode domains (e.g. Arabic IDNs starting with xn--) to Unicode."""
    try:
        return domain.encode("ascii").decode("idna")
    except Exception:  # noqa: BLE001
        return domain


def classify_ip_address(raw_ip: str) -> Dict[str, Any]:
    """Validate and classify an IPv4 or IPv6 address offline."""
    try:
        ip_obj = ipaddress.ip_address(raw_ip.strip())
    except ValueError:
        return {"valid": False, "reason": "Invalid IPv4/IPv6 address"}

    return {
        "valid": True,
        "ip": str(ip_obj),
        "version": ip_obj.version,
        "is_global": ip_obj.is_global,
        "is_private": ip_obj.is_private,
        "is_loopback": ip_obj.is_loopback,
        "is_reserved": ip_obj.is_reserved,
    }


def parse_crtsh_subdomains(raw_json: str, root_domain: str, limit: int = 50) -> List[str]:
    """Extract unique, cleaned subdomains from a crt.sh JSON response."""
    try:
        entries = json.loads(raw_json)
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(entries, list):
        return []

    found: Set[str] = set()
    suffix = root_domain.lower()
    for item in entries:
        name_val = str(item.get("name_value", ""))
        for line in name_val.splitlines():
            host = line.strip().lower().lstrip("*.")
            if host and (host == suffix or host.endswith(f".{suffix}")):
                found.add(host)
                if len(found) >= limit:
                    return sorted(found)
    return sorted(found)


def _dns_lookup_sync(domain: str) -> Dict[str, List[str]]:
    records: Dict[str, List[str]] = {}
    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6.0
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                ans = resolver.resolve(domain, rtype)
                records[rtype] = [str(r).strip('"') for r in ans][:10]
            except Exception:  # noqa: BLE001
                continue
    else:
        try:
            infos = socket.getaddrinfo(domain, None)
            ips = sorted({info[4][0] for info in infos})
            if ips:
                records["A/AAAA"] = ips
        except Exception:  # noqa: BLE001
            pass
    return records


class DomainNetOSINTModule(BaseOSINTModule):
    """Passive Domain, DNS, RDAP/WHOIS, crt.sh, and IP/ASN OSINT module."""

    metadata = ModuleMetadata(
        name="domain_net_osint",
        display_name="Domain, DNS, RDAP & IP/ASN Passive Recon",
        version="1.0.0",
        description="Performs passive DNS, RDAP/WHOIS, crt.sh subdomain discovery, IDN/MENA TLD analysis, and IP/ASN lookup.",
        supported_targets=[TargetType.DOMAIN, TargetType.IP],
        category="network_infra",
        requires_network=True,
        passive_only=True,
        enabled_by_default=True,
    )

    def __init__(self, config, offline_only: bool = False) -> None:
        super().__init__(config)
        self.offline_only = offline_only

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        if target_type == TargetType.IP:
            return await self._run_ip(target)
        return await self._run_domain(target)

    async def _run_ip(self, raw_ip: str) -> List[OSINTResult]:
        info = classify_ip_address(raw_ip)
        if not info["valid"]:
            return [
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="IP Validator",
                    target=raw_ip,
                    target_type=TargetType.IP,
                    status=ScanStatus.ERROR,
                    reason=str(info["reason"]),
                    category="network_infra",
                )
            ]

        ip_str = info["ip"]
        results: List[OSINTResult] = [
            OSINTResult(
                module_name=self.metadata.name,
                source_name="IP Classification",
                target=ip_str,
                target_type=TargetType.IP,
                status=ScanStatus.FOUND,
                category="network_infra",
                extracted_data=info,
            )
        ]

        # Passive reference portals
        for label, url in (
            ("Shodan Host Profile", f"https://www.shodan.io/host/{ip_str}"),
            ("Censys Host Profile", f"https://search.censys.io/hosts/{ip_str}"),
            ("VirusTotal IP Intel", f"https://www.virustotal.com/gui/ip-address/{ip_str}"),
            ("BGPView ASN / Prefix", f"https://bgpview.io/ip/{ip_str}"),
        ):
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name=label,
                    target=ip_str,
                    target_type=TargetType.IP,
                    status=ScanStatus.PASSIVE_DORK,
                    reason="Passive Intel Portal Ready",
                    url=url,
                    category="network_infra",
                )
            )

        if self.offline_only or not info["is_global"] or not HAS_HTTPX:
            return results

        async with MKAsyncClient(self.config) as client:
            rdap_url = f"https://rdap.org/ip/{ip_str}"
            resp = await client.fetch(rdap_url, extra_headers={"Accept": "application/rdap+json"})
            if resp.error_reason:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="RDAP IP / ASN",
                        target=ip_str,
                        target_type=TargetType.IP,
                        status=ScanStatus.ERROR,
                        reason=resp.error_reason,
                        url=rdap_url,
                        category="network_infra",
                    )
                )
            elif resp.status_code == 200:
                try:
                    data = json.loads(resp.text)
                    extracted = {
                        "network_name": data.get("name"),
                        "country": data.get("country"),
                        "handle": data.get("handle"),
                        "start_ip": data.get("startAddress"),
                        "end_ip": data.get("endAddress"),
                    }
                except Exception:  # noqa: BLE001
                    extracted = {}
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="RDAP IP / ASN",
                        target=ip_str,
                        target_type=TargetType.IP,
                        status=ScanStatus.FOUND,
                        url=rdap_url,
                        category="network_infra",
                        extracted_data={k: v for k, v in extracted.items() if v},
                    )
                )
            else:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="RDAP IP / ASN",
                        target=ip_str,
                        target_type=TargetType.IP,
                        status=ScanStatus.RATE_LIMITED if resp.status_code == 429 else ScanStatus.ERROR,
                        reason=f"HTTP {resp.status_code}",
                        url=rdap_url,
                        category="network_infra",
                    )
                )

        return results

    async def _run_domain(self, raw_domain: str) -> List[OSINTResult]:
        domain = normalize_domain(raw_domain)
        decoded = decode_idn_domain(domain)
        mena_country = next(
            (country for tld, country in MENA_COUNTRY_TLDS.items() if domain.endswith(tld)),
            None,
        )

        results: List[OSINTResult] = [
            OSINTResult(
                module_name=self.metadata.name,
                source_name="Domain Structural Profile",
                target=domain,
                target_type=TargetType.DOMAIN,
                status=ScanStatus.FOUND,
                category="network_infra",
                extracted_data={
                    "domain": domain,
                    "unicode_idn": decoded,
                    "mena_country": mena_country or "Global/Generic TLD",
                },
            )
        ]

        for label, url in (
            ("Wayback Machine Archive", f"https://web.archive.org/web/*/{domain}"),
            ("VirusTotal Domain Intel", f"https://www.virustotal.com/gui/domain/{domain}"),
            ("Shodan Domain Search", f"https://www.shodan.io/search?query=hostname:{domain}"),
            ("crt.sh Certificate Logs", f"https://crt.sh/?q=%25.{domain}"),
        ):
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name=label,
                    target=domain,
                    target_type=TargetType.DOMAIN,
                    status=ScanStatus.PASSIVE_DORK,
                    reason="Passive Intel Portal Ready",
                    url=url,
                    category="network_infra",
                )
            )

        if self.offline_only:
            return results

        # Passive DNS resolution
        dns_records = await asyncio.to_thread(_dns_lookup_sync, domain)
        results.append(
            OSINTResult(
                module_name=self.metadata.name,
                source_name="DNS Records (A/AAAA/MX/NS/TXT)",
                target=domain,
                target_type=TargetType.DOMAIN,
                status=ScanStatus.FOUND if dns_records else ScanStatus.NOT_FOUND,
                reason=None if dns_records else "No DNS records resolved",
                category="network_infra",
                extracted_data=dns_records,
            )
        )

        if not HAS_HTTPX:
            return results

        async with MKAsyncClient(self.config) as client:
            # 1. RDAP / WHOIS
            rdap_url = f"https://rdap.org/domain/{domain}"
            rdap_resp = await client.fetch(rdap_url, extra_headers={"Accept": "application/rdap+json"})
            if rdap_resp.error_reason:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="RDAP / WHOIS",
                        target=domain,
                        target_type=TargetType.DOMAIN,
                        status=ScanStatus.ERROR,
                        reason=rdap_resp.error_reason,
                        url=rdap_url,
                        category="network_infra",
                    )
                )
            elif rdap_resp.status_code == 200:
                try:
                    data = json.loads(rdap_resp.text)
                    events = {
                        ev.get("eventAction"): ev.get("eventDate")
                        for ev in data.get("events", [])
                        if isinstance(ev, dict)
                    }
                    nameservers = [
                        ns.get("ldhName") for ns in data.get("nameservers", []) if isinstance(ns, dict)
                    ]
                    extracted = {
                        "status": data.get("status", []),
                        "registered": events.get("registration"),
                        "expires": events.get("expiration"),
                        "nameservers": [n for n in nameservers if n][:6],
                    }
                except Exception:  # noqa: BLE001
                    extracted = {}
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="RDAP / WHOIS",
                        target=domain,
                        target_type=TargetType.DOMAIN,
                        status=ScanStatus.FOUND,
                        url=rdap_url,
                        category="network_infra",
                        extracted_data=extracted,
                    )
                )
            elif rdap_resp.status_code == 404:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="RDAP / WHOIS",
                        target=domain,
                        target_type=TargetType.DOMAIN,
                        status=ScanStatus.NOT_FOUND,
                        url=rdap_url,
                        category="network_infra",
                    )
                )
            else:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="RDAP / WHOIS",
                        target=domain,
                        target_type=TargetType.DOMAIN,
                        status=ScanStatus.RATE_LIMITED if rdap_resp.status_code == 429 else ScanStatus.ERROR,
                        reason=f"HTTP {rdap_resp.status_code}",
                        url=rdap_url,
                        category="network_infra",
                    )
                )

            # 2. Certificate Transparency Subdomain Discovery (crt.sh)
            crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
            crt_resp = await client.fetch(crt_url)
            if crt_resp.error_reason:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="crt.sh Passive Subdomains",
                        target=domain,
                        target_type=TargetType.DOMAIN,
                        status=ScanStatus.ERROR,
                        reason=crt_resp.error_reason,
                        url=crt_url,
                        category="network_infra",
                    )
                )
            elif crt_resp.status_code == 200:
                subs = parse_crtsh_subdomains(crt_resp.text, domain)
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="crt.sh Passive Subdomains",
                        target=domain,
                        target_type=TargetType.DOMAIN,
                        status=ScanStatus.FOUND if subs else ScanStatus.NOT_FOUND,
                        url=f"https://crt.sh/?q=%25.{domain}",
                        category="network_infra",
                        extracted_data={"subdomain_count": len(subs), "subdomains": subs[:20]},
                    )
                )
            else:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="crt.sh Passive Subdomains",
                        target=domain,
                        target_type=TargetType.DOMAIN,
                        status=ScanStatus.RATE_LIMITED if crt_resp.status_code == 429 else ScanStatus.ERROR,
                        reason=f"HTTP {crt_resp.status_code}",
                        url=crt_url,
                        category="network_infra",
                    )
                )

        return results
