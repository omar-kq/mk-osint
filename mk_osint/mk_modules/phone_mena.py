"""M.K Phase 6 — MENA + Israel Phone Intelligence OSINT Module.

Capabilities:
  1. Arabic-Indic numeral normalization (٠١٠... -> 010...).
  2. Offline MENA + Israel carrier, landline governorate/city, line-type, & timezone profiling.
  3. Optional enrichment via Google's `phonenumbers` library when installed.
  4. Multi-format Passive Search Dorks across Google, MENA classifieds (Haraj, Dubizzle,
     OpenSooq, Yad2), social mentions, and public documents without IP ban risk.
"""

from __future__ import annotations

from typing import List
from urllib.parse import quote_plus

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule
from mk_data.mena_telecom import analyze_mena_phone

try:
    import phonenumbers  # type: ignore
    from phonenumbers import carrier as pn_carrier  # type: ignore
    from phonenumbers import geocoder as pn_geocoder  # type: ignore

    HAS_PHONENUMBERS = True
except ImportError:  # pragma: no cover
    HAS_PHONENUMBERS = False


class PhoneMENAModule(BaseOSINTModule):
    """MENA & Israel phone metadata analyzer and passive dork generator."""

    metadata = ModuleMetadata(
        name="phone_mena",
        display_name="MENA + Israel Phone Intelligence",
        version="1.0.0",
        description="Analyzes MENA & Israel phone numbers (carrier, city/governorate, line type, timezone, Arabic numerals) and generates targeted passive dorks.",
        supported_targets=[TargetType.PHONE],
        category="phone",
        requires_network=False,
        passive_only=True,
        enabled_by_default=True,
    )

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        default_region = str(self.config.get("mena.default_region", "EG"))
        info = analyze_mena_phone(target, default_region=default_region)

        if not info.get("valid"):
            return [
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="Phone Validator",
                    target=target,
                    target_type=target_type,
                    status=ScanStatus.ERROR,
                    reason=str(info.get("reason", "Invalid phone number")),
                    category="phone",
                )
            ]

        e164 = str(info["e164"])
        extracted = dict(info)

        # Optional enrichment from Google's libphonenumber if installed on Kali
        if HAS_PHONENUMBERS:
            try:
                parsed = phonenumbers.parse(e164, None)
                extracted["libphonenumber_valid"] = phonenumbers.is_valid_number(parsed)
                lib_carrier = pn_carrier.name_for_number(parsed, "en")
                lib_geo = pn_geocoder.description_for_number(parsed, "en")
                if lib_carrier:
                    extracted["libphonenumber_carrier"] = lib_carrier
                if lib_geo:
                    extracted["libphonenumber_region"] = lib_geo
            except Exception:  # noqa: BLE001
                pass

        results: List[OSINTResult] = [
            OSINTResult(
                module_name=self.metadata.name,
                source_name=f"MENA Telecom Profile ({info['country']})",
                target=e164,
                target_type=target_type,
                status=ScanStatus.FOUND,
                category="phone",
                extracted_data=extracted,
            )
        ]

        # Generate multi-format passive dorks (zero direct scraping of protected platforms)
        variants = list(info.get("search_variants", [e164]))
        or_expr = " OR ".join(f'"{v}"' for v in variants[:3])
        enc_or = quote_plus(f"({or_expr})")
        enc_e164 = quote_plus(e164)

        dork_defs = [
            ("Google Multi-Format Mentions", f"https://www.google.com/search?q={enc_or}"),
            (
                "Social Media Public Mentions (FB/IG/X/TG)",
                f"https://www.google.com/search?q=(site:facebook.com+OR+site:instagram.com+OR+site:x.com+OR+site:t.me)+{enc_or}",
            ),
            (
                "MENA Classifieds (Haraj/Dubizzle/OpenSooq/Yad2)",
                f"https://www.google.com/search?q=(site:haraj.com.sa+OR+site:dubizzle.com.eg+OR+site:opensooq.com+OR+site:yad2.co.il)+{enc_or}",
            ),
            (
                "Public Docs & CVs (PDF/DOCX)",
                f"https://www.google.com/search?q={enc_or}+(filetype:pdf+OR+filetype:docx)",
            ),
            (
                "WhatsApp Direct Public Link Check",
                f"https://wa.me/{e164.lstrip('+')}",
            ),
            (
                "Truecaller Web Dork (Passive)",
                f"https://www.google.com/search?q=site:truecaller.com+{enc_e164}",
            ),
        ]

        for label, dork_url in dork_defs:
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name=label,
                    target=e164,
                    target_type=target_type,
                    status=ScanStatus.PASSIVE_DORK,
                    reason="Passive Search Query Ready",
                    url=dork_url,
                    category="phone",
                )
            )

        return results
