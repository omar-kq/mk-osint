"""Offline unit tests for M.K Phase 7 (Domain, DNS, RDAP, crt.sh, and IP/ASN OSINT)."""

from __future__ import annotations

import asyncio
import json
import unittest

from mk_core.config import ConfigManager
from mk_core.engine import MKEngine
from mk_core.models import ScanStatus, TargetType
from mk_modules.domain_net_osint import (
    DomainNetOSINTModule,
    classify_ip_address,
    decode_idn_domain,
    normalize_domain,
    parse_crtsh_subdomains,
)


class TestMKPhase7DomainNet(unittest.TestCase):
    def test_domain_normalization_and_arabic_idn(self) -> None:
        self.assertEqual(normalize_domain("https://Sub.Example.Com.EG/path"), "sub.example.com.eg")
        # Arabic IDN punycode for مصر (xn--wgbh1c)
        decoded = decode_idn_domain("xn--wgbh1c")
        self.assertEqual(decoded, "مصر")

    def test_ip_classification(self) -> None:
        priv = classify_ip_address("192.168.1.10")
        self.assertTrue(priv["valid"])
        self.assertTrue(priv["is_private"])
        self.assertFalse(priv["is_global"])

        pub = classify_ip_address("8.8.8.8")
        self.assertTrue(pub["valid"])
        self.assertTrue(pub["is_global"])

        bad = classify_ip_address("999.999.1.1")
        self.assertFalse(bad["valid"])

    def test_crtsh_subdomain_parser(self) -> None:
        sample = json.dumps([
            {"name_value": "*.example.com\nmail.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "unrelated.org"},
        ])
        subs = parse_crtsh_subdomains(sample, "example.com")
        self.assertEqual(subs, ["api.example.com", "example.com", "mail.example.com"])

    def test_offline_domain_and_ip_scans_and_engine_discovery(self) -> None:
        mod = DomainNetOSINTModule(ConfigManager(), offline_only=True)
        dom_res = asyncio.run(mod.run("news.gov.eg", TargetType.DOMAIN))
        self.assertEqual(dom_res[0].status, ScanStatus.FOUND)
        self.assertEqual(dom_res[0].extracted_data["mena_country"], "Egypt")
        self.assertEqual(len([r for r in dom_res if r.status == ScanStatus.PASSIVE_DORK]), 4)

        ip_res = asyncio.run(mod.run("8.8.8.8", TargetType.IP))
        self.assertEqual(ip_res[0].status, ScanStatus.FOUND)
        self.assertEqual(len([r for r in ip_res if r.status == ScanStatus.PASSIVE_DORK]), 4)

        engine = MKEngine()
        self.assertIsNotNone(engine.registry.get("domain_net_osint"))


if __name__ == "__main__":
    unittest.main()
