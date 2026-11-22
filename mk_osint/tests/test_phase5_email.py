"""Offline unit tests for M.K Phase 5 (Email OSINT Intelligence Module)."""

from __future__ import annotations

import asyncio
import unittest

from mk_core.config import ConfigManager
from mk_core.engine import MKEngine
from mk_core.models import ScanStatus, TargetType
from mk_modules.email_osint import EmailOSINTModule, parse_and_profile_email


class TestMKPhase5Email(unittest.TestCase):
    def test_gmail_canonicalization_and_username_candidates(self) -> None:
        info = parse_and_profile_email("Omar.Dev+work@gmail.com")
        self.assertTrue(info["valid"])
        self.assertEqual(info["canonical_email"], "omardev@gmail.com")
        self.assertEqual(info["provider_type"], "free_webmail")
        self.assertIn("omar.dev", info["candidate_usernames"])
        self.assertIn("omardev", info["candidate_usernames"])
        self.assertIn("omar_dev", info["candidate_usernames"])

    def test_arabic_disposable_and_mena_country_detection(self) -> None:
        disp = parse_and_profile_email("temp123@mohmal.com")
        self.assertTrue(disp["is_disposable"])

        eg = parse_and_profile_email("info@company.com.eg")
        self.assertEqual(eg["mena_country"], "Egypt")
        self.assertEqual(eg["provider_type"], "corporate_or_custom")

        il = parse_and_profile_email("user@walla.co.il")
        self.assertEqual(il["mena_country"], "Israel")

    def test_invalid_email_returns_error_status(self) -> None:
        mod = EmailOSINTModule(ConfigManager(), offline_only=True)
        res = asyncio.run(mod.run("not-an-email", TargetType.EMAIL))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].status, ScanStatus.ERROR)

    def test_offline_email_scan_and_engine_discovery(self) -> None:
        mod = EmailOSINTModule(ConfigManager(), offline_only=True)
        results = asyncio.run(mod.run("ahmed.ali@company.sa", TargetType.EMAIL))
        self.assertEqual(results[0].status, ScanStatus.FOUND)
        self.assertEqual(results[0].extracted_data["mena_country"], "Saudi Arabia")
        dorks = [r for r in results if r.status == ScanStatus.PASSIVE_DORK]
        self.assertEqual(len(dorks), 3)

        engine = MKEngine()
        self.assertIsNotNone(engine.registry.get("email_osint"))


if __name__ == "__main__":
    unittest.main()
