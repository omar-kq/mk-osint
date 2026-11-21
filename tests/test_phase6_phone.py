"""Offline unit tests for M.K Phase 6 (MENA + Israel Phone Intelligence)."""

from __future__ import annotations

import asyncio
import unittest

from mk_core.engine import MKEngine
from mk_core.models import ScanStatus, TargetType
from mk_data.mena_telecom import analyze_mena_phone


class TestMKPhase6Phone(unittest.TestCase):
    def test_egypt_mobile_and_arabic_numerals(self) -> None:
        info = analyze_mena_phone("٠١٠٠١٢٣٤٥٦٧", default_region="EG")
        self.assertTrue(info["valid"])
        self.assertEqual(info["e164"], "+201001234567")
        self.assertEqual(info["country"], "Egypt")
        self.assertEqual(info["line_type"], "Mobile")
        self.assertEqual(info["carrier_or_region"], "Vodafone Egypt")

        landline = analyze_mena_phone("+20693660000")
        self.assertEqual(landline["line_type"], "Landline")
        self.assertEqual(landline["carrier_or_region"], "South Sinai")

    def test_saudi_uae_israel_palestine_carriers(self) -> None:
        sa = analyze_mena_phone("+966501234567")
        self.assertEqual(sa["country"], "Saudi Arabia")
        self.assertEqual(sa["carrier_or_region"], "STC")

        ae = analyze_mena_phone("+971551234567")
        self.assertEqual(ae["country"], "United Arab Emirates")
        self.assertEqual(ae["carrier_or_region"], "du")

        il = analyze_mena_phone("+972521234567")
        self.assertEqual(il["country"], "Israel")
        self.assertEqual(il["carrier_or_region"], "Cellcom")

        ps = analyze_mena_phone("+970591234567")
        self.assertEqual(ps["country"], "Palestine")
        self.assertEqual(ps["carrier_or_region"], "Jawwal")

    def test_engine_runs_phone_mena_module(self) -> None:
        engine = MKEngine()
        summary = asyncio.run(
            engine.scan("+201551234567", target_type=TargetType.PHONE, module_names=["phone_mena"])
        )
        results = summary.results_by_module["phone_mena"]
        self.assertEqual(results[0].status, ScanStatus.FOUND)
        self.assertEqual(results[0].extracted_data["carrier_or_region"], "WE (Telecom Egypt)")
        dorks = [r for r in results if r.status == ScanStatus.PASSIVE_DORK]
        self.assertEqual(len(dorks), 6)


if __name__ == "__main__":
    unittest.main()
