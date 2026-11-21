"""Offline unit tests for M.K Phase 11 (Arabic / Franco-Arab Username Permutations)."""

from __future__ import annotations

import asyncio
import unittest

from mk_core.engine import MKEngine
from mk_core.models import ScanStatus, TargetType
from mk_intel.permutations import generate_username_permutations, transliterate_arabic_word


class TestMKPhase11Permutations(unittest.TestCase):
    def test_arabic_and_franco_transliteration(self) -> None:
        ahmed_vars = transliterate_arabic_word("أحمد")
        self.assertIn("ahmed", ahmed_vars)
        self.assertIn("a7med", ahmed_vars)

        omar_vars = transliterate_arabic_word("عمر")
        self.assertIn("omar", omar_vars)
        self.assertIn("3omar", omar_vars)

    def test_two_word_arabic_name_permutations(self) -> None:
        variants = generate_username_permutations("أحمد صلاح", region_code="eg")
        self.assertIn("ahmed_salah", variants)
        self.assertIn("a7med_salah", variants)
        self.assertIn("ahmed.salah", variants)
        self.assertIn("ahmed_eg", variants)

    def test_latin_username_permutations_and_engine_discovery(self) -> None:
        variants = generate_username_permutations("@khaled", region_code="sa", include_years=("99", "2000"))
        self.assertIn("khaled", variants)
        self.assertIn("khaled_sa", variants)
        self.assertIn("khaled99", variants)

        engine = MKEngine()
        self.assertIsNotNone(engine.registry.get("username_permutations"))
        summary = asyncio.run(
            engine.scan("عمر صلاح", target_type=TargetType.KEYWORD, module_names=["username_permutations"])
        )
        res = summary.results_by_module["username_permutations"][0]
        self.assertEqual(res.status, ScanStatus.FOUND)
        self.assertTrue(res.extracted_data["contains_arabic"])
        self.assertIn("omar_salah", res.extracted_data["variants"])


if __name__ == "__main__":
    unittest.main()
