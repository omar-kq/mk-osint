"""Offline unit tests for M.K Phase 4 (15-Category MENA Catalog & Username Engine)."""

from __future__ import annotations

import asyncio
import unittest

from mk_core.config import ConfigManager
from mk_core.engine import MKEngine
from mk_core.models import ScanStatus, SiteCategory, TargetType
from mk_data.site_loader import load_mena_sites
from mk_modules.username_mena import UsernameMENAModule, extract_bio_links


class TestMKPhase4Username(unittest.TestCase):
    def test_catalog_covers_all_15_categories(self) -> None:
        catalog = load_mena_sites()
        grouped = catalog.by_category()
        self.assertGreaterEqual(len(catalog.rules), 115)
        for cat in SiteCategory:
            self.assertIn(cat.value, grouped, f"Missing category {cat.value}")
            self.assertGreaterEqual(len(grouped[cat.value]), 5)

    def test_optional_academic_gov_category_disabled_by_default(self) -> None:
        catalog = load_mena_sites()
        default_rules = catalog.filter(include_optional_academic_gov=False)
        opt_rules = catalog.filter(include_optional_academic_gov=True)

        self.assertFalse(
            any(r.category == SiteCategory.ACADEMIC_PUBLIC_DORKS.value for r in default_rules)
        )
        self.assertTrue(
            any(r.category == SiteCategory.ACADEMIC_PUBLIC_DORKS.value for r in opt_rules)
        )
        self.assertGreater(len(opt_rules), len(default_rules))

    def test_protected_social_platforms_are_strictly_passive_dork(self) -> None:
        catalog = load_mena_sites()
        protected = catalog.filter(categories=[SiteCategory.SOCIAL_PROTECTED_DORKS.value])
        self.assertGreaterEqual(len(protected), 6)
        for rule in protected:
            self.assertEqual(rule.detection_mode, "passive_dork")

    def test_extract_bio_links_parses_social_urls(self) -> None:
        sample_html = """
        <a href="https://github.com/omar_dev">GitHub</a>
        <a href="https://khamsat.com/user/omar_dev">Khamsat</a>
        <a href="https://t.me/omar_dev">Telegram</a>
        <a href="https://github.com/omar_dev">Duplicate</a>
        """
        links = extract_bio_links(sample_html)
        self.assertEqual(len(links), 3)
        self.assertIn("https://khamsat.com/user/omar_dev", links)

    def test_passive_only_username_scan_runs_offline(self) -> None:
        cfg = ConfigManager()
        mod = UsernameMENAModule(cfg, passive_only=True)
        results = asyncio.run(mod.run("@omar_eg", TargetType.USERNAME))
        self.assertGreaterEqual(len(results), 30)
        self.assertTrue(all(r.status == ScanStatus.PASSIVE_DORK for r in results))
        self.assertTrue(all(r.target == "omar_eg" for r in results))

    def test_username_mena_auto_discovered_by_engine(self) -> None:
        engine = MKEngine()
        self.assertIsNotNone(engine.registry.get("username_mena"))


if __name__ == "__main__":
    unittest.main()
