"""Offline unit tests for M.K v2.2 upgrades (7-state SUSPENDED_OR_DELETED, Kali Bridge, Profile Enricher, ELA, dHash, Timeline, Favicon Hash, Circuit Breaker)."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from mk_core.config import ConfigManager
from mk_core.engine import MKEngine
from mk_core.models import OSINTResult, ScanStatus, SiteCategory, TargetType
from mk_data.site_loader import load_mena_sites
from mk_intel.avatar_matcher import HAS_PILLOW, compute_dhash, hamming_similarity
from mk_intel.favicon_hash import compute_shodan_favicon_hash
from mk_intel.timeline import OSINTTimelineBuilder
from mk_modules.kali_bridge import detect_kali_tools
from mk_modules.media_metadata import compute_ela_tampering_score
from mk_modules.profile_enricher import (
    build_bio_origin_dork,
    build_google_lens_url,
    compute_authenticity_score,
    parse_telegram_public_og,
)
from mk_net.circuit_breaker import DomainCircuitBreaker
from mk_net.classifier import ResponseClassifier, SiteRule


class TestMKv22Upgrades(unittest.TestCase):
    def test_suspended_or_deleted_arabic_and_english_detection(self) -> None:
        rule = SiteRule("X", "https://x.com/{target}", SiteCategory.SOCIAL_OPEN.value)

        st_en, reason_en = ResponseClassifier.classify(rule, 200, "This account has been suspended")
        self.assertEqual(st_en, ScanStatus.SUSPENDED_OR_DELETED)
        self.assertIn("Suspended", reason_en or "")

        st_ar, reason_ar = ResponseClassifier.classify(rule, 200, "عذراً، تم حظر هذا الحساب")
        self.assertEqual(st_ar, ScanStatus.SUSPENDED_OR_DELETED)
        self.assertIn("حظر", reason_ar or "")

        st_410, _ = ResponseClassifier.classify(rule, 410, "")
        self.assertEqual(st_410, ScanStatus.SUSPENDED_OR_DELETED)

    def test_circuit_breaker_trips_and_recovers(self) -> None:
        cb = DomainCircuitBreaker(failure_threshold=2, cooldown_seconds=60.0)
        self.assertFalse(cb.is_open("example.com"))
        self.assertFalse(cb.record_failure("example.com"))
        self.assertTrue(cb.record_failure("example.com"))
        self.assertTrue(cb.is_open("example.com"))
        cb.record_success("example.com")
        self.assertFalse(cb.is_open("example.com"))

    def test_profile_enricher_google_lens_bio_origin_and_fake_score(self) -> None:
        lens = build_google_lens_url("https://avatars.githubusercontent.com/u/1")
        self.assertIn("lens.google.com/uploadbyurl", lens)

        dork = build_bio_origin_dork("وما نيل المطالب بالتمني")
        self.assertIn("google.com/search", dork)

        og = parse_telegram_public_og(
            '<meta property="og:title" content="Omar"><meta property="og:description" content="Engineer">'
            '<meta property="og:image" content="https://cdn.t.me/avatar.jpg">'
        )
        self.assertEqual(og["title"], "Omar")
        self.assertEqual(og["avatar_url"], "https://cdn.t.me/avatar.jpg")

        fake = compute_authenticity_score(has_avatar=False, bio="", followers=0, following=200, activity_count=0)
        self.assertLess(fake["authenticity_score"], 40)

    def test_ela_tampering_and_dhash_avatar_matching(self) -> None:
        if not HAS_PILLOW:
            return
        from PIL import Image

        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "a.jpg"
            p2 = Path(tmp) / "b.jpg"
            img = Image.new("RGB", (128, 128), color=(40, 120, 200))
            img.save(p1, "JPEG", quality=95)
            img.resize((64, 64)).save(p2, "JPEG", quality=85)

            ela = compute_ela_tampering_score(p1)
            self.assertIsNotNone(ela)
            self.assertIn("ela_verdict", ela)

            h1 = compute_dhash(p1)
            h2 = compute_dhash(p2)
            self.assertIsNotNone(h1)
            self.assertEqual(hamming_similarity(h1, h2), 100.0)

    def test_timeline_builder_and_shodan_favicon_hash_and_kali_bridge(self) -> None:
        events = OSINTTimelineBuilder.build([
            OSINTResult("domain_net_osint", "RDAP", "example.com", TargetType.DOMAIN, ScanStatus.FOUND, extracted_data={"registered": "2019-03-10"}),
            OSINTResult("media_metadata", "EXIF", "pic.jpg", TargetType.FILE, ScanStatus.FOUND, extracted_data={"DateTimeOriginal": "2024:08:15 12:00:00"}),
        ])
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].date_str, "2019-03-10")

        h = compute_shodan_favicon_hash(b"MK-OSINT-FAVICON")
        self.assertIsInstance(h, int)

        tools_map = detect_kali_tools()
        self.assertIn("exiftool", tools_map)
        self.assertIn("theHarvester", tools_map)

        engine = MKEngine(ConfigManager())
        self.assertIsNotNone(engine.registry.get("kali_toolchain_bridge"))
        self.assertIsNotNone(engine.registry.get("profile_enricher"))
        self.assertGreaterEqual(len(load_mena_sites().rules), 150)


if __name__ == "__main__":
    unittest.main()
