"""Offline unit tests for M.K Phase 2 (Network, OPSEC, Rate Limiter, 6-State Classifier)."""

from __future__ import annotations

import asyncio
import time
import unittest

from mk_core.config import ConfigManager
from mk_core.engine import MKEngine
from mk_core.models import ScanStatus, SiteCategory
from mk_net.classifier import ResponseClassifier, SiteRule
from mk_net.headers import HeaderProfileBuilder
from mk_net.proxy import ProxyManager
from mk_net.rate_limiter import PerDomainRateLimiter


class TestMKPhase2Network(unittest.TestCase):
    def test_classifier_all_six_states(self) -> None:
        rule = SiteRule(
            name="ExampleMENA",
            url_template="https://example.com/{target}",
            category=SiteCategory.SOCIAL_OPEN.value,
            detection_mode="status_code",
            not_found_markers=["user not found", "المستخدم غير موجود"],
        )

        # 1. FOUND
        st, reason = ResponseClassifier.classify(rule, 200, "<html>Profile OK</html>")
        self.assertEqual(st, ScanStatus.FOUND)
        self.assertIsNone(reason)

        # 2. NOT_FOUND (HTTP 404 & Arabic text marker)
        st, reason = ResponseClassifier.classify(rule, 404, "")
        self.assertEqual(st, ScanStatus.NOT_FOUND)
        st2, _ = ResponseClassifier.classify(rule, 200, "المستخدم غير موجود")
        self.assertEqual(st2, ScanStatus.NOT_FOUND)

        # 3. BLOCKED (Cloudflare WAF / Login Wall)
        st, reason = ResponseClassifier.classify(
            rule, 403, "Attention Required! | Cloudflare", headers={"CF-Ray": "123"}
        )
        self.assertEqual(st, ScanStatus.BLOCKED)
        self.assertIn("Cloudflare", reason or "")

        st_login, reason_login = ResponseClassifier.classify(
            rule, 200, "<html>Log in</html>", final_url="https://example.com/accounts/login"
        )
        self.assertEqual(st_login, ScanStatus.BLOCKED)
        self.assertIn("Login Wall", reason_login or "")

        # 4. RATE_LIMITED
        st, reason = ResponseClassifier.classify(
            rule, 429, "Too Many Requests", headers={"Retry-After": "30"}
        )
        self.assertEqual(st, ScanStatus.RATE_LIMITED)
        self.assertIn("429", reason or "")

        # 5. ERROR (Timeout / 502)
        st, reason = ResponseClassifier.classify(rule, None, error_reason="Timeout (ReadTimeout)")
        self.assertEqual(st, ScanStatus.ERROR)
        self.assertIn("Timeout", reason or "")

        st_502, reason_502 = ResponseClassifier.classify(rule, 502, "Bad Gateway")
        self.assertEqual(st_502, ScanStatus.ERROR)
        self.assertIn("502", reason_502 or "")

        # 6. PASSIVE_DORK
        dork_rule = SiteRule(
            name="Facebook",
            url_template="https://www.google.com/search?q=site:facebook.com+%22{target}%22",
            category=SiteCategory.SOCIAL_PROTECTED_DORKS.value,
            detection_mode="passive_dork",
        )
        st, reason = ResponseClassifier.classify(dork_rule, None)
        self.assertEqual(st, ScanStatus.PASSIVE_DORK)
        self.assertIsNotNone(reason)

    def test_proxy_manager_validation(self) -> None:
        cfg = ConfigManager()
        cfg.set("opsec.use_proxy", True)
        cfg.set("opsec.proxy_url", "socks5h://127.0.0.1:9050")
        pm = ProxyManager(cfg)
        pc = pm.get_proxy_config()
        self.assertTrue(pc.enabled)
        self.assertTrue(pc.is_tor_default)

        cfg.set("opsec.proxy_url", "ftp://127.0.0.1:21")
        with self.assertRaises(ValueError):
            pm.get_proxy_config()

    def test_per_domain_rate_limiter_paces_requests(self) -> None:
        limiter = PerDomainRateLimiter(base_delay_ms=60.0, jitter_ms=0.0)

        async def _run() -> float:
            t0 = time.monotonic()
            await limiter.acquire("https://khamsat.com/user/test1")
            await limiter.acquire("https://khamsat.com/user/test2")
            return time.monotonic() - t0

        elapsed = asyncio.run(_run())
        self.assertGreaterEqual(elapsed, 0.05)

    def test_header_builder_arabic_locale(self) -> None:
        headers = HeaderProfileBuilder(prefer_arabic=True).build()
        self.assertIn("ar-EG", headers["Accept-Language"])
        self.assertIn("User-Agent", headers)

    def test_phase2_module_auto_discovered_by_phase1_engine(self) -> None:
        engine = MKEngine()
        self.assertIsNotNone(engine.registry.get("net_opsec_check"))
        summary = asyncio.run(engine.scan("omar_mena", module_names=["net_opsec_check"]))
        self.assertIn("net_opsec_check", summary.results_by_module)


if __name__ == "__main__":
    unittest.main()
