"""Automated unit and integration tests for M.K Phase 1 Core."""

from __future__ import annotations

import asyncio
import unittest

from mk_ai.interface import AIInsight, BaseAIProvider
from mk_core.config import ConfigManager
from mk_core.engine import MKEngine
from mk_core.models import OSINTResult, ScanStatus, ScanSummary, SiteCategory, TargetType
from mk_ui.console import MKConsole


class _MockAIProvider(BaseAIProvider):
    name = "mock_local_llm"

    def __init__(self) -> None:
        self.indexed: list[OSINTResult] = []
        self.summarized: list[ScanSummary] = []

    async def health_check(self) -> bool:
        return True

    async def index_result(self, result: OSINTResult) -> None:
        self.indexed.append(result)

    async def index_custom_database(self, file_path: str) -> int:
        return 42

    async def query_database(self, question: str, top_k: int = 5) -> AIInsight:
        return AIInsight(query=question, answer="mock ok", confidence=0.95, provider=self.name)

    async def summarize_scan(self, summary: ScanSummary) -> AIInsight:
        self.summarized.append(summary)
        return AIInsight(query=summary.target, answer="summary ok", confidence=0.9, provider=self.name)


class TestMKPhase1(unittest.TestCase):
    def test_target_type_detection(self) -> None:
        self.assertEqual(MKEngine.detect_target_type("omar@example.com"), TargetType.EMAIL)
        self.assertEqual(MKEngine.detect_target_type("+201001234567"), TargetType.PHONE)
        self.assertEqual(MKEngine.detect_target_type("192.168.1.1"), TargetType.IP)
        self.assertEqual(MKEngine.detect_target_type("example.com.eg"), TargetType.DOMAIN)
        self.assertEqual(MKEngine.detect_target_type("omar_dev99"), TargetType.USERNAME)

    def test_status_formatting_with_reason(self) -> None:
        res_blocked = OSINTResult(
            module_name="m1",
            source_name="Facebook",
            target="testuser",
            target_type=TargetType.USERNAME,
            status=ScanStatus.BLOCKED,
            reason="Cloudflare WAF",
        )
        self.assertEqual(res_blocked.formatted_status, "[BLOCKED (Cloudflare WAF)]")

        res_found = OSINTResult(
            module_name="m1",
            source_name="GitHub",
            target="testuser",
            target_type=TargetType.USERNAME,
            status=ScanStatus.FOUND,
        )
        self.assertEqual(res_found.formatted_status, "[FOUND]")

    def test_fifteen_mena_categories_defined(self) -> None:
        self.assertEqual(len(list(SiteCategory)), 15)

    def test_engine_scan_and_future_ai_hook(self) -> None:
        config = ConfigManager()
        config.set("ai.enabled", True)
        engine = MKEngine(config=config)
        mock_ai = _MockAIProvider()
        engine.ai_manager.set_provider(mock_ai)

        summary = asyncio.run(engine.scan("omar_mena", module_names=["core_diagnostics"]))
        self.assertIn("core_diagnostics", summary.results_by_module)
        self.assertGreaterEqual(len(summary.all_results()), 4)
        self.assertEqual(len(mock_ai.indexed), len(summary.all_results()))
        self.assertEqual(len(mock_ai.summarized), 1)

    def test_console_rendering_smoke(self) -> None:
        engine = MKEngine()
        ui = MKConsole(theme_name="desert_gold")
        summary = asyncio.run(engine.scan("test@example.com", module_names=["core_diagnostics"]))
        ui.show_banner(modules_loaded=len(engine.registry.list_all()))
        ui.show_modules(engine.registry.list_all())
        ui.show_scan_summary(summary)


if __name__ == "__main__":
    unittest.main()
