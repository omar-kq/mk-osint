"""Offline unit tests for M.K Phase 9 (Entity Correlation Graph & MENA Dork Builder)."""

from __future__ import annotations

import asyncio
import json
import unittest

from mk_core.config import ConfigManager
from mk_core.engine import MKEngine
from mk_core.models import OSINTResult, ScanStatus, TargetType
from mk_intel.correlator import EntityCorrelator
from mk_intel.dork_builder import MENADorkBuilder


class TestMKPhase9Intel(unittest.TestCase):
    def test_cross_module_correlation_and_graph_exports(self) -> None:
        sample_results = [
            OSINTResult(
                module_name="email_osint",
                source_name="Email Structural Profile",
                target="omar.dev@company.com.eg",
                target_type=TargetType.EMAIL,
                status=ScanStatus.FOUND,
                extracted_data={
                    "domain": "company.com.eg",
                    "candidate_usernames": ["omar.dev", "omar_dev"],
                },
            ),
            OSINTResult(
                module_name="username_mena",
                source_name="Khamsat / خمسات",
                target="omar_dev",
                target_type=TargetType.USERNAME,
                status=ScanStatus.FOUND,
                url="https://khamsat.com/user/omar_dev",
                extracted_data={"linked_accounts": ["https://github.com/omar_dev"]},
            ),
            OSINTResult(
                module_name="media_metadata",
                source_name="Extracted GPS Location",
                target="photo.jpg",
                target_type=TargetType.FILE,
                status=ScanStatus.FOUND,
                url="https://www.google.com/maps?q=30.0444,31.2357",
                extracted_data={"latitude": 30.0444, "longitude": 31.2357, "creator": "Omar"},
            ),
        ]

        graph = EntityCorrelator.build_graph(sample_results)
        self.assertGreaterEqual(len(graph.nodes), 6)
        self.assertGreaterEqual(len(graph.edges), 5)
        self.assertEqual(len(graph.pivots), 1)
        self.assertIn("omar_dev", graph.pivots[0])

        # Verify all 3 graph export formats
        parsed = json.loads(graph.to_json())
        self.assertEqual(parsed["node_count"], len(graph.nodes))
        self.assertIn("graph LR", graph.to_mermaid())
        self.assertIn("digraph MK_OSINT", graph.to_graphviz_dot())

    def test_dork_builder_opt_in_gating_and_engine_discovery(self) -> None:
        default_dorks = MENADorkBuilder.build_for_target("omar_eg", include_optional_academic_gov=False)
        opt_dorks = MENADorkBuilder.build_for_target("omar_eg", include_optional_academic_gov=True)
        self.assertEqual(len(default_dorks), 8)
        self.assertEqual(len(opt_dorks), 10)

        engine = MKEngine(ConfigManager())
        self.assertIsNotNone(engine.registry.get("mena_dorks"))
        summary = asyncio.run(engine.scan("omar_eg", module_names=["mena_dorks"]))
        self.assertEqual(len(summary.results_by_module["mena_dorks"]), 8)


if __name__ == "__main__":
    unittest.main()
