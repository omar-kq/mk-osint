"""End-to-end integration tests verifying all 10 phases of M.K v1.0.0 working together."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from mk_core.engine import MKEngine
from mk_core.models import TargetType
from mk_db.listener import StorageEventListener
from mk_db.repository import MKDatabase
from mk_intel.correlator import EntityCorrelator
from mk_report.exporter import ReportExporter


class TestMKPhase10EndToEnd(unittest.TestCase):
    def test_full_pipeline_scan_db_correlation_and_all_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db = MKDatabase(tmp_path / "mk_test.db")
            engine = MKEngine()
            StorageEventListener(db, engine.events)

            # Verify all 9 plugin modules are discovered cleanly
            loaded_names = {m.metadata.name for m in engine.registry.list_all()}
            expected_modules = {
                "core_diagnostics",
                "net_opsec_check",
                "local_case_search",
                "username_mena",
                "email_osint",
                "phone_mena",
                "domain_net_osint",
                "media_metadata",
                "mena_dorks",
            }
            self.assertTrue(expected_modules.issubset(loaded_names))

            # Create a Case and run an offline-safe phone + mena_dorks scan
            case = db.create_case("E2E MENA Investigation", tags=["EG", "Phase10"])
            summary = asyncio.run(
                engine.scan(
                    "+201001234567",
                    target_type=TargetType.PHONE,
                    module_names=["phone_mena", "mena_dorks"],
                    case_id=case.case_id,
                )
            )

            # Verify auto-persistence into SQLite & FTS5 search
            stored = db.get_results_by_case(case.case_id)
            self.assertIn("phone_mena", stored)
            self.assertIn("mena_dorks", stored)
            self.assertGreaterEqual(len(db.search_fts("Vodafone")), 1)
            self.assertGreaterEqual(len(db.export_ai_corpus(case_id=case.case_id)), 10)

            # Verify Correlation Graph
            graph = EntityCorrelator.build_graph(summary.all_results())
            self.assertGreaterEqual(len(graph.nodes), 2)

            # Verify HTML, JSON, CSV, and Markdown report generation
            exporter = ReportExporter(out_dir=tmp_path / "reports")
            files = exporter.export_all(summary)
            for fmt, fpath in files.items():
                self.assertTrue(fpath.exists(), f"Missing {fmt} report")
                self.assertGreater(fpath.stat().st_size, 100)

            html_text = files["html"].read_text(encoding="utf-8")
            self.assertIn("M.K OSINT Intelligence Report", html_text)
            self.assertIn("phone_mena", html_text)
            db.close()


if __name__ == "__main__":
    unittest.main()
