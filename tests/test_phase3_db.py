"""Automated tests for M.K Phase 3 (SQLite Case Management, Dedup, FTS5, AI Corpus & Auto-Save)."""

from __future__ import annotations

import asyncio
import unittest

from mk_core.engine import MKEngine
from mk_core.models import OSINTResult, ScanStatus, TargetType
from mk_db.listener import StorageEventListener
from mk_db.repository import MKDatabase


class TestMKPhase3Database(unittest.TestCase):
    def test_case_crud_and_deduplication(self) -> None:
        with MKDatabase(":memory:") as db:
            case = db.create_case(
                title="تحقيق شرق أوسط",
                description="ملف اختبار عربي وإنجليزي",
                tags=["MENA", "EG"],
            )
            self.assertEqual(case.status, "OPEN")
            self.assertEqual(len(db.list_cases(status="OPEN")), 1)

            engine = MKEngine()
            StorageEventListener(db, engine.events)
            summary = asyncio.run(
                engine.scan("omar_eg", module_names=["core_diagnostics"], case_id=case.case_id)
            )

            # Duplicate insert of identical result on same scan must be ignored
            first_res = summary.all_results()[0]
            inserted_again = db.save_result(summary.scan_id, first_res, case_id=case.case_id)
            self.assertFalse(inserted_again)

            grouped = db.get_results_by_case(case.case_id)
            self.assertIn("core_diagnostics", grouped)
            self.assertEqual(len(grouped["core_diagnostics"]), len(summary.all_results()))

            self.assertTrue(db.close_case(case.case_id))
            self.assertEqual(db.get_case(case.case_id).status, "CLOSED")

    def test_fts5_arabic_english_search_and_ai_corpus(self) -> None:
        with MKDatabase(":memory:") as db:
            case = db.create_case(title="MENA Search Test")
            engine = MKEngine()
            StorageEventListener(db, engine.events)
            summary = asyncio.run(
                engine.scan("khaled_sa", module_names=["core_diagnostics"], case_id=case.case_id)
            )

            # Add an Arabic-rich finding to verify unicode61 FTS5 indexing
            ar_res = OSINTResult(
                module_name="mena_username",
                source_name="خمسات",
                target="khaled_sa",
                target_type=TargetType.USERNAME,
                status=ScanStatus.FOUND,
                url="https://khamsat.com/user/khaled_sa",
                extracted_data={"bio": "مطور برمجيات من الرياض"},
            )
            self.assertTrue(db.save_result(summary.scan_id, ar_res, case_id=case.case_id))

            hits_ar = db.search_fts("الرياض")
            self.assertEqual(len(hits_ar), 1)
            self.assertEqual(hits_ar[0].source_name, "خمسات")

            hits_en = db.search_fts("Cloudflare")
            self.assertGreaterEqual(len(hits_en), 1)

            corpus = db.export_ai_corpus(case_id=case.case_id)
            self.assertGreaterEqual(len(corpus), 5)
            self.assertIn("ai_document", corpus[0])

            stats = db.get_stats()
            self.assertEqual(stats["cases"], 1)
            self.assertEqual(stats["scans"], 1)
            self.assertGreaterEqual(stats["results"], 5)


if __name__ == "__main__":
    unittest.main()
