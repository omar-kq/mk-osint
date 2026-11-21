"""Offline unit tests for M.K Phase 14 (Local AI / RAG & Custom CSV/JSON/SQLite Importer)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from mk_ai.custom_db_importer import normalize_arabic_english
from mk_ai.local_rag import LocalRAGProvider
from mk_core.config import ConfigManager
from mk_core.engine import MKEngine


class TestMKPhase14LocalAI(unittest.TestCase):
    def test_arabic_normalization_handles_alef_teh_diacritics(self) -> None:
        self.assertEqual(normalize_arabic_english("أَحْمَدُ مَحْمُود"), "احمد محمود")
        self.assertEqual(normalize_arabic_english("القاهرة الجديدة"), "القاهره الجديده")

    def test_custom_csv_json_sqlite_import_and_bilingual_bm25_search(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            # 1. Custom CSV (Arabic + English)
            csv_file = tmp_path / "contacts.csv"
            csv_file.write_text(
                "name,city,handle,notes\n"
                "أحمد صلاح,القاهرة,ahmed_eg,مهندس شبكات ومطور\n"
                "خالد العتيبي,الرياض,khaled_sa,محلل بيانات\n",
                encoding="utf-8-sig",
            )

            # 2. Custom JSON
            json_file = tmp_path / "domains.json"
            json_file.write_text(
                json.dumps([{"domain": "mena-tech.com.eg", "owner": "omar_dev", "city": "Alexandria"}]),
                encoding="utf-8",
            )

            # 3. Custom SQLite DB
            sql_file = tmp_path / "custom_notes.sqlite"
            conn = sqlite3.connect(str(sql_file))
            conn.execute("CREATE TABLE leads (id INTEGER, title TEXT, phone TEXT)")
            conn.execute("INSERT INTO leads VALUES (1, 'Vodafone Cairo Lead', '+201001234567')")
            conn.commit()
            conn.close()

            provider = LocalRAGProvider(index_db_path=tmp_path / "ai_index.db", use_ollama=False)
            try:
                c1 = asyncio.run(provider.index_custom_database(str(csv_file)))
                c2 = asyncio.run(provider.index_custom_database(str(json_file)))
                c3 = asyncio.run(provider.index_custom_database(str(sql_file)))
                self.assertEqual((c1, c2, c3), (2, 1, 1))

                # Arabic search without hamza must still match 'أحمد صلاح' in 'القاهرة'
                ar_insight = asyncio.run(provider.query_database("احمد القاهره"))
                self.assertGreaterEqual(len(ar_insight.matched_records), 1)
                self.assertIn("ahmed_eg", ar_insight.matched_records[0]["text"])

                # English + Phone search across SQLite table
                en_insight = asyncio.run(provider.query_database("Vodafone +201001234567"))
                self.assertGreaterEqual(len(en_insight.matched_records), 1)
                self.assertIn("Vodafone Cairo Lead", en_insight.matched_records[0]["text"])

                # Hot-swap into Phase 1's MKEngine with zero core changes
                cfg = ConfigManager()
                cfg.set("ai.enabled", True)
                engine = MKEngine(config=cfg)
                engine.ai_manager.set_provider(provider)
                asyncio.run(engine.scan("omar_mena", module_names=["core_diagnostics"]))
                self.assertIsNotNone(engine.registry.get("ai_db_search"))
            finally:
                provider.close()


if __name__ == "__main__":
    unittest.main()
