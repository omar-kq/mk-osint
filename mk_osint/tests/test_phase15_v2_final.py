"""Final verification tests for M.K v2.1.0 (Cyberpunk 3D Gear, Semantic Colors & Super Search)."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from mk import async_main, run_super_search
from mk_core import __version__
from mk_core.engine import MKEngine
from mk_core.models import TargetType
from mk_db.listener import StorageEventListener
from mk_db.repository import MKDatabase
from mk_ui.banner import GEAR_3D_FRAMES, GEAR_LOGO_3D
from mk_ui.console import MKConsole
from mk_ui.themes import get_theme
from mk_ui.tui_app import HAS_TEXTUAL


class TestMKPhase15V2Final(unittest.TestCase):
    def test_v2_1_cyberpunk_theme_3d_gear_and_all_12_modules(self) -> None:
        self.assertEqual(__version__, "3.0.0")
        theme = get_theme("cyberpunk_neon")
        self.assertIn("00ff9f", theme.found)    # Neon Green for FOUND
        self.assertIn("ff2a6d", theme.blocked)  # Neon Red for BLOCKED
        self.assertIn("ff003c", theme.error)    # Crimson Red for ERROR
        self.assertEqual(len(GEAR_3D_FRAMES), 4)
        self.assertIn("░▒▓", GEAR_LOGO_3D)

        engine = MKEngine()
        names = {m.metadata.name for m in engine.registry.list_all()}
        self.assertEqual(len(names), 14)
        self.assertIsInstance(HAS_TEXTUAL, bool)

    def test_super_search_runs_each_field_independently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = MKDatabase(Path(tmp) / "super.db")
            engine = MKEngine()
            StorageEventListener(db, engine.events)
            ui = MKConsole(theme_name="cyberpunk_neon")

            # Supply phone + keyword independently in one Super Search call
            summaries = asyncio.run(
                run_super_search(
                    engine=engine,
                    db=db,
                    ui=ui,
                    inputs={
                        TargetType.PHONE: "+201001234567",
                        TargetType.KEYWORD: "أحمد صلاح",
                    },
                    module_overrides={
                        TargetType.PHONE: ["phone_mena"],
                        TargetType.KEYWORD: ["username_permutations"],
                    },
                )
            )
            self.assertEqual(len(summaries), 2)
            self.assertEqual(summaries[0].target_type, TargetType.PHONE)
            self.assertEqual(summaries[1].target_type, TargetType.KEYWORD)
            self.assertIn("phone_mena", summaries[0].results_by_module)
            self.assertIn("username_permutations", summaries[1].results_by_module)
            db.close()

    def test_v2_cli_import_db_and_ai_ask_and_batch_e2e(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            csv_db = tmp_path / "mena_custom.csv"
            csv_db.write_text("name,city,phone\nعمر صلاح,القاهرة,+201001234567\n", encoding="utf-8-sig")

            batch_file = tmp_path / "targets.txt"
            batch_file.write_text("+201001234567\n+966501234567\n", encoding="utf-8")

            rc1 = asyncio.run(async_main(["--import-db", str(csv_db), "--ai-ask", "عمر القاهره"]))
            self.assertEqual(rc1, 0)

            rc2 = asyncio.run(
                async_main([
                    "--batch", str(batch_file),
                    "--checkpoint", str(tmp_path / "chk.json"),
                    "-m", "phone_mena",
                    "--export", "json",
                    "--out-dir", str(tmp_path / "reports"),
                ])
            )
            self.assertEqual(rc2, 0)
            self.assertEqual(len(list((tmp_path / "reports").glob("*.json"))), 2)


if __name__ == "__main__":
    unittest.main()
