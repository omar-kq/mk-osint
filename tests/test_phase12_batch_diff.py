"""Offline unit tests for M.K Phase 12 (Batch Queue Scanner & Scan Diff Monitor)."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from mk_core.engine import MKEngine
from mk_core.models import OSINTResult, ScanStatus, TargetType
from mk_intel.batch import BatchQueueScanner, load_targets_file
from mk_intel.diff_monitor import ScanDiffMonitor


class TestMKPhase12BatchAndDiff(unittest.TestCase):
    def test_batch_loader_and_checkpoint_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            txt_file = tmp_path / "targets.txt"
            txt_file.write_text("# MENA targets\n+201001234567\n+966501234567\n+201001234567\n", encoding="utf-8")

            items = load_targets_file(txt_file)
            self.assertEqual(len(items), 2)

            chk = tmp_path / "checkpoint.json"
            engine = MKEngine()
            scanner = BatchQueueScanner(engine, checkpoint_path=chk, max_parallel_targets=2)

            summaries1, skipped1 = asyncio.run(scanner.run_batch(items, module_names=["phone_mena"]))
            self.assertEqual(len(summaries1), 2)
            self.assertEqual(skipped1, 0)

            # Second run with resume=True must skip both already-completed targets
            summaries2, skipped2 = asyncio.run(scanner.run_batch(items, module_names=["phone_mena"], resume=True))
            self.assertEqual(len(summaries2), 0)
            self.assertEqual(skipped2, 2)

    def test_diff_monitor_detects_new_disappeared_and_changed(self) -> None:
        baseline = [
            OSINTResult("username_mena", "GitHub", "omar_eg", TargetType.USERNAME, ScanStatus.FOUND, url="https://github.com/omar_eg"),
            OSINTResult("username_mena", "Khamsat", "omar_eg", TargetType.USERNAME, ScanStatus.FOUND, url="https://khamsat.com/user/omar_eg"),
            OSINTResult("username_mena", "Kick", "omar_eg", TargetType.USERNAME, ScanStatus.BLOCKED, reason="Cloudflare"),
        ]
        current = [
            OSINTResult("username_mena", "GitHub", "omar_eg", TargetType.USERNAME, ScanStatus.FOUND, url="https://github.com/omar_eg"),
            OSINTResult("username_mena", "Khamsat", "omar_eg", TargetType.USERNAME, ScanStatus.NOT_FOUND),
            OSINTResult("username_mena", "Kick", "omar_eg", TargetType.USERNAME, ScanStatus.FOUND, url="https://kick.com/omar_eg"),
            OSINTResult("username_mena", "Mostaql", "omar_eg", TargetType.USERNAME, ScanStatus.FOUND, url="https://mostaql.com/u/omar_eg"),
        ]

        diff = ScanDiffMonitor.compare(baseline, current)
        self.assertTrue(diff.has_changes)
        self.assertEqual(diff.unchanged_count, 1)  # GitHub unchanged
        self.assertEqual(len(diff.newly_found), 2)  # Kick (BLOCKED->FOUND) + Mostaql (new)
        self.assertEqual(len(diff.disappeared), 1)  # Khamsat (FOUND->NOT_FOUND)
        self.assertEqual(len(diff.status_changed), 2)


if __name__ == "__main__":
    unittest.main()
