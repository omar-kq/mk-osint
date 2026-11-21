"""M.K Phase 12 — Batch Queue Scanner with JSON Checkpoint & Resume Support."""

from __future__ import annotations

import asyncio
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple

from mk_core.engine import MKEngine
from mk_core.models import ScanSummary, TargetType


@dataclass(frozen=True)
class BatchItem:
    target: str
    target_type: Optional[TargetType] = None


def load_targets_file(file_path: str | Path) -> List[BatchItem]:
    """Load investigation targets from a .txt (one per line) or .csv (target,type) file."""
    path = Path(file_path)
    items: List[BatchItem] = []
    seen: Set[str] = set()

    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                raw_target = (row.get("target") or "").strip()
                if not raw_target or raw_target in seen:
                    continue
                seen.add(raw_target)
                raw_type = (row.get("type") or "").strip().lower()
                t_type = (
                    TargetType(raw_type)
                    if raw_type in {t.value for t in TargetType}
                    else None
                )
                items.append(BatchItem(target=raw_target, target_type=t_type))
    else:
        for line in path.read_text(encoding="utf-8").splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#") or clean in seen:
                continue
            seen.add(clean)
            items.append(BatchItem(target=clean))
    return items


class BatchQueueScanner:
    """Runs multi-target OSINT batches with bounded concurrency and checkpoint resume."""

    def __init__(
        self,
        engine: MKEngine,
        checkpoint_path: Optional[str | Path] = None,
        max_parallel_targets: int = 3,
    ) -> None:
        self.engine = engine
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else None
        self.max_parallel_targets = max(1, max_parallel_targets)

    def _load_completed(self) -> Set[str]:
        if not self.checkpoint_path or not self.checkpoint_path.exists():
            return set()
        try:
            data = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            return set(data.get("completed_targets", []))
        except Exception:  # noqa: BLE001
            return set()

    def _save_completed(self, completed: Set[str]) -> None:
        if not self.checkpoint_path:
            return
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path.write_text(
            json.dumps({"completed_targets": sorted(completed)}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    async def run_batch(
        self,
        items: List[BatchItem],
        module_names: Optional[List[str]] = None,
        case_id: Optional[str] = None,
        resume: bool = True,
    ) -> Tuple[List[ScanSummary], int]:
        """Execute pending targets; returns (completed ScanSummaries, skipped_from_checkpoint_count)."""
        completed_set = self._load_completed() if resume else set()
        pending = [it for it in items if it.target not in completed_set]
        skipped = len(items) - len(pending)

        sem = asyncio.Semaphore(self.max_parallel_targets)
        summaries: List[ScanSummary] = []
        lock = asyncio.Lock()

        async def _worker(item: BatchItem) -> None:
            async with sem:
                summary = await self.engine.scan(
                    target=item.target,
                    target_type=item.target_type,
                    module_names=module_names,
                    case_id=case_id,
                )
                async with lock:
                    summaries.append(summary)
                    completed_set.add(item.target)
                    self._save_completed(completed_set)

        await asyncio.gather(*(_worker(it) for it in pending))
        return summaries, skipped
