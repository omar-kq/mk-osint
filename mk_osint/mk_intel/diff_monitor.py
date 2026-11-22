"""M.K Phase 12 — Scan Diff Monitor (Compares New vs. Baseline OSINT Results)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from mk_core.models import OSINTResult, ScanStatus


@dataclass
class StatusChange:
    module_name: str
    source_name: str
    target: str
    old_status: str
    new_status: str
    url: str = ""


@dataclass
class ScanDiffReport:
    """Delta summary highlighting newly appeared, disappeared, and changed findings."""

    newly_found: List[OSINTResult] = field(default_factory=list)
    disappeared: List[OSINTResult] = field(default_factory=list)
    status_changed: List[StatusChange] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.newly_found or self.disappeared or self.status_changed)

    def summary_dict(self) -> Dict[str, int]:
        return {
            "newly_found": len(self.newly_found),
            "disappeared": len(self.disappeared),
            "status_changed": len(self.status_changed),
            "unchanged": self.unchanged_count,
        }


class ScanDiffMonitor:
    """Computes exact deltas between a baseline result set and a newer scan."""

    @staticmethod
    def _key(res: OSINTResult) -> Tuple[str, str, str]:
        return (res.module_name, res.source_name, res.target.lower())

    @classmethod
    def compare(
        cls,
        baseline: List[OSINTResult],
        current: List[OSINTResult],
    ) -> ScanDiffReport:
        old_map: Dict[Tuple[str, str, str], OSINTResult] = {cls._key(r): r for r in baseline}
        new_map: Dict[Tuple[str, str, str], OSINTResult] = {cls._key(r): r for r in current}

        report = ScanDiffReport()

        for key, new_res in new_map.items():
            old_res = old_map.get(key)
            if old_res is None:
                if new_res.status == ScanStatus.FOUND:
                    report.newly_found.append(new_res)
                continue

            if old_res.status == new_res.status:
                report.unchanged_count += 1
            else:
                if old_res.status != ScanStatus.FOUND and new_res.status == ScanStatus.FOUND:
                    report.newly_found.append(new_res)
                elif old_res.status == ScanStatus.FOUND and new_res.status != ScanStatus.FOUND:
                    report.disappeared.append(old_res)
                report.status_changed.append(
                    StatusChange(
                        module_name=new_res.module_name,
                        source_name=new_res.source_name,
                        target=new_res.target,
                        old_status=old_res.formatted_status,
                        new_status=new_res.formatted_status,
                        url=new_res.url or old_res.url or "",
                    )
                )

        # Items previously FOUND that are completely absent from the new scan
        for key, old_res in old_map.items():
            if key not in new_map and old_res.status == ScanStatus.FOUND:
                report.disappeared.append(old_res)

        return report
