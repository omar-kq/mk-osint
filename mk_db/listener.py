"""EventBus listener that automatically persists MKEngine scans into SQLite."""

from __future__ import annotations

from typing import Optional

from mk_core.events import EventBus, MKEvent
from mk_core.models import ScanSummary
from mk_db.repository import MKDatabase


class StorageEventListener:
    """Subscribes to MKEngine's EventBus to auto-save every completed scan."""

    def __init__(self, db: MKDatabase, event_bus: EventBus) -> None:
        self.db = db
        self.events = event_bus
        self.events.subscribe("scan.completed", self._on_scan_completed)

    def _on_scan_completed(self, event: MKEvent) -> None:
        summary: Optional[ScanSummary] = event.payload.get("summary")
        if summary is not None:
            self.db.save_scan_summary(summary)
