"""M.K v2.2 — Chronological OSINT Timeline Builder across all M.K modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from mk_core.models import OSINTResult


TIMESTAMP_KEYS = (
    "registered",
    "expires",
    "created_at",
    "created",
    "DateTimeOriginal",
    "DateTime",
    "creationdate",
    "first_seen",
    "last_seen",
    "updated_at",
    "modified",
)


@dataclass(frozen=True)
class TimelineEvent:
    date_str: str
    event_type: str
    source: str
    target: str
    module: str


class OSINTTimelineBuilder:
    """Extracts and sorts public timestamps from OSINTResults into a chronological timeline."""

    @staticmethod
    def build(results: List[OSINTResult]) -> List[TimelineEvent]:
        events: List[TimelineEvent] = []
        for res in results:
            data = res.extracted_data or {}
            for key in TIMESTAMP_KEYS:
                val = data.get(key)
                if val and str(val).strip():
                    events.append(
                        TimelineEvent(
                            date_str=str(val).strip(),
                            event_type=key,
                            source=res.source_name,
                            target=res.target,
                            module=res.module_name,
                        )
                    )
        events.sort(key=lambda e: e.date_str)
        return events
