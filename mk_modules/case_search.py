"""Phase 3 local Case & FTS5 History Lookup module for M.K."""

from __future__ import annotations

from pathlib import Path
from typing import List

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule
from mk_db.repository import MKDatabase


class LocalCaseHistoryModule(BaseOSINTModule):
    """Searches previously saved local SQLite OSINT findings via FTS5."""

    metadata = ModuleMetadata(
        name="local_case_search",
        display_name="Local Case & FTS5 Archive",
        version="1.0.0",
        description="Queries local SQLite FTS5 archive for prior findings matching the target.",
        supported_targets=[
            TargetType.USERNAME,
            TargetType.EMAIL,
            TargetType.PHONE,
            TargetType.DOMAIN,
            TargetType.IP,
            TargetType.KEYWORD,
        ],
        category="storage",
        requires_network=False,
        passive_only=True,
        enabled_by_default=False,  # Run on demand via `-m local_case_search`
    )

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        data_dir = Path(self.config.get("app.data_dir", "data"))
        db_file = data_dir / "mk_osint.db"
        if not db_file.exists():
            return [
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="SQLite Archive",
                    target=target,
                    target_type=target_type,
                    status=ScanStatus.NOT_FOUND,
                    reason="No local database created yet",
                    category="storage",
                )
            ]

        with MKDatabase(db_file) as db:
            hits = db.search_fts(target, limit=25)
            if not hits:
                return [
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="SQLite Archive",
                        target=target,
                        target_type=target_type,
                        status=ScanStatus.NOT_FOUND,
                        category="storage",
                    )
                ]
            return [
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name=f"Archive:{h.module_name}/{h.source_name}",
                    target=target,
                    target_type=target_type,
                    status=h.status,
                    reason=h.reason,
                    url=h.url,
                    category="storage",
                    extracted_data={"original_timestamp": h.timestamp, **h.extracted_data},
                )
                for h in hits
            ]
