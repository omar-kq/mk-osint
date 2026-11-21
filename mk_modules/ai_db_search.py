"""M.K Phase 14 — Auto-discovered Local AI & Custom Database Semantic Search Module."""

from __future__ import annotations

from pathlib import Path
from typing import List

from mk_ai.local_rag import LocalRAGProvider
from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule


class LocalAIDBSearchModule(BaseOSINTModule):
    """Searches indexed custom databases & prior OSINT findings via LocalRAGProvider."""

    metadata = ModuleMetadata(
        name="ai_db_search",
        display_name="Local AI & Custom DB Search",
        version="1.0.0",
        description="Runs bilingual Arabic/English BM25 RAG search over imported custom CSV/JSON/SQLite databases.",
        supported_targets=[
            TargetType.KEYWORD,
            TargetType.USERNAME,
            TargetType.EMAIL,
            TargetType.PHONE,
            TargetType.DOMAIN,
        ],
        category="local_ai",
        requires_network=False,
        passive_only=True,
        enabled_by_default=False,  # Opt-in via `-m ai_db_search`
    )

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        data_dir = Path(self.config.get("app.data_dir", "data"))
        ai_db = data_dir / "ai_index.db"
        if not ai_db.exists():
            return [
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="Local AI Index",
                    target=target,
                    target_type=target_type,
                    status=ScanStatus.NOT_FOUND,
                    reason="No custom DB indexed yet (import via LocalRAGProvider.index_custom_database)",
                    category="local_ai",
                )
            ]

        provider = LocalRAGProvider(
            index_db_path=ai_db,
            ollama_endpoint=str(self.config.get("ai.endpoint", "http://127.0.0.1:11434")),
            model_name=str(self.config.get("ai.model_name", "qwen2.5:3b")),
            use_ollama=bool(self.config.get("ai.enabled", False)),
        )
        try:
            insight = await provider.query_database(target, top_k=10)
            if not insight.matched_records:
                return [
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name="Local AI Index",
                        target=target,
                        target_type=target_type,
                        status=ScanStatus.NOT_FOUND,
                        category="local_ai",
                    )
                ]
            return [
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name=f"AI-DB:{rec['source']}",
                    target=target,
                    target_type=target_type,
                    status=ScanStatus.FOUND,
                    category="local_ai",
                    confidence=min(1.0, float(rec["score"])),
                    extracted_data={"bm25_score": rec["score"], "snippet": rec["text"][:240]},
                )
                for rec in insight.matched_records
            ]
        finally:
            provider.close()
