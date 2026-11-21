"""Abstract contracts for M.K's optional future Local AI & Custom DB search engine.

Designed so that when a local LLM (Ollama / llama.cpp) and vector store
(FAISS / ChromaDB) are added later, they plug directly into these interfaces
with zero changes to core modules or the TUI.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List

from mk_core.models import OSINTResult, ScanSummary


@dataclass
class AIInsight:
    """Structured output returned by any local AI provider."""

    query: str
    answer: str
    matched_records: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    provider: str = "null"


class BaseAIProvider(ABC):
    """Contract for future offline LLM + Custom Database RAG providers."""

    name: str = "base"

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify whether the local model / vector database is reachable."""

    @abstractmethod
    async def index_result(self, result: OSINTResult) -> None:
        """Index a single OSINTResult into the local vector store."""

    @abstractmethod
    async def index_custom_database(self, file_path: str) -> int:
        """Ingest a user-supplied CSV/JSON/SQLite dataset and return indexed row count."""

    @abstractmethod
    async def query_database(self, question: str, top_k: int = 5) -> AIInsight:
        """Run semantic search (Arabic/English) across indexed OSINT results & custom DBs."""

    @abstractmethod
    async def summarize_scan(self, summary: ScanSummary) -> AIInsight:
        """Generate a concise intelligence brief and entity correlations for a ScanSummary."""


class NullAIProvider(BaseAIProvider):
    """Safe default no-op provider active while AI is disabled in config."""

    name: str = "null"

    async def health_check(self) -> bool:
        return False

    async def index_result(self, result: OSINTResult) -> None:
        return None

    async def index_custom_database(self, file_path: str) -> int:
        return 0

    async def query_database(self, question: str, top_k: int = 5) -> AIInsight:
        return AIInsight(
            query=question,
            answer="Local AI plugin is currently disabled (set ai.enabled=true when ready).",
            matched_records=[],
            confidence=0.0,
            provider=self.name,
        )

    async def summarize_scan(self, summary: ScanSummary) -> AIInsight:
        return AIInsight(
            query=f"summarize:{summary.target}",
            answer="Local AI summarization is disabled in Phase 1.",
            matched_records=[],
            confidence=0.0,
            provider=self.name,
        )
