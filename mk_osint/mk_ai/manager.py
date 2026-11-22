"""AIManager wires the optional Local AI provider into M.K's EventBus."""

from __future__ import annotations

from typing import Optional

from mk_ai.interface import AIInsight, BaseAIProvider, NullAIProvider
from mk_core.config import ConfigManager
from mk_core.events import EventBus, MKEvent
from mk_core.models import OSINTResult, ScanSummary


class AIManager:
    """Manages lifecycle, event subscriptions, and future provider swapping."""

    def __init__(
        self,
        config: ConfigManager,
        event_bus: EventBus,
        provider: Optional[BaseAIProvider] = None,
    ) -> None:
        self.config = config
        self.events = event_bus
        self.provider: BaseAIProvider = provider or NullAIProvider()
        self._register_hooks()

    @property
    def is_enabled(self) -> bool:
        return bool(self.config.get("ai.enabled", False)) and not isinstance(
            self.provider, NullAIProvider
        )

    def set_provider(self, provider: BaseAIProvider) -> None:
        """Hot-swap a real local LLM / RAG provider at runtime."""
        self.provider = provider

    def _register_hooks(self) -> None:
        self.events.subscribe("result.discovered", self._on_result_discovered)
        self.events.subscribe("scan.completed", self._on_scan_completed)

    async def _on_result_discovered(self, event: MKEvent) -> None:
        if not self.is_enabled or not self.config.get("ai.auto_index_results", True):
            return
        result: Optional[OSINTResult] = event.payload.get("result")
        if result is not None:
            await self.provider.index_result(result)

    async def _on_scan_completed(self, event: MKEvent) -> None:
        if not self.is_enabled:
            return
        summary: Optional[ScanSummary] = event.payload.get("summary")
        if summary is not None:
            await self.provider.summarize_scan(summary)

    async def ask(self, question: str, top_k: int = 5) -> AIInsight:
        return await self.provider.query_database(question, top_k=top_k)
