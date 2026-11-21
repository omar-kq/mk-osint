"""Future-ready Local AI & Custom Database RAG interface for M.K."""

from mk_ai.interface import AIInsight, BaseAIProvider, NullAIProvider
from mk_ai.manager import AIManager

__all__ = ["AIInsight", "BaseAIProvider", "NullAIProvider", "AIManager"]
