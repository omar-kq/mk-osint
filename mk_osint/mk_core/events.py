"""Asynchronous Event Bus for decoupling M.K core, TUI, storage, and future AI."""

from __future__ import annotations

import asyncio
import inspect
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List


@dataclass
class MKEvent:
    """Event payload emitted across the M.K framework."""

    name: str
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


EventHandler = Callable[[MKEvent], Any]


class EventBus:
    """Publish/subscribe async event dispatcher.

    Standard events:
      - 'scan.started'
      - 'module.started'
      - 'result.discovered'
      - 'module.completed'
      - 'module.failed'
      - 'scan.completed'
    """

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[EventHandler]] = defaultdict(list)

    def subscribe(self, event_name: str, handler: EventHandler) -> None:
        """Register a sync or async handler for a specific event (or '*' wildcard)."""
        if handler not in self._subscribers[event_name]:
            self._subscribers[event_name].append(handler)

    def unsubscribe(self, event_name: str, handler: EventHandler) -> None:
        if handler in self._subscribers.get(event_name, []):
            self._subscribers[event_name].remove(handler)

    async def emit(self, event_name: str, payload: Dict[str, Any] | None = None) -> None:
        """Emit an event to all matching subscribers safely."""
        event = MKEvent(name=event_name, payload=payload or {})
        handlers = list(self._subscribers.get(event_name, [])) + list(
            self._subscribers.get("*", [])
        )
        for handler in handlers:
            result = handler(event)
            if inspect.isawaitable(result):
                await result
