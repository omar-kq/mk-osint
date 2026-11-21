"""Core orchestration engine for the M.K OSINT Framework."""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from mk_ai.manager import AIManager
from mk_core.config import ConfigManager
from mk_core.events import EventBus
from mk_core.logger import setup_logger
from mk_core.models import OSINTResult, ScanStatus, ScanSummary, TargetType
from mk_core.registry import BaseOSINTModule, PluginRegistry


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[\d\s\-()]{7,20}$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


class MKEngine:
    """Coordinates target detection, concurrent module execution, events, and AI hooks."""

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        event_bus: Optional[EventBus] = None,
    ) -> None:
        self.config = config or ConfigManager()
        self.events = event_bus or EventBus()
        self.logger = setup_logger(
            log_dir=self.config.get("app.log_dir", "logs"),
            level=self.config.get("app.log_level", "INFO"),
        )
        self.registry = PluginRegistry(self.config)
        self.ai_manager = AIManager(self.config, self.events)
        self.registry.discover("mk_modules")

    @staticmethod
    def detect_target_type(target: str) -> TargetType:
        """Automatically infer whether a raw input is an email, phone, IP, domain, or username."""
        cleaned = target.strip()
        if EMAIL_RE.match(cleaned):
            return TargetType.EMAIL
        if IPV4_RE.match(cleaned):
            return TargetType.IP
        if PHONE_RE.match(cleaned) and sum(ch.isdigit() for ch in cleaned) >= 7:
            return TargetType.PHONE
        if DOMAIN_RE.match(cleaned) and " " not in cleaned:
            return TargetType.DOMAIN
        return TargetType.USERNAME

    async def scan(
        self,
        target: str,
        target_type: Optional[TargetType] = None,
        module_names: Optional[List[str]] = None,
        case_id: Optional[str] = None,
    ) -> ScanSummary:
        """Run all matching OSINT modules concurrently and isolate each module's results."""
        resolved_type = target_type or self.detect_target_type(target)
        scan_id = uuid.uuid4().hex[:10]
        summary = ScanSummary(
            scan_id=scan_id,
            case_id=case_id,
            target=target.strip(),
            target_type=resolved_type,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        modules = self.registry.get_for_target(resolved_type, selected_names=module_names)
        await self.events.emit(
            "scan.started",
            {
                "scan_id": scan_id,
                "target": summary.target,
                "target_type": resolved_type.value,
                "modules": [m.metadata.name for m in modules],
            },
        )

        max_conc = int(self.config.get("app.max_concurrency", 15))
        semaphore = asyncio.Semaphore(max(1, max_conc))

        async def _execute_module(mod: BaseOSINTModule) -> None:
            async with semaphore:
                await self.events.emit(
                    "module.started",
                    {"scan_id": scan_id, "module": mod.metadata.name},
                )
                try:
                    results = await mod.run(summary.target, resolved_type)
                    for res in results:
                        summary.add_result(res)
                        await self.events.emit(
                            "result.discovered",
                            {"scan_id": scan_id, "result": res},
                        )
                    await self.events.emit(
                        "module.completed",
                        {
                            "scan_id": scan_id,
                            "module": mod.metadata.name,
                            "count": len(results),
                        },
                    )
                except Exception as exc:  # noqa: BLE001
                    self.logger.exception("Module %s failed: %s", mod.metadata.name, exc)
                    err_result = OSINTResult(
                        module_name=mod.metadata.name,
                        source_name=mod.metadata.display_name,
                        target=summary.target,
                        target_type=resolved_type,
                        status=ScanStatus.ERROR,
                        reason=f"{type(exc).__name__}: {exc}",
                    )
                    summary.add_result(err_result)
                    await self.events.emit(
                        "module.failed",
                        {
                            "scan_id": scan_id,
                            "module": mod.metadata.name,
                            "error": str(exc),
                        },
                    )

        await asyncio.gather(*(_execute_module(m) for m in modules))
        summary.completed_at = datetime.now(timezone.utc).isoformat()
        await self.events.emit("scan.completed", {"summary": summary})
        return summary
