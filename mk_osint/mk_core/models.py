"""Unified data models and 7-state status classifiers for the M.K v2.2 OSINT Framework.

Every module in M.K emits standardized `OSINTResult` objects so that:
1. Each module's output is rendered cleanly in its own terminal section.
2. Results distinguish FOUND, SUSPENDED_OR_DELETED (banned/removed), NOT_FOUND,
   BLOCKED (with reason), RATE_LIMITED, ERROR, and PASSIVE_DORK.
3. Results are stored uniformly in SQLite and indexed by the local AI / RAG engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class TargetType(str, Enum):
    """Supported OSINT investigation input types."""

    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    FILE = "file"
    KEYWORD = "keyword"


class ScanStatus(str, Enum):
    """Seven-state status classifier distinguishing active, banned/deleted, absent, blocked, and errors."""

    FOUND = "FOUND"
    SUSPENDED_OR_DELETED = "SUSPENDED_OR_DELETED"
    NOT_FOUND = "NOT_FOUND"
    BLOCKED = "BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    ERROR = "ERROR"
    PASSIVE_DORK = "PASSIVE_DORK"


class SiteCategory(str, Enum):
    """The 15 MENA-prioritized OSINT platform categories."""

    SOCIAL_OPEN = "01_social_open"
    SOCIAL_PROTECTED_DORKS = "02_social_protected_dorks"
    LIVE_STREAMING_CHAT = "03_live_streaming_chat"
    GAMING_STREAMERS = "04_gaming_streamers"
    GAMING_PLATFORMS = "05_gaming_platforms"
    ANONYMOUS_QA = "06_anonymous_qa"
    ECOMMERCE_SHOPPING = "07_ecommerce_shopping"
    MENA_CLASSIFIEDS = "08_mena_classifieds"
    FREELANCE_JOBS = "09_freelance_jobs"
    DESIGN_CREATIVE = "10_design_creative"
    DEV_TECH_FORUMS = "11_dev_tech_forums"
    AUDIO_MUSIC = "12_audio_music"
    BOOKS_ANIME_MEDIA = "13_books_anime_media"
    LINK_IN_BIO = "14_link_in_bio"
    ACADEMIC_PUBLIC_DORKS = "15_academic_public_dorks"


@dataclass
class ModuleMetadata:
    """Self-describing metadata for every M.K plugin module."""

    name: str
    display_name: str
    version: str
    description: str
    supported_targets: List[TargetType]
    category: str = "general"
    requires_network: bool = True
    passive_only: bool = False
    enabled_by_default: bool = True
    author: str = "M.K Core"


@dataclass
class OSINTResult:
    """Single atomic finding returned by an M.K module."""

    module_name: str
    source_name: str
    target: str
    target_type: TargetType
    status: ScanStatus
    url: Optional[str] = None
    reason: Optional[str] = None
    category: Optional[str] = None
    confidence: float = 1.0
    http_status: Optional[int] = None
    response_time_ms: Optional[float] = None
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    result_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def formatted_status(self) -> str:
        """Format status with parenthesized reason when suspended, blocked, rate-limited, or errored."""
        if self.reason:
            return f"[{self.status.value} ({self.reason})]"
        return f"[{self.status.value}]"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["target_type"] = self.target_type.value
        data["status"] = self.status.value
        data["formatted_status"] = self.formatted_status
        return data

    def to_ai_document(self) -> str:
        parts = [
            f"Module: {self.module_name}",
            f"Source: {self.source_name}",
            f"Target ({self.target_type.value}): {self.target}",
            f"Status: {self.formatted_status}",
        ]
        if self.url:
            parts.append(f"URL: {self.url}")
        if self.extracted_data:
            details = ", ".join(f"{k}={v}" for k, v in self.extracted_data.items())
            parts.append(f"Data: {details}")
        return " | ".join(parts)


@dataclass
class ScanSummary:
    """Aggregated outcome of a single target scan across one or more modules."""

    scan_id: str
    case_id: Optional[str]
    target: str
    target_type: TargetType
    started_at: str
    completed_at: Optional[str] = None
    results_by_module: Dict[str, List[OSINTResult]] = field(default_factory=dict)

    def add_result(self, result: OSINTResult) -> None:
        self.results_by_module.setdefault(result.module_name, []).append(result)

    def all_results(self) -> List[OSINTResult]:
        merged: List[OSINTResult] = []
        for mod_results in self.results_by_module.values():
            merged.extend(mod_results)
        return merged

    def counts_by_status(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in ScanStatus}
        for res in self.all_results():
            counts[res.status.value] += 1
        return counts
