"""Case management, isolated result persistence, FTS5 search, and AI corpus export."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from mk_core.models import OSINTResult, ScanStatus, ScanSummary, TargetType
from mk_db.schema import SCHEMA_SQL


@dataclass
class CaseRecord:
    """Represents an OSINT investigation case grouping multiple scans."""

    case_id: str
    title: str
    description: str = ""
    status: str = "OPEN"
    tags: List[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class MKDatabase:
    """SQLite storage backend with zero external dependencies (stdlib sqlite3)."""

    def __init__(self, db_path: str | Path = "data/mk_osint.db") -> None:
        self.db_path = Path(db_path)
        if str(db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "MKDatabase":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Case Management
    # ------------------------------------------------------------------
    def create_case(
        self,
        title: str,
        description: str = "",
        tags: Optional[List[str]] = None,
        case_id: Optional[str] = None,
    ) -> CaseRecord:
        now = datetime.now(timezone.utc).isoformat()
        record = CaseRecord(
            case_id=case_id or f"CASE-{uuid.uuid4().hex[:8].upper()}",
            title=title.strip(),
            description=description.strip(),
            status="OPEN",
            tags=tags or [],
            created_at=now,
            updated_at=now,
        )
        self._conn.execute(
            """
            INSERT INTO cases (case_id, title, description, status, tags_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.case_id,
                record.title,
                record.description,
                record.status,
                json.dumps(record.tags, ensure_ascii=False),
                record.created_at,
                record.updated_at,
            ),
        )
        self._conn.commit()
        return record

    def get_case(self, case_id: str) -> Optional[CaseRecord]:
        row = self._conn.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_case(row)

    def list_cases(self, status: Optional[str] = None) -> List[CaseRecord]:
        if status:
            rows = self._conn.execute(
                "SELECT * FROM cases WHERE status = ? ORDER BY updated_at DESC",
                (status.upper(),),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM cases ORDER BY updated_at DESC"
            ).fetchall()
        return [self._row_to_case(r) for r in rows]

    def close_case(self, case_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        cur = self._conn.execute(
            "UPDATE cases SET status = 'CLOSED', updated_at = ? WHERE case_id = ?",
            (now, case_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Scans & Deduplicated Results
    # ------------------------------------------------------------------
    def save_scan_summary(self, summary: ScanSummary) -> int:
        """Persist a ScanSummary and all its isolated module results; returns saved count."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO scans (scan_id, case_id, target, target_type, started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                summary.scan_id,
                summary.case_id,
                summary.target,
                summary.target_type.value,
                summary.started_at,
                summary.completed_at,
            ),
        )
        saved = 0
        for result in summary.all_results():
            if self.save_result(summary.scan_id, result, case_id=summary.case_id, commit=False):
                saved += 1
        self._conn.commit()
        return saved

    def save_result(
        self,
        scan_id: str,
        result: OSINTResult,
        case_id: Optional[str] = None,
        commit: bool = True,
    ) -> bool:
        """Insert a single OSINTResult if not already stored for this scan; updates FTS5 index."""
        dedup_hash = self._compute_dedup_hash(result)
        extracted_json = json.dumps(result.extracted_data, ensure_ascii=False, sort_keys=True)
        tags_json = json.dumps(result.tags, ensure_ascii=False)
        ai_doc = result.to_ai_document()

        cur = self._conn.execute(
            """
            INSERT OR IGNORE INTO results (
                result_id, scan_id, case_id, dedup_hash, module_name, source_name,
                target, target_type, status, reason, url, category, confidence,
                http_status, response_time_ms, extracted_data_json, tags_json,
                ai_document, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.result_id,
                scan_id,
                case_id,
                dedup_hash,
                result.module_name,
                result.source_name,
                result.target,
                result.target_type.value,
                result.status.value,
                result.reason,
                result.url,
                result.category,
                result.confidence,
                result.http_status,
                result.response_time_ms,
                extracted_json,
                tags_json,
                ai_doc,
                result.timestamp,
            ),
        )
        inserted = cur.rowcount > 0
        if inserted:
            self._conn.execute(
                """
                INSERT INTO results_fts (
                    result_id, target, module_name, source_name, status,
                    reason, url, extracted_data_json, ai_document
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.result_id,
                    result.target,
                    result.module_name,
                    result.source_name,
                    result.status.value,
                    result.reason or "",
                    result.url or "",
                    extracted_json,
                    ai_doc,
                ),
            )
        if commit:
            self._conn.commit()
        return inserted

    def get_results_by_case(
        self,
        case_id: str,
        module_name: Optional[str] = None,
        status: Optional[ScanStatus] = None,
    ) -> Dict[str, List[OSINTResult]]:
        """Retrieve results for a case, strictly grouped by module_name."""
        query = "SELECT * FROM results WHERE case_id = ?"
        params: List[Any] = [case_id]
        if module_name:
            query += " AND module_name = ?"
            params.append(module_name)
        if status:
            query += " AND status = ?"
            params.append(status.value)
        query += " ORDER BY timestamp DESC"

        grouped: Dict[str, List[OSINTResult]] = {}
        for row in self._conn.execute(query, params).fetchall():
            item = self._row_to_result(row)
            grouped.setdefault(item.module_name, []).append(item)
        return grouped

    # ------------------------------------------------------------------
    # Full-Text Search (Arabic & English) + Future AI Corpus Export
    # ------------------------------------------------------------------
    def search_fts(self, query_text: str, limit: int = 50) -> List[OSINTResult]:
        """Search stored OSINT findings using SQLite FTS5 unicode61 tokenization."""
        cleaned = query_text.strip()
        if not cleaned:
            return []
        # Quote tokens safely so special chars like @, ., +, - do not break FTS syntax
        safe_query = '"' + cleaned.replace('"', '""') + '"'
        rows = self._conn.execute(
            """
            SELECT r.*
            FROM results_fts f
            JOIN results r ON r.result_id = f.result_id
            WHERE results_fts MATCH ?
            ORDER BY r.timestamp DESC
            LIMIT ?
            """,
            (safe_query, limit),
        ).fetchall()
        return [self._row_to_result(r) for r in rows]

    def export_ai_corpus(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Export normalized text chunks + metadata ready for future local Vector/RAG indexing."""
        if case_id:
            rows = self._conn.execute(
                "SELECT result_id, case_id, module_name, source_name, target, status, ai_document, timestamp "
                "FROM results WHERE case_id = ? ORDER BY timestamp ASC",
                (case_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT result_id, case_id, module_name, source_name, target, status, ai_document, timestamp "
                "FROM results ORDER BY timestamp ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> Dict[str, int]:
        cases_cnt = self._conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        scans_cnt = self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        results_cnt = self._conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]
        return {"cases": cases_cnt, "scans": scans_cnt, "results": results_cnt}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _compute_dedup_hash(result: OSINTResult) -> str:
        raw = "|".join(
            [
                result.module_name,
                result.source_name,
                result.target.lower(),
                result.status.value,
                result.url or "",
                result.reason or "",
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    @staticmethod
    def _row_to_case(row: sqlite3.Row) -> CaseRecord:
        return CaseRecord(
            case_id=row["case_id"],
            title=row["title"],
            description=row["description"] or "",
            status=row["status"],
            tags=json.loads(row["tags_json"] or "[]"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _row_to_result(row: sqlite3.Row) -> OSINTResult:
        return OSINTResult(
            result_id=row["result_id"],
            module_name=row["module_name"],
            source_name=row["source_name"],
            target=row["target"],
            target_type=TargetType(row["target_type"]),
            status=ScanStatus(row["status"]),
            reason=row["reason"],
            url=row["url"],
            category=row["category"],
            confidence=float(row["confidence"]),
            http_status=row["http_status"],
            response_time_ms=row["response_time_ms"],
            extracted_data=json.loads(row["extracted_data_json"] or "{}"),
            tags=json.loads(row["tags_json"] or "[]"),
            timestamp=row["timestamp"],
        )
