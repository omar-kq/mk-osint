"""M.K Phase 14 — Custom Database Importer (CSV, JSON, JSONL, SQLite, TXT) with Arabic Normalization."""

from __future__ import annotations

import csv
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


ARABIC_DIACRITICS_RE = re.compile(r"[\u064B-\u065F\u0670\u0640]")
NON_WORD_RE = re.compile(r"[^\w\u0600-\u06FF]+", re.UNICODE)


def normalize_arabic_english(text: str) -> str:
    """Normalize Arabic alef/teh/yeh variants and strip tashkeel for high-recall search."""
    cleaned = ARABIC_DIACRITICS_RE.sub("", text.lower())
    cleaned = (
        cleaned.replace("أ", "ا")
        .replace("إ", "ا")
        .replace("آ", "ا")
        .replace("ة", "ه")
        .replace("ى", "ي")
        .replace("ؤ", "و")
        .replace("ئ", "ي")
    )
    return cleaned


def tokenize_bilingual(text: str) -> List[str]:
    """Tokenize Arabic & English text into normalized search terms."""
    norm = normalize_arabic_english(text)
    return [tok for tok in NON_WORD_RE.split(norm) if len(tok) >= 2]


@dataclass
class CustomRecord:
    source_file: str
    record_key: str
    text: str
    raw_data: Dict[str, Any]


class CustomDBImporter:
    """Ingests user-created CSV, JSON/JSONL, SQLite, or TXT datasets into normalized CustomRecords."""

    @classmethod
    def load_file(cls, file_path: str | Path, max_rows: int = 50000) -> List[CustomRecord]:
        path = Path(file_path).expanduser()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Custom database file not found: {path}")

        ext = path.suffix.lower()
        if ext == ".csv":
            return cls._load_csv(path, max_rows)
        if ext in {".json", ".jsonl"}:
            return cls._load_json(path, max_rows)
        if ext in {".db", ".sqlite", ".sqlite3"}:
            return cls._load_sqlite(path, max_rows)
        return cls._load_text(path, max_rows)

    @staticmethod
    def _dict_to_text(row: Dict[str, Any]) -> str:
        return " | ".join(
            f"{k}: {v}" for k, v in row.items() if v is not None and str(v).strip()
        )

    @classmethod
    def _load_csv(cls, path: Path, max_rows: int) -> List[CustomRecord]:
        records: List[CustomRecord] = []
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            for idx, row in enumerate(reader, start=1):
                if idx > max_rows:
                    break
                text = cls._dict_to_text(row)
                if text:
                    records.append(CustomRecord(path.name, f"{path.name}#row{idx}", text, dict(row)))
        return records

    @classmethod
    def _load_json(cls, path: Path, max_rows: int) -> List[CustomRecord]:
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return []
        records: List[CustomRecord] = []
        if path.suffix.lower() == ".jsonl" or not raw.startswith(("[", "{")):
            for idx, line in enumerate(raw.splitlines(), start=1):
                if idx > max_rows or not line.strip():
                    continue
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(CustomRecord(path.name, f"{path.name}#line{idx}", cls._dict_to_text(obj), obj))
        else:
            parsed = json.loads(raw)
            items = parsed if isinstance(parsed, list) else [parsed]
            for idx, obj in enumerate(items[:max_rows], start=1):
                if isinstance(obj, dict):
                    records.append(CustomRecord(path.name, f"{path.name}#item{idx}", cls._dict_to_text(obj), obj))
        return records

    @classmethod
    def _load_sqlite(cls, path: Path, max_rows: int) -> List[CustomRecord]:
        records: List[CustomRecord] = []
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        try:
            tables = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            ]
            for tbl in tables:
                # Safe identifier quoting
                safe_tbl = tbl.replace('"', '""')
                rows = conn.execute(f'SELECT * FROM "{safe_tbl}" LIMIT ?', (max_rows,)).fetchall()
                for idx, row in enumerate(rows, start=1):
                    d = dict(row)
                    text = cls._dict_to_text(d)
                    if text:
                        records.append(CustomRecord(f"{path.name}:{tbl}", f"{tbl}#row{idx}", text, d))
                    if len(records) >= max_rows:
                        return records
        finally:
            conn.close()
        return records

    @staticmethod
    def _load_text(path: Path, max_rows: int) -> List[CustomRecord]:
        records: List[CustomRecord] = []
        for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines()[:max_rows], start=1):
            clean = line.strip()
            if clean:
                records.append(CustomRecord(path.name, f"{path.name}#line{idx}", clean, {"line": clean}))
        return records
