"""M.K Phase 14 — Offline Local AI / RAG Provider (BM25 Arabic/English Retriever + Optional Ollama LLM)."""

from __future__ import annotations

import json
import math
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mk_ai.custom_db_importer import CustomDBImporter, tokenize_bilingual
from mk_ai.interface import AIInsight, BaseAIProvider
from mk_core.models import OSINTResult, ScanSummary

try:
    import httpx

    HAS_HTTPX = True
except ImportError:  # pragma: no cover
    HAS_HTTPX = False


AI_INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_docs (
    doc_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    text TEXT NOT NULL,
    tokens_json TEXT NOT NULL,
    raw_json TEXT NOT NULL
);
"""


class LocalRAGProvider(BaseAIProvider):
    """Lightweight offline BM25 RAG engine with optional local Ollama LLM synthesis.

    Works 100% offline on CPU-only Kali machines without any GPU or heavy ML packages,
    and automatically upgrades to LLM-synthesized answers if a local Ollama server is running.
    """

    name: str = "local_rag_bm25_ollama"

    def __init__(
        self,
        index_db_path: str | Path = "data/ai_index.db",
        ollama_endpoint: str = "http://127.0.0.1:11434",
        model_name: str = "qwen2.5:3b",
        use_ollama: bool = False,
    ) -> None:
        self.index_db_path = Path(index_db_path)
        if str(index_db_path) != ":memory:":
            self.index_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ollama_endpoint = ollama_endpoint.rstrip("/")
        self.model_name = model_name
        self.use_ollama = use_ollama

        self._conn = sqlite3.connect(str(self.index_db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(AI_INDEX_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    async def health_check(self) -> bool:
        if not self.use_ollama:
            return True  # Offline BM25 engine is always ready
        if not HAS_HTTPX:
            return False
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                r = await client.get(f"{self.ollama_endpoint}/api/tags")
                return r.status_code == 200
        except Exception:  # noqa: BLE001
            return False

    def _upsert_doc(self, doc_id: str, source: str, text: str, raw: Dict[str, Any]) -> None:
        tokens = tokenize_bilingual(text)
        self._conn.execute(
            "INSERT OR REPLACE INTO ai_docs (doc_id, source, text, tokens_json, raw_json) VALUES (?, ?, ?, ?, ?)",
            (
                doc_id,
                source,
                text,
                json.dumps(tokens, ensure_ascii=False),
                json.dumps(raw, ensure_ascii=False),
            ),
        )

    async def index_result(self, result: OSINTResult) -> None:
        self._upsert_doc(
            doc_id=f"osint:{result.result_id}",
            source=f"{result.module_name}/{result.source_name}",
            text=result.to_ai_document(),
            raw=result.to_dict(),
        )
        self._conn.commit()

    async def index_custom_database(self, file_path: str) -> int:
        records = CustomDBImporter.load_file(file_path)
        for rec in records:
            self._upsert_doc(
                doc_id=f"custom:{rec.record_key}",
                source=rec.source_file,
                text=rec.text,
                raw=rec.raw_data,
            )
        self._conn.commit()
        return len(records)

    def _bm25_search(self, question: str, top_k: int = 5) -> List[Tuple[float, Dict[str, Any]]]:
        q_tokens = tokenize_bilingual(question)
        if not q_tokens:
            return []

        rows = self._conn.execute("SELECT doc_id, source, text, tokens_json, raw_json FROM ai_docs").fetchall()
        n_docs = len(rows)
        if n_docs == 0:
            return []

        parsed_docs = []
        df: Counter[str] = Counter()
        total_len = 0
        for row in rows:
            toks = json.loads(row["tokens_json"])
            total_len += len(toks)
            for unique_t in set(toks):
                df[unique_t] += 1
            parsed_docs.append((row, toks, Counter(toks)))

        avgdl = max(1.0, total_len / n_docs)
        k1, b = 1.5, 0.75
        scored: List[Tuple[float, Dict[str, Any]]] = []

        for row, toks, tf_map in parsed_docs:
            score = 0.0
            doc_len = len(toks)
            for qt in q_tokens:
                freq = tf_map.get(qt, 0)
                if freq == 0:
                    continue
                idf = math.log(1.0 + (n_docs - df[qt] + 0.5) / (df[qt] + 0.5))
                denom = freq + k1 * (1.0 - b + b * (doc_len / avgdl))
                score += idf * ((freq * (k1 + 1.0)) / denom)
            if score > 0:
                scored.append(
                    (
                        round(score, 4),
                        {
                            "doc_id": row["doc_id"],
                            "source": row["source"],
                            "text": row["text"],
                            "raw": json.loads(row["raw_json"]),
                        },
                    )
                )

        scored.sort(key=lambda item: item[0], reverse=True)
        return scored[:top_k]

    async def _ask_ollama(self, question: str, context_lines: List[str]) -> Optional[str]:
        if not self.use_ollama or not HAS_HTTPX:
            return None
        prompt = (
            "You are M.K's local offline OSINT research assistant. "
            "Answer concisely using ONLY the retrieved database records below.\n\n"
            "Records:\n" + "\n".join(f"- {line}" for line in context_lines) + f"\n\nQuestion: {question}\nAnswer:"
        )
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    f"{self.ollama_endpoint}/api/generate",
                    json={"model": self.model_name, "prompt": prompt, "stream": False},
                )
                if resp.status_code == 200:
                    return str(resp.json().get("response", "")).strip() or None
        except Exception:  # noqa: BLE001
            return None
        return None

    async def query_database(self, question: str, top_k: int = 5) -> AIInsight:
        hits = self._bm25_search(question, top_k=top_k)
        if not hits:
            return AIInsight(
                query=question,
                answer="No matching records found in the local AI index.",
                matched_records=[],
                confidence=0.0,
                provider=self.name,
            )

        matched = [{"score": score, **doc} for score, doc in hits]
        context_lines = [doc["text"] for _, doc in hits]

        llm_answer = await self._ask_ollama(question, context_lines)
        if llm_answer:
            answer = llm_answer
        else:
            top_preview = "; ".join(f"[{m['source']}] {m['text'][:140]}" for m in matched[:3])
            answer = f"Found {len(matched)} relevant local record(s): {top_preview}"

        return AIInsight(
            query=question,
            answer=answer,
            matched_records=matched,
            confidence=min(1.0, round(hits[0][0] / 3.0, 2)),
            provider=self.name,
        )

    async def summarize_scan(self, summary: ScanSummary) -> AIInsight:
        counts = summary.counts_by_status()
        found_items = [r for r in summary.all_results() if r.status.value == "FOUND"]
        preview = [f"{r.source_name}: {r.url or r.extracted_data}" for r in found_items[:10]]
        base_summary = (
            f"Target '{summary.target}' ({summary.target_type.value}): "
            f"FOUND={counts['FOUND']}, BLOCKED={counts['BLOCKED']}, PASSIVE_DORK={counts['PASSIVE_DORK']}."
        )
        llm_brief = await self._ask_ollama(f"Summarize OSINT scan for {summary.target}", preview or [base_summary])
        return AIInsight(
            query=f"summarize:{summary.target}",
            answer=llm_brief or base_summary,
            matched_records=[r.to_dict() for r in found_items[:10]],
            confidence=0.9 if found_items else 0.5,
            provider=self.name,
        )
