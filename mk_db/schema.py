"""SQLite schema & FTS5 full-text search definitions for M.K OSINT Framework."""

from __future__ import annotations

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'OPEN',
    tags_json TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    case_id TEXT,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS results (
    result_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    case_id TEXT,
    dedup_hash TEXT NOT NULL,
    module_name TEXT NOT NULL,
    source_name TEXT NOT NULL,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    url TEXT,
    category TEXT,
    confidence REAL DEFAULT 1.0,
    http_status INTEGER,
    response_time_ms REAL,
    extracted_data_json TEXT DEFAULT '{}',
    tags_json TEXT DEFAULT '[]',
    ai_document TEXT DEFAULT '',
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE SET NULL,
    UNIQUE(scan_id, dedup_hash)
);

CREATE INDEX IF NOT EXISTS idx_results_case ON results(case_id);
CREATE INDEX IF NOT EXISTS idx_results_module ON results(module_name);
CREATE INDEX IF NOT EXISTS idx_results_target ON results(target);
CREATE INDEX IF NOT EXISTS idx_results_status ON results(status);

CREATE VIRTUAL TABLE IF NOT EXISTS results_fts USING fts5(
    result_id UNINDEXED,
    target,
    module_name,
    source_name,
    status,
    reason,
    url,
    extracted_data_json,
    ai_document,
    tokenize='unicode61'
);
"""
