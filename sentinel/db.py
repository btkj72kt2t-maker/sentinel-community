from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import data_dir, db_path, evidence_dir, reports_dir

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS engagements (
 id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, active_enabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scope (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, value TEXT NOT NULL, allow_subdomains INTEGER NOT NULL DEFAULT 0,
 UNIQUE(engagement_id, kind, value)
);
CREATE TABLE IF NOT EXISTS entities (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, value TEXT NOT NULL, risk TEXT NOT NULL DEFAULT 'unknown',
 attributes TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
 UNIQUE(engagement_id, kind, value)
);
CREATE TABLE IF NOT EXISTS relationships (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 source_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
 target_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
 relation TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 1.0, evidence TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL, UNIQUE(engagement_id, source_id, target_id, relation)
);
CREATE TABLE IF NOT EXISTS findings (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 target TEXT NOT NULL, source TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
 details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_runs (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 tool TEXT NOT NULL, profile TEXT NOT NULL, target TEXT NOT NULL, command TEXT NOT NULL,
 status TEXT NOT NULL, exit_code INTEGER, stdout_path TEXT, stderr_path TEXT,
 started_at TEXT NOT NULL, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS workflows (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 profile TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
 current_step INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_steps (
 id INTEGER PRIMARY KEY, workflow_id INTEGER NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
 position INTEGER NOT NULL, tool TEXT NOT NULL, profile TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 tool_run_id INTEGER REFERENCES tool_runs(id) ON DELETE SET NULL, message TEXT,
 UNIQUE(workflow_id, position)
);
CREATE TABLE IF NOT EXISTS jobs (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
 attempts INTEGER NOT NULL DEFAULT 0, message TEXT, created_at TEXT NOT NULL,
 started_at TEXT, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 original_name TEXT NOT NULL, stored_path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
 action TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def initialize() -> Path:
    for path in (data_dir(), evidence_dir(), reports_dir()):
        path.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path()) as conn:
        conn.executescript(SCHEMA)
        columns = {r[1] for r in conn.execute("PRAGMA table_info(engagements)")}
        for name, declaration in (
            ("lab_mode", "INTEGER NOT NULL DEFAULT 0"),
            ("kill_switch", "INTEGER NOT NULL DEFAULT 0"),
            ("max_rate", "INTEGER NOT NULL DEFAULT 25"),
        ):
            if name not in columns:
                conn.execute(f"ALTER TABLE engagements ADD COLUMN {name} {declaration}")
        finding_columns = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
        for name, declaration in (
            ("fingerprint", "TEXT"),
            ("status", "TEXT NOT NULL DEFAULT 'open'"),
            ("risk_score", "REAL NOT NULL DEFAULT 0"),
            ("occurrences", "INTEGER NOT NULL DEFAULT 1"),
        ):
            if name not in finding_columns:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {name} {declaration}")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS findings_fingerprint_idx ON findings(engagement_id,fingerprint) WHERE fingerprint IS NOT NULL")
    return db_path()


@contextmanager
def connect():
    initialize()
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def audit(conn: sqlite3.Connection, action: str, data: dict, engagement_id: int | None = None) -> None:
    conn.execute(
        "INSERT INTO audit(engagement_id,action,data,created_at) VALUES(?,?,?,?)",
        (engagement_id, action, json.dumps(data, sort_keys=True), now()),
    )


def engagement(conn: sqlite3.Connection, name: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM engagements WHERE name=?", (name,)).fetchone()
    if not row:
        raise ValueError(f"Unknown engagement: {name}")
    return row
